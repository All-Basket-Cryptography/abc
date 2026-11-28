import Sha512Compression

namespace Abc.Refine.Sha512.Streaming

open Abc.Spec.Sha512

/-- Split bytes into complete 128-byte blocks and a short suffix. -/
def splitBlocks (bytes : Message) : List Message × Message :=
  if bytes.length < 128 then ([], bytes) else
    let rest := splitBlocks (bytes.drop 128)
    (bytes.take 128 :: rest.1, rest.2)
termination_by bytes.length
decreasing_by simp; omega

structure Partition (bytes : Message) (blocks : List Message) (pending : Message) : Prop where
  reconstruct : blocks.flatten ++ pending = bytes
  full : ∀ block ∈ blocks, block.length = 128
  short : pending.length < 128

theorem splitBlocks_partition (bytes : Message) :
    Partition bytes (splitBlocks bytes).1 (splitBlocks bytes).2 := by
  rw [splitBlocks]
  split
  next short =>
    exact ⟨rfl, by simp, short⟩
  next enough =>
    have tail := splitBlocks_partition (bytes.drop 128)
    constructor
    · simp only [List.flatten_cons, List.append_assoc, tail.reconstruct, List.take_append_drop]
    · intro block member
      rcases List.mem_cons.mp member with equal | later
      · subst block
        simp only [List.length_take]
        omega
      · exact tail.full block later
    · exact tail.short
termination_by bytes.length
decreasing_by simp; omega

theorem Partition.feed {message pending : Message} {blocks : List Message}
    (partition : Partition message blocks pending) (input : Message) :
    Partition (message ++ input) (blocks ++ (splitBlocks (pending ++ input)).1)
      (splitBlocks (pending ++ input)).2 := by
  have fresh := splitBlocks_partition (pending ++ input)
  constructor
  · simp only [List.flatten_append, List.append_assoc, fresh.reconstruct]
    rw [← List.append_assoc, partition.reconstruct]
  · intro block member
    exact (List.mem_append.mp member).elim (partition.full block) (fresh.full block)
  · exact fresh.short

/-- The successful write view keeps only the previously initialized prefix and new bytes. -/
def overwriteWindow (storage : Message) (offset : Nat) (input : Message) : Message :=
  storage.take offset ++ input ++ storage.drop (offset + input.length)

theorem overwrittenPrefix (storage input : Message) (offset : Nat) (valid : offset ≤ storage.length) :
    (overwriteWindow storage offset input).take (offset + input.length) =
      storage.take offset ++ input := by
  have prefixLength : (storage.take offset ++ input).length = offset + input.length := by
    simp [Nat.min_eq_left valid]
  rw [overwriteWindow, ← prefixLength, List.take_append_length]

/-- If the Rust update exits early after filling part of its pending block, no block is emitted. -/
theorem fill_buffer_short (pending input : Message) (short : pending.length < 128)
    (inputShort : input.length < 128 - pending.length) :
    splitBlocks (pending ++ input) =
      ([], pending ++ input.take (min (128 - pending.length) input.length)) := by
  have lengthShort : (pending ++ input).length < 128 := by simp; omega
  rw [splitBlocks, if_pos lengthShort, Nat.min_eq_right (by omega)]
  simp

/-- A completed pending block is emitted before splitting the remaining input into blocks. -/
theorem fill_buffer_full (pending input : Message) (short : pending.length < 128)
    (enough : 128 - pending.length ≤ input.length) :
    splitBlocks (pending ++ input) =
      ((pending ++ input.take (128 - pending.length)) ::
        (splitBlocks (input.drop (128 - pending.length))).1,
        (splitBlocks (input.drop (128 - pending.length))).2) := by
  have lengthFull : ¬ (pending ++ input).length < 128 := by simp; omega
  have takePending : pending.take 128 = pending := List.take_of_length_le (by omega)
  have dropPending : pending.drop 128 = [] := List.drop_eq_nil_of_le (by omega)
  rw [splitBlocks, if_neg lengthFull, List.take_append, List.drop_append, takePending, dropPending]
  simp

def maximumBytes : Nat := (2 ^ 128 - 1) / 8

/-- A 64-bit Rust slice length fits the widened 128-bit byte counter. -/
theorem length_cast64_exact (incoming : Nat) (fits : incoming < 2 ^ 64) :
    (BitVec.ofNat 128 incoming).toNat = incoming := by
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]

/-- Model the subtraction-based capacity check before the Rust update. -/
def checkedLength (prior incoming : Nat) : Option Nat :=
  if incoming ≤ maximumBytes - prior then some (prior + incoming) else none

theorem checkedLength_matches_domain (prior incoming : Nat) (priorAllowed : byteLengthAllowed prior) :
    checkedLength prior incoming =
      if byteLengthAllowed (prior + incoming) then some (prior + incoming) else none := by
  have equivalent : incoming ≤ maximumBytes - prior ↔ byteLengthAllowed (prior + incoming) := by
    unfold maximumBytes byteLengthAllowed at *
    omega
  simp only [checkedLength, equivalent]

theorem bitLength_fits (length : Nat) (valid : byteLengthAllowed length) :
    length * 8 < 2 ^ 128 := by
  simpa [byteLengthAllowed, Nat.mul_comm] using valid

/-- The pending bytes are the live prefix of the Rust array. The stale suffix is outside this view. -/
structure BufferView (α : Type) where
  chaining : α
  pending : Message
  length : Nat

def Represents {α : Type} (initial : α) (compress : α → Message → α)
    (view : BufferView α) (message : Message) : Prop :=
  ∃ blocks, Partition message blocks view.pending ∧
    view.length = message.length ∧ byteLengthAllowed message.length ∧
    view.chaining = blocks.foldl compress initial

theorem initial_represents {α : Type} (initial : α) (compress : α → Message → α) :
    Represents initial compress ⟨initial, [], 0⟩ [] := by
  refine ⟨[], ⟨rfl, by simp, ?_⟩, rfl, ?_, rfl⟩
  · change 0 < 128
    decide
  decide

/-- The counter is checked before constructing a new buffer or updating the compression fold. -/
def update {α : Type} (compress : α → Message → α) (view : BufferView α) (input : Message) :
    Bool × BufferView α :=
  match checkedLength view.length input.length with
  | none => (false, view)
  | some length =>
    let split := splitBlocks (view.pending ++ input)
    (true, ⟨split.1.foldl compress view.chaining, split.2, length⟩)

theorem update_rejects_without_mutation {α : Type} (compress : α → Message → α)
    (view : BufferView α) (input : Message)
    (priorAllowed : byteLengthAllowed view.length)
    (disallowed : ¬ byteLengthAllowed (view.length + input.length)) :
    update compress view input = (false, view) := by
  simp [update, checkedLength_matches_domain _ _ priorAllowed, disallowed]

theorem update_preserves_representation {α : Type} {initial : α} {compress : α → Message → α}
    {view : BufferView α} {message : Message} (representation : Represents initial compress view message)
    (input : Message) (allowed : byteLengthAllowed (message.length + input.length)) :
    (update compress view input).1 = true ∧
      Represents initial compress (update compress view input).2 (message ++ input) := by
  rcases representation with ⟨blocks, partition, lengthEq, priorAllowed, foldEq⟩
  have accepted : checkedLength view.length input.length = some (message.length + input.length) := by
    rw [lengthEq, checkedLength_matches_domain _ _ priorAllowed, if_pos allowed]
  rw [update, accepted]
  refine ⟨rfl, blocks ++ (splitBlocks (view.pending ++ input)).1, partition.feed input, ?_, ?_, ?_⟩
  · simp
  · simpa using allowed
  · simp [List.foldl_append, foldEq]

/-- The two Rust finalization branches emit one or two blocks with the same length suffix. -/
def finalBlocks (pending : Message) (length : Nat) : List Message :=
  let suffix := Abc.Foundation.bytesBigEndian 16 (length * 8)
  if pending.length < 112 then
    [pending ++ [0x80] ++ List.replicate (111 - pending.length) 0 ++ suffix]
  else
    [pending ++ [0x80] ++ List.replicate (127 - pending.length) 0,
      List.replicate 112 0 ++ suffix]

theorem finalBlocks_full (pending : Message) (length : Nat) (short : pending.length < 128) :
    ∀ block ∈ finalBlocks pending length, block.length = 128 := by
  intro block member
  unfold finalBlocks at member
  split at member
  next beforeCutoff =>
    simp only [List.mem_singleton] at member
    subst block
    simp [Abc.Foundation.bytesBigEndian]
    omega
  next afterCutoff =>
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with first | second
    · subst block
      simp
      omega
    · subst block
      simp [Abc.Foundation.bytesBigEndian]

theorem finalBlocks_bytes (message pending : Message)
    (short : pending.length < 128) (remainder : message.length % 128 = pending.length) :
    (finalBlocks pending message.length).flatten = pending ++ padding message.length := by
  unfold finalBlocks
  change (if pending.length < 112 then
    [pending ++ [0x80] ++ List.replicate (111 - pending.length) 0 ++
      Abc.Foundation.bytesBigEndian 16 (message.length * 8)]
    else [pending ++ [0x80] ++ List.replicate (127 - pending.length) 0,
      List.replicate 112 0 ++ Abc.Foundation.bytesBigEndian 16 (message.length * 8)]).flatten =
    pending ++ ([0x80] ++ List.replicate ((239 - message.length % 128) % 128) 0 ++
      Abc.Foundation.bytesBigEndian 16 (8 * message.length))
  rw [remainder, Nat.mul_comm 8 message.length]
  split
  next beforeCutoff =>
    have zeros : (239 - pending.length) % 128 = 111 - pending.length := by omega
    simp [zeros, List.append_assoc]
  next afterCutoff =>
    have zeros : (239 - pending.length) % 128 = (127 - pending.length) + 112 := by omega
    simp only [List.flatten_cons, List.flatten_nil, List.append_nil, zeros, List.append_assoc]
    rw [← List.append_assoc (List.replicate (127 - pending.length) (0 : Byte)) (List.replicate 112 0),
      List.replicate_append_replicate]

theorem fullBlocks_length (blocks : List Message) (full : ∀ block ∈ blocks, block.length = 128) :
    blocks.flatten.length = 128 * blocks.length := by
  induction blocks with
  | nil => rfl
  | cons block rest smaller =>
    have first := full block (by simp)
    have later := smaller (fun next member => full next (List.mem_cons_of_mem block member))
    simp only [List.flatten_cons, List.length_append, List.length_cons, first, later]
    omega

theorem Partition.pending_remainder {message pending : Message} {blocks : List Message}
    (partition : Partition message blocks pending) : message.length % 128 = pending.length := by
  have short := partition.short
  rw [← partition.reconstruct, List.length_append, fullBlocks_length blocks partition.full]
  omega

private theorem indexedBlocks_match (blocks : List Message) (full : ∀ block ∈ blocks, block.length = 128) :
    (List.range blocks.length).map
      (fun index => (blocks.flatten.drop (index * 128)).take 128) = blocks := by
  induction blocks with
  | nil => rfl
  | cons first rest smaller =>
    have firstLength : first.length = 128 := full first (by simp)
    have remainingFull : ∀ block ∈ rest, block.length = 128 :=
      fun block member => full block (List.mem_cons_of_mem first member)
    have firstSlice : (first ++ rest.flatten).take 128 = first := by
      rw [← firstLength, List.take_append_length]
    have remainingSlices :
        (List.range rest.length).map
          (fun i => ((first ++ rest.flatten).drop (Nat.succ i * 128)).take 128) = rest := by
      calc
        _ = (List.range rest.length).map (fun i => (rest.flatten.drop (i * 128)).take 128) := by
          apply List.map_congr_left
          intro i _
          have headDropped : first.drop (Nat.succ i * 128) = [] :=
            List.drop_eq_nil_of_le (by omega)
          have tailOffset : Nat.succ i * 128 - first.length = i * 128 := by omega
          rw [List.drop_append, headDropped, List.nil_append, tailOffset]
        _ = rest := smaller remainingFull
    simp only [List.length_cons, List.range_succ_eq_map, List.map_cons, List.map_map,
      Function.comp_def, Nat.zero_mul, List.drop_zero, List.flatten_cons, firstSlice, remainingSlices]

theorem finalize_fold_refines {α : Type} {initial : α} {compress : α → Message → α}
    {view : BufferView α} {message : Message} (representation : Represents initial compress view message) :
    (finalBlocks view.pending view.length).foldl compress view.chaining =
      (List.range ((message ++ padding message.length).length / 128)).foldl
        (fun state i => compress state (((message ++ padding message.length).drop (i * 128)).take 128)) initial := by
  rcases representation with ⟨blocks, partition, lengthEq, _, foldEq⟩
  let completed := blocks ++ finalBlocks view.pending view.length
  have full : ∀ block ∈ completed, block.length = 128 := by
    intro block member
    exact (List.mem_append.mp member).elim (partition.full block)
      (finalBlocks_full view.pending view.length partition.short block)
  have wire : completed.flatten = message ++ padding message.length := by
    change (blocks ++ finalBlocks view.pending view.length).flatten = _
    rw [List.flatten_append, lengthEq,
      finalBlocks_bytes message view.pending partition.short partition.pending_remainder,
      ← List.append_assoc, partition.reconstruct]
  have count : completed.flatten.length / 128 = completed.length := by
    rw [fullBlocks_length completed full]
    omega
  have indexedFold : (List.range completed.length).foldl
      (fun state i => compress state ((completed.flatten.drop (i * 128)).take 128)) initial =
      completed.foldl compress initial := by
    calc
      _ = ((List.range completed.length).map
          (fun i => (completed.flatten.drop (i * 128)).take 128)).foldl compress initial := by
            rw [List.foldl_map]
      _ = _ := by rw [indexedBlocks_match completed full]
  rw [← wire, count, indexedFold]
  change _ = (blocks ++ finalBlocks view.pending view.length).foldl compress initial
  rw [List.foldl_append, ← foldEq]

/-- A caller may continue after an error. Only accepted chunks contribute to its digest. -/
def acceptedAppend (message input : Message) : Message :=
  if byteLengthAllowed (message.length + input.length) then message ++ input else message

theorem trace_preserves_representation {α : Type} {initial : α} {compress : α → Message → α}
    {view : BufferView α} {message : Message}
    (representation : Represents initial compress view message) (chunks : List Message) :
    Represents initial compress
      (chunks.foldl (fun state input => (update compress state input).2) view)
      (chunks.foldl acceptedAppend message) := by
  induction chunks generalizing view message with
  | nil => exact representation
  | cons input remaining onward =>
    apply onward
    by_cases allowed : byteLengthAllowed (message.length + input.length)
    · simpa [acceptedAppend, allowed] using
        (update_preserves_representation representation input allowed).2
    · rcases representation with ⟨blocks, part, lengthEq, priorAllowed, foldEq⟩
      have rejected := update_rejects_without_mutation compress view input
        (by simpa [lengthEq] using priorAllowed) (by simpa [lengthEq] using allowed)
      simp [acceptedAppend, allowed, rejected]
      exact ⟨blocks, part, lengthEq, priorAllowed, foldEq⟩

theorem acceptedTrace_eq_concat (message : Message) (chunks : List Message)
    (allowed : byteLengthAllowed (message ++ chunks.flatten).length) :
    chunks.foldl acceptedAppend message = message ++ chunks.flatten := by
  induction chunks generalizing message with
  | nil => simp
  | cons input remaining onward =>
    have prefixAllowed : byteLengthAllowed (message.length + input.length) := by
      unfold byteLengthAllowed at *
      simp only [List.flatten_cons, List.length_append] at allowed
      omega
    have nextAllowed : byteLengthAllowed ((message ++ input) ++ remaining.flatten).length := by
      simpa only [List.flatten_cons, List.append_assoc] using allowed
    simp only [List.foldl_cons, acceptedAppend, if_pos prefixAllowed]
    rw [onward (message ++ input) nextAllowed, List.append_assoc, List.flatten_cons]

def initialRegisters : Registers :=
  ⟨rustInitial.getD 0 0, rustInitial.getD 1 0, rustInitial.getD 2 0, rustInitial.getD 3 0,
    rustInitial.getD 4 0, rustInitial.getD 5 0, rustInitial.getD 6 0, rustInitial.getD 7 0⟩

theorem initialRegisters_refines : toSpecState initialRegisters = Abc.Spec.Sha512.initial := by
  rfl

def encodeRegisters (r : Registers) : Message :=
  [r.a, r.b, r.c, r.d, r.e, r.f, r.g, r.h].flatMap
    (fun word => Abc.Foundation.bytesBigEndian 8 word.toNat)

theorem encodeRegisters_refines (r : Registers) :
    encodeRegisters r = Abc.Spec.Sha512.encode (toSpecState r) := by
  rfl

theorem foldCompress_refines (blocks : List Message) (state : Registers)
    (full : ∀ block ∈ blocks, block.length = 128) :
    toSpecState (blocks.foldl Abc.Refine.Sha512.compress state) =
      blocks.foldl Abc.Spec.Sha512.compress (toSpecState state) := by
  induction blocks generalizing state with
  | nil => rfl
  | cons first rest onward =>
    simp only [List.foldl_cons]
    rw [onward _ (fun block member => full block (List.mem_cons_of_mem first member)),
      compress_refines state first (full first (by simp))]

def mappedView (view : BufferView Registers) : BufferView State :=
  ⟨toSpecState view.chaining, view.pending, view.length⟩

theorem portable_representation_refines {view : BufferView Registers} {message : Message}
    (representation : Represents initialRegisters Abc.Refine.Sha512.compress view message) :
    Represents Abc.Spec.Sha512.initial Abc.Spec.Sha512.compress (mappedView view) message := by
  rcases representation with ⟨blocks, partition, exactLength, domain, foldEq⟩
  refine ⟨blocks, partition, exactLength, domain, ?_⟩
  change toSpecState view.chaining = blocks.foldl Abc.Spec.Sha512.compress Abc.Spec.Sha512.initial
  rw [foldEq, foldCompress_refines _ _ partition.full, initialRegisters_refines]

def finalizeView (view : BufferView Registers) : Message :=
  encodeRegisters ((finalBlocks view.pending view.length).foldl Abc.Refine.Sha512.compress view.chaining)

theorem finalize_refines_digest {view : BufferView Registers} {message : Message}
    (representation : Represents initialRegisters Abc.Refine.Sha512.compress view message) :
    some (finalizeView view) = Abc.Spec.Sha512.digest message := by
  obtain ⟨blocks, partition, lengthEq, valid, foldEq⟩ := representation
  have full := finalBlocks_full view.pending view.length partition.short
  rw [Abc.Spec.Sha512.digest, if_pos valid, finalizeView, encodeRegisters_refines,
    foldCompress_refines _ _ full]
  have specification := portable_representation_refines (view := view) (message := message)
    ⟨blocks, partition, lengthEq, valid, foldEq⟩
  exact congrArg (some ∘ Abc.Spec.Sha512.encode) (finalize_fold_refines specification)

def emptyView : BufferView Registers := ⟨initialRegisters, [], 0⟩

def digestView (message : Message) : Option Message :=
  let result := update Abc.Refine.Sha512.compress emptyView message
  if result.1 then some (finalizeView result.2) else none

theorem digestView_refines (message : Message) :
    digestView message = Abc.Spec.Sha512.digest message := by
  by_cases allowed : byteLengthAllowed message.length
  · have step := update_preserves_representation
      (initial_represents initialRegisters Abc.Refine.Sha512.compress) message (by simpa using allowed)
    unfold digestView
    rw [if_pos (by simpa [emptyView] using step.1)]
    exact finalize_refines_digest (by simpa [emptyView] using step.2)
  · have rejected := update_rejects_without_mutation Abc.Refine.Sha512.compress emptyView message
      (by show byteLengthAllowed 0; decide) (by simpa [emptyView] using allowed)
    simp [digestView, rejected, Abc.Spec.Sha512.digest, allowed]

def finalizeTrace (chunks : List Message) : Message :=
  finalizeView (chunks.foldl (fun view input => (update Abc.Refine.Sha512.compress view input).2) emptyView)

theorem finalizeTrace_refines_accepted (chunks : List Message) :
    some (finalizeTrace chunks) = Abc.Spec.Sha512.digest (chunks.foldl acceptedAppend []) :=
  finalize_refines_digest (trace_preserves_representation
    (initial_represents initialRegisters Abc.Refine.Sha512.compress) chunks)

theorem finalizeTrace_refines_concat (chunks : List Message)
    (allowed : byteLengthAllowed chunks.flatten.length) :
    some (finalizeTrace chunks) = Abc.Spec.Sha512.digest chunks.flatten := by
  simpa using (finalizeTrace_refines_accepted chunks).trans (congrArg Abc.Spec.Sha512.digest
    (acceptedTrace_eq_concat [] chunks (by simpa using allowed)))

#print axioms checkedLength_matches_domain
#print axioms finalBlocks_bytes
#print axioms update_rejects_without_mutation
#print axioms foldCompress_refines
#print axioms digestView_refines
#print axioms finalizeTrace_refines_accepted
#print axioms finalizeTrace_refines_concat

end Abc.Refine.Sha512.Streaming
