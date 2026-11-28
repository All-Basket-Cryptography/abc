import Init.Data.Nat.Bitwise.Lemmas

namespace Abc.Spec.Scrypt.Functional

abbrev Byte := BitVec 8
abbrev Bytes := List Byte

def iterate (step : α → α) (start : α) : Nat → α
  | 0 => start
  | n + 1 => step (iterate step start n)

-- RFC 7914 §5 stores consecutive BlockMix iterates in V.
def fillTable (blockMix : α → α) (start : α) : Nat → α × Array α
  | 0 => (start, #[])
  | n + 1 =>
    let previous := fillTable blockMix start n
    (blockMix previous.1, previous.2.push previous.1)

theorem fill_current (blockMix : α → α) (start : α) (count : Nat) :
    (fillTable blockMix start count).1 = iterate blockMix start count := by
  induction count with
  | zero => rfl
  | succ count ih => simp [fillTable, iterate, ih]

theorem fill_size (blockMix : α → α) (start : α) (count : Nat) :
    (fillTable blockMix start count).2.size = count := by
  induction count with
  | zero => rfl
  | succ count ih => simp [fillTable, ih]

theorem fill_lookup (blockMix : α → α) (start : α) (count slot : Nat) (inside : slot < count) :
    (fillTable blockMix start count).2.getD slot start = iterate blockMix start slot := by
  induction count with
  | zero => omega
  | succ previous ih =>
    by_cases last : slot = previous
    · subst slot
      rw [fillTable, Array.getD_eq_getD_getElem?, Array.getElem?_push, fill_size,
        if_pos rfl, Option.getD_some, fill_current]
    · have old : slot < previous := by omega
      have range : slot < (fillTable blockMix start previous).2.size := by
        rw [fill_size]
        exact old
      simpa only [fillTable, Array.getD_eq_getD_getElem?, Array.getElem?_push_lt range,
        getElem?_pos (fillTable blockMix start previous).2 slot range]
        using ih old

/-- The fixed-width slice in a byte workspace selects the corresponding logical row. -/
theorem packed_lookup (rows : List (List α)) (stride slot : Nat)
    (uniform : ∀ row ∈ rows, row.length = stride) (inside : slot < rows.length) :
    (rows.flatten.drop (slot * stride)).take stride = rows[slot] := by
  induction rows generalizing slot with
  | nil => simp at inside
  | cons first rest ih =>
    have firstSize : first.length = stride := uniform first (by simp)
    cases slot with
    | zero =>
      simp only [List.flatten_cons, Nat.zero_mul, List.drop_zero, List.getElem_cons_zero]
      rw [← firstSize, List.take_append_length]
    | succ slot =>
      have tailIndex : slot < rest.length := by simpa using inside
      have headDropped : first.drop (Nat.succ slot * stride) = [] := List.drop_eq_nil_of_le (by
        rw [Nat.succ_mul, firstSize]
        omega)
      have offset : Nat.succ slot * stride - first.length = slot * stride := by
        rw [Nat.succ_mul, firstSize]
        omega
      simp only [List.flatten_cons, List.getElem_cons_succ, List.drop_append, headDropped, List.nil_append, offset]
      exact ih slot (fun row member => uniform row (List.mem_cons_of_mem first member)) tailIndex

def decodeLittleEndian (bytes : Bytes) : Nat :=
  bytes.foldr (fun byte high => byte.toNat + 256 * high) 0

theorem decode_little_append (low high : Bytes) :
    decodeLittleEndian (low ++ high) =
      decodeLittleEndian low + 256 ^ low.length * decodeLittleEndian high := by
  induction low with
  | nil => simp [decodeLittleEndian]
  | cons first bytes ih =>
    change first.toNat + 256 * decodeLittleEndian (bytes ++ high) =
      (first.toNat + 256 * decodeLittleEndian bytes) +
        256 ^ (bytes.length + 1) * decodeLittleEndian high
    rw [ih, Nat.mul_add, Nat.pow_succ, Nat.mul_comm (256 ^ bytes.length) 256, Nat.mul_assoc, Nat.add_assoc]

theorem decode_little_bound (bytes : Bytes) : decodeLittleEndian bytes < 256 ^ bytes.length := by
  induction bytes with
  | nil => decide
  | cons first bytes ih =>
    have octet := first.isLt
    change first.toNat + 256 * decodeLittleEndian bytes < 256 ^ (bytes.length + 1)
    rw [Nat.pow_succ]
    omega

/-- Reading the first eight little-endian octets yields the low 64 bits. -/
theorem low_eight (bytes : Bytes) (fits : 8 ≤ bytes.length) :
    decodeLittleEndian (bytes.take 8) = decodeLittleEndian bytes % 2 ^ 64 := by
  have length : (bytes.take 8).length = 8 := by simp [Nat.min_eq_left fits]
  have low := decode_little_bound (bytes.take 8)
  rw [length] at low
  have split := decode_little_append (bytes.take 8) (bytes.drop 8)
  rw [List.take_append_drop, length] at split
  rw [split]
  change decodeLittleEndian (bytes.take 8) =
    (decodeLittleEndian (bytes.take 8) + 2 ^ 64 * decodeLittleEndian (bytes.drop 8)) % 2 ^ 64
  rw [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt low]

-- The Rust path decodes a u64, casts to usize, then applies the cost mask.
def machineIndex (integer width exponent : Nat) : Nat :=
  ((integer % 2 ^ 64) % 2 ^ width) &&& (2 ^ exponent - 1)

theorem machineIndex_refines (integer width exponent : Nat)
    (inWord : exponent ≤ 64) (inPointer : exponent ≤ width) :
    machineIndex integer width exponent = integer % 2 ^ exponent := by
  rw [machineIndex, Nat.and_two_pow_sub_one_eq_mod,
    Nat.mod_mod_of_dvd _ (Nat.pow_dvd_pow 2 inPointer),
    Nat.mod_mod_of_dvd _ (Nat.pow_dvd_pow 2 inWord)]

structure LaneOps (α : Type) where
  blockMix : α → α
  xor : α → α → α
  integerify : α → Nat

/-- RFC §5 with the original table expressed as the sequence of BlockMix iterates. -/
def rfcRomix (ops : LaneOps α) (lane : α) (count : Nat) : α :=
  let start := iterate ops.blockMix lane count
  iterate (fun current =>
    let j := ops.integerify current % count
    ops.blockMix (ops.xor current (iterate ops.blockMix lane j))) start count

/-- The workspace model builds the table once and looks up its entries in the second pass. -/
def workspaceRomix (ops : LaneOps α) (lane : α) (width exponent : Nat) : α :=
  let count := 2 ^ exponent
  let (current, table) := fillTable ops.blockMix lane count
  iterate (fun value =>
    let j := machineIndex (ops.integerify value) width exponent
    ops.blockMix (ops.xor value (table.getD j lane))) current count

theorem romix_refines (ops : LaneOps α) (lane : α) (width exponent : Nat)
    (inWord : exponent ≤ 64) (inPointer : exponent ≤ width) :
    workspaceRomix ops lane width exponent = rfcRomix ops lane (2 ^ exponent) := by
  let count := 2 ^ exponent
  have lookup (value : α) :
      (fillTable ops.blockMix lane count).2.getD (machineIndex (ops.integerify value) width exponent) lane =
        iterate ops.blockMix lane (ops.integerify value % count) := by
    rw [machineIndex_refines _ _ _ inWord inPointer]
    exact fill_lookup ops.blockMix lane count _ (Nat.mod_lt _ (Nat.two_pow_pos exponent))
  have steps :
      (fun value => ops.blockMix (ops.xor value
        ((fillTable ops.blockMix lane count).2.getD (machineIndex (ops.integerify value) width exponent) lane))) =
        (fun value => ops.blockMix (ops.xor value (iterate ops.blockMix lane (ops.integerify value % count)))) := by
    funext value
    rw [lookup value]
  change iterate _ (fillTable ops.blockMix lane count).1 count = iterate _ (iterate ops.blockMix lane count) count
  rw [steps, fill_current]

abbrev Chunk := Fin 64 → Byte
abbrev Pbkdf2 := Bytes → Bytes → Nat → Nat → Bytes

def xorChunk (first second : Chunk) : Chunk := fun i => first i ^^^ second i

def salsaChain (salsa : Chunk → Chunk) : Chunk → List Chunk → List Chunk
  | _, [] => []
  | previous, block :: blocks =>
    let current := salsa (xorChunk previous block)
    current :: salsaChain salsa current blocks

-- RFC §4 keeps the even-numbered Y blocks before the odd-numbered Y blocks.
def blockMix (salsa : Chunk → Chunk) (r : Nat) (lane : Bytes) : Bytes :=
  let zero : Chunk := fun _ => 0
  let blocks := (List.range (2 * r)).map (fun i (j : Fin 64) => lane[i * 64 + j.val]?.getD 0)
  let output := salsaChain salsa (blocks.getLastD zero) blocks
  let even := (List.range r).map (fun i => output[2 * i]?.getD zero)
  let odd := (List.range r).map (fun i => output[2 * i + 1]?.getD zero)
  (even ++ odd).flatMap List.ofFn

def byteOps (salsa : Chunk → Chunk) (r : Nat) : LaneOps Bytes :=
  ⟨blockMix salsa r, List.zipWith (· ^^^ ·), fun lane => decodeLittleEndian (lane.drop (lane.length - 64))⟩

-- RFC §6 sets the PBKDF2 iteration count to one in both calls.
def deriveWith (pbkdf2 : Pbkdf2) (mix : Bytes → Bytes) (password salt : Bytes)
    (r lanes output : Nat) : Bytes :=
  let stride := 128 * r
  let initial := pbkdf2 password salt 1 (stride * lanes)
  let mixed := (List.range lanes).flatMap
    (fun i => mix ((initial.drop (i * stride)).take stride))
  pbkdf2 password mixed 1 output

/-- Substitution of independently correct Salsa20/8 and PBKDF2 providers
lifts the per-lane result to the RFC construction. -/
theorem construction_refines
    (providerPbkdf2 rfcPbkdf2 : Pbkdf2)
    (providerSalsa rfcSalsa : Chunk → Chunk) (password salt : Bytes)
    (r lanes output width exponent : Nat)
    (pbkdf2Contract : ∀ p s n, providerPbkdf2 p s 1 n = rfcPbkdf2 p s 1 n)
    (salsaContract : ∀ block, providerSalsa block = rfcSalsa block)
    (inWord : exponent ≤ 64) (inPointer : exponent ≤ width) :
    deriveWith providerPbkdf2 (fun lane => workspaceRomix (byteOps providerSalsa r) lane width exponent)
      password salt r lanes output =
    deriveWith rfcPbkdf2 (fun lane => rfcRomix (byteOps rfcSalsa r) lane (2 ^ exponent))
      password salt r lanes output := by
  have sameSalsa : providerSalsa = rfcSalsa := funext salsaContract
  subst providerSalsa
  simp only [deriveWith, pbkdf2Contract, romix_refines _ _ _ _ inWord inPointer]

#print axioms fill_current
#print axioms fill_lookup
#print axioms packed_lookup
#print axioms low_eight
#print axioms machineIndex_refines
#print axioms romix_refines
#print axioms construction_refines

end Abc.Spec.Scrypt.Functional
