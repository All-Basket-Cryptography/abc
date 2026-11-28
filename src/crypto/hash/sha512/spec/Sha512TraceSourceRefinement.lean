import Sha512ApiSourceRefinement

namespace Abc.Refine.Sha512.ApiSource

open Abc.Spec.Sha512 (Message byteLengthAllowed)
open Abc.Refine.Sha512.Streaming
open Abc.Refine.Sha512.StreamSource

structure SourceContext where
  chaining : Registers
  storage : Message
  buffered : Nat
  length : Nat

def SourceContext.valid (ctx : SourceContext) : Prop :=
  ctx.storage.length = 128 ∧ ctx.buffered < 128

def SourceContext.view (ctx : SourceContext) : BufferView Registers :=
  ⟨ctx.chaining, ctx.storage.take ctx.buffered, ctx.length⟩

def sourceNew : SourceContext :=
  ⟨sourceInitialRegisters, sourceInitialStorage, sourceInitialBuffered, sourceInitialPrior⟩

def sourceUpdate (ctx : SourceContext) (input : Message) : Bool × SourceContext :=
  if sourceRejects ctx.length input.length then (false, ctx)
  else
    let next := sourceDriver ctx.storage ctx.buffered input
    (true, ⟨next.emitted.foldl Llbc.generatedCompression ctx.chaining,
      next.storage, next.buffered, sourceCount ctx.length input.length⟩)

def sourceFinalize (ctx : SourceContext) : Message :=
  sourceEncode ((emittedBlocks ctx.storage ctx.buffered ctx.length).foldl Llbc.generatedCompression ctx.chaining)

theorem sourceDigest_eq_composed (message : Message) :
    sourceDigest message =
      let result := sourceUpdate sourceNew message
      if result.1 then some (sourceFinalize result.2) else none := by
  by_cases rejected : sourceRejects sourceInitialPrior message.length
  · simp only [sourceDigest, sourceDigestUsing, sourceUpdate, sourceNew, if_pos rejected]
    rfl
  · simp only [sourceDigest, sourceDigestUsing, sourceUpdate, sourceNew, if_neg rejected]
    rfl

private theorem sameCompression : Llbc.generatedCompression = Abc.Refine.Sha512.compress :=
  funext (fun state => funext (Llbc.generatedCompression_eq state))

theorem sourceUpdate_refines (ctx : SourceContext) (input : Message) (layout : ctx.valid)
    (priorValid : byteLengthAllowed ctx.length) (fitsInput : input.length < 2 ^ 64) :
    let updated := sourceUpdate ctx input
    updated.2.valid ∧ (updated.1, updated.2.view) = update Abc.Refine.Sha512.compress ctx.view input := by
  have agrees := updateWithSourceGate_refines Abc.Refine.Sha512.compress ctx.view input priorValid fitsInput
  rw [← agrees]
  change (sourceUpdate ctx input).2.valid ∧
    ((sourceUpdate ctx input).1, (sourceUpdate ctx input).2.view) =
      updateWithSourceGate Abc.Refine.Sha512.compress ctx.view input
  by_cases rejected : sourceRejects ctx.length input.length
  · simp only [sourceUpdate, if_pos rejected, updateWithSourceGate, SourceContext.view]
    exact ⟨layout, trivial⟩
  · have contract := sourceDriver_refines ctx.storage input ctx.buffered layout.1 layout.2
    have blocks := congrArg Prod.fst contract.2.2
    have tail := congrArg Prod.snd contract.2.2
    dsimp only at blocks tail
    simp only [sourceUpdate, if_neg rejected, sameCompression, updateWithSourceGate, SourceContext.view]
    refine ⟨⟨contract.1, contract.2.1⟩, ?_⟩
    rw [blocks, tail]

theorem sourceFinalize_refines (ctx : SourceContext) (message : Message) (layout : ctx.valid)
    (representation : Represents initialRegisters Abc.Refine.Sha512.compress ctx.view message) :
    some (sourceFinalize ctx) = Abc.Spec.Sha512.digest message := by
  rw [sourceFinalize, sourceEncode_refines, sameCompression, emittedBlocks_refines _ _ _ layout.1 layout.2]
  exact finalize_refines_digest representation

private theorem sourceTrace_preserves (ctx : SourceContext) (msg : Message) (chunks : List Message)
    (layout : ctx.valid) (representation : Represents initialRegisters Abc.Refine.Sha512.compress ctx.view msg)
    (fitsChunks : ∀ input ∈ chunks, input.length < 2 ^ 64) :
    let next := chunks.foldl (fun state input => (sourceUpdate state input).2) ctx
    next.valid ∧ Represents initialRegisters Abc.Refine.Sha512.compress next.view
      (chunks.foldl acceptedAppend msg) := by
  induction chunks generalizing ctx msg with
  | nil => exact ⟨layout, representation⟩
  | cons input later onward =>
    obtain ⟨blocks, part, lengthEq, allowed, foldEq⟩ := representation
    have priorValid : byteLengthAllowed ctx.length := by
      change ctx.length = msg.length at lengthEq
      rw [lengthEq]
      exact allowed
    have agrees := sourceUpdate_refines ctx input layout priorValid (fitsChunks input (by simp))
    have right := congrArg Prod.snd agrees.2
    dsimp only at right
    apply onward _ _ agrees.1
    · rw [right]
      exact trace_preserves_representation ⟨blocks, part, lengthEq, allowed, foldEq⟩ [input]
    · intro chunk member
      exact fitsChunks chunk (List.mem_cons_of_mem input member)

theorem sourceTrace_refines_accepted (chunks : List Message)
    (fitsChunks : ∀ input ∈ chunks, input.length < 2 ^ 64) :
    some (sourceFinalize (chunks.foldl (fun state input => (sourceUpdate state input).2) sourceNew)) =
      Abc.Spec.Sha512.digest (chunks.foldl acceptedAppend []) := by
  have layout : sourceNew.valid := ⟨sourceInitial_refines.2.1, by decide⟩
  have initial : sourceNew.view = emptyView := by
    simp only [SourceContext.view, sourceNew, emptyView, sourceInitial_refines.1,
      sourceInitial_refines.2.2.1, sourceInitial_refines.2.2.2]
  have representation : Represents initialRegisters Abc.Refine.Sha512.compress sourceNew.view [] := by
    rw [initial]
    exact initial_represents _ _
  have trace := sourceTrace_preserves sourceNew [] chunks layout representation fitsChunks
  exact sourceFinalize_refines _ _ trace.1 trace.2

theorem sourceTrace_refines_concat (chunks : List Message)
    (fitsChunks : ∀ input ∈ chunks, input.length < 2 ^ 64)
    (admissible : byteLengthAllowed chunks.flatten.length) :
    some (sourceFinalize (chunks.foldl (fun state input => (sourceUpdate state input).2) sourceNew)) =
      Abc.Spec.Sha512.digest chunks.flatten := by
  rw [sourceTrace_refines_accepted chunks fitsChunks,
    acceptedTrace_eq_concat [] chunks (by simpa using admissible), List.nil_append]

#print axioms sourceDigest_eq_composed
#print axioms sourceUpdate_refines
#print axioms sourceFinalize_refines
#print axioms sourceTrace_refines_accepted
#print axioms sourceTrace_refines_concat

end Abc.Refine.Sha512.ApiSource
