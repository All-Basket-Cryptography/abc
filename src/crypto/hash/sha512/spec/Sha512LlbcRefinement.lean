import Sha512Llbc

namespace Abc.Refine.Sha512.Llbc

open Abc.Spec.Sha512 (Byte)

def generatedLoadWord (block : List Byte) (i : Nat) : UInt64 :=
  load (fun j => readByte block (8 * i + j.val)) 0

theorem generatedLoad_eq (block : List Byte) (i : Nat) :
    generatedLoadWord block i = loadWord block i := by
  rfl

theorem generatedLoad_refines (block : List Byte) (i : Nat) (bound : 8 * i + 8 ≤ block.length) :
    (generatedLoadWord block i).toBitVec = Abc.Spec.Sha512.parseWord ((block.drop (8 * i)).take 8) := by
  rw [generatedLoad_eq, loadWord_refines block i bound]

/-- On the schedule loop's admitted range, the extracted cut reads FIPS dependencies and returns its destination. -/
theorem generatedSchedule_refines (wordAt : Nat → UInt64) (i : Nat)
    (_lower : 16 ≤ i) (_upper : i < 80) :
    (scheduleStep wordAt i).1 = i ∧
    (scheduleStep wordAt i).2.toBitVec =
      Abc.Spec.Sha512.scheduleOne (wordAt (i - 2)).toBitVec + (wordAt (i - 7)).toBitVec +
        Abc.Spec.Sha512.scheduleZero (wordAt (i - 15)).toBitVec + (wordAt (i - 16)).toBitVec := by
  exact ⟨rfl, rfl⟩

theorem generatedRound_refines (state : Registers) (constant messageWord : UInt64) :
    toSpecState (roundStep state constant messageWord) =
      Abc.Spec.Sha512.round (toSpecState state) constant.toBitVec messageWord.toBitVec := by
  rfl

theorem generatedFeed_refines (left right : UInt64) :
    (feedStep left right).toBitVec = left.toBitVec + right.toBitVec := by
  rfl

def generatedSeed (block : List Byte) : Array UInt64 :=
  Array.ofFn fun i : Fin 80 => if i.val < 16 then generatedLoadWord block i.val else 0

def generatedUpdate (fixed : Array UInt64) (i : Nat) : Array UInt64 :=
  let step := scheduleStep (fun j => fixed.getD j 0) (i + 16)
  fixed.setIfInBounds step.1 step.2

def generatedSchedule (block : List Byte) : Array UInt64 :=
  (List.range 64).foldl generatedUpdate (generatedSeed block)

def generatedRounds (words : Array UInt64) (initial : Registers) : Registers :=
  (List.range 80).foldl
    (fun state i => roundStep state (rustConstants.getD i 0) (words.getD i 0)) initial

def generatedFeed (left right : Registers) : Registers :=
  ⟨feedStep left.a right.a, feedStep left.b right.b, feedStep left.c right.c, feedStep left.d right.d,
    feedStep left.e right.e, feedStep left.f right.f, feedStep left.g right.g, feedStep left.h right.h⟩

/-- The SHA-512 compression driver model with all four operations filled from generated LLBC. -/
def generatedCompression (state : Registers) (block : List Byte) : Registers :=
  generatedFeed state (generatedRounds (generatedSchedule block) state)

theorem generatedCompression_eq (state : Registers) (block : List Byte) :
    generatedCompression state block = compress state block := by
  rfl

theorem generatedCompression_refines (state : Registers) (block : List Byte) (width : block.length = 128) :
    toSpecState (generatedCompression state block) =
      Abc.Spec.Sha512.compress (toSpecState state) block := by
  rw [generatedCompression_eq, compress_refines state block width]

#print axioms generatedLoad_refines
#print axioms generatedSchedule_refines
#print axioms generatedRound_refines
#print axioms generatedFeed_refines
#print axioms generatedCompression_eq
#print axioms generatedCompression_refines

end Abc.Refine.Sha512.Llbc
