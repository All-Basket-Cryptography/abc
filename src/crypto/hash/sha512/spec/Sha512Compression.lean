import Sha512Spec
import Sha512RustConstants

namespace Abc.Refine.Sha512

open Abc.Spec.Sha512 (Byte Word State)

/-- Unsigned words model the wrapping arithmetic and shifts of the portable Rust core. -/
structure Registers where
  a : UInt64
  b : UInt64
  c : UInt64
  d : UInt64
  e : UInt64
  f : UInt64
  g : UInt64
  h : UInt64

def toSpecState (r : Registers) : State :=
  ⟨r.a.toBitVec, r.b.toBitVec, r.c.toBitVec, r.d.toBitVec,
    r.e.toBitVec, r.f.toBitVec, r.g.toBitVec, r.h.toBitVec⟩

def ofSpecState (s : State) : Registers :=
  ⟨UInt64.ofBitVec s.a, UInt64.ofBitVec s.b, UInt64.ofBitVec s.c, UInt64.ofBitVec s.d,
    UInt64.ofBitVec s.e, UInt64.ofBitVec s.f, UInt64.ofBitVec s.g, UInt64.ofBitVec s.h⟩

@[simp] theorem toSpecState_ofSpecState (s : State) : toSpecState (ofSpecState s) = s := by
  cases s
  rfl

@[simp] theorem ofSpecState_toSpecState (r : Registers) : ofSpecState (toSpecState r) = r := by
  cases r
  rfl

def rotate (value : UInt64) (count : Nat) : UInt64 :=
  UInt64.ofBitVec (value.toBitVec.rotateRight count)

def scheduleWord (w16 w15 w7 w2 : UInt64) : UInt64 :=
  let lower0 := rotate w15 1 ^^^ rotate w15 8 ^^^ (w15 >>> 7)
  let lower1 := rotate w2 19 ^^^ rotate w2 61 ^^^ (w2 >>> 6)
  lower1 + w7 + lower0 + w16

theorem scheduleWord_refines (w16 w15 w7 w2 : UInt64) :
    (scheduleWord w16 w15 w7 w2).toBitVec =
      Abc.Spec.Sha512.scheduleOne w2.toBitVec + w7.toBitVec +
        Abc.Spec.Sha512.scheduleZero w15.toBitVec + w16.toBitVec := by
  rfl

def round (r : Registers) (constant word : UInt64) : Registers :=
  let upper1 := rotate r.e 14 ^^^ rotate r.e 18 ^^^ rotate r.e 41
  let choose := (r.e &&& r.f) ^^^ ((~~~r.e) &&& r.g)
  let temp1 := r.h + upper1 + choose + constant + word
  let upper0 := rotate r.a 28 ^^^ rotate r.a 34 ^^^ rotate r.a 39
  let majority := (r.a &&& r.b) ^^^ (r.a &&& r.c) ^^^ (r.b &&& r.c)
  let temp2 := upper0 + majority
  ⟨temp1 + temp2, r.a, r.b, r.c, r.d + temp1, r.e, r.f, r.g⟩

theorem round_refines (r : Registers) (constant word : UInt64) :
    toSpecState (round r constant word) =
      Abc.Spec.Sha512.round (toSpecState r) constant.toBitVec word.toBitVec := by
  rfl

def feedForward (initial work : Registers) : Registers :=
  ⟨initial.a + work.a, initial.b + work.b, initial.c + work.c, initial.d + work.d,
    initial.e + work.e, initial.f + work.f, initial.g + work.g, initial.h + work.h⟩

theorem feedForward_refines (initial work : Registers) :
    toSpecState (feedForward initial work) =
      Abc.Spec.Sha512.addState (toSpecState initial) (toSpecState work) := by
  rfl

def readByte (block : List Byte) (i : Nat) : Byte := block[i]?.getD 0

/-- Read the bytes assigned to one u64 by the original block's 8-byte chunking. -/
def loadWord (block : List Byte) (i : Nat) : UInt64 :=
  let offset := 8 * i
  UInt64.ofBitVec (((((((readByte block offset ++ readByte block (offset + 1)) ++
    readByte block (offset + 2)) ++ readByte block (offset + 3)) ++
    readByte block (offset + 4)) ++ readByte block (offset + 5)) ++
    readByte block (offset + 6)) ++ readByte block (offset + 7))

private theorem appendByte_toNat {width : Nat} (high : BitVec width) (byte : Byte) :
    (high ++ byte).toNat = 256 * high.toNat + byte.toNat := by
  rw [BitVec.toNat_append]
  rw [← Nat.shiftLeft_add_eq_or_of_lt byte.isLt, Nat.shiftLeft_eq]
  simp [Nat.mul_comm]

private theorem eightBytes_eq (block : List Byte) (offset : Nat)
    (bound : offset + 8 ≤ block.length) :
    (block.drop offset).take 8 =
      [readByte block offset, readByte block (offset + 1), readByte block (offset + 2),
       readByte block (offset + 3), readByte block (offset + 4), readByte block (offset + 5),
       readByte block (offset + 6), readByte block (offset + 7)] := by
  apply List.ext_getElem?
  intro j
  by_cases inside : j < 8
  · have alternatives : j = 0 ∨ j = 1 ∨ j = 2 ∨ j = 3 ∨ j = 4 ∨ j = 5 ∨ j = 6 ∨ j = 7 := by omega
    have within (k : Nat) (h : k < 8) : offset + k < block.length := by omega
    have first : offset < block.length := by omega
    rcases alternatives with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp [readByte, List.getElem?_drop, getElem?_pos, inside, within, first, Nat.add_comm]
  · rw [List.getElem?_take_eq_none (by omega)]
    exact (List.getElem?_eq_none (by simp; omega)).symm

theorem loadWord_refines (block : List Byte) (i : Nat) (bound : 8 * i + 8 ≤ block.length) :
    (loadWord block i).toBitVec = Abc.Spec.Sha512.parseWord ((block.drop (8 * i)).take 8) := by
  rw [eightBytes_eq block (8 * i) bound]
  apply BitVec.eq_of_toNat_eq
  simp [loadWord, appendByte_toNat, Abc.Spec.Sha512.parseWord, Abc.Foundation.decodeBigEndian]
  omega

def seedSchedule (block : List Byte) : Array UInt64 :=
  Array.ofFn fun i : Fin 80 => if i.val < 16 then loadWord block i.val else 0

def updateSchedule (fixed : Array UInt64) (i : Nat) : Array UInt64 :=
  let t := i + 16
  fixed.setIfInBounds t (scheduleWord (fixed.getD (t - 16) 0) (fixed.getD (t - 15) 0)
    (fixed.getD (t - 7) 0) (fixed.getD (t - 2) 0))

def SchedulePrefix (fixed : Array UInt64) (growing : Array Word) (processed : Nat) : Prop :=
  fixed.size = 80 ∧ growing.size = processed + 16 ∧
    ∀ i < growing.size, (fixed.getD i 0).toBitVec = growing.getD i 0

theorem seedSchedule_refines (block : List Byte) (blockSize : block.length = 128) :
    SchedulePrefix (seedSchedule block) (Abc.Spec.Sha512.seedSchedule block) 0 := by
  refine ⟨by simp [seedSchedule], by simp [Abc.Spec.Sha512.seedSchedule], ?_⟩
  intro i limit
  have h16 : i < 16 := by simpa [Abc.Spec.Sha512.seedSchedule] using limit
  have h80 : i < 80 := by omega
  simp [seedSchedule, Abc.Spec.Sha512.seedSchedule, h16, h80, loadWord_refines block i (by omega)]

theorem updateSchedule_refines (fixed : Array UInt64) (growing : Array Word) (i : Nat)
    (hRound : i < 64) (hPrefix : SchedulePrefix fixed growing i) :
    SchedulePrefix (updateSchedule fixed i) (Abc.Spec.Sha512.appendScheduleWord growing i) (i + 1) := by
  obtain ⟨fixedSize, growingSize, agrees⟩ := hPrefix
  have writeBound : i + 16 < fixed.size := by omega
  have valueAgrees :
      (scheduleWord (fixed.getD (i + 16 - 16) 0) (fixed.getD (i + 16 - 15) 0)
        (fixed.getD (i + 16 - 7) 0) (fixed.getD (i + 16 - 2) 0)).toBitVec =
        Abc.Spec.Sha512.scheduleOne (growing.getD (i + 14) 0) + growing.getD (i + 9) 0 +
          Abc.Spec.Sha512.scheduleZero (growing.getD (i + 1) 0) + growing.getD i 0 := by
    rw [scheduleWord_refines]
    have h0 : i + 16 - 16 = i := by omega
    have h1 : i + 16 - 15 = i + 1 := by omega
    have h9 : i + 16 - 7 = i + 9 := by omega
    have h14 : i + 16 - 2 = i + 14 := by omega
    rw [h0, h1, h9, h14, agrees i (by omega), agrees (i + 1) (by omega),
      agrees (i + 9) (by omega), agrees (i + 14) (by omega)]
  refine ⟨by simp [updateSchedule, fixedSize], by simp [Abc.Spec.Sha512.appendScheduleWord, growingSize], ?_⟩
  intro index indexBound
  have limit : index < growing.size + 1 := by simpa [Abc.Spec.Sha512.appendScheduleWord] using indexBound
  by_cases written : index = i + 16
  · subst index
    simpa only [updateSchedule, Abc.Spec.Sha512.appendScheduleWord, Array.getD_eq_getD_getElem?,
      Array.getElem?_setIfInBounds_self_of_lt writeBound, Array.getElem?_push, growingSize,
      if_true, Option.getD_some] using valueAgrees
  · have old : index < growing.size := by omega
    have different : i + 16 ≠ index := Ne.symm written
    simpa only [updateSchedule, Abc.Spec.Sha512.appendScheduleWord, Array.getD_eq_getD_getElem?,
      Array.getElem?_setIfInBounds_ne different, Array.getElem?_push_lt old, getElem?_pos growing index old]
      using agrees index old

def schedule (block : List Byte) : Array UInt64 :=
  (List.range 64).foldl updateSchedule (seedSchedule block)

theorem schedulePrefix_refines (block : List Byte) (blockSize : block.length = 128)
    (processed : Nat) (bound : processed ≤ 64) :
    SchedulePrefix ((List.range processed).foldl updateSchedule (seedSchedule block))
      ((List.range processed).foldl Abc.Spec.Sha512.appendScheduleWord
        (Abc.Spec.Sha512.seedSchedule block)) processed := by
  induction processed with
  | zero => exact seedSchedule_refines block blockSize
  | succ i ih =>
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    exact updateSchedule_refines _ _ i (by omega) (ih (by omega))

theorem schedule_refines (block : List Byte) (blockSize : block.length = 128) :
    SchedulePrefix (schedule block) (Abc.Spec.Sha512.messageSchedule block) 64 :=
  schedulePrefix_refines block blockSize 64 (by decide)

def rounds (constants words : Array UInt64) (initial : Registers) (count : Nat) : Registers :=
  (List.range count).foldl (fun r i => round r (constants.getD i 0) (words.getD i 0)) initial

theorem rounds_refine (constants words : Array UInt64) (referenceConstants referenceWords : Array Word)
    (initial : Registers) (count : Nat)
    (hConstants : ∀ i < count, (constants.getD i 0).toBitVec = referenceConstants.getD i 0)
    (hWords : ∀ i < count, (words.getD i 0).toBitVec = referenceWords.getD i 0) :
    toSpecState (rounds constants words initial count) = (List.range count).foldl
      (fun work i => Abc.Spec.Sha512.round work (referenceConstants.getD i 0) (referenceWords.getD i 0))
      (toSpecState initial) := by
  induction count with
  | zero => rfl
  | succ i ih =>
    simp only [rounds, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, round_refines]
    have prior := ih (fun j hj => hConstants j (by omega)) (fun j hj => hWords j (by omega))
    unfold rounds at prior
    rw [prior, hConstants i (by omega), hWords i (by omega)]

theorem constantTable_refines :
    Abc.Refine.Sha512.rustConstants.map UInt64.toBitVec = Abc.Spec.Sha512.constants := by
  apply Array.toList_inj.mp
  rw [Array.toList_map]
  rfl

private theorem constLookup (i : Nat) (bound : i < 80) :
    (rustConstants.getD i 0).toBitVec = Abc.Spec.Sha512.constants.getD i 0 := by
  have inside : i < rustConstants.size := by
    change i < 80
    exact bound
  rw [← constantTable_refines]
  simp [Array.getD_eq_getD_getElem?, getElem?_pos, inside]

def compress (initial : Registers) (block : List Byte) : Registers :=
  feedForward initial (rounds rustConstants (schedule block) initial 80)

/-- Every input byte and chaining word is arbitrary, and every feed-forward word is checked. -/
theorem compress_refines (initial : Registers) (block : List Byte) (blockSize : block.length = 128) :
    toSpecState (compress initial block) = Abc.Spec.Sha512.compress (toSpecState initial) block := by
  obtain ⟨_, size, agrees⟩ := schedule_refines block blockSize
  have wordsAgree (i : Nat) (bound : i < 80) :
      ((schedule block).getD i 0).toBitVec = (Abc.Spec.Sha512.messageSchedule block).getD i 0 :=
    agrees i (by omega)
  unfold compress Abc.Spec.Sha512.compress
  rw [feedForward_refines, rounds_refine _ _ _ _ _ _ constLookup wordsAgree]

#print axioms loadWord_refines
#print axioms schedule_refines
#print axioms rounds_refine
#print axioms constantTable_refines
#print axioms compress_refines

end Abc.Refine.Sha512
