import Sha256Spec

/-!
Word-level equivalence for a mathematical model of the portable compression
loops. The bridge from the generated Rust model is a separate obligation.
-/

namespace Abc.Refinement.Sha256

open Abc.Spec.Sha256 (Byte Word State)

structure Registers where
  a : UInt32
  b : UInt32
  c : UInt32
  d : UInt32
  e : UInt32
  f : UInt32
  g : UInt32
  h : UInt32

def toSpecState (r : Registers) : State :=
  ⟨r.a.toBitVec, r.b.toBitVec, r.c.toBitVec, r.d.toBitVec,
    r.e.toBitVec, r.f.toBitVec, r.g.toBitVec, r.h.toBitVec⟩

def ofSpecState (s : State) : Registers :=
  ⟨UInt32.ofBitVec s.a, UInt32.ofBitVec s.b, UInt32.ofBitVec s.c, UInt32.ofBitVec s.d,
    UInt32.ofBitVec s.e, UInt32.ofBitVec s.f, UInt32.ofBitVec s.g, UInt32.ofBitVec s.h⟩

@[simp] theorem toSpecState_ofSpecState (s : State) : toSpecState (ofSpecState s) = s := by
  cases s
  rfl

@[simp] theorem ofSpecState_toSpecState (r : Registers) : ofSpecState (toSpecState r) = r := by
  cases r
  rfl

def rotateRight32 (value : UInt32) (count : Nat) : UInt32 :=
  UInt32.ofBitVec (value.toBitVec.rotateRight count)

def scheduleWord32 (w16 w15 w7 w2 : UInt32) : UInt32 :=
  let sigma0 := rotateRight32 w15 7 ^^^ rotateRight32 w15 18 ^^^ (w15 >>> 3)
  let sigma1 := rotateRight32 w2 17 ^^^ rotateRight32 w2 19 ^^^ (w2 >>> 10)
  w16 + sigma0 + w7 + sigma1

theorem scheduleWord32_toBitVec (w16 w15 w7 w2 : UInt32) :
    (scheduleWord32 w16 w15 w7 w2).toBitVec =
      Abc.Spec.Sha256.scheduleOne w2.toBitVec + w7.toBitVec +
        Abc.Spec.Sha256.scheduleZero w15.toBitVec + w16.toBitVec := by
  have shift3 : (w15 >>> (3 : UInt32)).toBitVec = w15.toBitVec >>> (3 : Nat) := rfl
  have shift10 : (w2 >>> (10 : UInt32)).toBitVec = w2.toBitVec >>> (10 : Nat) := rfl
  simp only [scheduleWord32, UInt32.toBitVec_add, UInt32.toBitVec_xor, shift3, shift10,
    rotateRight32, Abc.Spec.Sha256.scheduleOne, Abc.Spec.Sha256.scheduleZero]
  ac_rfl

def round32 (r : Registers) (constant word : UInt32) : Registers :=
  let sigma1 := rotateRight32 r.e 6 ^^^ rotateRight32 r.e 11 ^^^ rotateRight32 r.e 25
  let choose := (r.e &&& r.f) ^^^ ((~~~r.e) &&& r.g)
  let temp1 := r.h + sigma1 + choose + constant + word
  let sigma0 := rotateRight32 r.a 2 ^^^ rotateRight32 r.a 13 ^^^ rotateRight32 r.a 22
  let majority := (r.a &&& r.b) ^^^ (r.a &&& r.c) ^^^ (r.b &&& r.c)
  let temp2 := sigma0 + majority
  ⟨temp1 + temp2, r.a, r.b, r.c, r.d + temp1, r.e, r.f, r.g⟩

theorem round32_refines (r : Registers) (constant word : UInt32) :
    toSpecState (round32 r constant word) =
      Abc.Spec.Sha256.round (toSpecState r) constant.toBitVec word.toBitVec := by
  rfl

def feedForward32 (initial work : Registers) : Registers :=
  ⟨initial.a + work.a, initial.b + work.b, initial.c + work.c, initial.d + work.d,
    initial.e + work.e, initial.f + work.f, initial.g + work.g, initial.h + work.h⟩

theorem feedForward32_refines (initial work : Registers) :
    toSpecState (feedForward32 initial work) =
      Abc.Spec.Sha256.addState (toSpecState initial) (toSpecState work) := by
  rfl

def parseWord32 (bytes : List Byte) : UInt32 :=
  UInt32.ofNat (bytes.foldl (fun value byte => 256 * value + byte.toNat) 0)

theorem parseWord32_toBitVec (bytes : List Byte) :
    (parseWord32 bytes).toBitVec = Abc.Spec.Sha256.parseWord bytes := by
  rfl

/-- Adding one low byte to a full-width tail fits after extending by eight bits. -/
theorem lowByte_toNat {width : Nat} (tail : BitVec width) (byte : Byte) :
    ((byte.setWidth (width + 8)) ||| (tail.setWidth (width + 8) <<< (8 : Nat))).toNat =
      256 * tail.toNat + byte.toNat := by
  have shiftBound : tail.toNat <<< 8 < 2 ^ (width + 8) := by
    rw [Nat.shiftLeft_eq, Nat.pow_add]
    exact Nat.mul_lt_mul_of_pos_right tail.isLt (by decide)
  rw [BitVec.toNat_or, BitVec.toNat_setWidth_of_le (by omega), BitVec.toNat_shiftLeft,
    BitVec.toNat_setWidth_of_le (by omega), Nat.mod_eq_of_lt shiftBound, Nat.or_comm,
    ← Nat.shiftLeft_add_eq_or_of_lt byte.isLt, Nat.shiftLeft_eq]
  simp [Nat.mul_comm]

theorem decodeBigEndian_append_byte (bytes : List Byte) (byte : Byte) :
    Abc.Foundation.decodeBigEndian (bytes ++ [byte]) =
      256 * Abc.Foundation.decodeBigEndian bytes + byte.toNat := by
  simp [Abc.Foundation.decodeBigEndian]

theorem takeFour_eq_elements {α : Type} (block : List α) (offset : Nat) (h : offset + 4 ≤ block.length) :
    (block.drop offset).take 4 =
      [block[offset]'(by omega), block[offset + 1]'(by omega),
       block[offset + 2]'(by omega), block[offset + 3]'(by omega)] := by
  apply List.ext_getElem?
  intro i
  by_cases hi : i < 4
  · have casesI : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 := by omega
    rcases casesI with rfl | rfl | rfl | rfl <;>
      simp [List.getElem?_drop, getElem?_pos, hi] <;> omega
  · rw [List.getElem?_take_eq_none (by omega)]
    exact (List.getElem?_eq_none (by simp; omega)).symm

def seedSchedule32 (block : List Byte) : Array UInt32 :=
  Array.ofFn fun index : Fin 64 =>
    if index.val < 16 then parseWord32 ((block.drop (4 * index.val)).take 4) else 0

def seedSpecSchedule (block : List Byte) : Array Word :=
  ((List.range 16).map fun i => Abc.Spec.Sha256.parseWord ((block.drop (4 * i)).take 4)).toArray

def growSpecSchedule (growing : Array Word) (i : Nat) : Array Word :=
  growing.push (Abc.Spec.Sha256.scheduleOne (growing.getD (i + 14) 0) + growing.getD (i + 9) 0 +
    Abc.Spec.Sha256.scheduleZero (growing.getD (i + 1) 0) + growing.getD i 0)

def updateSchedule32 (fixed : Array UInt32) (i : Nat) : Array UInt32 :=
  let round := i + 16
  fixed.setIfInBounds round (scheduleWord32 (fixed.getD (round - 16) 0) (fixed.getD (round - 15) 0)
    (fixed.getD (round - 7) 0) (fixed.getD (round - 2) 0))

def SchedulePrefix (fixed : Array UInt32) (growing : Array Word) (processed : Nat) : Prop :=
  fixed.size = 64 ∧ growing.size = processed + 16 ∧
    ∀ index < growing.size, (fixed.getD index 0).toBitVec = growing.getD index 0

theorem seedSchedule32_refines (block : List Byte) :
    SchedulePrefix (seedSchedule32 block) (seedSpecSchedule block) 0 := by
  refine ⟨by simp [seedSchedule32], by simp [seedSpecSchedule], ?_⟩
  intro index indexBound
  have h16 : index < 16 := by simpa [seedSpecSchedule] using indexBound
  have h64 : index < 64 := by omega
  simp [seedSchedule32, seedSpecSchedule, h16, h64, parseWord32_toBitVec]

theorem updateSchedule32_refines (fixed : Array UInt32) (growing : Array Word) (i : Nat)
    (hRound : i < 48) (hPrefix : SchedulePrefix fixed growing i) :
    SchedulePrefix (updateSchedule32 fixed i) (growSpecSchedule growing i) (i + 1) := by
  obtain ⟨fixedSize, growingSize, agrees⟩ := hPrefix
  have writeBound : i + 16 < fixed.size := by omega
  have valueAgrees :
      (scheduleWord32 (fixed.getD (i + 16 - 16) 0) (fixed.getD (i + 16 - 15) 0)
        (fixed.getD (i + 16 - 7) 0) (fixed.getD (i + 16 - 2) 0)).toBitVec =
        Abc.Spec.Sha256.scheduleOne (growing.getD (i + 14) 0) + growing.getD (i + 9) 0 +
          Abc.Spec.Sha256.scheduleZero (growing.getD (i + 1) 0) + growing.getD i 0 := by
    rw [scheduleWord32_toBitVec]
    have h0 : i + 16 - 16 = i := by omega
    have h1 : i + 16 - 15 = i + 1 := by omega
    have h9 : i + 16 - 7 = i + 9 := by omega
    have h14 : i + 16 - 2 = i + 14 := by omega
    rw [h0, h1, h9, h14, agrees i (by omega), agrees (i + 1) (by omega),
      agrees (i + 9) (by omega), agrees (i + 14) (by omega)]
  refine ⟨by simp [updateSchedule32, fixedSize], by simp [growSpecSchedule, growingSize], ?_⟩
  intro index indexBound
  have limit : index < growing.size + 1 := by simpa [growSpecSchedule] using indexBound
  by_cases written : index = i + 16
  · subst index
    simpa only [updateSchedule32, growSpecSchedule, Array.getD_eq_getD_getElem?,
      Array.getElem?_setIfInBounds_self_of_lt writeBound, Array.getElem?_push, growingSize,
      if_true, Option.getD_some] using valueAgrees
  · have old : index < growing.size := by omega
    have different : i + 16 ≠ index := Ne.symm written
    simpa only [updateSchedule32, growSpecSchedule, Array.getD_eq_getD_getElem?,
      Array.getElem?_setIfInBounds_ne different, Array.getElem?_push_lt old, getElem?_pos growing index old]
      using agrees index old

def schedule32 (block : List Byte) : Array UInt32 :=
  (List.range 48).foldl updateSchedule32 (seedSchedule32 block)

theorem schedulePrefix_refines (block : List Byte) (processed : Nat) (h : processed ≤ 48) :
    SchedulePrefix ((List.range processed).foldl updateSchedule32 (seedSchedule32 block))
      ((List.range processed).foldl growSpecSchedule (seedSpecSchedule block)) processed := by
  induction processed with
  | zero => exact seedSchedule32_refines block
  | succ i ih =>
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    exact updateSchedule32_refines _ _ i (by omega) (ih (by omega))

theorem schedule32_refines (block : List Byte) : SchedulePrefix (schedule32 block)
    (Abc.Spec.Sha256.messageSchedule block) 48 := by
  exact schedulePrefix_refines block 48 (by decide)

def rounds32 (constants schedule : Array UInt32) (state : Registers) (count : Nat) : Registers :=
  (List.range count).foldl (fun work i => round32 work (constants.getD i 0) (schedule.getD i 0)) state

theorem rounds32_refines (constants schedule : Array UInt32) (specConstants specSchedule : Array Word)
    (state : Registers) (count : Nat)
    (hConstants : ∀ i < count, (constants.getD i 0).toBitVec = specConstants.getD i 0)
    (hSchedule : ∀ i < count, (schedule.getD i 0).toBitVec = specSchedule.getD i 0) :
    toSpecState (rounds32 constants schedule state count) = (List.range count).foldl
      (fun work i => Abc.Spec.Sha256.round work (specConstants.getD i 0) (specSchedule.getD i 0))
      (toSpecState state) := by
  induction count with
  | zero => rfl
  | succ i ih =>
    simp only [rounds32, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, round32_refines]
    have prior := ih (fun j hj => hConstants j (by omega)) (fun j hj => hSchedule j (by omega))
    unfold rounds32 at prior
    rw [prior, hConstants i (by omega), hSchedule i (by omega)]

def compress32 (constants : Array UInt32) (state : Registers) (block : List Byte) : Registers :=
  feedForward32 state (rounds32 constants (schedule32 block) state 64)

theorem compress32_refines (constants : Array UInt32) (state : Registers) (block : List Byte)
    (hConstants : ∀ i < 64, (constants.getD i 0).toBitVec = Abc.Spec.Sha256.constants.getD i 0) :
    toSpecState (compress32 constants state block) = Abc.Spec.Sha256.compress (toSpecState state) block := by
  obtain ⟨_, size, agrees⟩ := schedule32_refines block
  have hSchedule (i : Nat) (bound : i < 64) :
      ((schedule32 block).getD i 0).toBitVec = (Abc.Spec.Sha256.messageSchedule block).getD i 0 :=
    agrees i (by omega)
  unfold compress32 Abc.Spec.Sha256.compress
  rw [feedForward32_refines, rounds32_refines _ _ _ _ _ _ hConstants hSchedule]

end Abc.Refinement.Sha256
