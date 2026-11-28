import Std

namespace Abc.Spec.Aes256Gcm.Composition

abbrev Byte := BitVec 8
abbrev Block := BitVec 128
abbrev Key := BitVec 256
abbrev Nonce := BitVec 96
abbrev Tag := Vector Byte 16
abbrev Encrypt := Key → Block → Block

def payloadLimit : Nat := (2^32 - 2) * 16
def aadLimit : Nat := (2^64 - 1) / 8

private def reduction : Block := 0xe1000000000000000000000000000000

abbrev ProductState := Block × Block

-- SP 800-38D Algorithm 1 scans the first operand from its most significant bit.
private def nistMultiplyStep (input : Block) (bit : Nat) (state : ProductState) : ProductState :=
  let (z, v) := state
  (if input.getLsbD bit then z ^^^ v else z,
   if v.getLsbD 0 then (v >>> 1) ^^^ reduction else v >>> 1)

def maskMultiplyStep (input : Block) (bit : Nat) (state : ProductState) : ProductState :=
  let (z, v) := state
  (z ^^^ (v &&& (0 - ((input >>> bit) &&& 1))),
   (v >>> 1) ^^^ (reduction &&& (0 - (v &&& 1))))

private theorem subtraction_mask (selected word : Block) :
    word &&& (0 - (selected &&& 1)) = if selected.getLsbD 0 then word else 0 := by
  change word &&& (0#128 - (selected &&& 1#128)) =
    if selected.getLsbD 0 then word else 0#128
  rw [BitVec.and_one_eq_setWidth_ofBool_getLsbD]
  cases h : selected.getLsbD 0
  · change word &&& (0#128 - 0#128) = 0#128
    simp
  · change word &&& (0#128 - 1#128) = word
    rw [show (0#128 - 1#128) = BitVec.allOnes 128 by decide +kernel, BitVec.and_allOnes]

private theorem mask_step_refines (input : Block) (bit : Nat) (state : ProductState) :
    maskMultiplyStep input bit state = nistMultiplyStep input bit state := by
  obtain ⟨z, v⟩ := state
  simp only [maskMultiplyStep, nistMultiplyStep, subtraction_mask, BitVec.getLsbD_ushiftRight,
    Nat.add_zero]
  apply Prod.ext
  · by_cases h : input.getLsbD bit <;> simp [h]
  · change (v >>> 1) ^^^ (if v.getLsbD 0 then reduction else 0#128) =
      if v.getLsbD 0 then (v >>> 1) ^^^ reduction else v >>> 1
    by_cases h : v.getLsbD 0 = true
    · rw [if_pos h, if_pos h]
    · rw [if_neg h, if_neg h, BitVec.xor_zero]

def descendingLoop (step : Nat → ProductState → ProductState) :
    Nat → ProductState → ProductState
  | 0, state => state
  | n + 1, state => descendingLoop step n (step n state)

def multiply (input key : Block) : Block :=
  (descendingLoop (nistMultiplyStep input) 128 (0, key)).1

def multiplyMask (input key : Block) : Block :=
  (descendingLoop (maskMultiplyStep input) 128 (0, key)).1

theorem multiplyMask_refines_nist (input key : Block) :
    multiplyMask input key = multiply input key := by
  have step : maskMultiplyStep input = nistMultiplyStep input := by
    funext bit state
    exact mask_step_refines input bit state
  simp [multiplyMask, multiply, step]

private def littleEndian : Nat → Nat → List Byte
  | 0, _ => []
  | n + 1, value => BitVec.ofNat 8 value :: littleEndian n (value / 256)

private def decodeLittleEndian : List Byte → Nat
  | [] => 0
  | x :: xs => x.toNat + 256 * decodeLittleEndian xs

def bigEndian (width value : Nat) : List Byte := (littleEndian width value).reverse

def decodeBigEndian (bytes : List Byte) : Nat := decodeLittleEndian bytes.reverse

private theorem littleEndian_length (width value : Nat) :
    (littleEndian width value).length = width := by
  induction width generalizing value with
  | zero => rfl
  | succ width ih => simp [littleEndian, ih]

@[simp] theorem bigEndian_length (width value : Nat) :
    (bigEndian width value).length = width := by
  simp [bigEndian, littleEndian_length]

private theorem decodeLittleEndian_littleEndian (width value : Nat) :
    decodeLittleEndian (littleEndian width value) = value % 256^width := by
  induction width generalizing value with
  | zero => simp [littleEndian, decodeLittleEndian, Nat.mod_one]
  | succ width ih =>
    simp only [littleEndian, decodeLittleEndian, BitVec.toNat_ofNat, ih]
    change value % 256 + 256 * (value / 256 % 256^width) = value % 256^(width + 1)
    rw [Nat.pow_succ']
    exact Nat.mod_mul.symm

theorem decodeBigEndian_bigEndian (width value : Nat) :
    decodeBigEndian (bigEndian width value) = value % 256^width := by
  simp [decodeBigEndian, bigEndian, decodeLittleEndian_littleEndian]

private theorem decodeLittleEndian_append (left right : List Byte) :
    decodeLittleEndian (left ++ right) =
      decodeLittleEndian left + 256^left.length * decodeLittleEndian right := by
  induction left with
  | nil => simp [decodeLittleEndian]
  | cons b bs ih =>
    simp only [List.cons_append, decodeLittleEndian, ih, List.length_cons,
      Nat.pow_succ', Nat.mul_add, Nat.mul_assoc, Nat.add_assoc]

theorem decodeBigEndian_append (left right : List Byte) :
    decodeBigEndian (left ++ right) =
      decodeBigEndian left * 256^right.length + decodeBigEndian right := by
  simp [decodeBigEndian, List.reverse_append, decodeLittleEndian_append, Nat.add_comm, Nat.mul_comm]

def asBlock (bytes : List Byte) : Block := BitVec.ofNat 128 (decodeBigEndian bytes)

def asTag (block : Block) : Tag :=
  let bytes := bigEndian 16 block.toNat
  ⟨bytes.toArray, by simp [bytes]⟩

private theorem decodeLittleEndian_bound (bytes : List Byte) :
    decodeLittleEndian bytes < 256^bytes.length := by
  induction bytes with
  | nil => decide
  | cons byte bytes ih =>
    have bound := byte.isLt
    simp only [decodeLittleEndian, List.length_cons, Nat.pow_succ']
    omega

private theorem littleEndian_decodeLittleEndian (bytes : List Byte) :
    littleEndian bytes.length (decodeLittleEndian bytes) = bytes := by
  induction bytes with
  | nil => rfl
  | cons byte bytes ih =>
    have bound := byte.isLt
    have lower : (byte.toNat + 256 * decodeLittleEndian bytes) % 256 = byte.toNat := by omega
    have upper : (byte.toNat + 256 * decodeLittleEndian bytes) / 256 = decodeLittleEndian bytes := by omega
    simp only [List.length_cons, littleEndian, decodeLittleEndian, upper, ih]
    congr 1
    apply BitVec.eq_of_toNat_eq
    rw [BitVec.toNat_ofNat, lower]

theorem asBlock_asTag (word : Block) : asBlock (asTag word).toList = word := by
  apply BitVec.eq_of_toNat_eq
  simp only [asBlock, asTag, Vector.toList_mk, decodeBigEndian_bigEndian, BitVec.toNat_ofNat]
  have bound := word.isLt
  change (word.toNat % 2^128) % 2^128 = word.toNat
  rw [Nat.mod_eq_of_lt bound, Nat.mod_eq_of_lt bound]

theorem asTag_asBlock (tag : Tag) : asTag (asBlock tag.toList) = tag := by
  apply Vector.toList_inj.mp
  have bounds : decodeBigEndian tag.toList < 2^128 := by
    simpa [decodeBigEndian] using decodeLittleEndian_bound tag.toList.reverse
  simp only [asTag, asBlock, Vector.toList_mk, BitVec.toNat_ofNat, Nat.mod_eq_of_lt bounds]
  have encoded := congrArg List.reverse (littleEndian_decodeLittleEndian tag.toList.reverse)
  simpa [bigEndian, decodeBigEndian] using encoded

def lengthBytes (aadLength cipherLength : Nat) : List Byte :=
  bigEndian 8 (8 * aadLength) ++ bigEndian 8 (8 * cipherLength)

def packedLength (aadLength cipherLength : Nat) : Block :=
  ((BitVec.ofNat 128 (8 * aadLength)) <<< 64) ||| BitVec.ofNat 128 (8 * cipherLength)

private theorem pack_halves (high low : BitVec 64) :
    ((high.zeroExtend 128) <<< 64) ||| low.zeroExtend 128 = high ++ low := by
  rw [BitVec.append_def, BitVec.shiftLeftZeroExtend_eq, BitVec.setWidth'_eq]

private theorem widen_natural (value : Nat) (fits : value < 2^64) :
    (BitVec.ofNat 64 value).zeroExtend 128 = BitVec.ofNat 128 value := by
  apply BitVec.eq_of_toNat_eq
  simp only [BitVec.zeroExtend, BitVec.toNat_setWidth, BitVec.toNat_ofNat, Nat.mod_eq_of_lt fits]

theorem packedLength_matches_bytes (aadLength cipherLength : Nat)
    (aadFits : 8 * aadLength < 2^64) (cipherFits : 8 * cipherLength < 2^64) :
    packedLength aadLength cipherLength = asBlock (lengthBytes aadLength cipherLength) := by
  unfold packedLength
  rw [← widen_natural _ aadFits, ← widen_natural _ cipherFits, pack_halves]
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_append, BitVec.toNat_ofNat, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt aadFits, Nat.mod_eq_of_lt cipherFits]
  rw [← Nat.shiftLeft_add_eq_or_of_lt cipherFits, Nat.shiftLeft_eq]
  unfold asBlock lengthBytes
  rw [BitVec.toNat_ofNat, decodeBigEndian_append, bigEndian_length,
    decodeBigEndian_bigEndian, decodeBigEndian_bigEndian]
  change 8 * aadLength * 2^64 + 8 * cipherLength =
    ((8 * aadLength % 2^64) * 2^64 + (8 * cipherLength % 2^64)) % 2^128
  rw [Nat.mod_eq_of_lt aadFits, Nat.mod_eq_of_lt cipherFits]
  symm
  apply Nat.mod_eq_of_lt
  omega

def padding (length : Nat) : Nat := (16 - length % 16) % 16

def padded (bytes : List Byte) : List Byte :=
  bytes ++ List.replicate (padding bytes.length) 0

theorem padded_aligned (bytes : List Byte) : (padded bytes).length % 16 = 0 := by
  simp only [padded, List.length_append, List.length_replicate, padding]
  omega

private theorem padded_append_of_aligned (full tail : List Byte)
    (aligned : full.length % 16 = 0) : padded (full ++ tail) = full ++ padded tail := by
  have remainder : (full ++ tail).length % 16 = tail.length % 16 := by
    simp only [List.length_append]
    omega
  simp only [padded, padding, remainder, List.append_assoc]

def transcript (aad ciphertext : List Byte) : List Byte :=
  (padded aad ++ padded ciphertext) ++ lengthBytes aad.length ciphertext.length

private def readTranscriptLengths (wire : List Byte) : Nat × Nat :=
  let footer := wire.drop (wire.length - 16)
  (decodeBigEndian (footer.take 8) / 8, decodeBigEndian (footer.drop 8) / 8)

private theorem transcript_has_lengths (aad ciphertext : List Byte)
    (aadFits : 8 * aad.length < 2^64) (cipherFits : 8 * ciphertext.length < 2^64) :
    readTranscriptLengths (transcript aad ciphertext) = (aad.length, ciphertext.length) := by
  have footer : (lengthBytes aad.length ciphertext.length).length = 16 := by simp [lengthBytes]
  have lengthEq : (transcript aad ciphertext).length - 16 =
      (padded aad ++ padded ciphertext).length := by
    simp only [transcript, List.length_append, footer, Nat.add_sub_cancel]
  unfold readTranscriptLengths transcript
  rw [show ((padded aad ++ padded ciphertext) ++
    lengthBytes aad.length ciphertext.length).length - 16 =
    (padded aad ++ padded ciphertext).length from lengthEq, List.drop_left]
  have takeEq : (lengthBytes aad.length ciphertext.length).take 8 =
      bigEndian 8 (8 * aad.length) := by
    simpa only [lengthBytes, bigEndian_length] using
      (List.take_left (l₁ := bigEndian 8 (8 * aad.length)) (l₂ := bigEndian 8 (8 * ciphertext.length)))
  have dropEq : (lengthBytes aad.length ciphertext.length).drop 8 =
      bigEndian 8 (8 * ciphertext.length) := by
    simpa only [lengthBytes, bigEndian_length] using
      (List.drop_left (l₁ := bigEndian 8 (8 * aad.length)) (l₂ := bigEndian 8 (8 * ciphertext.length)))
  simp only [takeEq, dropEq, decodeBigEndian_bigEndian]
  change ((8 * aad.length % 2^64) / 8, (8 * ciphertext.length % 2^64) / 8) =
    (aad.length, ciphertext.length)
  rw [Nat.mod_eq_of_lt aadFits, Nat.mod_eq_of_lt cipherFits]
  exact Prod.ext (by omega) (by omega)

def readTranscript (wire : List Byte) : List Byte × List Byte :=
  let (a, c) := readTranscriptLengths wire
  (wire.take a, (wire.drop (a + padding a)).take c)

theorem transcript_recovers_inputs (aad ciphertext : List Byte)
    (aadFits : 8 * aad.length < 2^64) (cipherFits : 8 * ciphertext.length < 2^64) :
    readTranscript (transcript aad ciphertext) = (aad, ciphertext) := by
  unfold readTranscript
  rw [transcript_has_lengths aad ciphertext aadFits cipherFits]
  apply Prod.ext
  · simp only [transcript, padded, List.append_assoc, List.take_left]
  · have paddedLength : (padded aad).length = aad.length + padding aad.length := by simp [padded]
    simp only [transcript, List.append_assoc, ← paddedLength, List.drop_left]
    simp only [padded, List.append_assoc, List.take_left]

theorem transcript_injective (aad₁ cipher₁ aad₂ cipher₂ : List Byte)
    (aadFits₁ : 8 * aad₁.length < 2^64) (cipherFits₁ : 8 * cipher₁.length < 2^64)
    (aadFits₂ : 8 * aad₂.length < 2^64) (cipherFits₂ : 8 * cipher₂.length < 2^64)
    (equal : transcript aad₁ cipher₁ = transcript aad₂ cipher₂) :
    aad₁ = aad₂ ∧ cipher₁ = cipher₂ := by
  have decoded := congrArg readTranscript equal
  rw [transcript_recovers_inputs _ _ aadFits₁ cipherFits₁,
    transcript_recovers_inputs _ _ aadFits₂ cipherFits₂] at decoded
  exact ⟨congrArg Prod.fst decoded, congrArg Prod.snd decoded⟩

def blockWords (wire : List Byte) : List Block :=
  if _full : 16 ≤ wire.length then asBlock (wire.take 16) :: blockWords (wire.drop 16)
  else []
termination_by wire.length
decreasing_by simp only [List.length_drop]; omega

private theorem blockWords_append_of_aligned (left right : List Byte)
    (aligned : left.length % 16 = 0) :
    blockWords (left ++ right) = blockWords left ++ blockWords right := by
  by_cases empty : left = []
  · simp [empty, blockWords.eq_def []]
  · have nonzero : left.length ≠ 0 := fun h => empty (List.eq_nil_iff_length_eq_zero.mpr h)
    have full : 16 ≤ left.length := by omega
    have fullAppend : 16 ≤ (left ++ right).length := by simp only [List.length_append]; omega
    have tailAligned : (left.drop 16).length % 16 = 0 := by simp only [List.length_drop]; omega
    rw [blockWords.eq_def (left ++ right), dif_pos fullAppend,
      blockWords.eq_def left, dif_pos full,
      List.take_append_of_le_length full, List.drop_append_of_le_length full,
      blockWords_append_of_aligned _ _ tailAligned, List.cons_append]
termination_by left.length
decreasing_by simp only [List.length_drop]; omega

private theorem blockWords_exact_block (wire : List Byte) (width : wire.length = 16) :
    blockWords wire = [asBlock wire] := by
  rw [blockWords.eq_def wire, dif_pos (by omega)]
  rw [← width, List.take_length, List.drop_length]
  simp [blockWords.eq_def []]

def sourceBlocks (bytes : List Byte) : List Block :=
  let boundary := bytes.length / 16 * 16
  let tail := bytes.drop boundary
  blockWords (bytes.take boundary) ++ if tail = [] then [] else [asBlock (padded tail)]

theorem sourceBlocks_refines_padded (bytes : List Byte) : sourceBlocks bytes = blockWords (padded bytes) := by
  let boundary := bytes.length / 16 * 16
  let full := bytes.take boundary
  let tail := bytes.drop boundary
  have spans : full ++ tail = bytes := List.take_append_drop boundary bytes
  have inside : boundary ≤ bytes.length := by dsimp [boundary]; omega
  have aligned : full.length % 16 = 0 := by
    simp only [full, List.length_take, Nat.min_eq_left inside]
    dsimp [boundary]
    omega
  have short : tail.length < 16 := by
    simp only [tail, List.length_drop, boundary]
    omega
  have tailWords : blockWords (padded tail) = if tail = [] then [] else [asBlock (padded tail)] := by
    by_cases empty : tail = []
    · simp [empty, padded, padding, blockWords.eq_def []]
    · rw [if_neg empty]
      have nonzero : tail.length ≠ 0 := fun h => empty (List.eq_nil_iff_length_eq_zero.mpr h)
      apply blockWords_exact_block
      simp only [padded, List.length_append, List.length_replicate, padding]
      omega
  change blockWords full ++ (if tail = [] then [] else [asBlock (padded tail)]) = _
  rw [← tailWords, ← blockWords_append_of_aligned _ _ aligned,
    ← padded_append_of_aligned _ _ aligned, spans]

private def hashFold (mul : Block → Block → Block) (key acc : Block) (words : List Block) : Block :=
  words.foldl (fun state word => mul (state ^^^ word) key) acc

def ghash (key : Block) (wire : List Byte) : Block :=
  hashFold multiply key 0 (blockWords wire)

def ghashSource (key : Block) (aad ciphertext : List Byte) : Block :=
  let aadState := hashFold multiplyMask key 0 (sourceBlocks aad)
  let cipherState := hashFold multiplyMask key aadState (sourceBlocks ciphertext)
  multiplyMask (cipherState ^^^ packedLength aad.length ciphertext.length) key

theorem ghashSource_refines_nist (key : Block) (aad ciphertext : List Byte)
    (aadFits : 8 * aad.length < 2^64) (cipherFits : 8 * ciphertext.length < 2^64) :
    ghashSource key aad ciphertext = ghash key (transcript aad ciphertext) := by
  have aligned : (padded aad ++ padded ciphertext).length % 16 = 0 := by
    have ha := padded_aligned aad
    have hc := padded_aligned ciphertext
    simp only [List.length_append]
    omega
  have footer : (lengthBytes aad.length ciphertext.length).length = 16 := by simp [lengthBytes]
  unfold ghashSource ghash transcript
  rw [blockWords_append_of_aligned _ _ aligned,
    blockWords_append_of_aligned _ _ (padded_aligned aad),
    blockWords_exact_block _ footer]
  simp only [sourceBlocks_refines_padded, packedLength_matches_bytes _ _ aadFits cipherFits,
    multiplyMask_refines_nist, hashFold, List.foldl_append, List.foldl_cons, List.foldl_nil]

def counterBlock (nonce : Nonce) (counter : Nat) : Block :=
  nonce ++ BitVec.ofNat 32 counter

def byteAt (block : Block) (index : Nat) : Byte :=
  (block >>> (8 * (15 - index))).truncate 8

private def xorFrom (stream : Nat → Byte) (offset : Nat) : List Byte → List Byte
  | [] => []
  | byte :: tail => (byte ^^^ stream offset) :: xorFrom stream (offset + 1) tail

@[simp] private theorem xorFrom_length (stream : Nat → Byte) (offset : Nat) (bytes : List Byte) :
    (xorFrom stream offset bytes).length = bytes.length := by
  induction bytes generalizing offset with
  | nil => rfl
  | cons head tail ih => simp [xorFrom, ih]

private theorem xorFrom_twice (stream : Nat → Byte) (offset : Nat) (bytes : List Byte) :
    xorFrom stream offset (xorFrom stream offset bytes) = bytes := by
  induction bytes generalizing offset with
  | nil => rfl
  | cons head tail ih => simp [xorFrom, ih, BitVec.xor_assoc]

private theorem xorFrom_append (stream : Nat → Byte) (offset : Nat) (left right : List Byte) :
    xorFrom stream offset (left ++ right) =
      xorFrom stream offset left ++ xorFrom stream (offset + left.length) right := by
  induction left generalizing offset with
  | nil => simp [xorFrom]
  | cons b bs ih =>
    simp only [List.cons_append, xorFrom, ih, List.length_cons]
    rw [show offset + 1 + bs.length = offset + (bs.length + 1) by omega]

private theorem xorFrom_congr (a b : Nat → Byte) (aOffset bOffset : Nat) (data : List Byte)
    (same : ∀ i, i < data.length → a (aOffset + i) = b (bOffset + i)) :
    xorFrom a aOffset data = xorFrom b bOffset data := by
  induction data generalizing aOffset bOffset with
  | nil => rfl
  | cons byte tail ih =>
    have head := same 0 (by simp)
    simp only [Nat.add_zero] at head
    have next (i : Nat) (within : i < tail.length) : a (aOffset + 1 + i) = b (bOffset + 1 + i) := by
      rw [show aOffset + 1 + i = aOffset + (i + 1) by omega,
        show bOffset + 1 + i = bOffset + (i + 1) by omega]
      exact same (i + 1) (by simp only [List.length_cons]; omega)
    simp only [xorFrom, head, ih _ _ next]

private def payloadStream (encrypt : Block → Block) (nonce : Nonce) (start offset : Nat) : Byte :=
  byteAt (encrypt (counterBlock nonce (start + offset / 16))) (offset % 16)

def gctr (encrypt : Block → Block) (nonce : Nonce) (start : Nat) (data : List Byte) : List Byte :=
  xorFrom (payloadStream encrypt nonce start) 0 data

@[simp] theorem gctr_length (encrypt : Block → Block) (nonce : Nonce) (start : Nat)
    (data : List Byte) : (gctr encrypt nonce start data).length = data.length := by
  simp [gctr]

theorem gctr_twice (encrypt : Block → Block) (nonce : Nonce) (start : Nat)
    (data : List Byte) : gctr encrypt nonce start (gctr encrypt nonce start data) = data := by
  exact xorFrom_twice _ _ _

def gctrSource (encrypt : Block → Block) (nonce : Nonce) (counter : Nat) (data : List Byte) :
    List Byte :=
  if _empty : data = [] then []
  else
    let stream := byteAt (encrypt (counterBlock nonce counter))
    xorFrom stream 0 (data.take 16) ++ gctrSource encrypt nonce (counter + 1) (data.drop 16)
termination_by data.length
decreasing_by
  simp only [List.length_drop]
  have nonzero : data.length ≠ 0 := fun h => _empty (List.eq_nil_iff_length_eq_zero.mpr h)
  omega

theorem gctrSource_refines_nist (encrypt : Block → Block) (nonce : Nonce) (counter : Nat)
    (data : List Byte) : gctrSource encrypt nonce counter data = gctr encrypt nonce counter data := by
  by_cases empty : data = []
  · simp [empty, gctrSource.eq_def, gctr, xorFrom]
  · rw [gctrSource.eq_def encrypt nonce counter data, dif_neg empty]
    rw [gctrSource_refines_nist encrypt nonce (counter + 1) (data.drop 16)]
    unfold gctr
    dsimp only
    have first : xorFrom (byteAt (encrypt (counterBlock nonce counter))) 0 (data.take 16) =
        xorFrom (payloadStream encrypt nonce counter) 0 (data.take 16) := by
      apply xorFrom_congr
      intro index within
      have small : index < 16 := by simp only [List.length_take] at within; omega
      simp [payloadStream, Nat.div_eq_of_lt small, Nat.mod_eq_of_lt small]
    rw [first]
    have rest : xorFrom (payloadStream encrypt nonce (counter + 1)) 0 (data.drop 16) =
        xorFrom (payloadStream encrypt nonce counter) (data.take 16).length (data.drop 16) := by
      by_cases tailEmpty : data.drop 16 = []
      · simp [tailEmpty, xorFrom]
      · have full : (data.take 16).length = 16 := by
          have nonzero : (data.drop 16).length ≠ 0 := fun h =>
            tailEmpty (List.eq_nil_iff_length_eq_zero.mpr h)
          simp only [List.length_drop] at nonzero
          simp only [List.length_take]
          omega
        rw [full]
        apply xorFrom_congr
        intro index _
        have blockOffset : counter + (16 + index) / 16 = counter + 1 + index / 16 := by omega
        have byteOffset : (16 + index) % 16 = index % 16 := by omega
        simp only [payloadStream, Nat.zero_add, blockOffset, byteOffset]
    rw [rest]
    simpa only [Nat.zero_add, List.take_append_drop] using
      (xorFrom_append (payloadStream encrypt nonce counter) 0 (data.take 16) (data.drop 16)).symm
termination_by data.length
decreasing_by
  simp only [List.length_drop]
  have nonzero : data.length ≠ 0 := fun h => empty (List.eq_nil_iff_length_eq_zero.mpr h)
  omega

theorem payload_counter_in_range (length offset : Nat)
    (admitted : length ≤ payloadLimit) (inside : offset < length) :
    1 < 2 + offset / 16 ∧ 2 + offset / 16 < 2^32 := by
  unfold payloadLimit at admitted
  omega

private def tagDifference : List Byte → List Byte → Byte
  | [], [] => 0
  | x :: xs, y :: ys => (x ^^^ y) ||| tagDifference xs ys
  | _, _ => 1

private theorem tagDifference_zero (left right : List Byte) :
    tagDifference left right = 0#8 ↔ left = right := by
  induction left generalizing right with
  | nil => cases right <;> simp [tagDifference]
  | cons x xs ih =>
    cases right with
    | nil => simp [tagDifference]
    | cons y ys =>
      change (x ^^^ y ||| tagDifference xs ys) = 0#8 ↔ x :: xs = y :: ys
      rw [BitVec.or_eq_zero_iff, BitVec.xor_eq_zero_iff, ih, List.cons.injEq]

private def accumulateDifferences (acc : Byte) (left right : List Byte) : Byte :=
  (List.zipWith (· ^^^ ·) left right).foldl (· ||| ·) acc

private theorem accumulateDifferences_eq (acc : Byte) (left right : List Byte)
    (width : left.length = right.length) :
    accumulateDifferences acc left right = acc ||| tagDifference left right := by
  induction left generalizing acc right with
  | nil => cases right <;> simp_all [accumulateDifferences, tagDifference]
  | cons x xs ih =>
    cases right with
    | nil => simp at width
    | cons y ys =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at width
      simp only [accumulateDifferences, List.zipWith_cons_cons, List.foldl_cons]
      change accumulateDifferences (acc ||| (x ^^^ y)) xs ys = _
      rw [ih _ _ width, BitVec.or_assoc, tagDifference]

def fullTagMatches (actual expected : Tag) : Bool :=
  accumulateDifferences 0#8 actual.toList expected.toList == 0#8

theorem fullTagMatches_iff (actual expected : Tag) :
    fullTagMatches actual expected = true ↔ actual = expected := by
  unfold fullTagMatches
  rw [accumulateDifferences_eq _ _ _ (by simp), BitVec.zero_or]
  simp only [beq_iff_eq, tagDifference_zero, Vector.toList_inj]

def authenticate (encrypt : Block → Block) (nonce : Nonce) (aad ciphertext : List Byte) : Tag :=
  asTag (ghash (encrypt 0) (transcript aad ciphertext) ^^^ encrypt (counterBlock nonce 1))

def authenticateSource (encrypt : Block → Block) (nonce : Nonce) (aad ciphertext : List Byte) : Tag :=
  asTag (ghashSource (encrypt 0) aad ciphertext ^^^ encrypt (counterBlock nonce 1))

theorem authenticateSource_refines_nist (encrypt : Block → Block) (nonce : Nonce)
    (aad ciphertext : List Byte) (aadFits : 8 * aad.length < 2^64) (cipherFits : 8 * ciphertext.length < 2^64) :
    authenticateSource encrypt nonce aad ciphertext = authenticate encrypt nonce aad ciphertext := by
  rw [authenticateSource, authenticate, ghashSource_refines_nist _ _ _ aadFits cipherFits]

inductive Error where
  | messageTooLong
  | associatedDataTooLong
  | authenticationFailed
  deriving DecidableEq, Repr

structure Outcome (α : Type) where
  result : Except Error α
  bytes : List Byte

def sealReference (encrypt : Encrypt) (key : Key) (nonce : Nonce) (aad data : List Byte) : Outcome Tag :=
  if payloadLimit < data.length then ⟨.error .messageTooLong, data⟩
  else if aadLimit < aad.length then ⟨.error .associatedDataTooLong, data⟩
  else
    let ciphertext := gctr (encrypt key) nonce 2 data
    ⟨.ok (authenticate (encrypt key) nonce aad ciphertext), ciphertext⟩

def openReference (encrypt : Encrypt) (key : Key) (nonce : Nonce)
    (aad data : List Byte) (tag : Tag) : Outcome Unit :=
  if payloadLimit < data.length then ⟨.error .messageTooLong, data⟩
  else if aadLimit < aad.length then ⟨.error .associatedDataTooLong, data⟩
  else if authenticate (encrypt key) nonce aad data = tag then
    ⟨.ok (), gctr (encrypt key) nonce 2 data⟩
  else ⟨.error .authenticationFailed, data⟩

structure AesApi where
  Context : Type
  init : Key → Context
  encryptBlock : Context → Block → Block

-- The external AES-256 proof must supply this functional contract.
def AesApi.Refines (api : AesApi) (reference : Encrypt) : Prop :=
  ∀ key input, api.encryptBlock (api.init key) input = reference key input

def sealWithApi (api : AesApi) (key : Key) (nonce : Nonce)
    (aad data : List Byte) : Outcome Tag :=
  if payloadLimit < data.length then ⟨.error .messageTooLong, data⟩
  else if aadLimit < aad.length then ⟨.error .associatedDataTooLong, data⟩
  else
    let encrypt := api.encryptBlock (api.init key)
    let ciphertext := gctrSource encrypt nonce 2 data
    ⟨.ok (authenticateSource encrypt nonce aad ciphertext), ciphertext⟩

def openWithApi (api : AesApi) (key : Key) (nonce : Nonce)
    (aad data : List Byte) (tag : Tag) : Outcome Unit :=
  if payloadLimit < data.length then ⟨.error .messageTooLong, data⟩
  else if aadLimit < aad.length then ⟨.error .associatedDataTooLong, data⟩
  else
    let encrypt := api.encryptBlock (api.init key)
    if fullTagMatches (authenticateSource encrypt nonce aad data) tag then
      ⟨.ok (), gctrSource encrypt nonce 2 data⟩
    else ⟨.error .authenticationFailed, data⟩

private theorem aad_bits_fit (length : Nat) (admitted : length ≤ aadLimit) : 8 * length < 2^64 := by
  unfold aadLimit at admitted
  omega

private theorem payload_bits_fit (length : Nat) (admitted : length ≤ payloadLimit) : 8 * length < 2^64 := by
  unfold payloadLimit at admitted
  omega

theorem sealWithApi_refines_nist (api : AesApi) (encrypt : Encrypt) (apiSound : api.Refines encrypt)
    (key : Key) (nonce : Nonce) (aad data : List Byte) :
    sealWithApi api key nonce aad data = sealReference encrypt key nonce aad data := by
  by_cases rejected : payloadLimit < data.length
  · simp [sealWithApi, sealReference, rejected]
  · by_cases aadRejected : aadLimit < aad.length
    · simp [sealWithApi, sealReference, rejected, aadRejected]
    · have block : api.encryptBlock (api.init key) = encrypt key := funext (apiSound key)
      have pdf : 8 * (gctr (encrypt key) nonce 2 data).length < 2^64 := by
        rw [gctr_length]
        exact payload_bits_fit _ (by omega)
      simp only [sealWithApi, sealReference, rejected, aadRejected, if_false, block, gctrSource_refines_nist]
      rw [authenticateSource_refines_nist _ _ _ _ (aad_bits_fit _ (by omega)) pdf]

theorem openWithApi_refines_nist (api : AesApi) (encrypt : Encrypt) (apiSound : api.Refines encrypt)
    (key : Key) (nonce : Nonce) (aad data : List Byte) (tag : Tag) :
    openWithApi api key nonce aad data tag = openReference encrypt key nonce aad data tag := by
  by_cases rejected : payloadLimit < data.length
  · simp [openWithApi, openReference, rejected]
  · by_cases aadRejected : aadLimit < aad.length
    · simp [openWithApi, openReference, rejected, aadRejected]
    · have block : api.encryptBlock (api.init key) = encrypt key := funext (apiSound key)
      have auth := authenticateSource_refines_nist (encrypt key) nonce aad data
        (aad_bits_fit aad.length (by omega)) (payload_bits_fit data.length (by omega))
      simp only [openWithApi, openReference, rejected, aadRejected, if_false, block, gctrSource_refines_nist,
        auth, fullTagMatches_iff]

theorem openWithApi_error_preserves_bytes (api : AesApi) (key : Key) (nonce : Nonce)
    (aad data : List Byte) (tag : Tag) (error : Error)
    (failed : (openWithApi api key nonce aad data tag).result = .error error) :
    (openWithApi api key nonce aad data tag).bytes = data := by
  by_cases rejected : payloadLimit < data.length
  · simp [openWithApi, rejected]
  · by_cases aadRejected : aadLimit < aad.length
    · simp [openWithApi, rejected, aadRejected]
    · by_cases valid : fullTagMatches (authenticateSource (api.encryptBlock (api.init key)) nonce aad data) tag = true
      · simp [openWithApi, rejected, aadRejected, valid] at failed
      · simp [openWithApi, rejected, aadRejected, valid]

theorem sealWithApi_error_preserves_bytes (api : AesApi) (key : Key) (nonce : Nonce)
    (aad data : List Byte) (error : Error)
    (failed : (sealWithApi api key nonce aad data).result = .error error) :
    (sealWithApi api key nonce aad data).bytes = data := by
  by_cases rejected : payloadLimit < data.length
  · simp [sealWithApi, rejected]
  · by_cases aadRejected : aadLimit < aad.length
    · simp [sealWithApi, rejected, aadRejected]
    · simp [sealWithApi, rejected, aadRejected] at failed

theorem openWithApi_rejects_wrong_tag (api : AesApi) (encrypt : Encrypt) (apiSound : api.Refines encrypt)
    (key : Key) (nonce : Nonce) (aad data : List Byte) (tag : Tag)
    (payloadAdmitted : data.length ≤ payloadLimit) (aadAdmitted : aad.length ≤ aadLimit)
    (wrong : tag ≠ authenticate (encrypt key) nonce aad data) :
    openWithApi api key nonce aad data tag = ⟨.error .authenticationFailed, data⟩ := by
  rw [openWithApi_refines_nist _ _ apiSound]
  simp [openReference, Nat.not_lt.mpr payloadAdmitted, Nat.not_lt.mpr aadAdmitted, Ne.symm wrong]

theorem open_seal_roundtrip (api : AesApi) (encrypt : Encrypt) (apiSound : api.Refines encrypt)
    (key : Key) (nonce : Nonce) (aad data : List Byte)
    (payloadAdmitted : data.length ≤ payloadLimit) (aadAdmitted : aad.length ≤ aadLimit) :
    ∃ tag, (sealWithApi api key nonce aad data).result = .ok tag ∧
      openWithApi api key nonce aad (sealWithApi api key nonce aad data).bytes tag = ⟨.ok (), data⟩ := by
  rw [sealWithApi_refines_nist _ _ apiSound]
  unfold sealReference
  rw [if_neg (Nat.not_lt.mpr payloadAdmitted), if_neg (Nat.not_lt.mpr aadAdmitted)]
  refine ⟨_, rfl, ?_⟩
  rw [openWithApi_refines_nist _ _ apiSound]
  simp [openReference, Nat.not_lt.mpr payloadAdmitted, Nat.not_lt.mpr aadAdmitted, gctr_twice]

-- GCM-AES256 Example #5 supplies each AES result the known-answer case uses.
private def exampleNonce : Nonce := 0xcafebabefacedbaddecaf888
private def exampleKey : Key := 0xfeffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308

private def exampleEncrypt (input : Block) : Block :=
  if input = 0 then 0xacbef20579b4b8ebce889bac8732dad7
  else if input = counterBlock exampleNonce 1 then 0xfd2caa16a5832e76aa132c1453eeda7e
  else if input = counterBlock exampleNonce 2 then 0x8b1cf3d561d27be251263e66857164e7
  else if input = counterBlock exampleNonce 3 then 0xe29d258faad137135bd49280af645bd8
  else if input = counterBlock exampleNonce 4 then 0x908c82ddcc65b26e887f85341f243d1d
  else if input = counterBlock exampleNonce 5 then 0x749cf39639b79c5d06aa8d5b932fc7f8
  else 0

private def exampleApi : AesApi :=
  { Context := Unit, init := fun _ => (), encryptBlock := fun _ => exampleEncrypt }

private def exampleAad : List Byte :=
  [0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e,
   0xca, 0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85]

private def examplePlaintext : List Byte :=
  [0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59,
   0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
   0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
   0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
   0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a,
   0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39]

private def exampleCiphertext : List Byte :=
  [0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f,
   0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc,
   0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55,
   0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
   0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6,
   0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62]

private def exampleTag : List Byte :=
  [0xe0, 0x97, 0x19, 0x5f, 0x45, 0x32, 0xda, 0x89, 0x5f, 0xb9,
   0x17, 0xa5, 0xa5, 0x5c, 0x6a, 0xa0]

set_option maxRecDepth 8192 in
theorem nist_example_5_ghash :
    ghashSource (exampleEncrypt 0) exampleAad exampleCiphertext =
      0x1dbbb349e0b1f4fff5aa3bb1f6b2b0de := by
  decide +kernel

set_option maxRecDepth 8192 in
theorem nist_example_5_seal_and_open :
    let sealed := sealWithApi exampleApi exampleKey exampleNonce exampleAad examplePlaintext
    let opened := openWithApi exampleApi exampleKey exampleNonce exampleAad exampleCiphertext
      (asTag 0xe097195f4532da895fb917a5a55c6aa0)
    sealed.bytes = exampleCiphertext ∧ sealed.result.toOption.map Vector.toList = some exampleTag ∧
      opened.result.toOption = some () ∧ opened.bytes = examplePlaintext := by
  decide +kernel

#print axioms multiplyMask_refines_nist
#print axioms decodeBigEndian_bigEndian
#print axioms packedLength_matches_bytes
#print axioms transcript_recovers_inputs
#print axioms transcript_injective
#print axioms sourceBlocks_refines_padded
#print axioms ghashSource_refines_nist
#print axioms gctrSource_refines_nist
#print axioms gctr_twice
#print axioms payload_counter_in_range
#print axioms fullTagMatches_iff
#print axioms authenticateSource_refines_nist
#print axioms sealWithApi_refines_nist
#print axioms openWithApi_refines_nist
#print axioms sealWithApi_error_preserves_bytes
#print axioms openWithApi_error_preserves_bytes
#print axioms openWithApi_rejects_wrong_tag
#print axioms open_seal_roundtrip
#print axioms nist_example_5_ghash
#print axioms nist_example_5_seal_and_open

end Abc.Spec.Aes256Gcm.Composition
