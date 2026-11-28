import Std

namespace Abc.Spec.ChaCha20Poly1305.Rfc

abbrev Byte := UInt8
abbrev Key := Vector Byte 32
abbrev Nonce := Vector Byte 12
abbrev Block := Vector Byte 64
abbrev Tag := Vector Byte 16
abbrev BlockFunction := Key → Nonce → Nat → Block

def payloadLimit : Nat := (2^32 - 1) * 64

def littleEndian : Nat → Nat → List Byte
  | 0, _ => []
  | n + 1, value => UInt8.ofNat value :: littleEndian n (value / 256)

def decodeLittleEndian : List Byte → Nat
  | [] => 0
  | b :: tail => b.toNat + 256 * decodeLittleEndian tail

@[simp] theorem littleEndian_length (width value : Nat) :
    (littleEndian width value).length = width := by
  induction width generalizing value with
  | zero => rfl
  | succ width ih => simp [littleEndian, ih]

theorem decodeLittleEndian_littleEndian (width value : Nat) :
    decodeLittleEndian (littleEndian width value) = value % 256^width := by
  induction width generalizing value with
  | zero => simp [littleEndian, decodeLittleEndian, Nat.mod_one]
  | succ width ih =>
    simp only [littleEndian, decodeLittleEndian, ih]
    change value % 256 + 256 * (value / 256 % 256^width) = value % 256^(width + 1)
    rw [Nat.pow_succ']
    exact Nat.mod_mul.symm

def padding (n : Nat) : Nat := (16 - n % 16) % 16

def paddingBytes (data : List Byte) : List Byte :=
  List.replicate (padding data.length) 0

def padded (data : List Byte) : List Byte := data ++ paddingBytes data

def lengthFields (aad ciphertext : List Byte) : List Byte :=
  littleEndian 8 aad.length ++ littleEndian 8 ciphertext.length

def transcript (aad ciphertext : List Byte) : List Byte :=
  (padded aad ++ padded ciphertext) ++ lengthFields aad ciphertext

theorem transcript_aligned (aad ciphertext : List Byte) :
    (transcript aad ciphertext).length % 16 = 0 := by
  simp only [transcript, padded, lengthFields, paddingBytes, padding,
    List.length_append, List.length_replicate, littleEndian_length]
  omega

def transcriptLengths (wire : List Byte) : Nat × Nat :=
  let fields := wire.drop (wire.length - 16)
  (decodeLittleEndian (fields.take 8), decodeLittleEndian (fields.drop 8))

theorem transcriptLengths_transcript (aad ciphertext : List Byte)
    (aadBound : aad.length < 2^64) (cipherBound : ciphertext.length < 2^64) :
    transcriptLengths (transcript aad ciphertext) = (aad.length, ciphertext.length) := by
  have fields : (lengthFields aad ciphertext).length = 16 := by simp [lengthFields]
  have lengthEq : (transcript aad ciphertext).length - 16 =
      (padded aad ++ padded ciphertext).length := by
    simp only [transcript, List.length_append, fields, Nat.add_sub_cancel]
  unfold transcriptLengths
  rw [lengthEq]
  unfold transcript
  rw [List.drop_left]
  unfold lengthFields
  have takeEq : (littleEndian 8 aad.length ++ littleEndian 8 ciphertext.length).take 8 =
      littleEndian 8 aad.length := by
    simpa only [littleEndian_length] using
      (List.take_left (l₁ := littleEndian 8 aad.length) (l₂ := littleEndian 8 ciphertext.length))
  have dropEq : (littleEndian 8 aad.length ++ littleEndian 8 ciphertext.length).drop 8 =
      littleEndian 8 ciphertext.length := by
    simpa only [littleEndian_length] using
      (List.drop_left (l₁ := littleEndian 8 aad.length) (l₂ := littleEndian 8 ciphertext.length))
  simp only [takeEq, dropEq]
  rw [decodeLittleEndian_littleEndian, decodeLittleEndian_littleEndian]
  exact Prod.ext (Nat.mod_eq_of_lt aadBound) (Nat.mod_eq_of_lt cipherBound)

def decodeTranscript (wire : List Byte) : List Byte × List Byte :=
  let (a, c) := transcriptLengths wire
  (wire.take a, (wire.drop (a + padding a)).take c)

theorem decodeTranscript_transcript (aad ciphertext : List Byte)
    (aadBound : aad.length < 2^64) (cipherBound : ciphertext.length < 2^64) :
    decodeTranscript (transcript aad ciphertext) = (aad, ciphertext) := by
  unfold decodeTranscript
  rw [transcriptLengths_transcript aad ciphertext aadBound cipherBound]
  apply Prod.ext
  · simp only [transcript, padded, List.append_assoc, List.take_left]
  · have paddedLength : (padded aad).length = aad.length + padding aad.length := by
      simp [padded, paddingBytes]
    simp only [transcript, List.append_assoc, ← paddedLength, List.drop_left]
    simp only [padded, List.append_assoc, List.take_left]

theorem transcript_injective (aad₁ ciphertext₁ aad₂ ciphertext₂ : List Byte)
    (aadBound₁ : aad₁.length < 2^64) (cipherBound₁ : ciphertext₁.length < 2^64)
    (aadBound₂ : aad₂.length < 2^64) (cipherBound₂ : ciphertext₂.length < 2^64)
    (same : transcript aad₁ ciphertext₁ = transcript aad₂ ciphertext₂) :
    aad₁ = aad₂ ∧ ciphertext₁ = ciphertext₂ := by
  have decoded := congrArg decodeTranscript same
  rw [decodeTranscript_transcript _ _ aadBound₁ cipherBound₁,
    decodeTranscript_transcript _ _ aadBound₂ cipherBound₂] at decoded
  exact ⟨congrArg Prod.fst decoded, congrArg Prod.snd decoded⟩

def xorFrom (stream : Nat → Byte) (offset : Nat) : List Byte → List Byte
  | [] => []
  | byte :: tail => (byte ^^^ stream offset) :: xorFrom stream (offset + 1) tail

@[simp] theorem xorFrom_length (stream : Nat → Byte) (offset : Nat) (bytes : List Byte) :
    (xorFrom stream offset bytes).length = bytes.length := by
  induction bytes generalizing offset with
  | nil => rfl
  | cons byte tail ih => simp [xorFrom, ih]

theorem xorFrom_involutive (stream : Nat → Byte) (offset : Nat) (bytes : List Byte) :
    xorFrom stream offset (xorFrom stream offset bytes) = bytes := by
  induction bytes generalizing offset with
  | nil => rfl
  | cons byte tail ih => simp [xorFrom, ih, UInt8.xor_assoc]

def xorWithBlocks (block : BlockFunction) (key : Key) (nonce : Nonce) (counter : Nat)
    (bytes : List Byte) : List Byte :=
  xorFrom (fun offset => (block key nonce (counter + offset / 64))[offset % 64]'(Nat.mod_lt _ (by decide))) 0 bytes

theorem modeled_payload_counter_bounds (length offset : Nat)
    (bounded : length ≤ payloadLimit) (inside : offset < length) :
    0 < 1 + offset / 64 ∧ 1 + offset / 64 < 2^32 := by
  unfold payloadLimit at bounded
  omega

def keyFromBlock (block : BlockFunction) (key : Key) (nonce : Nonce) : List Byte :=
  (block key nonce 0).toList.take 32

private def clampedMultiplier (polyKey : List Byte) : Nat :=
  decodeLittleEndian (polyKey.take 16) &&& 0x0ffffffc0ffffffc0ffffffc0fffffff

private def polyStep (r h : Nat) (bytes : List Byte) : Nat :=
  ((h + decodeLittleEndian bytes + 256^bytes.length) * r) % (2^130 - 5)

private def polyAbsorb (r h : Nat) (bytes : List Byte) : Nat :=
  if _hEmpty : bytes.isEmpty then h
  else polyAbsorb r (polyStep r h (bytes.take 16)) (bytes.drop 16)
termination_by bytes.length
decreasing_by
  simp only [List.length_drop]
  have hLength : 0 < bytes.length := by
    cases bytes <;> simp_all
  omega

def polyTag (polyKey bytes : List Byte) : Tag :=
  let r := clampedMultiplier polyKey
  let pad := decodeLittleEndian (polyKey.drop 16)
  let encoded := littleEndian 16 (polyAbsorb r 0 bytes + pad)
  ⟨encoded.toArray, by simp [encoded]⟩

def authenticate (block : BlockFunction) (key : Key) (nonce : Nonce)
    (aad ciphertext : List Byte) : Tag :=
  polyTag (keyFromBlock block key nonce) (transcript aad ciphertext)

def tagDifference : List Byte → List Byte → Byte
  | [], [] => 0
  | a :: atail, b :: btail => (a ^^^ b) ||| tagDifference atail btail
  | _, _ => 1

theorem tagDifference_zero (left right : List Byte) :
    tagDifference left right = 0 ↔ left = right := by
  induction left generalizing right with
  | nil => cases right <;> simp [tagDifference]
  | cons a left ih =>
    cases right with
    | nil => simp [tagDifference]
    | cons b right =>
      simp [tagDifference, UInt8.or_eq_zero_iff, UInt8.xor_eq_zero_iff, ih]

private def accumulateDifferences (initial : Byte) (actual expected : List Byte) : Byte :=
  (List.zipWith (· ^^^ ·) actual expected).foldl (· ||| ·) initial

private theorem accumulateDifferences_eq (initial : Byte) (actual expected : List Byte)
    (sameLength : actual.length = expected.length) :
    accumulateDifferences initial actual expected = initial ||| tagDifference actual expected := by
  induction actual generalizing expected initial with
  | nil =>
    cases expected <;> simp_all [accumulateDifferences, tagDifference]
  | cons a actual ih =>
    cases expected with
    | nil => simp at sameLength
    | cons b expected =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at sameLength
      simp only [accumulateDifferences, List.zipWith_cons_cons, List.foldl_cons]
      change accumulateDifferences (initial ||| (a ^^^ b)) actual expected = _
      rw [ih _ _ sameLength, UInt8.or_assoc, tagDifference]

def fullTagMatches (actual expected : Tag) : Bool :=
  accumulateDifferences 0 actual.toList expected.toList == 0

theorem fullTagMatches_iff (actual expected : Tag) :
    fullTagMatches actual expected = true ↔ actual = expected := by
  unfold fullTagMatches
  rw [accumulateDifferences_eq _ _ _ (by simp), UInt8.zero_or]
  simp only [beq_iff_eq, tagDifference_zero, Vector.toList_inj]

inductive Error where
  | messageTooLong
  | authenticationFailed
  deriving DecidableEq, Repr

structure Outcome (α : Type) where
  result : Except Error α
  bytes : List Byte

def sealReference (block : BlockFunction) (key : Key) (nonce : Nonce) (aad plaintext : List Byte) :
    Outcome Tag :=
  if plaintext.length ≤ payloadLimit then
    let ciphertext := xorWithBlocks block key nonce 1 plaintext
    ⟨.ok (authenticate block key nonce aad ciphertext), ciphertext⟩
  else ⟨.error .messageTooLong, plaintext⟩

def openReference (block : BlockFunction) (key : Key) (nonce : Nonce) (aad ciphertext : List Byte)
    (tag : Tag) : Outcome Unit :=
  if ciphertext.length ≤ payloadLimit then
    if authenticate block key nonce aad ciphertext = tag then
      ⟨.ok (), xorWithBlocks block key nonce 1 ciphertext⟩
    else ⟨.error .authenticationFailed, ciphertext⟩
  else ⟨.error .messageTooLong, ciphertext⟩

theorem open_seal_roundtrip (block : BlockFunction) (key : Key) (nonce : Nonce)
    (aad plaintext : List Byte) (admitted : plaintext.length ≤ payloadLimit) :
    ∃ tag, (sealReference block key nonce aad plaintext).result = .ok tag ∧
      openReference block key nonce aad (sealReference block key nonce aad plaintext).bytes tag = ⟨.ok (), plaintext⟩ := by
  unfold sealReference
  rw [if_pos admitted]
  refine ⟨_, rfl, ?_⟩
  simp [openReference, xorWithBlocks, admitted, xorFrom_involutive]

theorem open_rejects_wrong_tag (block : BlockFunction) (key : Key) (nonce : Nonce)
    (aad ciphertext : List Byte) (tag : Tag) (admitted : ciphertext.length ≤ payloadLimit)
    (wrong : tag ≠ authenticate block key nonce aad ciphertext) :
    openReference block key nonce aad ciphertext tag = ⟨.error .authenticationFailed, ciphertext⟩ := by
  simp [openReference, admitted, Ne.symm wrong]

theorem open_error_preserves_bytes (block : BlockFunction) (key : Key) (nonce : Nonce)
    (aad ciphertext : List Byte) (tag : Tag) (error : Error)
    (failed : (openReference block key nonce aad ciphertext tag).result = .error error) :
    (openReference block key nonce aad ciphertext tag).bytes = ciphertext := by
  by_cases admitted : ciphertext.length ≤ payloadLimit
  · by_cases valid : authenticate block key nonce aad ciphertext = tag
    · simp [openReference, admitted, valid] at failed
    · simp [openReference, admitted, valid]
  · simp [openReference, admitted]

structure MacApi where
  State : Type
  start : List Byte → State
  update : State → List Byte → State
  finish : State → Tag

structure MacApi.Refines (api : MacApi) where
  -- The invariant relates pending bytes and accumulator state to the entire absorbed message.
  represents : api.State → List Byte → List Byte → Prop
  start_sound (key : List Byte) (fixed : key.length = 32) : represents (api.start key) key []
  update_sound (state : api.State) (key absorbed chunk : List Byte)
    (state_sound : represents state key absorbed) : represents (api.update state chunk) key (absorbed ++ chunk)
  finish_sound (state : api.State) (key absorbed : List Byte)
    (state_sound : represents state key absorbed) : api.finish state = polyTag key absorbed

private theorem mac_trace_refines (api : MacApi) (mac : api.Refines) (state : api.State)
    (key absorbed : List Byte) (chunks : List (List Byte)) (valid : mac.represents state key absorbed) :
    mac.represents (chunks.foldl api.update state) key (absorbed ++ chunks.flatten) := by
  induction chunks generalizing state absorbed with
  | nil => simpa using valid
  | cons chunk chunks ih =>
    simp only [List.flatten_cons, List.foldl_cons, ← List.append_assoc]
    exact ih (api.update state chunk) (absorbed ++ chunk) (mac.update_sound state key absorbed chunk valid)

def authenticationChunks (aad ciphertext : List Byte) : List (List Byte) :=
  [aad, paddingBytes aad, ciphertext, paddingBytes ciphertext,
    littleEndian 8 aad.length, littleEndian 8 ciphertext.length]

def authenticateVia (api : MacApi) (polyKey aad ciphertext : List Byte) : Tag :=
  api.finish ((authenticationChunks aad ciphertext).foldl api.update (api.start polyKey))

theorem authenticateVia_refines (api : MacApi) (mac : api.Refines)
    (polyKey aad ciphertext : List Byte) (fixed : polyKey.length = 32) :
    authenticateVia api polyKey aad ciphertext = polyTag polyKey (transcript aad ciphertext) := by
  unfold authenticateVia
  have trace := mac_trace_refines api mac (api.start polyKey) polyKey []
    (authenticationChunks aad ciphertext) (mac.start_sound polyKey fixed)
  simpa only [transcript, padded, lengthFields, authenticationChunks, List.flatten_cons, List.flatten_nil,
    List.nil_append, List.append_nil, List.append_assoc] using mac.finish_sound _ _ _ trace

structure StreamApi where
  apply : Key → Nonce → Nat → List Byte → Option (List Byte)

structure StreamApi.Refines (api : StreamApi) (block : BlockFunction) : Prop where
  key_sound (key : Key) (nonce : Nonce) :
    api.apply key nonce 0 (List.replicate 32 0) = some (keyFromBlock block key nonce)
  payload_sound (key : Key) (nonce : Nonce) (input : List Byte)
    (admitted : input.length ≤ payloadLimit) :
    api.apply key nonce 1 input = some (xorWithBlocks block key nonce 1 input)

def authenticateWithApis (stream : StreamApi) (mac : MacApi) (key : Key) (nonce : Nonce)
    (aad ciphertext : List Byte) : Option Tag :=
  (stream.apply key nonce 0 (List.replicate 32 0)).map (fun polyKey => authenticateVia mac polyKey aad ciphertext)

theorem authenticateWithApis_refines (stream : StreamApi) (mac : MacApi) (block : BlockFunction)
    (streamSound : stream.Refines block) (macSound : mac.Refines)
    (key : Key) (nonce : Nonce) (aad ciphertext : List Byte) :
    authenticateWithApis stream mac key nonce aad ciphertext =
      some (authenticate block key nonce aad ciphertext) := by
  rw [authenticateWithApis, streamSound.key_sound]
  simp only [Option.map_some, authenticate]
  have fixed : (keyFromBlock block key nonce).length = 32 := by simp [keyFromBlock]
  rw [authenticateVia_refines mac macSound _ _ _ fixed]

def sealWithApis (stream : StreamApi) (mac : MacApi) (key : Key) (nonce : Nonce)
    (aad plaintext : List Byte) : Outcome Tag :=
  if plaintext.length ≤ payloadLimit then
    match stream.apply key nonce 1 plaintext with
    | none => ⟨.error .messageTooLong, plaintext⟩
    | some ciphertext =>
      match authenticateWithApis stream mac key nonce aad ciphertext with
      | none => ⟨.error .messageTooLong, ciphertext⟩
      | some tag => ⟨.ok tag, ciphertext⟩
  else ⟨.error .messageTooLong, plaintext⟩

def openWithApis (stream : StreamApi) (mac : MacApi) (key : Key) (nonce : Nonce)
    (aad ciphertext : List Byte) (tag : Tag) : Outcome Unit :=
  if ciphertext.length ≤ payloadLimit then
    match authenticateWithApis stream mac key nonce aad ciphertext with
    | none => ⟨.error .messageTooLong, ciphertext⟩
    | some actual =>
      if fullTagMatches actual tag then
        match stream.apply key nonce 1 ciphertext with
        | none => ⟨.error .messageTooLong, ciphertext⟩
        | some plaintext => ⟨.ok (), plaintext⟩
      else ⟨.error .authenticationFailed, ciphertext⟩
  else ⟨.error .messageTooLong, ciphertext⟩

theorem sealWithApis_refines (stream : StreamApi) (mac : MacApi) (block : BlockFunction)
    (streamSound : stream.Refines block) (macSound : mac.Refines)
    (key : Key) (nonce : Nonce) (aad plaintext : List Byte) :
    sealWithApis stream mac key nonce aad plaintext = sealReference block key nonce aad plaintext := by
  by_cases admitted : plaintext.length ≤ payloadLimit
  · simp only [sealWithApis, sealReference, if_pos admitted, streamSound.payload_sound _ _ _ admitted]
    rw [authenticateWithApis_refines _ _ _ streamSound macSound]
  · simp [sealWithApis, sealReference, admitted]

theorem openWithApis_refines (stream : StreamApi) (mac : MacApi) (block : BlockFunction)
    (streamSound : stream.Refines block) (macSound : mac.Refines)
    (key : Key) (nonce : Nonce) (aad ciphertext : List Byte) (tag : Tag) :
    openWithApis stream mac key nonce aad ciphertext tag = openReference block key nonce aad ciphertext tag := by
  by_cases admitted : ciphertext.length ≤ payloadLimit
  · simp only [openWithApis, openReference, if_pos admitted,
      authenticateWithApis_refines _ _ _ streamSound macSound, fullTagMatches_iff,
      streamSound.payload_sound _ _ _ admitted]
  · simp [openWithApis, openReference, admitted]

theorem openWithApis_error_preserves_bytes (stream : StreamApi) (mac : MacApi)
    (key : Key) (nonce : Nonce) (aad ciphertext : List Byte) (tag : Tag) (error : Error)
    (failed : (openWithApis stream mac key nonce aad ciphertext tag).result = .error error) :
    (openWithApis stream mac key nonce aad ciphertext tag).bytes = ciphertext := by
  by_cases admitted : ciphertext.length ≤ payloadLimit
  · cases auth : authenticateWithApis stream mac key nonce aad ciphertext with
    | none => simp [openWithApis, admitted, auth]
    | some actual =>
      by_cases valid : fullTagMatches actual tag = true
      · cases decrypted : stream.apply key nonce 1 ciphertext with
        | none => simp [openWithApis, admitted, auth, valid, decrypted]
        | some plaintext => simp [openWithApis, admitted, auth, valid, decrypted] at failed
      · simp [openWithApis, admitted, auth, valid]
  · simp [openWithApis, admitted]

theorem openWithApis_sealWithApis_roundtrip (stream : StreamApi) (mac : MacApi)
    (block : BlockFunction) (streamSound : stream.Refines block) (macSound : mac.Refines)
    (key : Key) (nonce : Nonce) (aad plaintext : List Byte)
    (admitted : plaintext.length ≤ payloadLimit) :
    ∃ tag, (sealWithApis stream mac key nonce aad plaintext).result = .ok tag ∧
      openWithApis stream mac key nonce aad (sealWithApis stream mac key nonce aad plaintext).bytes tag =
        ⟨.ok (), plaintext⟩ := by
  rw [sealWithApis_refines _ _ _ streamSound macSound]
  obtain ⟨tag, sealed, opened⟩ := open_seal_roundtrip block key nonce aad plaintext admitted
  refine ⟨tag, sealed, ?_⟩
  rw [openWithApis_refines _ _ _ streamSound macSound]
  exact opened

private def examplePolyKey : List Byte :=
  [0x7b, 0xac, 0x2b, 0x25, 0x2d, 0xb4, 0x47, 0xaf, 0x09, 0xb6, 0x7a, 0x55,
   0xa4, 0xe9, 0x55, 0x84, 0x0a, 0xe1, 0xd6, 0x73, 0x10, 0x75, 0xd9, 0xeb,
   0x2a, 0x93, 0x75, 0x78, 0x3e, 0xd5, 0x53, 0xff]

private def exampleAad : List Byte :=
  [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]

private def exampleCiphertext : List Byte :=
  [0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
   0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
   0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
   0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
   0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
   0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
   0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
   0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
   0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
   0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16]

private def exampleTag : List Byte :=
  [0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
   0xd0, 0x60, 0x06, 0x91]

-- RFC 8439 §2.8.2 supplies the key from block zero and the ciphertext.
set_option maxRecDepth 8192 in
theorem rfc8439_authentication_vector :
    (polyTag examplePolyKey (transcript exampleAad exampleCiphertext)).toList = exampleTag := by
  decide +kernel

#print axioms decodeLittleEndian_littleEndian
#print axioms transcript_aligned
#print axioms transcript_injective
#print axioms xorFrom_involutive
#print axioms modeled_payload_counter_bounds
#print axioms fullTagMatches_iff
#print axioms open_seal_roundtrip
#print axioms open_rejects_wrong_tag
#print axioms open_error_preserves_bytes
#print axioms authenticateVia_refines
#print axioms authenticateWithApis_refines
#print axioms sealWithApis_refines
#print axioms openWithApis_refines
#print axioms openWithApis_error_preserves_bytes
#print axioms openWithApis_sealWithApis_roundtrip
#print axioms rfc8439_authentication_vector

end Abc.Spec.ChaCha20Poly1305.Rfc
