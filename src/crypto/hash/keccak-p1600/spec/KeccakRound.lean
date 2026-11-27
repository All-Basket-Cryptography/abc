namespace Abc.Spec.KeccakRound

abbrev Lane := BitVec 64
abbrev LaneIndex := Fin 25
abbrev RoundIndex := Fin 24
abbrev State := LaneIndex → Lane

-- Lane (x,y) is stored at flat index x + 5*y.
def atXY (x y : Nat) : LaneIndex :=
  ⟨x % 5 + 5 * (y % 5), by omega⟩

def piFormula (a : LaneIndex) : LaneIndex :=
  atXY (a.val / 5) (2 * (a.val % 5) + 3 * (a.val / 5))

def piInverse (a : LaneIndex) : LaneIndex :=
  atXY (a.val % 5 + 3 * (a.val / 5)) (a.val % 5)

def piTable (a : LaneIndex) : LaneIndex :=
  Fin.ofNat 25 (#[0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22,
    23, 8, 18, 3, 13, 14, 24, 9, 19, 4][a.val]!)

theorem pi_table_matches : ∀ a : LaneIndex, piTable a = piFormula a := by decide
theorem pi_left_inverse : ∀ a : LaneIndex, piInverse (piFormula a) = a := by decide
theorem pi_right_inverse : ∀ a : LaneIndex, piFormula (piInverse a) = a := by decide

-- The rho orbit begins at (1,0) and follows the FIPS 202 coordinate recurrence.
def rhoOrbit : Nat → LaneIndex
  | 0 => atXY 1 0
  | n + 1 => piFormula (rhoOrbit n)

def rhoFormula (a : LaneIndex) : Nat :=
  match (List.range 24).find? (fun i => rhoOrbit i == a) with
  | none => 0
  | some t => ((t + 1) * (t + 2) / 2) % 64

def rhoTable (a : LaneIndex) : Nat :=
  #[0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15,
    21, 8, 18, 2, 61, 56, 14][a.val]!

theorem rho_table_matches : ∀ a : LaneIndex, rhoTable a = rhoFormula a := by decide

-- In this representation bit zero is the first bit of FIPS 202 Algorithm 5.
def lfsr : Nat → BitVec 8
  | 0 => 1
  | n + 1 =>
    let x := lfsr n
    (x <<< 1) ^^^ (if x.getLsbD 7 then 0x71 else 0)

def iotaFormula (round : RoundIndex) : Lane :=
  (List.range 7).foldl (fun acc j =>
    if (lfsr ((j + 7 * round.val) % 255)).getLsbD 0
    then acc ^^^ ((1 : Lane) <<< (2 ^ j - 1)) else acc) 0

def iotaTable (round : RoundIndex) : Lane :=
  #[0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008][round.val]!

set_option maxRecDepth 4096 in
theorem iota_table_matches : ∀ round : RoundIndex, iotaTable round = iotaFormula round := by decide

def parity (state : State) (x : Nat) : Lane :=
  state (atXY x 0) ^^^ state (atXY x 1) ^^^ state (atXY x 2) ^^^
  state (atXY x 3) ^^^ state (atXY x 4)

def theta (state : State) : State :=
  fun a =>
    let x := a.val % 5
    state a ^^^ (parity state (x + 4) ^^^ (parity state (x + 1)).rotateLeft 1)

def tableSource (target : LaneIndex) : LaneIndex :=
  ((List.finRange 25).find? (fun source => piTable source == target)).getD 0

theorem table_source_matches : ∀ a : LaneIndex, tableSource a = piInverse a := by decide

theorem scatter_recovers_lane (a : LaneIndex) : tableSource (piTable a) = a := by
  rw [table_source_matches, pi_table_matches, pi_left_inverse]

def rhoPi (state : State) (source : LaneIndex → LaneIndex) (rotation : LaneIndex → Nat) : State :=
  fun a => (state (source a)).rotateLeft (rotation (source a))

def chi (state : State) : State :=
  fun a =>
    let x := a.val % 5
    let y := a.val / 5
    state a ^^^ (~~~state (atXY (x + 1) y) &&& state (atXY (x + 2) y))

def chiAndNot (state : State) : State :=
  fun a =>
    let x := a.val % 5
    let y := a.val / 5
    state a ^^^ (state (atXY (x + 2) y) &&& ~~~state (atXY (x + 1) y))

def addIota (state : State) (constant : Lane) : State :=
  fun a => if a.val = 0 then state a ^^^ constant else state a

def referenceRound (state : State) (round : RoundIndex) : State :=
  addIota (chi (rhoPi (theta state) piInverse rhoFormula)) (iotaFormula round)

def tableRound (state : State) (round : RoundIndex) : State :=
  addIota (chiAndNot (rhoPi (theta state) tableSource rhoTable)) (iotaTable round)

theorem table_round_matches (state : State) (round : RoundIndex) :
    tableRound state round = referenceRound state round := by
  have sameSource : tableSource = piInverse := funext table_source_matches
  have sameRotation : rhoTable = rhoFormula := funext rho_table_matches
  have sameChi : chiAndNot = chi := by
    funext input lane
    simp only [chi, chiAndNot]
    rw [BitVec.and_comm]
  simp only [tableRound, referenceRound, sameSource, sameRotation, sameChi, iota_table_matches]

def runRounds (applyRound : State → RoundIndex → State) (rounds : List RoundIndex)
    (initial : State) : State :=
  rounds.foldl applyRound initial

theorem all_rounds_match (rounds : List RoundIndex) (state : State) :
    runRounds tableRound rounds state = runRounds referenceRound rounds state := by
  have sameRound : tableRound = referenceRound :=
    funext fun state => funext fun round => table_round_matches state round
  rw [sameRound]

theorem permutation_matches (state : State) :
    runRounds tableRound (List.finRange 24) state =
    runRounds referenceRound (List.finRange 24) state :=
  all_rounds_match (List.finRange 24) state

abbrev BitIndex := Fin 64
abbrev BitState := LaneIndex → BitIndex → Bool

def bitsOf (state : State) : BitState :=
  fun lane z => (state lane).getLsbD z.val

def fromRotation (r : Nat) (z : BitIndex) : BitIndex :=
  Fin.ofNat 64 (64 - r % 64 + z.val)

theorem rotate_bit (word : Lane) (r : Nat) (z : BitIndex) :
    (word.rotateLeft r).getLsbD z.val = word.getLsbD (fromRotation r z).val := by
  rw [BitVec.getLsbD_rotateLeft]
  have inRange := z.isLt
  change (bif decide (z.val < r % 64) then word.getLsbD (64 - r % 64 + z.val)
    else (decide (z.val < 64) && word.getLsbD (z.val - r % 64))) =
    word.getLsbD ((64 - r % 64 + z.val) % 64)
  by_cases wrap : z.val < r % 64
  · have noExtra : (64 - r % 64 + z.val) % 64 = 64 - r % 64 + z.val := by omega
    simp [wrap, noExtra]
  · have noExtra : (64 - r % 64 + z.val) % 64 = z.val - r % 64 := by omega
    simp [wrap, noExtra, inRange]

def bitParity (state : BitState) (x : Nat) (z : BitIndex) : Bool :=
  state (atXY x 0) z ^^ state (atXY x 1) z ^^ state (atXY x 2) z ^^
  state (atXY x 3) z ^^ state (atXY x 4) z

def bitTheta (state : BitState) : BitState :=
  fun a z =>
    let x := a.val % 5
    state a z ^^ (bitParity state (x + 4) z ^^ bitParity state (x + 1) (fromRotation 1 z))

def bitRhoPi (state : BitState) : BitState :=
  fun a z =>
    let source := piInverse a
    state source (fromRotation (rhoFormula source) z)

def bitChi (state : BitState) : BitState :=
  fun a z =>
    let x := a.val % 5
    let y := a.val / 5
    state a z ^^ (!state (atXY (x + 1) y) z && state (atXY (x + 2) y) z)

def bitIota (state : BitState) (constant : Lane) : BitState :=
  fun a z => if a.val = 0 then state a z ^^ constant.getLsbD z.val else state a z

theorem theta_lifts (state : State) : bitsOf (theta state) = bitTheta (bitsOf state) := by
  funext a z
  simp only [bitsOf, theta, bitTheta, BitVec.getLsbD_xor]
  rw [rotate_bit]
  simp only [parity, bitParity, bitsOf, BitVec.getLsbD_xor]

theorem rhoPi_lifts (state : State) :
    bitsOf (rhoPi state piInverse rhoFormula) = bitRhoPi (bitsOf state) := by
  funext a z
  exact rotate_bit _ _ _

theorem chi_lifts (state : State) : bitsOf (chi state) = bitChi (bitsOf state) := by
  funext a z
  simp [bitsOf, chi, bitChi, z.isLt]

theorem iota_lifts (state : State) (constant : Lane) :
    bitsOf (addIota state constant) = bitIota (bitsOf state) constant := by
  funext a z
  by_cases first : a.val = 0 <;> simp [bitsOf, addIota, bitIota, first]

def bitRound (state : BitState) (round : RoundIndex) : BitState :=
  bitIota (bitChi (bitRhoPi (bitTheta state))) (iotaFormula round)

theorem table_round_bits (state : State) (round : RoundIndex) :
    bitsOf (tableRound state round) = bitRound (bitsOf state) round := by
  simp only [table_round_matches, referenceRound, iota_lifts, chi_lifts, rhoPi_lifts, theta_lifts,
    bitRound]

theorem round_sequence_bits (rounds : List RoundIndex) (state : State) :
    bitsOf (runRounds tableRound rounds state) = rounds.foldl bitRound (bitsOf state) := by
  induction rounds generalizing state with
  | nil => rfl
  | cons next rest ih =>
    change bitsOf (runRounds tableRound rest (tableRound state next)) =
      rest.foldl bitRound (bitRound (bitsOf state) next)
    rw [ih, table_round_bits]

theorem permutation_bits (state : State) :
    bitsOf (runRounds tableRound (List.finRange 24) state) =
    (List.finRange 24).foldl bitRound (bitsOf state) :=
  round_sequence_bits (List.finRange 24) state

abbrev Byte := BitVec 8
abbrev Block := Fin 136 → Byte

def packLE : (count : Nat) → (Nat → Byte) → BitVec (8 * count)
  | 0, _ => 0
  | n + 1, bytes => packLE n (fun i => bytes (i + 1)) ++ bytes 0

theorem packed_bit (count : Nat) (bytes : Nat → Byte) (z : Nat) (within : z < 8 * count) :
    (packLE count bytes).getLsbD z = (bytes (z / 8)).getLsbD (z % 8) := by
  induction count generalizing bytes z with
  | zero => simp at within
  | succ n previous =>
    simp only [packLE, BitVec.getLsbD_append]
    by_cases first : z < 8
    · simp [first, Nat.div_eq_of_lt first, Nat.mod_eq_of_lt first]
    · rw [if_neg first, previous (fun i => bytes (i + 1)) (z - 8) (by omega)]
      have byteIndex : (z - 8) / 8 + 1 = z / 8 := by omega
      have bitIndex : (z - 8) % 8 = z % 8 := by omega
      simp only [byteIndex, bitIndex]

theorem packed_lane_byte (bytes : Nat → Byte) (byte : Fin 8) :
    (packLE 8 bytes).extractLsb' (8 * byte.val) 8 = bytes byte.val := by
  apply BitVec.eq_of_getLsbD_eq
  intro i within
  rw [BitVec.getLsbD_extractLsb', packed_bit 8 bytes _ (by have b := byte.isLt; omega)]
  have byteIndex : (8 * byte.val + i) / 8 = byte.val := by omega
  have bitIndex : (8 * byte.val + i) % 8 = i := by omega
  simp [byteIndex, bitIndex, within]

inductive Domain where
  | sha3
  | shake

def domainByte : Domain → Byte
  | .sha3 => 0x06
  | .shake => 0x1f

def mergedByte : Domain → Byte
  | .sha3 => 0x86
  | .shake => 0x9f

def paddingWrites (domain : Domain) (used : Nat) (tail : Block) : Block :=
  fun i =>
    (if i.val < used then tail i else if i.val = used then domainByte domain else 0) |||
    (if i.val = 135 then 0x80 else 0)

def paddedRate (domain : Domain) (used : Nat) (tail : Block) : Block :=
  fun i => if i.val < used then tail i
    else if i.val = 135 then if i.val = used then mergedByte domain else 0x80
    else if i.val = used then domainByte domain else 0

theorem padding_writes_match (domain : Domain) (used : Nat) (within : used < 136) (tail : Block) :
    paddingWrites domain used tail = paddedRate domain used tail := by
  funext i
  by_cases last : i.val = 135
  · have before : ¬ 135 < used := by omega
    by_cases atSuffix : 135 = used <;>
      cases domain <;> simp [paddingWrites, paddedRate, last, before, atSuffix, domainByte, mergedByte]
  · simp [paddingWrites, paddedRate, last]

abbrev BitBlock := Fin 136 → Fin 8 → Bool

def blockBits (block : Block) : BitBlock :=
  fun byte z => (block byte).getLsbD z.val

def absorbBytes (state : State) (block : Block) : State :=
  fun lane => if lane.val < 17 then
    state lane ^^^ packLE 8 (fun byte => block (Fin.ofNat 136 (8 * lane.val + byte)))
    else state lane

def absorbBits (state : BitState) (block : BitBlock) : BitState :=
  fun lane z => if lane.val < 17 then
    state lane z ^^ block (Fin.ofNat 136 (8 * lane.val + z.val / 8)) (Fin.ofNat 8 z.val)
    else state lane z

theorem absorb_rate_lifts (state : State) (block : Block) :
    bitsOf (absorbBytes state block) = absorbBits (bitsOf state) (blockBits block) := by
  funext lane z
  by_cases rate : lane.val < 17
  · simp only [bitsOf, absorbBytes, absorbBits, blockBits, rate, if_true, BitVec.getLsbD_xor]
    rw [packed_bit 8 _ _ z.isLt]
    rfl
  · simp [bitsOf, absorbBytes, absorbBits, rate]

def wordPermutation (state : State) : State :=
  runRounds tableRound (List.finRange 24) state

def bitPermutation (state : BitState) : BitState :=
  (List.finRange 24).foldl bitRound state

def wordAbsorb (state : State) (block : Block) : State :=
  wordPermutation (absorbBytes state block)

def bitAbsorb (state : BitState) (block : Block) : BitState :=
  bitPermutation (absorbBits state (blockBits block))

theorem absorb_block_lifts (state : State) (block : Block) :
    bitsOf (wordAbsorb state block) = bitAbsorb (bitsOf state) block := by
  simp only [wordAbsorb, wordPermutation, permutation_bits, absorb_rate_lifts, bitAbsorb, bitPermutation]

theorem absorb_blocks_lifts (blocks : List Block) (state : State) :
    bitsOf (blocks.foldl wordAbsorb state) = blocks.foldl bitAbsorb (bitsOf state) := by
  induction blocks generalizing state with
  | nil => rfl
  | cons block rest ih =>
    change bitsOf (rest.foldl wordAbsorb (wordAbsorb state block)) =
      rest.foldl bitAbsorb (bitAbsorb (bitsOf state) block)
    rw [ih, absorb_block_lifts]

def wordRate (state : State) : Block :=
  fun byte => (state (Fin.ofNat 25 (byte.val / 8))).extractLsb' (8 * (byte.val % 8)) 8

def bitRate (state : BitState) : BitBlock :=
  fun byte z => state (Fin.ofNat 25 (byte.val / 8)) (Fin.ofNat 64 (8 * (byte.val % 8) + z.val))

theorem output_rate_lifts (state : State) : blockBits (wordRate state) = bitRate (bitsOf state) := by
  funext byte z
  have bitRange : 8 * (byte.val % 8) + z.val < 64 := by have h := z.isLt; omega
  simp [blockBits, wordRate, bitRate, bitsOf, z.isLt, Fin.ofNat, Nat.mod_eq_of_lt bitRange]

def wordOutput : Nat → State → List Block
  | 0, _ => []
  | n + 1, state => wordRate state :: wordOutput n (wordPermutation state)

def bitOutput : Nat → BitState → List BitBlock
  | 0, _ => []
  | n + 1, state => bitRate state :: bitOutput n (bitPermutation state)

theorem output_blocks_lift (count : Nat) (state : State) :
    (wordOutput count state).map blockBits = bitOutput count (bitsOf state) := by
  induction count generalizing state with
  | zero => rfl
  | succ n ih =>
    simp only [wordOutput, bitOutput, List.map_cons, output_rate_lifts, ih, wordPermutation,
      permutation_bits, bitPermutation]

theorem sponge_blocks_match (domain : Domain) (used : Nat) (within : used < 136)
    (blocks : List Block) (tail : Block) (state : State) (count : Nat) :
    (wordOutput count (wordAbsorb (blocks.foldl wordAbsorb state)
      (paddingWrites domain used tail))).map blockBits =
    bitOutput count (bitAbsorb (blocks.foldl bitAbsorb (bitsOf state))
      (paddedRate domain used tail)) := by
  rw [output_blocks_lift, absorb_block_lifts, absorb_blocks_lifts, padding_writes_match domain used within]

#print axioms pi_table_matches
#print axioms pi_left_inverse
#print axioms pi_right_inverse
#print axioms scatter_recovers_lane
#print axioms rho_table_matches
#print axioms iota_table_matches
#print axioms permutation_matches
#print axioms permutation_bits
#print axioms packed_lane_byte
#print axioms padding_writes_match
#print axioms sponge_blocks_match

end Abc.Spec.KeccakRound
