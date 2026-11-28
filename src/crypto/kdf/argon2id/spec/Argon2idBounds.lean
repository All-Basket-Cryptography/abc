import Init.Omega

namespace Abc.Spec.Argon2id

def segmentBlocks (memory lanes : Nat) : Nat := memory / (4 * lanes)
def laneBlocks (segment : Nat) : Nat := 4 * segment
def workspaceBlocks (memory lanes : Nat) : Nat := segmentBlocks memory lanes * (4 * lanes)

theorem rounded_workspace (memory lanes : Nat) (positive : 0 < lanes)
    (admitted : 8 * lanes ≤ memory) :
    2 ≤ segmentBlocks memory lanes ∧
    workspaceBlocks memory lanes ≤ memory ∧
    memory - workspaceBlocks memory lanes = memory % (4 * lanes) ∧
    memory % (4 * lanes) < 4 * lanes ∧
    workspaceBlocks memory lanes = lanes * laneBlocks (segmentBlocks memory lanes) := by
  have divisorPositive : 0 < 4 * lanes := by omega
  have segmentMinimum : 2 ≤ segmentBlocks memory lanes := by
    apply (Nat.le_div_iff_mul_le divisorPositive).2
    rw [← Nat.mul_assoc]
    exact admitted
  have roundedSum :
      memory % (4 * lanes) + workspaceBlocks memory lanes = memory := by
    simpa only [workspaceBlocks, segmentBlocks, Nat.mul_comm] using
      Nat.mod_add_div memory (4 * lanes)
  refine ⟨segmentMinimum, ?_, ?_, Nat.mod_lt _ divisorPositive, ?_⟩
  · omega
  · omega
  · simp [workspaceBlocks, laneBlocks, Nat.mul_comm, Nat.mul_assoc]

theorem parameter_products_fit (lanes : Nat) (laneLimit : lanes < 2 ^ 24) :
    4 * lanes < 2 ^ 32 ∧ 8 * lanes < 2 ^ 32 := by
  omega

def matrixIndex (segment lane column : Nat) : Nat := lane * laneBlocks segment + column

theorem matrix_index_in_range (segment lanes lane column : Nat)
    (laneInRange : lane < lanes) (columnInRange : column < laneBlocks segment) :
    matrixIndex segment lane column < lanes * laneBlocks segment := by
  have endInRange := Nat.mul_le_mul_right (laneBlocks segment)
    (show lane + 1 ≤ lanes by omega)
  rw [Nat.add_mul, Nat.one_mul] at endInRange
  unfold matrixIndex
  omega

theorem workspace_address_bound (occupied index addressLimit : Nat)
    (indexInWorkspace : index < occupied) (workspaceFits : occupied * 1024 ≤ addressLimit) :
    (index + 1) * 1024 ≤ addressLimit ∧ 2 * occupied ≤ addressLimit := by
  omega

theorem initial_index_in_workspace (memory lanes lane index : Nat)
    (laneInRange : lane < lanes) (admitted : 8 * lanes ≤ memory) (initial : index < 2) :
    matrixIndex (segmentBlocks memory lanes) lane index < workspaceBlocks memory lanes := by
  obtain ⟨segmentMinimum, _, _, _, layout⟩ := rounded_workspace memory lanes (by omega) admitted
  rw [layout]
  apply matrix_index_in_range _ _ _ _ laneInRange
  unfold laneBlocks
  omega

def segmentColumn (segment slice index : Nat) : Nat := slice * segment + index

theorem segment_column_in_range (segment slice index : Nat)
    (sliceInRange : slice < 4) (indexInRange : index < segment) :
    segmentColumn segment slice index < laneBlocks segment := by
  have sliceMaximum := Nat.mul_le_mul_right segment (show slice ≤ 3 by omega)
  unfold segmentColumn laneBlocks
  omega

def precedingColumn (segment column : Nat) : Nat :=
  if column = 0 then laneBlocks segment - 1 else column - 1

theorem preceding_column_in_range (segment column : Nat) (segmentPositive : 0 < segment)
    (columnInRange : column < laneBlocks segment) :
    precedingColumn segment column < laneBlocks segment := by
  by_cases zero : column = 0 <;> simp [precedingColumn, zero, laneBlocks] at * <;> omega

def firstBlockIndex (pass slice : Nat) : Nat :=
  if pass = 0 ∧ slice = 0 then 2 else 0

def referenceLane (lanes pass slice lane j2 : Nat) : Nat :=
  if pass = 0 ∧ slice = 0 then lane else j2 % lanes

theorem reference_lane_in_range (lanes pass slice lane j2 : Nat) (laneInRange : lane < lanes) :
    referenceLane lanes pass slice lane j2 < lanes := by
  by_cases first : pass = 0 ∧ slice = 0
  · simpa [referenceLane, first] using laneInRange
  · simpa [referenceLane, first] using Nat.mod_lt j2 (show 0 < lanes by omega)

def finishedBlocks (segment pass slice : Nat) : Nat :=
  if pass = 0 then slice * segment else laneBlocks segment - segment

def referenceArea (segment pass slice index : Nat) (sameLane : Bool) : Nat :=
  let finished := finishedBlocks segment pass slice
  if sameLane then finished + index - 1 else finished - (if index = 0 then 1 else 0)

theorem reference_area_in_range (segment pass slice index : Nat) (sameLane : Bool)
    (segmentMinimum : 2 ≤ segment) (sliceInRange : slice < 4) (indexInRange : index < segment)
    (fillStarts : firstBlockIndex pass slice ≤ index)
    (firstUsesSameLane : pass = 0 → slice = 0 → sameLane = true) :
    0 < referenceArea segment pass slice index sameLane ∧
    referenceArea segment pass slice index sameLane < laneBlocks segment := by
  have sliceMaximum := Nat.mul_le_mul_right segment (show slice ≤ 3 by omega)
  by_cases firstPass : pass = 0
  · by_cases firstSlice : slice = 0
    · have twoSkipped : 2 ≤ index := by simpa [firstBlockIndex, firstPass, firstSlice] using fillStarts
      simp [referenceArea, finishedBlocks, firstPass, firstSlice, firstUsesSameLane firstPass firstSlice,
        laneBlocks]
      omega
    · have atLeastOneSlice := Nat.mul_le_mul_right segment (show 1 ≤ slice by omega)
      cases sameLane <;> by_cases initial : index = 0 <;>
        simp [referenceArea, finishedBlocks, firstPass, initial, laneBlocks] <;> omega
  · cases sameLane <;> by_cases initial : index = 0 <;>
      simp [referenceArea, finishedBlocks, firstPass, initial, laneBlocks] <;> omega

abbrev wordBase : Nat := 2 ^ 32

def scaledDistance (area j1 : Nat) : Nat := area * ((j1 * j1) / wordBase) / wordBase
def relativeColumn (area j1 : Nat) : Nat := area - 1 - scaledDistance area j1

theorem index_products_and_distance (area j1 : Nat)
    (areaPositive : 0 < area) (areaFits : area < wordBase) (j1Fits : j1 < wordBase) :
    j1 * j1 < 2 ^ 64 ∧ area * ((j1 * j1) / wordBase) < 2 ^ 64 ∧
    scaledDistance area j1 < area ∧ relativeColumn area j1 < area := by
  have wordPositive : 0 < wordBase := by decide
  have wordSquare : wordBase * wordBase = 2 ^ 64 := by decide
  have squareBound : j1 * j1 < wordBase * wordBase :=
    Nat.lt_of_le_of_lt (Nat.mul_le_mul (Nat.le_of_lt j1Fits) (Nat.le_refl j1))
      (Nat.mul_lt_mul_of_pos_left j1Fits wordPositive)
  have shiftBound : (j1 * j1) / wordBase < wordBase :=
    (Nat.div_lt_iff_lt_mul wordPositive).2 squareBound
  have scaledProductBound : area * ((j1 * j1) / wordBase) < area * wordBase :=
    Nat.mul_lt_mul_of_pos_left shiftBound areaPositive
  have scaledBound : scaledDistance area j1 < area :=
    (Nat.div_lt_iff_lt_mul wordPositive).2 scaledProductBound
  refine ⟨?_, ?_, scaledBound, ?_⟩
  · simpa only [wordSquare] using squareBound
  · rw [← wordSquare]
    exact Nat.lt_of_lt_of_le scaledProductBound
      (Nat.mul_le_mul_right wordBase (Nat.le_of_lt areaFits))
  · unfold relativeColumn
    omega

def referenceStart (segment pass slice : Nat) : Nat :=
  if pass ≠ 0 ∧ slice ≠ 3 then (slice + 1) * segment else 0

theorem reference_start_in_range (segment pass slice : Nat) (sliceInRange : slice < 4) :
    referenceStart segment pass slice ≤ 3 * segment := by
  by_cases wraps : pass ≠ 0 ∧ slice ≠ 3
  · simp only [referenceStart, if_pos wraps]
    exact Nat.mul_le_mul_right segment (by have := wraps.2; omega)
  · simp [referenceStart, wraps]

def referenceColumn (segment pass slice index : Nat) (sameLane : Bool) (j1 : Nat) : Nat :=
  (referenceStart segment pass slice + relativeColumn (referenceArea segment pass slice index sameLane) j1)
    % laneBlocks segment

theorem reference_arithmetic_in_range (memory lanes pass slice lane index j1 j2 : Nat)
    (laneInRange : lane < lanes) (admitted : 8 * lanes ≤ memory) (memoryFits : memory < wordBase)
    (sliceInRange : slice < 4) (indexInRange : index < segmentBlocks memory lanes)
    (fillStarts : firstBlockIndex pass slice ≤ index) (j1Fits : j1 < wordBase) :
    let segment := segmentBlocks memory lanes
    let sameLane := referenceLane lanes pass slice lane j2 == lane
    let area := referenceArea segment pass slice index sameLane
    0 < area ∧ area < laneBlocks segment ∧
    j1 * j1 < 2 ^ 64 ∧ area * ((j1 * j1) / wordBase) < 2 ^ 64 ∧
    scaledDistance area j1 < area ∧
    referenceStart segment pass slice + relativeColumn area j1 < 2 * workspaceBlocks memory lanes := by
  let segment := segmentBlocks memory lanes
  let sameLane := referenceLane lanes pass slice lane j2 == lane
  let area := referenceArea segment pass slice index sameLane
  change 0 < area ∧ area < laneBlocks segment ∧
    j1 * j1 < 2 ^ 64 ∧ area * ((j1 * j1) / wordBase) < 2 ^ 64 ∧
    scaledDistance area j1 < area ∧
    referenceStart segment pass slice + relativeColumn area j1 < 2 * workspaceBlocks memory lanes
  obtain ⟨segmentMinimum, workspaceFits, _, _, layout⟩ :=
    rounded_workspace memory lanes (by omega) admitted
  have sameOnFirst : pass = 0 → slice = 0 → sameLane = true := by
    intro firstPass firstSlice
    simp [sameLane, referenceLane, firstPass, firstSlice]
  obtain ⟨areaPositive, areaInLane⟩ :=
    reference_area_in_range segment pass slice index sameLane
      segmentMinimum sliceInRange indexInRange fillStarts sameOnFirst
  have laneInWorkspace : laneBlocks segment ≤ workspaceBlocks memory lanes := by
    rw [layout]
    simpa only [Nat.one_mul] using
      Nat.mul_le_mul_right (laneBlocks segment) (show 1 ≤ lanes by omega)
  have areaFits : area < wordBase := by omega
  obtain ⟨squareFits, scaledFits, scaledInArea, relativeInArea⟩ :=
    index_products_and_distance area j1 areaPositive areaFits j1Fits
  refine ⟨areaPositive, areaInLane, squareFits, scaledFits, scaledInArea, ?_⟩
  have startInRange := reference_start_in_range segment pass slice sliceInRange
  unfold laneBlocks at areaInLane laneInWorkspace
  omega

theorem fill_indices_in_workspace (memory lanes pass slice lane index j1 j2 : Nat)
    (laneInRange : lane < lanes) (admitted : 8 * lanes ≤ memory) (sliceInRange : slice < 4)
    (indexInRange : index < segmentBlocks memory lanes) :
    let segment := segmentBlocks memory lanes
    let column := segmentColumn segment slice index
    let other := referenceLane lanes pass slice lane j2
    matrixIndex segment lane column < workspaceBlocks memory lanes ∧
    matrixIndex segment lane (precedingColumn segment column) < workspaceBlocks memory lanes ∧
    matrixIndex segment other (referenceColumn segment pass slice index (other == lane) j1)
      < workspaceBlocks memory lanes := by
  dsimp
  obtain ⟨minimum, _, _, _, layout⟩ := rounded_workspace memory lanes (by omega) admitted
  have columnInRange := segment_column_in_range _ _ _ sliceInRange indexInRange
  have segmentPositive : 0 < segmentBlocks memory lanes := by omega
  rw [layout]
  refine ⟨matrix_index_in_range _ _ _ _ laneInRange columnInRange,
    matrix_index_in_range _ _ _ _ laneInRange (preceding_column_in_range _ _ segmentPositive columnInRange),
    matrix_index_in_range _ _ _ _ (reference_lane_in_range _ _ _ _ _ laneInRange) ?_⟩
  exact Nat.mod_lt _ (show 0 < laneBlocks (segmentBlocks memory lanes) by unfold laneBlocks; omega)

#print axioms rounded_workspace
#print axioms parameter_products_fit
#print axioms workspace_address_bound
#print axioms initial_index_in_workspace
#print axioms reference_arithmetic_in_range
#print axioms fill_indices_in_workspace

end Abc.Spec.Argon2id
