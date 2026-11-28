namespace Abc.Spec.Aes256Gcm.Jvm

def tagBytes : Nat := 16
def jvmMaxArrayLength : Nat := 2 ^ 31 - 1
def maxArrayPayload : Nat := jvmMaxArrayLength - tagBytes
def nistMaxPayload : Nat := (2 ^ 32 - 2) * 16

theorem joined_length_fits (payload : Nat) (admitted : payload ≤ maxArrayPayload) :
    payload + tagBytes ≤ jvmMaxArrayLength ∧ payload ≤ nistMaxPayload := by
  simp only [maxArrayPayload, tagBytes, jvmMaxArrayLength, nistMaxPayload] at *
  omega

theorem length_fields_fit (payload aad : Nat) (hp : payload ≤ maxArrayPayload)
    (ha : aad ≤ jvmMaxArrayLength) : payload * 8 < 2 ^ 64 ∧ aad * 8 < 2 ^ 64 := by
  unfold maxArrayPayload tagBytes jvmMaxArrayLength at *
  omega

theorem detached_layout (ciphertext tag : List UInt8) :
    (ciphertext ++ tag).take ciphertext.length = ciphertext ∧
    (ciphertext ++ tag).drop ciphertext.length = tag := by
  simp

#print axioms joined_length_fits
#print axioms length_fields_fit
#print axioms detached_layout

end Abc.Spec.Aes256Gcm.Jvm
