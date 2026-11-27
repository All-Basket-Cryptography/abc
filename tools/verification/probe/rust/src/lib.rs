#![no_std]
#![forbid(unsafe_code)]

/// Add two words whose mathematical sum fits in a `u32`.
///
/// The toolchain probe's contract excludes inputs whose sum exceeds `u32::MAX`.
pub fn bounded_add(left: u32, right: u32) -> u32 {
    left + right
}
