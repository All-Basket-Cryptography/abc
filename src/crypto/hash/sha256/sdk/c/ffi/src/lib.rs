//! Version 1 of the ABC research C ABI. Pointer obligations are in the C SDK documentation.

#![deny(unsafe_op_in_unsafe_fn)]

use abc_sha256::{Sha256, DIGEST_BYTES, IMPLEMENTATION_ID, MAX_MESSAGE_BYTES};
use std::alloc::{alloc, Layout};
use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::{ptr, slice};

pub const ABC_OK: i32 = 0;
pub const ABC_ERROR_NULL: i32 = 1;
pub const ABC_ERROR_LENGTH: i32 = 2;
pub const ABC_ERROR_STATE: i32 = 3;
pub const ABC_ERROR_ALIGNMENT: i32 = 4;
pub const ABC_ERROR_ALLOC: i32 = 5;
pub const ABC_ERROR_PANIC: i32 = 6;

pub struct AbcSha256(Option<Sha256>);

static C_IMPLEMENTATION_ID: [u8; IMPLEMENTATION_ID.len() + 1] = {
    let mut output = [0; IMPLEMENTATION_ID.len() + 1];
    let source = IMPLEMENTATION_ID.as_bytes();
    let mut index = 0;
    while index < source.len() {
        output[index] = source[index];
        index += 1;
    }
    output
};

#[no_mangle]
pub extern "C" fn abc_abi_version() -> u32 {
    0x0001_0000
}

#[no_mangle]
pub extern "C" fn abc_sha256_implementation() -> *const c_char {
    C_IMPLEMENTATION_ID.as_ptr().cast()
}

fn guard(body: impl FnOnce() -> Result<(), i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => ABC_OK,
        Ok(Err(status)) => status,
        Err(_) => ABC_ERROR_PANIC,
    }
}

fn validate_pointer<T>(pointer: *const T) -> Result<(), i32> {
    if pointer.is_null() {
        Err(ABC_ERROR_NULL)
    } else if !pointer.is_aligned() {
        Err(ABC_ERROR_ALIGNMENT)
    } else {
        Ok(())
    }
}

unsafe fn input_bytes<'a>(input: *const u8, length: usize) -> Result<&'a [u8], i32> {
    if length > isize::MAX as usize || length as u64 > MAX_MESSAGE_BYTES {
        return Err(ABC_ERROR_LENGTH);
    }
    if length == 0 {
        return Ok(&[]);
    }
    validate_pointer(input)?;
    // The caller owns a readable allocation for the indicated length.
    Ok(unsafe { slice::from_raw_parts(input, length) })
}

fn validate_output(output: *mut u8, capacity: usize) -> Result<(), i32> {
    validate_pointer(output)?;
    if capacity < DIGEST_BYTES {
        return Err(ABC_ERROR_LENGTH);
    }
    Ok(())
}

/// # Safety
/// The input is readable for `input_len` bytes when nonempty. The output is writable for
/// `output_capacity` bytes. The two buffers do not overlap.
#[no_mangle]
pub unsafe extern "C" fn abc_sha256_digest(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
) -> i32 {
    guard(|| {
        validate_output(output, output_capacity)?;
        let input = unsafe { input_bytes(input, input_len)? };
        let digest = abc_sha256::digest(input).map_err(|_| ABC_ERROR_LENGTH)?;
        unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), output, DIGEST_BYTES) };
        Ok(())
    })
}

/// # Safety
/// With a nonnull, aligned `output`, the caller provides writable storage for one handle pointer.
#[no_mangle]
pub unsafe extern "C" fn abc_sha256_new(output: *mut *mut AbcSha256) -> i32 {
    guard(|| {
        validate_pointer(output)?;
        unsafe { output.write(ptr::null_mut()) };
        let layout = Layout::new::<AbcSha256>();
        let value = unsafe { alloc(layout).cast::<AbcSha256>() };
        if value.is_null() {
            return Err(ABC_ERROR_ALLOC);
        }
        unsafe {
            value.write(AbcSha256(Some(Sha256::new())));
            output.write(value);
        }
        Ok(())
    })
}

/// # Safety
/// `context` is a live handle returned by `abc_sha256_new`. The caller serializes access to it and
/// provides a readable, nonoverlapping input buffer for any nonzero input length.
#[no_mangle]
pub unsafe extern "C" fn abc_sha256_update(
    context: *mut AbcSha256,
    input: *const u8,
    input_len: usize,
) -> i32 {
    guard(|| {
        validate_pointer(context)?;
        let context = unsafe { &mut *context };
        let state = context.0.as_mut().ok_or(ABC_ERROR_STATE)?;
        let input = unsafe { input_bytes(input, input_len)? };
        state.update(input).map_err(|_| ABC_ERROR_LENGTH)
    })
}

/// # Safety
/// `context` is a live handle returned by `abc_sha256_new`. The caller serializes access to it and
/// provides a writable, nonoverlapping output buffer for `output_capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn abc_sha256_finalize(
    context: *mut AbcSha256,
    output: *mut u8,
    output_capacity: usize,
) -> i32 {
    guard(|| {
        validate_pointer(context)?;
        validate_output(output, output_capacity)?;
        let context = unsafe { &mut *context };
        let digest = context.0.take().ok_or(ABC_ERROR_STATE)?.finalize();
        unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), output, DIGEST_BYTES) };
        Ok(())
    })
}

/// # Safety
/// `context` is a live handle returned by `abc_sha256_new`; the caller serializes access to it.
#[no_mangle]
pub unsafe extern "C" fn abc_sha256_reset(context: *mut AbcSha256) -> i32 {
    guard(|| {
        validate_pointer(context)?;
        unsafe { (*context).0 = Some(Sha256::new()) };
        Ok(())
    })
}

/// # Safety
/// A nonnull context is the unique live handle from `abc_sha256_new`. The caller stops using the
/// handle after this call. A null handle is allowed.
#[no_mangle]
pub unsafe extern "C" fn abc_sha256_free(context: *mut AbcSha256) {
    if !context.is_null() {
        // Both allocation and drop use Rust's global allocator and the same layout.
        unsafe { drop(Box::from_raw(context)) };
    }
}
