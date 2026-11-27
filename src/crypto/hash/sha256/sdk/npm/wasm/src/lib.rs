//! The JavaScript binding owns the lifetime of WASM state handles.

use abc_sha256::Sha256;
use std::{cell::RefCell, collections::BTreeMap};

const BUFFER_SIZE: usize = 4096;

#[derive(Default)]
struct Runtime {
    next: u32,
    contexts: BTreeMap<u32, Sha256>,
}

thread_local! {
    static RUNTIME: RefCell<Runtime> = RefCell::default();
    static BUFFER: RefCell<[u8; BUFFER_SIZE]> = const { RefCell::new([0; BUFFER_SIZE]) };
}

#[no_mangle]
pub extern "C" fn abc_abi_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn abc_buffer_size() -> u32 {
    BUFFER_SIZE as u32
}

#[no_mangle]
pub extern "C" fn abc_buffer_address() -> *mut u8 {
    BUFFER.with(|buffer| buffer.borrow_mut().as_mut_ptr())
}

#[no_mangle]
pub extern "C" fn abc_new() -> u32 {
    RUNTIME.with(|cell| {
        let mut state = cell.borrow_mut();
        let Some(handle) = state.next.checked_add(1) else {
            return 0;
        };
        state.next = handle;
        state.contexts.insert(handle, Sha256::new());
        handle
    })
}

#[no_mangle]
pub extern "C" fn abc_update(handle: u32, length: u32) -> u32 {
    RUNTIME.with(|cell| {
        let mut state = cell.borrow_mut();
        let Some(context) = state.contexts.get_mut(&handle) else {
            return 1;
        };
        BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            let Some(chunk) = buffer.get_mut(..length as usize) else {
                return 2;
            };
            let result = context.update(chunk);
            chunk.fill(0);
            if result.is_ok() {
                0
            } else {
                3
            }
        })
    })
}

#[no_mangle]
pub extern "C" fn abc_finish(handle: u32) -> u32 {
    RUNTIME.with(|cell| {
        let Some(context) = cell.borrow_mut().contexts.remove(&handle) else {
            return 1;
        };
        let digest = context.finalize();
        BUFFER.with(|buffer| buffer.borrow_mut()[..digest.len()].copy_from_slice(&digest));
        0
    })
}

#[no_mangle]
pub extern "C" fn abc_drop(handle: u32) {
    RUNTIME.with(|cell| cell.borrow_mut().contexts.remove(&handle));
}
