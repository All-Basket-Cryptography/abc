#![no_main]

use abc_crypto::*;
use libfuzzer_sys::fuzz_target;
use std::ptr;

fuzz_target!(|data: &[u8]| {
    let Some((&control, message)) = data.split_first() else {
        return;
    };
    let expected = abc_sha256::digest(message).unwrap();
    let mut output = [0xa5u8; 40];
    let mut context = ptr::null_mut();
    let capacity = usize::from(control) % (output.len() + 1);
    let split = usize::from(control) % (message.len() + 1);

    unsafe {
        assert_eq!(abc_sha256_new(&mut context), ABC_OK);
        let status = abc_sha256_digest(
            message.as_ptr(),
            message.len(),
            output.as_mut_ptr(),
            capacity,
        );
        if capacity < expected.len() {
            assert_eq!(status, ABC_ERROR_LENGTH);
            assert_eq!(output, [0xa5; 40]);
        } else {
            assert_eq!(status, ABC_OK);
            assert_eq!(output[..32], expected);
            assert_eq!(output[32..], [0xa5; 8]);
        }

        assert_eq!(abc_sha256_update(context, message.as_ptr(), split), ABC_OK);
        assert_eq!(abc_sha256_update(context, ptr::null(), 0), ABC_OK);
        assert_eq!(
            abc_sha256_update(context, message[split..].as_ptr(), message.len() - split),
            ABC_OK
        );
        if capacity < expected.len() {
            let unchanged = output;
            assert_eq!(
                abc_sha256_finalize(context, output.as_mut_ptr(), capacity),
                ABC_ERROR_LENGTH
            );
            assert_eq!(output, unchanged);
        }
        assert_eq!(
            abc_sha256_finalize(context, output.as_mut_ptr(), output.len()),
            ABC_OK
        );
        assert_eq!(output[..32], expected);
        assert_eq!(output[32..], [0xa5; 8]);
        assert_eq!(abc_sha256_update(context, ptr::null(), 0), ABC_ERROR_STATE);
        assert_eq!(abc_sha256_reset(context), ABC_OK);
        assert_eq!(
            abc_sha256_finalize(context, output.as_mut_ptr(), output.len()),
            ABC_OK
        );
        assert_eq!(output[..32], abc_sha256::digest(&[]).unwrap());
        abc_sha256_free(context);
    }
});
