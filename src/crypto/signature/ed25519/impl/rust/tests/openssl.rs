use abc_ed25519::{public_key, sign, verify_strict, SIGNATURE_BYTES};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

// RFC 8410 Ed25519 PKCS#8 PrivateKeyInfo and SubjectPublicKeyInfo DER prefixes.
const PRIVATE_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PUBLIC_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const FILES: [&str; 5] = [
    "key.der",
    "public.der",
    "message.bin",
    "abc.sig",
    "openssl.sig",
];

struct Scratch(PathBuf);

impl Scratch {
    fn create() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let folder = env::temp_dir().join(format!("abc-ed25519-{}-{nanos}", std::process::id()));
        fs::create_dir(&folder).unwrap();
        Self(folder)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        for file in FILES {
            let _ = fs::remove_file(self.0.join(file));
        }
        let _ = fs::remove_dir(&self.0);
    }
}

fn openssl(program: &OsStr, working_dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new(program)
        .current_dir(working_dir)
        .args(args)
        .output()
        .expect("Select an OpenSSL executable with ABC_ED25519_OPENSSL or PATH");
    assert!(
        output.status.success(),
        "OpenSSL {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
#[ignore = "Requires an independent OpenSSL CLI"]
fn openssl_known_interoperability() {
    let program = env::var_os("ABC_ED25519_OPENSSL").unwrap_or_else(|| "openssl".into());
    let scratch = Scratch::create();
    let working_dir = &scratch.0;
    let version = openssl(&program, working_dir, &["version"]);
    println!("{}", String::from_utf8_lossy(&version).trim());
    for (size, fill) in [(1, 0x11), (257, 0x56), (4097, 0xac)] {
        let seed = [fill; 32];
        let message: Vec<u8> = (0..size).map(|index| (index * 37 + 13) as u8).collect();
        let public = public_key(&seed);
        let signature = sign(&seed, &message);
        fs::write(
            working_dir.join("key.der"),
            [&PRIVATE_PREFIX[..], &seed].concat(),
        )
        .unwrap();
        fs::write(working_dir.join("message.bin"), &message).unwrap();
        fs::write(working_dir.join("abc.sig"), signature).unwrap();

        openssl(
            &program,
            working_dir,
            &[
                "pkey",
                "-in",
                "key.der",
                "-inform",
                "DER",
                "-pubout",
                "-outform",
                "DER",
                "-out",
                "public.der",
            ],
        );
        assert_eq!(
            fs::read(working_dir.join("public.der")).unwrap(),
            [&PUBLIC_PREFIX[..], &public].concat()
        );
        openssl(
            &program,
            working_dir,
            &[
                "pkeyutl",
                "-sign",
                "-rawin",
                "-keyform",
                "DER",
                "-inkey",
                "key.der",
                "-in",
                "message.bin",
                "-out",
                "openssl.sig",
            ],
        );
        let independent: [u8; SIGNATURE_BYTES] = fs::read(working_dir.join("openssl.sig"))
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(independent, signature);
        assert_eq!(verify_strict(&public, &message, &independent), Ok(()));
        openssl(
            &program,
            working_dir,
            &[
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                "public.der",
                "-in",
                "message.bin",
                "-sigfile",
                "abc.sig",
            ],
        );
    }
    println!("public_key_comparisons=3\ndeterministic_signature_comparisons=3\nreciprocal_verification=3");
}
