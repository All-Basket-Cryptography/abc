use abc_aes256_gcm_accelerated::{
    open_in_place, seal_in_place, Error, KEY_BYTES, NONCE_BYTES, TAG_BYTES,
};
use std::{
    fmt::Write as _,
    io::Write as _,
    process::{Command, Stdio},
};

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn encoded(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

#[test]
fn nist_known_answers() {
    let cases = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        ),
        (
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "3ad77bb40d7a3660a89ecaf32466ef97f5d3d585",
            concat!(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
                "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
            ),
            concat!(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
            ),
            "e097195f4532da895fb917a5a55c6aa0",
        ),
    ];
    for (key, nonce, aad, plaintext, ciphertext, expected_tag) in cases {
        let key = bytes(key).try_into().unwrap();
        let nonce = bytes(nonce).try_into().unwrap();
        let aad = bytes(aad);
        let plaintext = bytes(plaintext);
        let mut data = plaintext.clone();
        let tag = seal_in_place(&key, &nonce, &aad, &mut data).unwrap();
        assert_eq!(data, bytes(ciphertext));
        assert_eq!(tag.as_slice(), bytes(expected_tag));
        open_in_place(&key, &nonce, &aad, &mut data, &tag).unwrap();
        assert_eq!(data, plaintext);
    }
}

#[test]
fn rejection_preserves_the_destination() {
    let key = [21; KEY_BYTES];
    let aad = b"known context";
    for (index, length) in [0, 1, 15, 16, 17, 31, 63, 64, 65, 257]
        .into_iter()
        .enumerate()
    {
        let mut nonce = [0; NONCE_BYTES];
        nonce[0] = index as u8;
        let mut data = vec![31; length];
        let tag = seal_in_place(&key, &nonce, aad, &mut data).unwrap();
        for index in 0..TAG_BYTES {
            let mut invalid = tag;
            invalid[index] ^= 1;
            rejected(&key, &nonce, aad, &data, &invalid);
        }
        rejected(&key, &nonce, b"other context", &data, &tag);
        if length != 0 {
            data[0] ^= 1;
            rejected(&key, &nonce, aad, &data, &tag);
        }
    }
}

fn rejected(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_BYTES],
) {
    let mut output = ciphertext.to_vec();
    assert_eq!(
        open_in_place(key, nonce, aad, &mut output, tag),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(output, ciphertext);
}

fn public_test_bytes(seed: &mut u64, bytes: &mut [u8]) {
    for byte in bytes {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (*seed >> 53) as u8;
    }
}

struct Case {
    key: [u8; KEY_BYTES],
    nonce: [u8; NONCE_BYTES],
    aad: Vec<u8>,
    plaintext: Vec<u8>,
}

#[test]
fn openssl_interoperability() {
    match Command::new("node").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("independent provider unavailable: Node.js is required");
            return;
        }
        result => assert!(result.unwrap().status.success()),
    }
    let boundaries = [0, 1, 15, 16, 17, 63, 64, 65];
    let mut seed = 0xb17_cafe;
    let mut test_cases = Vec::new();
    let mut request = String::new();
    for index in 0..174 {
        let (width, aad_width) = if index < boundaries.len() * boundaries.len() {
            (
                boundaries[index / boundaries.len()],
                boundaries[index % boundaries.len()],
            )
        } else {
            (index * 91 % 517, index * 37 % 121)
        };
        let mut case = Case {
            key: [0; KEY_BYTES],
            nonce: [0; NONCE_BYTES],
            aad: vec![0; aad_width],
            plaintext: vec![0; width],
        };
        public_test_bytes(&mut seed, &mut case.key);
        public_test_bytes(&mut seed, &mut case.nonce);
        public_test_bytes(&mut seed, &mut case.aad);
        public_test_bytes(&mut seed, &mut case.plaintext);
        let mut ciphertext = case.plaintext.clone();
        let tag = seal_in_place(&case.key, &case.nonce, &case.aad, &mut ciphertext).unwrap();
        writeln!(
            request,
            "{}:{}:{}:{}:{}:{}",
            encoded(&case.key),
            encoded(&case.nonce),
            encoded(&case.aad),
            encoded(&case.plaintext),
            encoded(&ciphertext),
            encoded(&tag)
        )
        .unwrap();
        test_cases.push((case, ciphertext, tag));
    }
    let oracle = r#"
const crypto = require('node:crypto');
const fs = require('node:fs');
const buffer = s => Buffer.from(s, 'hex');
console.log(process.versions.openssl);
for (const line of fs.readFileSync(0, 'utf8').trim().split('\n')) {
  const [key, nonce, aad, plaintext, ciphertext, tag] = line.split(':').map(buffer);
  const seal = crypto.createCipheriv('aes-256-gcm', key, nonce, {authTagLength: 16});
  seal.setAAD(aad);
  const wire = Buffer.concat([seal.update(plaintext), seal.final()]);
  const open = crypto.createDecipheriv('aes-256-gcm', key, nonce, {authTagLength: 16});
  open.setAAD(aad);
  open.setAuthTag(tag);
  const clear = Buffer.concat([open.update(ciphertext), open.final()]);
  if (!clear.equals(plaintext)) throw Error('Rust ciphertext did not open');
  console.log(wire.toString('hex') + ':' + seal.getAuthTag().toString('hex'));
}
"#;
    let mut child = Command::new("node")
        .args(["-e", oracle])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    let mut lines = report.lines();
    let version = lines.next().unwrap();
    for (index, (case, ciphertext, tag)) in test_cases.iter().enumerate() {
        let (reference_cipher, reference_tag) = lines.next().unwrap().split_once(':').unwrap();
        let mut reference_cipher = bytes(reference_cipher);
        let reference_tag: [u8; TAG_BYTES] = bytes(reference_tag).try_into().unwrap();
        assert_eq!(&reference_cipher, ciphertext, "OpenSSL ciphertext #{index}");
        assert_eq!(&reference_tag, tag, "OpenSSL tag #{index}");
        open_in_place(
            &case.key,
            &case.nonce,
            &case.aad,
            &mut reference_cipher,
            &reference_tag,
        )
        .unwrap();
        assert_eq!(reference_cipher, case.plaintext, "Rust opening #{index}");
    }
    assert!(lines.next().is_none());
    println!("{} bidirectional OpenSSL {version} cases", test_cases.len());
}
