use abc_sha256::{digest, Sha256, IMPLEMENTATION_ID};

fn main() {
    let mut hash = Sha256::new();
    hash.update(b"a").unwrap();
    hash.update(b"bc").unwrap();
    let got: String = hash.finalize().into_iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(got, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(digest(b"").unwrap()[..4], [0xe3, 0xb0, 0xc4, 0x42]);
    assert_eq!(IMPLEMENTATION_ID, "sha256-abc-rust-portable");
    println!("External Rust SHA-256 consumer passed");
}
