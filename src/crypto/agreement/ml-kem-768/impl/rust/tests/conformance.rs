use abc_ml_kem_768::{Error, decapsulate, encapsulate, public_key};
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};

#[test]
fn published_key_and_wire_rejection() {
    let fixture = include_str!("../../../spec/acvp.json");
    // The pinned fixture lists d, z and ek in the key-generation cases.
    let field = |name: &str| {
        let marker = format!("\"{name}\": \"");
        let text = fixture
            .split_once(&marker)
            .unwrap()
            .1
            .split_once('"')
            .unwrap()
            .0;
        (0..text.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let seed = [field("d"), field("z")].concat().try_into().unwrap();
    let public = public_key(&seed);
    assert_eq!(public.as_slice(), field("ek").as_slice());
    let (mut ciphertext, expected) = encapsulate(&public).unwrap();
    assert_eq!(decapsulate(&seed, &ciphertext), Ok(expected));
    ciphertext[0] ^= 1;
    let mut rejection = [0; 32];
    let mut shake = Shake256::default();
    shake.update(&seed[32..]);
    shake.update(&ciphertext);
    shake.finalize_xof().read(&mut rejection);
    assert_eq!(decapsulate(&seed, &ciphertext), Ok(rejection));
    assert_eq!(
        decapsulate(&seed, &ciphertext[..1087]),
        Err(Error::CiphertextLength)
    );
    assert_eq!(encapsulate(&[255; 1184]), Err(Error::PublicKey));
}
