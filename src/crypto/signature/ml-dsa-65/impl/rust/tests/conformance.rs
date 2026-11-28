use abc_ml_dsa_65::{Error, public_key, sign, verify};

fn decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect()
}

#[test]
fn acvp_and_deterministic_context() {
    let fixture = include_str!("../../../spec/acvp-fips204-sample.json");
    let field = |name: &str| {
        let marker = format!("\"{name}\": \"");
        decode(
            fixture
                .split_once(&marker)
                .unwrap()
                .1
                .split_once('"')
                .unwrap()
                .0,
        )
    };
    let seed = field("seed").try_into().unwrap();
    let message = field("message");
    let context = field("context");
    let signature = field("signature");
    assert!(verify(&field("pk"), &message, &signature, &context));
    assert!(!verify(
        &field("pk"),
        &message,
        &signature,
        b"wrong context"
    ));

    let key = public_key(&seed);
    for context in [&[][..], &[0, 255][..], &[11; 255][..]] {
        let signed = sign(&seed, &message, context).unwrap();
        assert_eq!(sign(&seed, &message, context), Ok(signed));
        assert!(verify(&key, &message, &signed, context));
        assert!(!verify(&key, &message, &signed[..3308], context));
    }
    assert_eq!(sign(&seed, &message, &[0; 256]), Err(Error::ContextLength));
    assert!(!verify(&key, &message, &signature, &[0; 256]));
}
