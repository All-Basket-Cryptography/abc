use abc_x25519::{public_key, shared_secret, InvalidPeer};

fn decode(hex: &str) -> [u8; 32] {
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn rfc_7748_diffie_hellman() {
    let alice_private = decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_private = decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_public = decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let secret = decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(public_key(&alice_private), alice_public);
    assert_eq!(public_key(&bob_private), bob_public);
    assert_eq!(shared_secret(&alice_private, &bob_public), Ok(secret));
    assert_eq!(shared_secret(&bob_private, &alice_public), Ok(secret));
}

#[test]
fn rfc_7748_ladder_iterations() {
    let mut scalar = [0; 32];
    scalar[0] = 9;
    let mut coordinate = scalar;
    for iteration in 1..=1000 {
        (scalar, coordinate) = (shared_secret(&scalar, &coordinate).unwrap(), scalar);
        if iteration == 1 {
            assert_eq!(
                scalar,
                decode("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
            );
        }
    }
    assert_eq!(
        scalar,
        decode("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
    );
}

#[test]
fn accepts_noncanonical_coordinates_and_masks_bit_255() {
    let scalar = [0x7c; 32];
    let mut nine = [0; 32];
    nine[0] = 9;
    let expected = shared_secret(&scalar, &nine);
    assert_eq!(expected, Ok(public_key(&scalar)));
    let mut alternate = [255; 32];
    alternate[0] = 246; // p + 9, with bit 255 set.
    assert_eq!(shared_secret(&scalar, &alternate), expected);
    nine[31] = 128;
    assert_eq!(shared_secret(&scalar, &nine), expected);
}

#[test]
fn rejects_low_order_peers() {
    let scalar = [0xff; 32];
    for encoded in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let mut peer = decode(encoded);
        assert_eq!(shared_secret(&scalar, &peer), Err(InvalidPeer));
        peer[31] |= 128;
        assert_eq!(shared_secret(&scalar, &peer), Err(InvalidPeer));
    }
}
