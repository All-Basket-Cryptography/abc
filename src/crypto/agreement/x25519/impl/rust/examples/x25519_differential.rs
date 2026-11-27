use abc_x25519::{public_key, shared_secret};
use std::io::{self, BufRead, Write};

fn decode(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}

fn main() -> io::Result<()> {
    let mut output = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        let private = decode(fields.next().expect("private key"));
        let result = match fields.next() {
            None => Ok(public_key(&private)),
            Some(peer) => shared_secret(&private, &decode(peer)),
        };
        if let Ok(bytes) = result {
            for byte in bytes {
                write!(output, "{byte:02x}")?;
            }
            writeln!(output)?;
        } else {
            writeln!(output, "invalid-peer")?;
        }
    }
    Ok(())
}
