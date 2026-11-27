use abc_sha256::{Sha256, IMPLEMENTATION_ID};
use std::io::{self, Read, Write};

fn digest_stream(mut input: impl Read) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut state = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(state.finalize()),
            Ok(length) => state.update(&buffer[..length])?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    args.next();
    match (args.next().as_deref(), args.next()) {
        (None, _) => {
            let digest = digest_stream(io::stdin().lock())?;
            let mut output = io::stdout().lock();
            for byte in digest {
                write!(output, "{byte:02x}")?;
            }
            writeln!(output)?;
        }
        (Some("--identity"), None) => println!("{IMPLEMENTATION_ID}"),
        _ => {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "expected stdin or --identity").into(),
            )
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::digest_stream;

    #[test]
    fn hashes_multiple_buffer_lengths() {
        let bytes = [0x2a; 19_000];
        assert_eq!(
            digest_stream(&bytes[..]).unwrap(),
            abc_sha256::digest(&bytes).unwrap()
        );
    }
}
