//! Read only public artifacts. Verify with the library used by Tauri's updater.
use base64::{engine::general_purpose::STANDARD, Engine};
use minisign_verify::{PublicKey, Signature};
use std::{env, fs, path::Path};

fn signed_version(comment: &str, expected: &str) -> Result<(), &'static str> {
    let versions: Vec<_> = comment
        .split('\t')
        .filter_map(|field| field.strip_prefix("version:"))
        .collect();
    if versions.len() != 1 || versions[0] != expected {
        return Err("Signature does not bind the approved app version.");
    }
    Ok(())
}

fn verify(public: &str, signature: &str, bytes: &[u8], version: &str) -> Result<(), &'static str> {
    let decoded = STANDARD
        .decode(public.trim())
        .map_err(|_| "Invalid public key encoding.")?;
    let public = std::str::from_utf8(&decoded).map_err(|_| "Invalid public key text.")?;
    let public = PublicKey::decode(public).map_err(|_| "Invalid public key.")?;
    let decoded = STANDARD
        .decode(signature.trim())
        .map_err(|_| "Invalid signature encoding.")?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| "Invalid signature text.")?;
    let signature = Signature::decode(decoded).map_err(|_| "Invalid signature.")?;
    public
        .verify(bytes, &signature, false)
        .map_err(|_| "Updater signature verification failed.")?;
    signed_version(signature.trusted_comment(), version)
}

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("Expected archive, signature, public-key file and approved version.");
    }
    let archive = Path::new(&args[0]);
    let bytes = fs::read(archive).map_err(|_| "Could not read updater archive.")?;
    let signature =
        fs::read_to_string(&args[1]).map_err(|_| "Could not read updater signature.")?;
    let public = fs::read_to_string(&args[2]).map_err(|_| "Could not read updater public key.")?;
    verify(&public, &signature, &bytes, &args[3])
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    println!("Updater signature and approved app version verified.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_binding_requires_one_exact_field() {
        assert!(signed_version("timestamp:1\tfile:test\tversion:0.6.2", "0.6.2").is_ok());
        for value in [
            "timestamp:1\tfile:test",
            "version:0.6.1",
            "version:0.6.2\tversion:0.6.2",
            "version:0.6.20",
        ] {
            assert!(signed_version(value, "0.6.2").is_err(), "{value}");
        }
    }

    // Published public test vector from minisign-verify's documentation. No keys generated.
    const PUBLIC: &str = "untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
    const SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==\n";

    #[test]
    fn authentic_public_vector_reaches_version_guard_but_tampering_does_not() {
        let public = STANDARD.encode(PUBLIC);
        let signature = STANDARD.encode(SIGNATURE);
        assert_eq!(
            verify(&public, &signature, b"test", "0.6.2"),
            Err("Signature does not bind the approved app version.")
        );
        assert_eq!(
            verify(&public, &signature, b"tampered", "0.6.2"),
            Err("Updater signature verification failed.")
        );
        let forged = STANDARD.encode(SIGNATURE.replace("prehashed", "version:0.6.2"));
        assert_eq!(
            verify(&public, &forged, b"test", "0.6.2"),
            Err("Updater signature verification failed.")
        );
    }
}
