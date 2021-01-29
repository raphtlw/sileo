use io::Cursor;
use libflate::gzip;
use pgp::{crypto::KeyPair, serialize::Serialize};
// use pgp::{
//     composed::{key::SecretKeyParamsBuilder, KeyType},
//     crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm, PublicKeyAlgorithm},
//     packet,
//     ser::Serialize,
//     types::{CompressionAlgorithm, KeyTrait, PublicKeyTrait, SecretKeyTrait},
//     PublicKey, Signature, SignedSecretKey,
// };
use sequoia_openpgp as pgp;
use sequoia_openpgp::{
    cert::prelude::*,
    crypto::SessionKey,
    parse::{stream::*, Parse},
    policy::{Policy, StandardPolicy},
    serialize::stream::*,
    types::SymmetricAlgorithm,
};
use std::{
    collections::HashMap,
    error::Error,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};
use walkdir::WalkDir;

use crate::{SileoError, PRIVATE_KEY_PATH};

pub fn archive_folder(folder: &Path, outpath: &Path) -> Result<(), Box<dyn Error>> {
    if folder.is_dir() {
        if !outpath.is_dir() {
            if !outpath.exists() {
                log::debug!("Output file does not exist, creating...");
                fs::write(outpath, "")?;
            }

            let outfile = OpenOptions::new()
                .append(true)
                .read(true)
                .write(true)
                .open(outpath)?;
            let mut archive = tar::Builder::new(outfile);

            for entry in WalkDir::new(folder) {
                archive.append_path(entry?.path())?;
            }
        } else {
            return Err(SileoError::new("Output path exists and is a directory!"));
        }
    } else {
        return Err(SileoError::new("Input path is not a directory!"));
    }

    Ok(())
}

pub fn compress_file(filepath: &Path, outpath: &Path) -> Result<(), Box<dyn Error>> {
    let mut infile = Cursor::new(fs::read(filepath)?);

    let mut encoder = gzip::Encoder::new(Vec::new())?;

    io::copy(&mut infile, &mut encoder)?;

    fs::write(outpath, encoder.finish().into_result()?)?;

    Ok(())
}

pub fn encrypt_file(filepath: &Path, outpath: &Path, key: Cert) -> Result<(), Box<dyn Error>> {
    let input_data = fs::read(filepath)?;

    let encrypted_data = encrypt_data(input_data, &key)?;

    fs::write(outpath, encrypted_data)?;

    Ok(())
}

pub fn encrypt_data(data: Vec<u8>, key: &Cert) -> Result<Vec<u8>, Box<dyn Error>> {
    let p = &StandardPolicy::new();

    let encrypted = Vec::new();

    let recipients = key
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    // Start streaming an pgp message.
    let message = Message::new(encrypted);

    // We want to encrypt a literal data packet.
    let message = Encryptor::for_recipients(message, recipients).build()?;

    // Emit a literal data packet.
    let mut message = LiteralWriter::new(message).build()?;

    // Encrypt the data.
    message.write_all(&data)?;

    // Finalize the pgp message to make sure that all data is
    // written.
    message.finalize()?;

    Ok(data)
}

/// Generates a signing key
pub fn generate_key() -> Result<Cert, Box<dyn Error>> {
    let (cert, _revokation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate()?;

    if !PRIVATE_KEY_PATH.lock()?.exists() {
        fs::write(PRIVATE_KEY_PATH.lock()?.clone(), "")?;
        let mut key_file = OpenOptions::new()
            .write(true)
            .open(PRIVATE_KEY_PATH.lock()?.clone())?;

        cert.export(&mut key_file)?;
    }

    Ok(cert)
}

pub fn apply_checksum(filepath: &Path) -> Result<String, Box<dyn Error>> {
    let file_bytes = fs::read(filepath)?;
    let digest = md5::compute(file_bytes);

    let checksum = format!("{:x}", digest);

    Ok(checksum)
}

pub fn verify_checksum(filepath: &Path, checksum: &String) -> Result<bool, Box<dyn Error>> {
    let file_bytes = fs::read(filepath)?;
    let digest = md5::compute(file_bytes);

    let file_checksum = format!("{:x}", digest);

    if &file_checksum == checksum {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn decrypt_file(filepath: &Path, outpath: &Path, key: Cert) -> Result<(), Box<dyn Error>> {
    let encrypted_data = fs::read(filepath)?;

    let decrypted_data = decrypt_data(encrypted_data, key)?;

    fs::write(outpath, decrypted_data)?;

    Ok(())
}

pub fn decrypt_data(data: Vec<u8>, key: Cert) -> Result<Vec<u8>, Box<dyn Error>> {
    let p = &StandardPolicy::new();

    let mut decrypted = Vec::new();

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor =
        DecryptorBuilder::from_bytes(&data)?.with_policy(p, None, Helper::new(p, vec![key]))?;

    // Decrypt the data.
    io::copy(&mut decryptor, &mut decrypted)?;

    Ok(decrypted)
}

/// This helper provides secrets for the decryption, fetches public
/// keys for the signature verification and implements the
/// verification policy.
struct Helper {
    keys: HashMap<pgp::KeyID, KeyPair>,
}

impl Helper {
    /// Creates a Helper for the given Certs with appropriate secrets.
    fn new(p: &dyn Policy, certs: Vec<pgp::Cert>) -> Self {
        // Map (sub)KeyIDs to secrets.
        let mut keys = HashMap::new();
        for cert in certs {
            for ka in cert
                .keys()
                .unencrypted_secret()
                .with_policy(p, None)
                .for_storage_encryption()
                .for_transport_encryption()
            {
                keys.insert(ka.key().keyid(), ka.key().clone().into_keypair().unwrap());
            }
        }

        Helper { keys }
    }
}

impl DecryptionHelper for Helper {
    fn decrypt<D>(
        &mut self,
        pkesks: &[pgp::packet::PKESK],
        _skesks: &[pgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> pgp::Result<Option<pgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        // Try each PKESK until we succeed.
        for pkesk in pkesks {
            if let Some(pair) = self.keys.get_mut(pkesk.recipient()) {
                if pkesk
                    .decrypt(pair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key))
                    .unwrap_or(false)
                {
                    break;
                }
            }
        }
        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
        Ok(None)
    }
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[pgp::KeyHandle]) -> pgp::Result<Vec<pgp::Cert>> {
        Ok(Vec::new()) // Feed the Certs to the verifier here.
    }
    fn check(&mut self, structure: MessageStructure) -> pgp::Result<()> {
        for layer in structure.iter() {
            match layer {
                MessageLayer::Compression { algo } => eprintln!("Compressed using {}", algo),
                MessageLayer::Encryption {
                    sym_algo,
                    aead_algo,
                } => {
                    if let Some(aead_algo) = aead_algo {
                        eprintln!("Encrypted and protected using {}/{}", sym_algo, aead_algo);
                    } else {
                        eprintln!("Encrypted using {}", sym_algo);
                    }
                }
                MessageLayer::SignatureGroup { ref results } => {
                    for result in results {
                        match result {
                            Ok(GoodChecksum { ka, .. }) => {
                                eprintln!("Good signature from {}", ka.cert());
                            }
                            Err(e) => eprintln!("Error: {:?}", e),
                        }
                    }
                }
            }
        }
        Ok(()) // Implement your verification policy here.
    }
}

pub fn uncompress_file(filepath: &Path, outpath: &Path) -> Result<(), Box<dyn Error>> {
    let compressed = Cursor::new(fs::read(filepath)?);

    let mut decoder = gzip::Decoder::new(compressed)?;

    let mut uncompressed = OpenOptions::new().write(true).open(outpath)?;

    io::copy(&mut decoder, &mut uncompressed)?;

    Ok(())
}

pub fn unarchive_folder(filepath: &Path, outpath: &Path) -> Result<(), Box<dyn Error>> {
    if !outpath.exists() {
        fs::create_dir_all(outpath)?;
    }

    let infile = Cursor::new(fs::read(filepath)?);

    let mut archive = tar::Archive::new(infile);
    archive.unpack(outpath)?;

    Ok(())
}
