use io::Cursor;
use libflate::gzip;
use pgp::{
    composed::{key::SecretKeyParamsBuilder, KeyType},
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm, PublicKeyAlgorithm},
    packet,
    ser::Serialize,
    types::{CompressionAlgorithm, KeyTrait, PublicKeyTrait, SecretKeyTrait},
    PublicKey, Signature, SignedSecretKey,
};
use sha2::{Digest, Sha256};
use smallvec::smallvec;
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io,
    path::Path,
};
use tar::Builder;
use walkdir::WalkDir;

use crate::{SileoError, PRIVATE_KEY_PATH};

pub fn archive_folder(folder: &Path, outpath: &Path) -> Result<(), Box<dyn Error>> {
    if folder.is_dir() {
        if !outpath.exists() {
            fs::write(outpath, "")?
        }

        let outfile = OpenOptions::new()
            .append(true)
            .read(true)
            .write(true)
            .open(outpath)?;
        let mut archive = Builder::new(outfile);

        for entry in WalkDir::new(folder) {
            archive.append_path(entry?.path())?;
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

pub fn encrypt_file(
    filepath: &Path,
    outpath: &Path,
    signing_key: SignedSecretKey,
    verification_key: PublicKey,
) -> Result<(), Box<dyn Error>> {
    let input_data = fs::read(filepath)?;

    let encrypted_data = encrypt_data(input_data, signing_key, verification_key)?;

    fs::write(outpath, encrypted_data)?;

    Ok(())
}

pub fn encrypt_data(
    data: Vec<u8>,
    signing_key: SignedSecretKey,
    verification_key: PublicKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let now = chrono::Utc::now();
    let passwd_fn = || String::new();

    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    };
    let digest = digest.as_slice();

    // creates the cryptographic core of the signature without any metadata
    let signature = signing_key
        .create_signature(passwd_fn, HashAlgorithm::SHA2_256, digest)
        .expect("Failed to crate signature");

    // the signature can already be verified
    verification_key
        .verify_signature(HashAlgorithm::SHA2_256, digest, &signature)
        .expect("Failed to validate signature");

    // wraps the signature in the apropriate package fmt ready to be serialized
    let signature = Signature::new(
        pgp::types::Version::Old,
        packet::SignatureVersion::V4,
        packet::SignatureType::Binary,
        PublicKeyAlgorithm::RSA,
        HashAlgorithm::SHA2_256,
        [digest[0], digest[1]],
        signature,
        vec![
            packet::Subpacket::SignatureCreationTime(now),
            packet::Subpacket::Issuer(signing_key.key_id()),
        ],
        vec![],
    );

    // sign and and write the package (the package written here is NOT rfc4880 compliant)
    let mut signature_bytes = Vec::with_capacity(1024);

    let mut buff = Cursor::new(&mut signature_bytes);
    packet::write_packet(&mut buff, &signature).expect("Write must succeed");

    let raw_signature = signature.signature;
    verification_key
        .verify_signature(HashAlgorithm::SHA2_256, digest, &raw_signature)
        .expect("Verify must succeed");

    Ok(signature_bytes)
}

pub fn generate_key() -> Result<(SignedSecretKey, PublicKey), Box<dyn Error>> {
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Rsa(2048))
        .can_create_certificates(false)
        .can_sign(true)
        .primary_user_id("Me <me@example.com>".into())
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256])
        .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB]);
    let secret_key_params = key_params
        .build()
        .expect("Must be able to create secret key params");
    let secret_key = secret_key_params
        .generate()
        .expect("Failed to generate a plain key.");
    let passwd_fn = || String::new();
    let signed_secret_key = secret_key
        .sign(passwd_fn)
        .expect("Must be able to sign its own metadata");
    let public_key = signed_secret_key.public_key();

    let signed_secret_key_bytes = signed_secret_key.to_bytes()?;

    fs::write(PRIVATE_KEY_PATH.lock()?.clone(), signed_secret_key_bytes)?;

    Ok((signed_secret_key, public_key))
}
