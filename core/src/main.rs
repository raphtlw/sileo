mod error;
mod util;

use error::*;
use util::*;

use clap::{App, Arg};
use clap_v3 as clap;
use once_cell::sync::Lazy;
use pgp::{types::SecretKeyTrait, Deserializable, SignedSecretKey};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

const NAME: &'static str = env!("CARGO_PKG_NAME");

static TEMP_DIR: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
    let mut path = dirs::cache_dir().unwrap();
    path.push(NAME);
    Mutex::new(path)
});

static DATA_DIR: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
    let mut path = dirs::data_dir().unwrap();
    path.push(NAME);
    Mutex::new(path)
});

static PRIVATE_KEY_PATH: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
    let mut path = PathBuf::from(DATA_DIR.lock().unwrap().clone());
    path.push("private.key");
    Mutex::new(path)
});

static LOG_FILE_PATH: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
    let mut path = PathBuf::from(TEMP_DIR.lock().unwrap().clone());
    path.push("sileo.log");
    Mutex::new(path)
});

static CHECKSUM_PATH: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
    let mut path = PathBuf::from(DATA_DIR.lock().unwrap().clone());
    path.push("checksums.txt");
    Mutex::new(path)
});

fn main() -> Result<(), Box<dyn Error>> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .chain(fern::log_file(LOG_FILE_PATH.lock()?.clone())?)
        .apply()?;

    let args = App::new("Sileo")
        .arg(
            Arg::new("INPUT")
                .help("Input file/folder path")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    // Create directories if they don't exist
    if !TEMP_DIR.lock()?.exists() {
        fs::create_dir_all(TEMP_DIR.lock()?.clone())?;
    }
    if !DATA_DIR.lock()?.exists() {
        fs::create_dir_all(DATA_DIR.lock()?.clone())?;
    }

    if let Some(input) = args.value_of("INPUT") {
        let input_path = Path::new(input);

        if input_path.exists() {
            let full_path = fs::canonicalize(input_path)?;

            log::debug!("Full input path: {:?}", full_path);

            let mut archive_path = TEMP_DIR.lock()?.clone();
            archive_path.push(format!("{}.tar", input));

            if input_path.is_dir() {
                log::info!("Archiving folder...");
                archive_folder(input_path, &archive_path)?;
            }

            let compressed_archive_path = format!("{}.gz", archive_path.to_string_lossy());
            let compressed_archive_path = Path::new(&compressed_archive_path);

            log::info!("Compressing archive/file...");
            compress_file(&archive_path, compressed_archive_path)?;

            let encrypted_file_path = format!("{}.pgp", compressed_archive_path.to_string_lossy());
            let encrypted_file_path = Path::new(&encrypted_file_path);

            // generate key if not found
            let (secret_key, public_key) = if !PRIVATE_KEY_PATH.lock()?.clone().exists() {
                log::info!("Generating PGP key...");
                generate_key()?
            } else {
                log::info!("PGP key already exists, using existing key...");
                let secret_key_bytes = fs::read(PRIVATE_KEY_PATH.lock()?.clone())?;
                let secret_key = SignedSecretKey::from_bytes(&secret_key_bytes[..])?;
                let public_key = secret_key.public_key();
                (secret_key, public_key)
            };

            log::info!("Encrypting file...");
            encrypt_file(
                compressed_archive_path,
                encrypted_file_path,
                secret_key,
                public_key,
            )?;

            log::info!("Applying checksum...");
            let checksum = apply_checksum(encrypted_file_path)?;
            log::info!("Verifying checksum...");
            let checksum_verified = verify_checksum(encrypted_file_path, &checksum)?;

            if !checksum_verified {
                panic!("Checksum not valid!");
            }

            let checksum_file_name = encrypted_file_path.file_name().unwrap().to_str().unwrap();

            let checksum_map_line = format!("{}={}", checksum_file_name, &checksum);

            fs::write(CHECKSUM_PATH.lock()?.clone(), checksum_map_line)?;
        } else {
            panic!("Input path doesn't exist!");
        }
    }

    Ok(())
}
