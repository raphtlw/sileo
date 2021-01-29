mod error;
mod util;

use error::*;
use util::*;

use clap::{App, Arg};
use clap_v3 as clap;
use once_cell::sync::Lazy;
use sequoia_openpgp::{parse::Parse, Cert};
use std::{
    env,
    error::Error,
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
    sync::Mutex,
};

const NAME: &'static str = env!("CARGO_PKG_NAME");

// static TEMP_DIR: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
//     let mut path = dirs::cache_dir().unwrap();
//     path.push(NAME);
//     Mutex::new(path)
// });

static TEMP_DIR: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
    let mut path = env::current_dir().unwrap();
    path.push(NAME);
    Mutex::new(path)
});

static DATA_DIR: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
    let mut path = dirs::data_dir().unwrap();
    path.push(NAME);
    Mutex::new(path)
});

// static DATA_DIR: Lazy<Mutex<PathBuf>> = Lazy::new(|| {
//     let mut path = env::current_dir().unwrap();
//     path.push("");
//     Mutex::new(path)
// });

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
    // Create directories if they don't exist
    if !TEMP_DIR.lock()?.exists() {
        fs::create_dir_all(TEMP_DIR.lock()?.clone())?;
    }
    if !DATA_DIR.lock()?.exists() {
        fs::create_dir_all(DATA_DIR.lock()?.clone())?;
    }

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
        .arg(
            Arg::new("decrypt")
                .short('d')
                .long("decrypt")
                .help("Decrypt instead of encrypt"),
        )
        .get_matches();

    if let Some(input) = args.value_of("INPUT") {
        let input_path = Path::new(input);

        if input_path.exists() {
            let full_path = fs::canonicalize(input_path)?;
            log::debug!("Full input path: {:?}", full_path);

            let file_name = full_path.file_name().unwrap().to_str().unwrap();
            log::debug!("File name: {}", file_name);

            if !args.is_present("decrypt") {
                // Encrypt

                let mut archive_path = TEMP_DIR.lock()?.clone();
                archive_path.push(format!("{}.tar", file_name));

                if input_path.is_dir() {
                    log::info!("Archiving folder...");
                    archive_folder(input_path, &archive_path)?;
                }

                let compressed_archive_path = format!("{}.gz", archive_path.to_string_lossy());
                let compressed_archive_path = Path::new(&compressed_archive_path);

                log::info!("Compressing archive/file...");
                compress_file(&archive_path, compressed_archive_path)?;

                let encrypted_file_path =
                    format!("{}.pgp", compressed_archive_path.to_string_lossy());
                let encrypted_file_path = Path::new(&encrypted_file_path);

                // generate key if not found
                let pgp_key = if !PRIVATE_KEY_PATH.lock()?.clone().exists() {
                    log::info!("Generating PGP key...");
                    generate_key()?
                } else {
                    log::info!("PGP key already exists, using existing key...");
                    Cert::from_file(PRIVATE_KEY_PATH.lock()?.clone())?
                };

                log::info!("Encrypting file...");
                encrypt_file(compressed_archive_path, encrypted_file_path, pgp_key)?;

                log::info!("Applying checksum...");
                let checksum = apply_checksum(encrypted_file_path)?;
                log::info!("Verifying checksum...");
                let checksum_verified = verify_checksum(encrypted_file_path, &checksum)?;
                if !checksum_verified {
                    panic!("Checksum not valid!");
                }
                log::info!("Checksum verified!");

                let checksum_file_name = encrypted_file_path.file_name().unwrap().to_str().unwrap();
                let checksum_map_line = format!("{}={}", checksum_file_name, &checksum);

                if !CHECKSUM_PATH.lock()?.clone().exists() {
                    fs::write(CHECKSUM_PATH.lock()?.clone(), "")?;
                }

                let mut checksum_file = fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open(CHECKSUM_PATH.lock()?.clone())?;

                writeln!(checksum_file, "{}", checksum_map_line)?;

                log::info!("Done!");
            } else {
                // Decrypt

                log::info!("Verifying checksum...");
                let checksum_list = fs::read_to_string(CHECKSUM_PATH.lock()?.clone())?;
                log::debug!("Checksum list: {}", checksum_list);
                let checksum = checksum_list
                    .split("\n")
                    .find(|&x| x.split("=").collect::<Vec<&str>>()[0] == file_name)
                    .unwrap()
                    .split("=")
                    .collect::<Vec<&str>>()[1];
                log::debug!("Checksum: {}", checksum);
                let checksum_verified = verify_checksum(&full_path, &String::from(checksum))?;
                if !checksum_verified {
                    panic!("Checksum not valid!");
                }

                log::info!("Reading existing PGP key...");
                let key = Cert::from_file(PRIVATE_KEY_PATH.lock()?.clone())?;

                let decrypted_file_path_str = full_path.to_string_lossy().replace(".pgp", "");
                let decrypted_file_path = Path::new(&decrypted_file_path_str);

                log::info!("Decrypting file...");
                decrypt_file(&full_path, decrypted_file_path, key)?;

                let uncompressed_file_path_str = decrypted_file_path_str.replace(".gz", "");
                let uncompressed_file_path = Path::new(&uncompressed_file_path_str);

                log::info!("Uncompressing archive/file...");
                uncompress_file(decrypted_file_path, uncompressed_file_path)?;

                if uncompressed_file_path_str.contains(".tar") {
                    log::info!("File is archive");
                    log::info!("Unarchiving file...");

                    let output_path_str = uncompressed_file_path_str.replace(".tar", "");
                    let output_path = Path::new(&output_path_str);
                    unarchive_folder(uncompressed_file_path, output_path)?;
                }

                log::info!("Done!");
            }
        } else {
            panic!("Input path doesn't exist!");
        }
    }

    Ok(())
}
