use clap::{App, Arg};
use rand::RngCore;
use rayon::prelude::*;
use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use tracing::{error, info};
use tracing_subscriber;

const STEP: u32 = 10000;

fn private_to_address(secp: &secp256k1::Secp256k1<secp256k1::All>, private_key: &[u8]) -> String {
    let public_key = PublicKey::from_secret_key(
        secp,
        &secp256k1::SecretKey::from_slice(private_key).unwrap(),
    );
    let public_key_bytes = &public_key.serialize_uncompressed()[1..];
    let mut hasher = Keccak256::new();
    hasher.update(public_key_bytes);
    let hash = hasher.finalize();
    let address = &hash[12..];
    hex::encode(address)
}

fn get_random_wallet(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    rng: &mut impl RngCore,
) -> (String, String) {
    let mut private_key = [0u8; 32];
    rng.fill_bytes(&mut private_key);
    let address = private_to_address(secp, &private_key);
    (address, hex::encode(private_key))
}

fn is_valid_address(address: &str, input: &str, is_checksum: bool, is_suffix: bool) -> bool {
    let sub_str = if is_suffix {
        &address[40 - input.len()..]
    } else {
        &address[..input.len()]
    };

    if !is_checksum {
        return input.eq_ignore_ascii_case(sub_str);
    }

    if input.to_lowercase() != sub_str.to_lowercase() {
        return false;
    }

    is_valid_checksum(address, input, is_suffix)
}

fn is_valid_checksum(address: &str, input: &str, is_suffix: bool) -> bool {
    let address_lower = address.to_lowercase();
    let mut hasher = Keccak256::new();
    hasher.update(address_lower.as_bytes());
    let hash = hasher.finalize();
    let shift = if is_suffix { 40 - input.len() } else { 0 };

    for (i, input_char) in input.chars().enumerate() {
        let j = i + shift;
        let hash_byte = hash[j / 2];
        let hash_nibble = if j % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0F
        };
        let address_char = address.chars().nth(j).unwrap();
        let expected_char = if hash_nibble >= 8 {
            address_char.to_ascii_uppercase()
        } else {
            address_char.to_ascii_lowercase()
        };

        if input_char != expected_char {
            return false;
        }
    }
    true
}

fn to_checksum_address(address: &str) -> String {
    let address_lower = address.to_lowercase();
    let mut hasher = Keccak256::new();
    hasher.update(address_lower.as_bytes());
    let hash = hasher.finalize();
    let mut ret = String::with_capacity(40);

    for (i, address_char) in address_lower.chars().enumerate() {
        let hash_byte = hash[i / 2];
        let hash_nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0F
        };
        if hash_nibble >= 8 {
            ret.push(address_char.to_ascii_uppercase());
        } else {
            ret.push(address_char);
        }
    }
    ret
}

fn workers(
    input: &str,
    is_checksum: bool,
    is_suffix: bool,
    num_threads: usize,
) -> (String, String, u32) {
    let attempts = AtomicU32::new(0);

    let result = (0..num_threads)
        .into_par_iter()
        .map(|_| {
            let secp = secp256k1::Secp256k1::new();
            let mut rng = rand::rngs::OsRng;

            let mut local_attempts = 0;
            loop {
                let (address, private_key) = get_random_wallet(&secp, &mut rng);
                local_attempts += 1;

                if is_valid_address(&address, input, is_checksum, is_suffix) {
                    return (address, private_key, local_attempts);
                }

                if local_attempts % STEP == 0 {
                    let total_attempts = attempts.fetch_add(STEP, Ordering::Relaxed) + STEP;
                    info!("Attempts: {}", total_attempts);
                }
            }
        })
        .find_any(|_| true)
        .unwrap();

    let total_attempts = attempts.load(Ordering::Relaxed) + result.2 % STEP;
    (
        format!("0x{}", to_checksum_address(&result.0)),
        result.1,
        total_attempts,
    )
}

fn main() {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Define CLI arguments using clap
    let matches = App::new("Ethereum Vanity Address Generator")
        .version("1.0")
        .author("Sander Loman <sanderfeitsma13@gmail.com>")
        .about("Generates Ethereum addresses with desired prefix or suffix")
        .arg(
            Arg::with_name("INPUT")
                .help("Desired prefix or suffix for the Ethereum address")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("checksum")
                .short('c')
                .long("checksum")
                .help("Enable case-sensitive search (checksum)"),
        )
        .arg(
            Arg::with_name("suffix")
                .short('s')
                .long("suffix")
                .help("Search for the input as a suffix instead of prefix"),
        )
        .arg(
            Arg::with_name("threads")
                .short('t')
                .long("threads")
                .help("Number of threads to use")
                .takes_value(true)
                .default_value("20"),
        )
        .get_matches();

    let input = matches.value_of("INPUT").unwrap();
    let is_checksum = matches.is_present("checksum");
    let is_suffix = matches.is_present("suffix");
    let num_threads = matches
        .value_of("threads")
        .unwrap()
        .parse::<usize>()
        .unwrap_or_else(|_| {
            error!("Invalid number of threads specified.");
            std::process::exit(1);
        });

    info!("Starting vanity address generation...");
    info!(
        "Desired {}: {}",
        if is_suffix { "suffix" } else { "prefix" },
        input
    );
    info!("Case-sensitive search (checksum): {}", is_checksum);
    info!("Number of threads: {}", num_threads);

    let start_time = Instant::now();
    let (address, private_key, attempts) = workers(input, is_checksum, is_suffix, num_threads);
    let elapsed_time = start_time.elapsed();

    println!(
        "\nAddress: {}\nPrivate Key: {}\n\nAttempts: {}\n",
        address, private_key, attempts
    );

    println!("Time taken: {:.6} seconds", elapsed_time.as_secs_f64());
}
