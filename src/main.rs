use rand::Rng;
use rayon::prelude::*;
use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

const STEP: u32 = 10000;

fn private_to_address(private_key: &[u8]) -> String {
    let secp = secp256k1::Secp256k1::new();
    let public_key = PublicKey::from_secret_key(
        &secp,
        &secp256k1::SecretKey::from_slice(private_key).unwrap(),
    );
    let public_key_bytes = public_key.serialize_uncompressed()[1..].to_vec();
    let mut hasher = Keccak256::new();
    hasher.update(public_key_bytes);
    let address = hasher.finalize().to_vec()[12..].to_vec();
    hex::encode(address)
}

fn get_random_wallet() -> (String, String) {
    let private_key: [u8; 32] = rand::thread_rng().gen();
    let address = private_to_address(&private_key);
    (address, hex::encode(private_key))
}

fn is_valid_address(address: &str, input: &str, is_checksum: bool, is_suffix: bool) -> bool {
    let sub_str = if is_suffix {
        &address[40 - input.len()..]
    } else {
        &address[0..input.len()]
    };

    if !is_checksum {
        return input == sub_str;
    }

    if input.to_lowercase() != sub_str.to_string() {
        return false;
    }

    is_valid_checksum(address, input, is_suffix)
}

fn is_valid_checksum(address: &str, input: &str, is_suffix: bool) -> bool {
    let mut hasher = Keccak256::new();
    hasher.update(address);
    let hash = hasher.finalize();
    let hash_str = hex::encode(hash);
    let shift = if is_suffix { 40 - input.len() } else { 0 };

    for (i, input_char) in input.chars().enumerate() {
        let j = i + shift;
        let hash_char = u16::from_str_radix(&hash_str[j..=j], 16).unwrap();
        let address_char = address.chars().nth(j).unwrap();
        let expected_char = if hash_char >= 8 {
            address_char.to_uppercase().next().unwrap()
        } else {
            address_char
        };

        if input_char != expected_char {
            return false;
        }
    }
    true
}

fn to_checksum_address(address: &str) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(address);
    let hash = hasher.finalize();
    let hash_str = hex::encode(hash);
    let mut ret = String::new();

    for (i, address_char) in address.chars().enumerate() {
        let hash_char = u16::from_str_radix(&hash_str[i..=i], 16).unwrap();
        ret.push(if hash_char >= 8 {
            address_char.to_uppercase().next().unwrap()
        } else {
            address_char
        });
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
        .map(|_| loop {
            let (address, private_key) = get_random_wallet();
            attempts.fetch_add(1, Ordering::Relaxed);

            if is_valid_address(&address, input, is_checksum, is_suffix) {
                break (address, private_key);
            }

            if attempts.load(Ordering::Relaxed) % STEP == 0 {
                println!("Attempts: {}", attempts.load(Ordering::Relaxed));
            }
        })
        .find_any(|_| true)
        .unwrap();

    (
        "0x".to_string() + &to_checksum_address(&result.0),
        result.1,
        attempts.load(Ordering::Relaxed),
    )
}

fn main() {
    let input = "000"; // The desired prefix or suffix choose from  e.g. "A B C D E F" and "0 1 2 3 4 5 6 7 8 9"
    let is_checksum = false; // Whether the input is case-sensitive
    let is_suffix = false; // Whether the input is a suffix or a prefix. true for suffix (meaning at the end of the address)
    let num_threads = 16; // The number of threads you want to use

    let start_time = Instant::now();
    let (address, private_key, attempts) = workers(input, is_checksum, is_suffix, num_threads);
    let elapsed_time = start_time.elapsed();

    println!(
        "\nAddress: {}\nPrivate Key: {}\n\nAttempts: {}\n",
        address, private_key, attempts
    );

    println!("Time taken: {} seconds", elapsed_time.as_secs_f64());
}
