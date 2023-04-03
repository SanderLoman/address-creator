use rand::Rng;
use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};

const STEP: u32 = 1;

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

fn is_valid_vanity_address(address: &str, input: &str, is_checksum: bool, is_suffix: bool) -> bool {
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

fn get_vanity_wallet(
    input: &str,
    is_checksum: bool,
    is_suffix: bool,
) -> Result<(String, String, u32), String> {
    let input = if is_checksum {
        input.to_string()
    } else {
        input.to_lowercase()
    };
    let mut attempts: u32 = 0;

    loop {
        let (address, private_key) = get_random_wallet();
        attempts += 1;

        if is_valid_vanity_address(&address, &input, is_checksum, is_suffix) {
            return Ok((
                "0x".to_string() + &to_checksum_address(&address),
                private_key,
                attempts,
            ));
        }

        if attempts % STEP == 0 {
            println!("Attempts: {}", attempts);
        }
    }
}
fn main() {
    let input = "0000"; // The desired prefix or suffix choose from  e.g. "A B C D E F" and "0 1 2 3 4 5 6 7 8 9"
    let is_checksum = false; // Whether the input is case-sensitive
    let is_suffix = false; // Whether the input is a suffix or a prefix. true for suffix (meaning at the end of the address)

    match get_vanity_wallet(input, is_checksum, is_suffix) {
        Ok((address, private_key, attempts)) => {
            println!(
                "Address: {}\nPrivate Key: {}\nAttempts: {}",
                address, private_key, attempts
            );
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}
