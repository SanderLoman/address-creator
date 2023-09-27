# Ethereum Address Generator in Rust

## Overview

This Rust program generates Ethereum addresses and their corresponding private keys. It uses multi-threading to speed up the process and allows you to specify certain conditions for the generated address, such as a specific prefix or suffix and whether it should be a checksum address.

## Prerequisites

- Rust programming language
- Cargo package manager
- Required Rust libraries:
  - `rand`
  - `rayon`
  - `secp256k1`
  - `sha3`
  - `hex`

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/SanderLoman/address-creator.git
    ```

2. Navigate to the project directory:
    ```bash
    cd address-creator
    ```

## Usage

1. Run the program:
    ```bash
    cargo run
    ```

2. The program will generate Ethereum addresses and private keys based on the conditions specified in the `main()` function.

3. The generated address and private key will be displayed on the console, along with the number of attempts made and the time taken.

## Code Explanation

### Functions

- `private_to_address`: Converts a private key to an Ethereum address.
- `get_random_wallet`: Generates a random Ethereum address and its corresponding private key.
- `is_valid_address`: Checks if a generated address meets the specified conditions.
- `is_valid_checksum`: Validates the checksum of an Ethereum address.
- `to_checksum_address`: Converts an Ethereum address to its checksum form.
- `workers`: Multi-threaded function that generates Ethereum addresses until it finds one that meets the specified conditions.
- `main`: The entry point of the program. Specifies the conditions for the generated address and runs the `workers` function.
