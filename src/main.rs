use aes::{Aes256, cipher::{BlockEncrypt, BlockDecrypt, KeyInit}};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Parser, Subcommand};
use rand::{distributions::Alphanumeric, Rng};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};

const DB_FILE: &str = "passwords.db";
const SALT: [u8; 16] = *b"RustyPassSalt123";

#[derive(Serialize, Deserialize, Debug)]
struct PasswordEntry {
    service: String,
    username: String,
    password: String,
}

#[derive(Parser)]
#[command(name = "rusty-pass")]
#[command(about = "A secure password manager CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new password entry
    Add {
        service: String,
        username: String,
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Get password for a service
    Get { service: String },
    /// Delete password entry for a service
    Delete { service: String },
    /// List all services
    List,
    /// Generate a secure password
    Generate { length: Option<usize> },
}

fn encrypt(data: &str, key: &[u8; 32]) -> String {
    let cipher = Aes256::new_from_slice(key).unwrap();
    let mut buf = data.as_bytes().to_vec();
    // Pad to block size
    while buf.len() % 16 != 0 {
        buf.push(0);
    }
    // Encrypt in place
    for chunk in buf.chunks_mut(16) {
        cipher.encrypt_block(chunk.into());
    BASE64.encode(buf)
}

fn decrypt(data: &str, key: &[u8; 32]) -> Result<String, Box<dyn std::error::Error>> {
    let cipher = Aes256::new_from_slice(key).unwrap();
    let mut buf = BASE64.decode(data)?;
    // Decrypt in place
    for chunk in buf.chunks_mut(16) {
        cipher.decrypt_block(chunk.into());
    // Remove padding
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(String::from_utf8(buf)?)
}

fn derive_key(master_password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut input = master_password.as_bytes().to_vec();
    input.extend_from_slice(SALT);
    key.copy_from_slice(&input[..32]);
    key
}

fn generate_password(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn load_passwords(key: &[u8; 32]) -> Result<HashMap<String, PasswordEntry>, Box<dyn std::error::Error>> {
    if !Path::new(DB_FILE).exists() {
        return Ok(HashMap::new());
    }
    let encrypted = fs::read_to_string(DB_FILE)?;
    let decrypted = decrypt(&encrypted, key)?;
    Ok(serde_json::from_str(&decrypted)?)
}

fn save_passwords(
    passwords: &HashMap<String, PasswordEntry>,
    key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(passwords)?;
    let encrypted = encrypt(&json, key);
    fs::write(DB_FILE, encrypted)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    print!("Enter master password: ");
    let master_password = read_password()?;
    let key = derive_key(&master_password);

    let mut passwords = load_passwords(&key)?;

    match cli.command {
        Commands::Add {
            service,
            username,
            password,
        } => {
            let password = if let Some(pass) = password {
                pass
            } else {
                print!("Enter password for {}: ", service);
                read_password()?
            };

            passwords.insert(
                service.clone(),
                PasswordEntry {
                    service,
                    username,
                    password,
                },
            );
            save_passwords(&passwords, &key)?;
            println!("Password added successfully!");
        }
        Commands::Get { service } => {
            if let Some(entry) = passwords.get(&service) {
                println!("Service: {}", entry.service);
                println!("Username: {}", entry.username);
                println!("Password: {}", entry.password);
            } else {
                println!("No password found for service: {}", service);
            }
        }
        Commands::Delete { service } => {
            if passwords.remove(&service).is_some() {
                save_passwords(&passwords, &key)?;
                println!("Password deleted successfully!");
            } else {
                println!("No password found for service: {}", service);
            }
        }
        Commands::List => {
            if passwords.is_empty() {
                println!("No passwords stored.");
            } else {
                println!("Stored passwords:");
                for entry in passwords.values() {
                    println!("Service: {}, Username: {}", entry.service, entry.username);
                }
            }
        }
        Commands::Generate { length } => {
            let length = length.unwrap_or(16);
            let password = generate_password(length);
            println!("Generated password: {}", password);
        }
    }

    Ok(())
}
