# Rusty-Pass Password Manager

A secure command-line password manager written in Rust. It provides encrypted storage of passwords with a master password protection.

## Features

- Secure password storage using AES-256 encryption
- Master password protection
- Command-line interface with intuitive commands
- Password generation capability
- Local encrypted storage in `passwords.db` file

## Usage

### Add a new password
```bash
rusty-pass add <service> <username> [--password <password>]
```
If --password is not provided, you will be prompted to enter it securely.

### Get a password
```bash
rusty-pass get <service>
```

### Delete a password
```bash
rusty-pass delete <service>
```

### List all services
```bash
rusty-pass list
```

### Generate a secure password
```bash
rusty-pass generate [length]
```
Default length is 16 characters if not specified.

## Security

- All passwords are encrypted using AES-256
- Master password is required for all operations
- Passwords are stored locally in an encrypted database file
- Password input is hidden from terminal output

## Building from Source

```bash
cargo build --release
```

The binary will be available in `target/release/rusty-pass`