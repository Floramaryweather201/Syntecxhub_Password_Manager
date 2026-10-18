
# Syntecxhub Password Manager

## Project Overview
A Python-based local password manager developed as part of the Syntecxhub Cybersecurity Internship.

The application securely stores credentials in an encrypted vault protected by a master password.

## Features
- AES-256-GCM authenticated encryption
- Master password authentication
- Scrypt key derivation
- Add new credentials
- Retrieve saved credentials
- Search for accounts
- Delete credentials
- Encrypted local JSON vault storage

## Technologies Used
- Python 3
- cryptography library
- AES-GCM
- Scrypt
- Visual Studio Code

## Installation

Install the required dependency:

```bash
pip install -r requirements.txt
```

## How to Run

```bash
python3 Password_manager.py
```

Create a master password when prompted. The application will create an encrypted local vault.

## Menu Options

1. Add credential
2. Retrieve credential
3. Search credentials
4. Delete credential
5. Exit

## Testing

Successfully tested:
- Vault creation
- Credential encryption and storage
- Credential retrieval
- Account searching
- Credential deletion
- Reopening the encrypted vault

## Security Considerations

The master password is not stored on disk. The application uses Scrypt to derive an encryption key and AES-GCM to protect credential data.

The encrypted `vault.enc` file is excluded from the public repository.

This is an educational project and is not intended to replace a production password manager.

[📸 View Password Manager Screenshots (PDF)](https://github.com/Floramaryweather201/Syntecxhub_Password_Manager/blob/main/Password_Manager_Project_2_Screenshots_NEW.pdf)

## Author

Developed for the Syntecxhub Cybersecurity Internship.
