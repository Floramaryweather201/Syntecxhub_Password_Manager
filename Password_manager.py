
import os
import json
import base64
import getpass
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

VAULT_FILE = Path("vault.enc")


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(data):
    return base64.b64decode(data, validate=True)


def derive_key(master_password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_vault(entries, master_password):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(master_password, salt)

    plaintext = json.dumps(entries).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    return {
        "version": 1,
        "kdf": "scrypt",
        "salt": encode(salt),
        "nonce": encode(nonce),
        "ciphertext": encode(ciphertext)
    }


def save_vault(entries, master_password):
    vault_data = encrypt_vault(entries, master_password)

    fd, temporary_path = tempfile.mkstemp(
        prefix=".vault-",
        dir=VAULT_FILE.parent
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(vault_data, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, VAULT_FILE)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def load_vault(master_password):
    if not VAULT_FILE.exists():
        return None

    data = json.loads(VAULT_FILE.read_text(encoding="utf-8"))

    if data.get("version") != 1 or data.get("kdf") != "scrypt":
        raise ValueError("Unsupported vault format")

    salt = decode(data["salt"])
    nonce = decode(data["nonce"])
    ciphertext = decode(data["ciphertext"])

    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("Invalid vault format")

    key = derive_key(master_password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    entries = json.loads(plaintext.decode("utf-8"))

    if not isinstance(entries, dict):
        raise ValueError("Invalid vault contents")

    return entries


def add_entry(entries):
    name = input("Account name: ").strip()
    if not name:
        print("Account name cannot be empty.")
        return False

    if name in entries:
        print("That account already exists.")
        return False

    username = input("Username: ").strip()
    password = getpass.getpass("Account password: ")

    entries[name] = {
        "username": username,
        "password": password
    }

    print("Credential added.")
    return True


def retrieve_entry(entries):
    name = input("Account name: ").strip()
    entry = entries.get(name)

    if entry is None:
        print("Account not found.")
        return

    print(f"Account: {name}")
    print(f"Username: {entry['username']}")

    confirm = input("Reveal password? (yes/no): ").lower()
    if confirm == "yes":
        print(f"Password: {entry['password']}")


def search_entries(entries):
    query = input("Search account names: ").strip().lower()

    matches = [
        name for name in entries
        if query in name.lower()
    ]

    if matches:
        for name in sorted(matches):
            print(f"- {name}")
    else:
        print("No matching accounts.")


def delete_entry(entries):
    name = input("Account to delete: ").strip()

    if name not in entries:
        print("Account not found.")
        return False

    confirm = input(f"Delete '{name}'? (yes/no): ").lower()
    if confirm == "yes":
        del entries[name]
        print("Credential deleted.")
        return True

    print("Deletion cancelled.")
    return False


def main():
    print("=== Syntecxhub Password Manager ===")

    if VAULT_FILE.exists():
        master = getpass.getpass("Enter master password: ")

        try:
            entries = load_vault(master)
        except InvalidTag:
            print("Incorrect master password or damaged vault.")
            return
        except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError):
            print("Unable to read vault. File may be damaged.")
            return

        print("Vault unlocked!")
    else:
        print("Create a new encrypted vault.")

        master = getpass.getpass("Create master password: ")
        confirm = getpass.getpass("Confirm master password: ")

        if master != confirm:
            print("Passwords do not match.")
            return

        if len(master) < 12:
            print("Use a master password of at least 12 characters.")
            return

        entries = {}
        save_vault(entries, master)
        print("Encrypted vault created!")

    while True:
        print("\n=== Menu ===")
        print("1. Add credential")
        print("2. Retrieve credential")
        print("3. Search credentials")
        print("4. Delete credential")
        print("5. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            changed = add_entry(entries)
        elif choice == "2":
            retrieve_entry(entries)
            changed = False
        elif choice == "3":
            search_entries(entries)
            changed = False
        elif choice == "4":
            changed = delete_entry(entries)
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")
            changed = False

        if changed:
            save_vault(entries, master)
            print("Encrypted vault saved.")


if __name__ == "__main__":
    main()

