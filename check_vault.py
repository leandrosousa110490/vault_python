from cryptography.fernet import Fernet
import sys
import os

KEY_FILE = "vault_key.key"
VAULT_FILE = "vault.json"

def load_key():
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except Exception as e:
        print(f"Error reading key file: {e}")
        return None

def check_vault():
    key = load_key()
    if not key:
        return False
    
    try:
        cipher_suite = Fernet(key)
        with open(VAULT_FILE, 'rb') as file:
            encrypted_data = file.read()
            cipher_suite.decrypt(encrypted_data)
        return True
    except Exception as e:
        print(f"Error decrypting vault: {e}")
        return False

if __name__ == "__main__":
    if check_vault():
        print("SUCCESS: Vault can be decrypted with current key.")
    else:
        print("FAILED: Vault cannot be decrypted with current key.") 