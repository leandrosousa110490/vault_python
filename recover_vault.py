import os
import json
import base64
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_FILE = "vault_key.key"
VAULT_FILE = "vault.json"
BACKUP_DIR = "backups"

def load_key():
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=310000,
    )
    key = kdf.derive(password.encode())
    return {
        'salt': base64.urlsafe_b64encode(salt).decode(),
        'key': base64.urlsafe_b64encode(key).decode()
    }

def verify_password(stored_password, stored_salt, provided_password):
    salt = base64.urlsafe_b64decode(stored_salt.encode())
    stored_key = base64.urlsafe_b64decode(stored_password.encode())
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=310000,
    )
    try:
        kdf.verify(provided_password.encode(), stored_key)
        return True
    except:
        return False

def load_vault_data():
    cipher_suite = Fernet(load_key())
    with open(VAULT_FILE, 'rb') as file:
        encrypted_data = file.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        return json.loads(decrypted_data)

def save_vault_data(vault_data):
    cipher_suite = Fernet(load_key())
    data_json = json.dumps(vault_data).encode()
    encrypted_data = cipher_suite.encrypt(data_json)
    with open(VAULT_FILE, 'wb') as file:
        file.write(encrypted_data)
    print("Vault saved successfully.")

def reset_master_password(new_password):
    vault_data = load_vault_data()
    hashed = hash_password(new_password)
    vault_data['master_password'] = {
        'salt': hashed['salt'],
        'hash': hashed['key']
    }
    save_vault_data(vault_data)
    print("Master password reset successfully!")

def check_master_password(password):
    try:
        vault_data = load_vault_data()
        stored_master = vault_data.get('master_password', {})
        if not stored_master:
            print("ERROR: Vault is corrupted or missing master password.")
            return False
            
        stored_hash = stored_master.get('hash')
        stored_salt = stored_master.get('salt')
        
        if verify_password(stored_hash, stored_salt, password):
            print("SUCCESS: Password is correct!")
            return True
        else:
            print("FAILED: Password is incorrect.")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def view_vault_structure():
    vault_data = load_vault_data()
    print("\nVault Structure:")
    print("- Has master password:", 'master_password' in vault_data)
    entries = vault_data.get('entries', [])
    print(f"- Number of entries: {len(entries)}")
    
    categories = {}
    for entry in entries:
        category = entry.get('category')
        categories[category] = categories.get(category, 0) + 1
    
    print("- Categories:")
    for category, count in categories.items():
        print(f"  - {category}: {count} entries")

def list_backups():
    if not os.path.exists(BACKUP_DIR):
        print("No backup directory found.")
        return []
        
    backups = [f for f in os.listdir(BACKUP_DIR) 
                if f.startswith("vault_backup_") and f.endswith(".enc")]
    
    if not backups:
        print("No backup files found.")
        return []
        
    print("\nAvailable backups:")
    backups.sort(reverse=True)
    for i, backup in enumerate(backups):
        print(f"{i+1}. {backup}")
    
    return backups

def try_known_passwords():
    """Try some commonly used passwords"""
    common_passwords = [
        "password", "123456", "admin", "welcome", 
        "password123", "admin123", "qwerty", "letmein",
        # Check variations with first character capitalized and/or ! at the end
        "Password", "Password!", "Admin", "Admin!", 
        "Welcome", "Welcome!"
    ]
    
    print("\nTrying some common passwords:")
    for password in common_passwords:
        print(f"Checking: {password}")
        if check_master_password(password):
            return True
    
    print("None of the common passwords matched.")
    return False

def reset_password_from_backup():
    """Reset password using a backup file"""
    backups = list_backups()
    if not backups:
        return False
    
    try:
        backup_idx = int(input("\nEnter backup number to restore from (or 0 to cancel): ")) - 1
        if backup_idx < 0:
            print("Operation cancelled.")
            return False
        
        backup_file = os.path.join(BACKUP_DIR, backups[backup_idx])
        
        new_password = input("Enter new master password for the vault: ")
        confirm_password = input("Confirm new master password: ")
        
        if new_password != confirm_password:
            print("Passwords don't match. Operation cancelled.")
            return False
        
        # Copy the backup to a temporary file
        import shutil
        temp_vault = "temp_vault.json"
        shutil.copy2(backup_file, temp_vault)
        
        # Create new vault with the password
        cipher_suite = Fernet(load_key())
        with open(temp_vault, 'rb') as file:
            encrypted_data = file.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
            vault_data = json.loads(decrypted_data)
        
        # Update password
        hashed = hash_password(new_password)
        vault_data['master_password'] = {
            'salt': hashed['salt'],
            'hash': hashed['key']
        }
        
        # Save back to main vault
        data_json = json.dumps(vault_data).encode()
        encrypted_data = cipher_suite.encrypt(data_json)
        with open(VAULT_FILE, 'wb') as file:
            file.write(encrypted_data)
        
        # Clean up
        os.remove(temp_vault)
        
        print("Vault restored from backup with new password!")
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def check_password_input(password=None):
    """Directly check a password provided by input or as argument"""
    if password is None:
        password = input("\nEnter the password to check: ")
    
    return check_master_password(password)

def main():
    print("===== Vault Recovery Tool =====")
    
    # If an argument was provided, check it as a password first
    if len(sys.argv) > 1:
        password = sys.argv[1]
        print(f"Checking provided password argument...")
        if check_master_password(password):
            return
    
    # First, try to check the vault structure to ensure it can be decrypted
    try:
        vault_data = load_vault_data()
        print("\nGood news! Your vault can be decrypted with the current key file.")
        print("The issue is likely that you're using a different master password than expected.")
    except Exception as e:
        print(f"\nERROR: Could not decrypt vault with current key file: {e}")
        print("The key file might be corrupted or replaced.")
        return
    
    print("\nWhat would you like to do?")
    print("1. Check a specific password")
    print("2. Try common passwords automatically")
    print("3. Reset master password")
    print("4. Reset password from a backup")
    print("5. View vault structure")
    print("6. List available backups")
    print("7. Exit")
    
    choice = input("\nEnter your choice (1-7): ")
    
    if choice == '1':
        check_password_input()
    
    elif choice == '2':
        try_known_passwords()
    
    elif choice == '3':
        print("\nWARNING: This will reset your master password.")
        confirm = input("Are you sure you want to continue? (y/n): ")
        if confirm.lower() != 'y':
            print("Operation cancelled.")
            return
            
        new_password = input("Enter new master password: ")
        confirm_password = input("Confirm new master password: ")
        
        if new_password != confirm_password:
            print("Passwords don't match.")
            return
            
        reset_master_password(new_password)
    
    elif choice == '4':
        reset_password_from_backup()
    
    elif choice == '5':
        try:
            view_vault_structure()
        except Exception as e:
            print(f"Error: {e}")
    
    elif choice == '6':
        list_backups()
        
    elif choice == '7':
        print("Exiting...")
        return
        
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main() 