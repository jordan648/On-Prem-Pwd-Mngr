from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import os
import base64


# Generate a random salt
def generate_salt():
    return os.urandom(16)

# Derive a key from the master password
def derive_key(master_password, salt):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

# Encrypt data
def encrypt_data(key, data):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data
def decrypt_data(key, encrypted_data):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

# Save data to a file
def save_data(file_path, salt, encrypted_data):
    with open(file_path, 'wb') as file:
        file.write(salt + encrypted_data)

# Load data from a file
def load_data(file_path):
    with open(file_path, 'rb') as file:
        salt = file.read(16)  # First 16 bytes are the salt
        encrypted_data = file.read()  # The rest is the encrypted data
    return salt, encrypted_data
    
def main():
    file_path = "password_manager.enc"

    # Prompt for the master password
    master_password = input("Enter your master password: ")

    if os.path.exists(file_path):
        # Load existing encrypted data
        salt, encrypted_data = load_data(file_path)
        key = derive_key(master_password, salt)

        try:
            decrypted_data = decrypt_data(key, encrypted_data)
            credentials = json.loads(decrypted_data)
        except Exception:
            print("Invalid master password or corrupted file.")
            return
    else:
        # No file exists, create a new password vault
        credentials = {}
        salt = generate_salt()
        key = derive_key(master_password, salt)

    # Menu
    while True:
        print("\nMenu:")
        print("1. Add a new credential")
        print("2. View all credentials")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            # Add a new credential
            service = input("Enter service name: ")
            username = input("Enter username: ")
            password = generate_password()
            print(f"Generated password for {service}: {password}")
            credentials[service] = {"username": username, "password": password}

        elif choice == "2":
            # View credentials
            for service, data in credentials.items():
                print(f"Service: {service}, Username: {data['username']}, Password: {data['password']}")

        elif choice == "3":
            # Save and exit
            encrypted_data = encrypt_data(key, json.dumps(credentials))
            save_data(file_path, salt, encrypted_data)
            print("Data saved securely. Goodbye!")
            break