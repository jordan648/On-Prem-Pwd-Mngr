import secrets
import string
import json
from cryptography.fernet import Fernet

def generate_password(length=16, use_special_chars=True):
    alphabet = string.ascii_letters + string.digits
    if use_special_chars:
        alphabet += string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_key(master_password):
    return Fernet(Fernet.generate_key())

def encrypt_data(key, data):
    return key.encrypt(data.encode())

def decrypt_data(key, encrypted_data):
    return key.decrypt(encrypted_data).decode()

def save_credentials(filename, encrypted_data):
    with open(filename, 'wb') as f:
        f.write(encrypted_data)

def load_credentials(filename):
    with open(filename, 'rb') as f:
        return f.read()
    
def main():
    master_password = input('Enter your master password: ')
    key = generate_key(master_password)

    print('1. Generate a new password')
    print('2. Save your credentials')
    print('3. View your credentials')
    print('4. Exit')

    choice = input("Chosse an option:")

    if choice == '1':
        password = generate_password()
        print(f'Generated password: {password}')

    elif choice == '2':
        username = input('Enter your username: ')
        password = input('Enter your password: ')
        credentails = {"username": username, "password": password}
        encrypted_data = encrypt_data(key, json.dumps(credentails))
        save_credentials('credentials.enc', encrypted_data)

    elif choice == '3':
        try:
            encrypted_data = load_credentials('credentials.enc')
            decrypted_data = decrypt_data(key, encrypted_data)
            print('Credentials:', decrypted_data)
        except Exception as e:
            print('Failed to decrypt data: ', e)

    elif choice == '4':
        print('Exiting...')
        exit()