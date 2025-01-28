import secrets
import string

def generate_password(length=16, use_special_chars=True):
    alphabet = string.ascii_letters + string.digits
    if use_special_chars:
        alphabet += string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

from cryptography.fernet import Fernet