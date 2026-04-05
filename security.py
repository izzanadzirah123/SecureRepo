import pyotp
from cryptography.fernet import Fernet

# 1. AES Encryption Logic (For Document Security)
def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_data, key):
    f = Fernet(key)
    return f.encrypt(file_data)

def decrypt_file(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data)

# 2. MFA Logic (For Secure Authentication)
def generate_mfa_secret():
    return pyotp.random_base32()

def verify_mfa(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)