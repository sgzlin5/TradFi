import json
import base64
import os
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """使用PBKDF2从密码派生加密密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(input_file, output_file, password):
    # 生成随机盐
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    # 将盐和加密数据一起保存（盐不需要加密）
    with open(output_file, 'wb') as f:
        f.write(salt + encrypted_data)

if __name__ == "__main__":
    password = getpass.getpass("Enter encryption password: ")
    encrypt_file('config.json', 'config.enc', password)
    print("Encrypted config saved to config.enc")
