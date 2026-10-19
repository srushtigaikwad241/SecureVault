import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

MASTER_KEY = os.getenv("SECUREVAULT_MASTER_KEY")

if not MASTER_KEY:
    raise RuntimeError(
        "SECUREVAULT_MASTER_KEY is missing from .env"
    )

fernet = Fernet(MASTER_KEY.encode())


def encrypt_key(key):
    """
    Encrypt/wrap the AES file key
    before storing it in the database.
    """
    return fernet.encrypt(key).decode()


def decrypt_key(encrypted_key):
    """
    Recover the original AES file key
    from the encrypted database value.
    """
    return fernet.decrypt(
        encrypted_key.encode()
    )