from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

# Load environment variables from a .env file, if you're using it
load_dotenv()

class EncryptionManager:
    def __init__(self):
        # Load the encryption key from an environment variable
        encryption_key = os.environ.get("ENCRYPTION_KEY")
        if encryption_key is None:
            raise ValueError("ENCRYPTION_KEY environment variable is not set")
        
        self.cipher_suite = Fernet(encryption_key.encode())

    @staticmethod
    def generate_key():
        """Generates a new encryption key."""
        return Fernet.generate_key()

    def encrypt(self, data):
        """Encrypts data using Fernet symmetric encryption."""
        if isinstance(data, str):
            data = data.encode()  # Convert to bytes
        encrypted_data = self.cipher_suite.encrypt(data)
        return encrypted_data.decode()  # Convert bytes to string for storage

    def decrypt(self, encrypted_data):
        """Decrypts data using Fernet symmetric encryption."""
        encrypted_data = encrypted_data.encode()  # Convert to bytes
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        return decrypted_data.decode()  # Convert bytes to string
