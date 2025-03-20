#!/usr/bin/env python3
import base64
import hashlib
import logging
import os
import threading
import time
from cryptography.fernet import Fernet, InvalidToken
from getpass import getpass

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for key derivation
PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16  # 128-bit salt

def generate_salt() -> bytes:
    """
    Generates a cryptographically secure random salt.
    """
    salt = os.urandom(SALT_SIZE)
    logging.debug("Generated random salt.")
    return salt

def generate_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derives a secure encryption key from a passphrase using PBKDF2_HMAC.
    :param passphrase: The passphrase provided by the user.
    :param salt: A salt value (should be random and unique per encryption session).
    :return: A base64-encoded key suitable for Fernet.
    """
    # Derive a 32-byte key using PBKDF2 (sha256)
    derived_key = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, PBKDF2_ITERATIONS)
    key = base64.urlsafe_b64encode(derived_key)
    logging.debug("Derived encryption key using PBKDF2.")
    return key

def encrypt_string(plain_text: str, key: bytes) -> str:
    """
    Encrypts the plain_text string using the provided key with Fernet.
    :param plain_text: The string to encrypt.
    :param key: The encryption key.
    :return: The encrypted string.
    """
    fernet = Fernet(key)
    encrypted = fernet.encrypt(plain_text.encode())
    logging.debug("String encrypted successfully.")
    return encrypted.decode()

def decrypt_string(cipher_text: str, key: bytes) -> str:
    """
    Decrypts the cipher_text string using the provided key with Fernet.
    :param cipher_text: The encrypted string.
    :param key: The encryption key.
    :return: The decrypted string.
    """
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(cipher_text.encode())
        logging.debug("String decrypted successfully.")
        return decrypted.decode()
    except InvalidToken as e:
        logging.error("Invalid key or corrupted data.")
        raise e

class TimeoutException(Exception):
    """Custom exception raised when an input operation times out."""
    pass

def get_input_with_timeout(prompt: str, timeout: int) -> str:
    """
    Obtains input from the user with a timeout.
    :param prompt: The input prompt.
    :param timeout: Timeout in seconds.
    :return: The user input string.
    :raises TimeoutException: if the input is not received within the timeout period.
    """
    result = [None]

    def inner_input():
        # Use getpass for passphrase prompts to avoid echoing sensitive input.
        result[0] = getpass(prompt) if 'passphrase' in prompt.lower() else input(prompt)

    thread = threading.Thread(target=inner_input, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        logging.warning("Input timeout reached.")
        raise TimeoutException("Input timed out.")
    if result[0] is None:
        raise TimeoutException("No input received.")
    return result[0]

def obfuscate_file(file_path: str, passphrase: str) -> None:
    """
    Reads a Python file, encrypts its content, and writes an obfuscated version that 
    automatically decrypts and executes the original code.
    The output file includes the salt used for key derivation.
    :param file_path: Path to the original Python file.
    :param passphrase: The passphrase to derive the encryption key.
    """
    try:
        # Read original code securely
        with open(file_path, 'r', encoding='utf-8') as file:
            original_code = file.read()
        logging.info(f"Successfully read the file: {file_path}")

        # Generate random salt and derive key
        salt = generate_salt()
        key = generate_key(passphrase, salt)
        encrypted_code = encrypt_string(original_code, key)

        # Write the obfuscated file with a header that contains the salt and key info
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write("# Obfuscated and encrypted Python code\n")
            file.write("import base64\n")
            file.write("import hashlib\n")
            file.write("from cryptography.fernet import Fernet, InvalidToken\n")
            file.write("\n")
            # Store salt (encoded) along with encrypted content
            file.write(f"salt = {repr(base64.urlsafe_b64encode(salt).decode())}\n")
            file.write(f"encrypted_code = {repr(encrypted_code)}\n")
            file.write("\n")
            file.write("def derive_key(passphrase, salt_b64):\n")
            file.write("    salt = base64.urlsafe_b64decode(salt_b64.encode())\n")
            file.write("    derived = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000)\n")
            file.write("    return base64.urlsafe_b64encode(derived)\n")
            file.write("\n")
            file.write("try:\n")
            file.write("    # In a secure environment, retrieve the passphrase securely\n")
            file.write("    from getpass import getpass\n")
            file.write("    user_passphrase = getpass('Enter the passphrase to decrypt: ')\n")
            file.write("    key = derive_key(user_passphrase, salt)\n")
            file.write("    fernet = Fernet(key)\n")
            file.write("    decrypted_code = fernet.decrypt(encrypted_code.encode()).decode()\n")
            file.write("    exec(decrypted_code)\n")
            file.write("except InvalidToken:\n")
            file.write("    print('Decryption failed: Invalid passphrase or corrupted data.')\n")
        logging.info("File obfuscation and encryption completed successfully.")
    except FileNotFoundError:
        logging.error("The specified file does not exist.")
    except PermissionError:
        logging.error("Permission denied when accessing the file.")
    except Exception as e:
        logging.exception(f"An error occurred during obfuscation: {e}")
        raise

def main():
    """
    Main function to obtain user input and perform file obfuscation.
    """
    try:
        # Obtain passphrase securely with a timeout
        passphrase = get_input_with_timeout("Enter the passphrase for key generation (you have 60 seconds): ", 60)
        # Obtain file path from the user with a timeout
        file_path = get_input_with_timeout("Enter the path to your Python (.py) file (you have 60 seconds): ", 60)
        obfuscate_file(file_path, passphrase)
    except TimeoutException as te:
        logging.error(f"Timeout: {te}")
    except KeyboardInterrupt:
        logging.warning("User interrupted the program.")
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()

# ---------------------------
# Unit Test Scaffolding (Expand as needed)
# ---------------------------
if __name__ == "__main__" and os.environ.get("RUN_TESTS") == "1":
    import unittest

    class TestEncryptionFunctions(unittest.TestCase):
        def setUp(self):
            self.passphrase = "StrongPassphrase!"
            self.sample_text = "Sensitive data to encrypt"
            self.salt = generate_salt()
            self.key = generate_key(self.passphrase, self.salt)

        def test_encryption_decryption(self):
            encrypted = encrypt_string(self.sample_text, self.key)
            decrypted = decrypt_string(encrypted, self.key)
            self.assertEqual(self.sample_text, decrypted)

        def test_invalid_decryption(self):
            encrypted = encrypt_string(self.sample_text, self.key)
            with self.assertRaises(InvalidToken):
                # Alter the key to simulate wrong passphrase
                wrong_key = generate_key("WrongPassphrase", self.salt)
                decrypt_string(encrypted, wrong_key)

    unittest.main()
