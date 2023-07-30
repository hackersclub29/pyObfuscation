import base64
import hashlib
from cryptography.fernet import Fernet
import threading

# Function to generate a secure encryption key from a passphrase with salting
def generate_key(passphrase):
    salt = "S@lt!nG#f4Ke"  # You can choose any salt value you prefer
    salted_passphrase = salt + passphrase
    hashed_passphrase = hashlib.sha256(salted_passphrase.encode()).digest()
    return base64.urlsafe_b64encode(hashed_passphrase)

# Function for string encryption using Fernet encryption
def encrypt_string(s, key):
    fernet = Fernet(key)
    encrypted_str = fernet.encrypt(s.encode()).decode()
    return encrypted_str

# Function for string decryption using Fernet encryption
def decrypt_string(s, key):
    fernet = Fernet(key)
    decrypted_str = fernet.decrypt(s.encode()).decode()
    return decrypted_str

# Custom exception for handling timeouts
class TimeoutException(Exception):
    pass

# Function to get input with a timeout
def get_input_with_timeout(prompt, timeout):
    result = [None]

    def get_input():
        result[0] = input(prompt)

    input_thread = threading.Thread(target=get_input)
    input_thread.start()
    input_thread.join(timeout)

    if input_thread.is_alive():
        print("\nTimeout! Exiting the code.")
        raise TimeoutException()
    return result[0]

# Function to encrypt and obfuscate the file content with a given key
def obfuscate_file(file_path, key):
    try:
        with open(file_path, 'r') as file:
            original_code = file.read()

        encrypted_code = encrypt_string(original_code, key)

        with open(file_path, 'w') as file:
            file.write("# Obfuscated and encrypted Python code\n")
            file.write("import base64\n")
            file.write("from cryptography.fernet import Fernet\n")
            file.write(f"key = {repr(key)}\n")
            file.write(f"encrypted_code = {repr(encrypted_code)}\n")
            file.write("fernet = Fernet(key)\n")
            file.write("decrypted_code = fernet.decrypt(encrypted_code.encode()).decode()\n")
            file.write("exec(decrypted_code)\n")

        print("Obfuscation and encryption completed successfully.")
    except FileNotFoundError:
        print("Error: The specified file does not exist.")
    except PermissionError:
        print("Error: Permission denied. Unable to access the file.")
    except Exception as e:
        print(f"An error occurred: {e}")
        raise

if __name__ == "__main__":
    try:
        passphrase = get_input_with_timeout("Enter the passphrase for key generation (you have 1 minute): ", 60)
        key = generate_key(passphrase)

        file_path = get_input_with_timeout("Enter the path to your Python .py file (you have 1 minute): ", 60)
        obfuscate_file(file_path, key)

    except TimeoutException:
        print("Timeout! Exiting the code.")
    except KeyboardInterrupt:
        print("\nUser interrupted the program.")
    except Exception as e:
        print(f"An error occurred: {e}")
