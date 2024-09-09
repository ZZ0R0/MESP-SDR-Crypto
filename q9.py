import itertools
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import sqlite3
from tqdm import tqdm

# Encryption/Decryption Functions
def des_encrypt(key, plaintext):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return ct

def des_decrypt(key, ciphertext):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    unpadded_data = unpadder.update(pt) + unpadder.finalize()
    return unpadded_data

def is_ascii(s):
    """Check if all bytes in the string are within the ASCII range (0-127)"""
    return all(0 <= byte < 128 for byte in s)

def brute_force(ciphered, partial_key, num_octets, alphabet):
    missing_key_length = num_octets - len(partial_key)

    # Create an SQLite database to store the results
    conn = sqlite3.connect('bruteforce_results.db')
    c = conn.cursor()

    # Drop the table if it exists, ensuring it's emptied each time the script is run
    c.execute("DROP TABLE IF EXISTS results")
    
    # Dynamically create a table with fields char0...charN, IS_ASCII, and UNCIPHERED
    fields = ', '.join([f'char{i} TEXT' for i in range(missing_key_length)]) + ', IS_ASCII BOOLEAN, UNCIPHERED BLOB'
    c.execute(f"CREATE TABLE results ({fields})")
    
    # Generate all possible combinations for the missing key characters
    total_combinations = len(alphabet) ** missing_key_length
    with tqdm(total=total_combinations, desc="Brute Forcing", ncols=100) as pbar:
        for combo in itertools.product(alphabet, repeat=missing_key_length):
            key_guess = partial_key + ''.join(combo).encode('utf-8')
            
            try:
                # Try to decrypt with the current key guess
                decrypted_message = des_decrypt(key_guess, ciphered)
                
                # Check if all characters in the decrypted message are within the ASCII range
                ascii_check = is_ascii(decrypted_message)
                
                # Insert into database: combination of characters, the ASCII check, and the raw unciphered message
                values = ', '.join([f"'{char}'" for char in combo] + [str(int(ascii_check)), "?"])
                c.execute(f"INSERT INTO results VALUES ({values})", (decrypted_message,))
            
            except Exception as e:
                # If there's an error (likely wrong key), skip this combination
                pass
            
            # Update progress bar
            pbar.update(1)

    # Commit and close database connection
    conn.commit()
    conn.close()

# Sample usage

# Ciphered message and known part of the key
ciphered_message = b'\xd72U\xc03.\xda\x99Q\xb5\x020\xc4\xb8\x16\xc6\xfa-\xb9U+\xda\\\x126L\xf3~\xbd8\x12q\x02?\x80\xeaVI\xa9\xe1'
partial_key = b'12345678bien'
num_octets = 16  # Adjust this depending on the expected total key size

# Define the alphabet to use in brute-force
alphabet = string.ascii_lowercase + string.digits

# Call brute-force function
brute_force(ciphered_message, partial_key, num_octets, alphabet)
