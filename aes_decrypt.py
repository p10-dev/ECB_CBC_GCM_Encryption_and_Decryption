from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_ecb(key, mode, input_file):
    cipher = Cipher(algorithms.AES(key), mode)
    decryptor = cipher.decryptor()

    output_file_decrypted = decryptor.update(input_file) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(output_file_decrypted) + unpadder.finalize()

    return unpadded_data
def decrypt_cbc(key, input_file):
    IV = input_file[:16]
    input_file = input_file[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()

    output_file_decrypted = decryptor.update(input_file) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(output_file_decrypted) + unpadder.finalize()

    return unpadded_data

def decrypt_gcm(key, input_file):
    IV = input_file[:12]
    input_file = input_file[12:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(IV), backend=default_backend())
    decryptor = cipher.decryptor()

    output_file_decrypted = decryptor.update(input_file) + decryptor.finalize_with_tag(input_file)

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(output_file_decrypted) + unpadder.finalize()

    return unpadded_data


def main():
    mode = modes.ECB()
    key = input("Enter the key here: ").encode('utf-8')
    input_file_hex = input("Enter the encrypted message: ")
    decryption_mode = input("Choose decryption mode (ECB or CBC or GCM): ").strip().upper()

    if decryption_mode == "ECB":
        try:
            input_file = bytes.fromhex(input_file_hex)

            output_file = decrypt_ecb(key, mode, input_file)
            print("Decrypted message: ")
            print(output_file.decode('utf-8'))
        except ValueError:
            print("Invalid hexadecimal input")
    elif decryption_mode == "CBC":
        try:
            input_file = bytes.fromhex(input_file_hex)

            output_file = decrypt_cbc(key, input_file)

            print("Decrypted message: ")
            print(output_file.decode('utf-8'))
        except ValueError:
         print("Invalid hexadecimal input")
    elif decryption_mode == "GCM":
        try:
            input_file = bytes.fromhex(input_file_hex)

            output_file = decrypt_gcm(key, input_file)
            print("Decrypted message: ")
            print(output_file.decode('utf-8'))
        except ValueError:
         print("Invalid hexadecimal input")
    else:
        print("Decryption mode not found")

if __name__ == "__main__":
    main()
    