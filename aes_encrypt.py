from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_ecb(key, mode, input_file):
    cipher = Cipher(algorithms.AES(key), mode)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(input_file) + padder.finalize()

    output_file = encryptor.update(padded_data) + encryptor.finalize()

    return output_file

def encrypt_cbc(key, input_file):
    
    IV = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(input_file) + padder.finalize()

    output_file = encryptor.update(padded_data) + encryptor.finalize()

    return IV + output_file

def encrypt_gcm(key, input_file):
    IV = b'\x00' * 12
    cipher = Cipher(algorithms.AES(key), modes.GCM(IV))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(input_file) + padder.finalize()

    output_file = encryptor.update(padded_data) + encryptor.finalize()
    tag = encryptor.tag

    return IV + output_file + tag

def main():
    key = input("Enter the key: ").encode('UTF-8')
    mode = modes.ECB()
    input_file = input("Enter the message to encrypt: ").encode('UTF-8')
    encryption_mode = input("choose encryption mode (ECB, CBC or GCM): ").strip().upper()

    if encryption_mode not in {"ECB", "CBC", "GCM"}:
        print("Invalid encryption mode. Please choose either ECB, CBC or GCM")
        return
    if encryption_mode == "ECB":
       output_file = encrypt_ecb(key, mode, input_file)
    elif encryption_mode == "CBC":
        output_file = encrypt_cbc(key, input_file)
    else:
        output_file = encrypt_gcm(key, input_file)

    
    print("The encrypted message is: ")
    print(output_file.hex())
if __name__ == "__main__":
    main()

  






