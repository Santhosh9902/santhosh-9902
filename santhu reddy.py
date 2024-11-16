import os

def encrypt_message(key, message):
    iv = os.urandom(size/16)
    cipher = cipher(algorithms.AEs(key), modes.CBC(iv))
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encryptor =cipher.encryptor()
    ciphertext = encrptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, encrypted_message):
     iv = encrypted_message[:16]
     ciphertext = encrypted_message[16:]
     cipher = cipher(algorithms.AES(key), modes.CBC(iv))
     unpadder = padding.PKSC7(algorithms.AES.block_size).unpadder()
     decryptor = cipher.decrytor()
     decrypted_paddded_messade = decryptor.update(ciphertext) + decrytor.finalize()
     decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
     return decrypted_message.decode()

original_message = "santhu reddy"
print("original message is:",original_message)

encrypt_message = encrypt_message, message=original_message
print("encrypted message is:", encrypted_message)

decrypted_message = decrypted_message(key=key, encrypted_message=encrypted_message)
print("decrypted message is:", decrypted_message)