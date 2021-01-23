
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SymmetricCipher:

    def __init__(self,password):
        self.password = password

        salt = b'\x00'
        kdf = PBKDF2HMAC( hashes.SHA1(), 16, salt, 1000, default_backend())
        self.key = kdf.derive(bytes(password,'UTF-8'))
    
    def cipher(self,plaintext,k):

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(k), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        if not isinstance(plaintext,bytes):
            plaintext = bytes(plaintext,"utf-8")

        padded = padder.update(plaintext) + padder.finalize()
        ciphered_text = encryptor.update(padded) + encryptor.finalize()

        return iv + ciphered_text

    def decipher(self,ciphered_text,k):

        iv = ciphered_text[:16]
        ciphered_text = ciphered_text[16:]

        cipher = Cipher(algorithms.AES(k), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        plaintext = decryptor.update(ciphered_text) + decryptor.finalize()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()

        return unpadded

    @staticmethod
    def s_decipher(ciphered_text,k):

        iv = ciphered_text[:16]
        ciphered_text = ciphered_text[16:]

        cipher = Cipher(algorithms.AES(k), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        plaintext = decryptor.update(ciphered_text) + decryptor.finalize()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()

        return unpadded