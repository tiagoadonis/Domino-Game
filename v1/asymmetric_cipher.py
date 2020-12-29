from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

class AsymmetricCipher:

    def __init__(self,key_size = 1024):

        self.key_size = key_size
        self.private_key = rsa.generate_private_key(65537, key_size, default_backend())
        self.public_key = self.private_key.public_key()
    
    def serializePublicKey(self):
        return self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    @staticmethod
    def loadPublicKey(k_bytes):
        return load_pem_public_key(k_bytes)

    @staticmethod
    def cipher(plaintext,pub_k):

        if type(plaintext) is not bytes:
            plaintext = bytes(plaintext, 'utf-8')

        #maxLength = (pub_k.key_size // 8) - 2 * hashes.SHA256.digest_size - 2

        ciphered_text = pub_k.encrypt(plaintext,padding.OAEP(padding.MGF1(hashes.SHA256()),hashes.SHA256(),None))

        return ciphered_text
    
    @staticmethod
    def decipher(ciphered_text,priv_k):

        deciphered_text = priv_k.decrypt(ciphered_text,padding.OAEP(padding.MGF1(hashes.SHA256()),hashes.SHA256(),None))

        return deciphered_text.decode('utf-8')

    @staticmethod
    def sign(plaintext,priv_k):

        if type(plaintext) is not bytes:
            plaintext = bytes(plaintext, 'utf-8')
        
        signature = priv_k.sign(plaintext,padding.PSS(padding.MGF1(hashes.SHA256()),padding.PSS.MAX_LENGTH),hashes.SHA256())

        return signature

    @staticmethod
    def validate_signature(signature,plaintext, pub_k):
        try:
            if type(plaintext) is not bytes:
                plaintext = bytes(plaintext, 'utf-8')
            
            pub_k.verify(signature, plaintext,padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())

            return True
        except InvalidSignature:
            return False
