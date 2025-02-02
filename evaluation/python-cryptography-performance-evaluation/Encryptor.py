import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES128,AES256
from cryptography.hazmat.primitives.ciphers.modes import CBC

from Timeable import Timeable

class Encryptor(Timeable):
    def __init__(self, identifier):
        self.identifier = identifier

    def encrypt(self, data):
        raise NotImplementedError()

    def decrypt(self, data):
        raise NotImplementedError()

    def encryptTimed(self, data):
        time = self.executeTimed(lambda: self.encrypt(data))
        output = self.encrypt(data)
        return (time, output)

    def decryptTimed(self, data):
        time = self.executeTimed(lambda: self.decrypt(data))
        output = self.decrypt(data)
        return (time, output)

class RSA2048_SHA256_OAEP(Encryptor):
    def __init__(self):
        super().__init__("RSA2048_SHA256_OAEP")
        # Initialize keys
        self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.publicKey = self.privateKey.public_key()

        # Initialize hash algorithm & padding
        self.hash = hashes.SHA256()
        self.padding = padding.OAEP(mgf=padding.MGF1(algorithm=self.hash), algorithm=self.hash, label=None)
        

    def encrypt(self, data):
        return self.publicKey.encrypt(data, self.padding)

    def decrypt(self, data):
        return self.privateKey.decrypt(data, self.padding)

class RSA4096_SHA512_OAEP(Encryptor):
    def __init__(self):
        super().__init__("RSA4096_SHA512_OAEP")
        # Initialize keys
        self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.publicKey = self.privateKey.public_key()

        # Initialize hash algorithm & padding
        self.hash = hashes.SHA512()
        self.padding = padding.OAEP(mgf=padding.MGF1(algorithm=self.hash), algorithm=self.hash, label=None)

    def encrypt(self, data):
        return self.publicKey.encrypt(data, self.padding)

    def decrypt(self, data):
        return self.privateKey.decrypt(data, self.padding)

class AES128_CBC(Encryptor):
    def __init__(self):
        super().__init__("AES128_CBC")
        # Initialize cipher with key & vector
        key = os.urandom(16)
        vector = os.urandom(16)
        self.cipher = Cipher(AES128(key), CBC(vector))

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

class AES256_CBC(Encryptor):
    def __init__(self):
        super().__init__("AES256_CBC")
        # Initialize cipher with key & vector
        key = os.urandom(32)
        vector = os.urandom(16)
        self.cipher = Cipher(AES256(key), CBC(vector))

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

class AES128_GCM(Encryptor):
    def __init__(self):
        super().__init__("AES128_GCM")
        # Initialize cipher with key & vector
        key = AESGCM.generate_key(bit_length=128)
        self.cipher = AESGCM(key)
        self.nonce = os.urandom(12)

    def encrypt(self, data):
        return self.cipher.encrypt(self.nonce, data, None)

    def decrypt(self, data):
        return self.cipher.decrypt(self.nonce, data, None)

class AES256_GCM(Encryptor):
    def __init__(self):
        super().__init__("AES256_GCM")
        # Initialize cipher with key & vector
        key = AESGCM.generate_key(bit_length=256)
        self.cipher = AESGCM(key)
        self.nonce = os.urandom(12)

    def encrypt(self, data):
        return self.cipher.encrypt(self.nonce, data, None)

    def decrypt(self, data):
        return self.cipher.decrypt(self.nonce, data, None)
