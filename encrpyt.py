import base64
import hashlib


def encrypt(clear, key="Secret key"):
    enc = []
    for i, c in enumerate(clear):
        key_c = key[i % len(key)]
        enc_c = chr((ord(c) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def encrypt_password(password):
    password_bytes = password.encode('utf-8')
    encoded_bytes = base64.b64encode(password_bytes)
    return encoded_bytes.decode('utf-8')


def hash2(password):
    sha512_hash = hashlib.sha3_512(password.encode()).hexdigest()
    return sha512_hash


def hash0(password):
    sha256 = hashlib.sha3_256(password.encode()).hexdigest()
    return sha256


def hash1(password):
    sha384 = hashlib.sha3_384(password.encode()).hexdigest()
    return sha384

