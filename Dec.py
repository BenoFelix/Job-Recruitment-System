import base64


def decrypt(enc, key="Secret key"):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i, c in enumerate(enc):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(c) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
