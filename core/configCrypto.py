# core/crypto.py

import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from typing import Any, Dict


def decrypt_base64_aes(ct_b64: str) -> Dict[str, Any]:
    key = b'X#9kL$mN2pQ!rS4tU@vW6xY*zB8cD0eF'
    iv = b'A!tL@s#I$v%2^0&2'
    ct = base64.b64decode(ct_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return json.loads(pt.decode('utf-8'))


def decrypt_base64_xor(ciphertext: str) -> Dict[str, Any]:
    decoded = base64.b64decode(ciphertext)
    decrypted_bytes = xor_decrypt(decoded, 'fujreibd157538ljgsawjn')
    return json.loads(decrypted_bytes.decode())


def xor_decrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    key_len = len(key_bytes)

    return bytes([
        b ^ key_bytes[i % key_len]
        for i, b in enumerate(data)
    ])
def base64_decode(b64: str) -> Dict[str, Any]:
    if "{" in b64:
        return json.loads(b64)
    else:
        decoded = base64.b64decode(b64)
        return json.loads(decoded.decode('utf-8'))

