import binascii
import gzip
import json
from typing import Dict
from Crypto.Cipher import AES
import base64


class BACryptor:
    def decrypt(self, raw: bytes, is_resp: bool = False) -> dict:
        try:
            raw = base64.b64decode(raw, validate=True)
        except binascii.Error:
            raw = raw
        if not is_resp:
            data = gzip.decompress(raw[4:])
        else:
            data = raw
        data_decrypted = self.aes_decrypt(data)
        return json.loads(data_decrypted.decode())

    @staticmethod
    def aes_decrypt(raw_data: bytes) -> bytes:
        def remove_padding(data: bytes) -> bytes:
            padding_size = data[-1]
            if data[-padding_size:] != bytes([padding_size]) * padding_size:
                return data
            return data[:-padding_size]

        key = raw_data[-32:]
        iv = b'JOSYdf8ys97uhFYS'
        return remove_padding(AES.new(key, AES.MODE_CBC, iv).decrypt(raw_data[:-32]))
