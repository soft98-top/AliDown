import requests
import json
import os
import argparse
import time
import base64
import sys
import rsa

requests.packages.urllib3.disable_warnings()
# 程序运行时的banner
BANNER = r'''
 ___  ___  ___ _____ ___ ___ 
/ __|/ _ \| __|_   _/ _ ( _ )
\__ \ (_) | _|  | | \_, / _ \
|___/\___/|_|   |_|  /_/\___/
    alidown-mgt by Soft98    
       QQ群: 775916840
'''
# 程序版本
VERSION = '2.0'
# 程序作者
AUTHOR = 'Soft98'
# 链接配置
CONFIG = {
    'passwd': '',
    'code': '',
    'targets': [],
    'cur_target': ''
}
# 密钥
PUBLIC_KEY = None
# 代理
PROXY = None
# 目标
TARGET = 'http://127.0.0.1:5000'
# 获取程序所在目录
BASE_PATH = os.path.dirname(sys.executable) + '/'
## 判断如果是py文件运行，则获取py文件所在目录
if os.path.basename(sys.executable) in ['python.exe', 'python3.exe', 'python', 'python3']:
    BASE_PATH = os.path.dirname(os.path.abspath(__file__)) + '/'

# 退出输出
def exit_print(msg):
    msg = f'[*] {msg}\n[*] 如有疑问请添加QQ群:775916840'
    print(msg)
    os._exit(0)

# RSA加解密
class RSA:
    def __init__(self, key):
        self.key = key
    def encrypt(self, text):
        text = json.dumps(text)
        text = text.encode('utf-8')
        return base64.b64encode(rsa.encrypt(text, self.key))

def save_key(pubkey, is_remote=False):
    with open(BASE_PATH + 'public.pem', 'w+') as f:
        if is_remote:
            f.write(pubkey)
        else:
            f.write(pubkey.save_pkcs1().decode('utf-8'))
def load_key():
    global PUBLIC_KEY
    # 判断是否存在密钥文件
    if not os.path.exists('public.pem'):
        exit_print('请先获取公钥')
    with open(BASE_PATH + 'public.pem', 'r') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read().encode('utf-8'))
    PUBLIC_KEY = pubkey

# 请求数据
def post_data(func, data):
    retry = 0
    while True:
        try:
            req_data = {
                'func': func,
                'data': data,
            }
            enc_data = req_data
            if PUBLIC_KEY:
                enc_data = RSA(PUBLIC_KEY).encrypt(req_data)
            if PROXY:
                resp = requests.post(TARGET + '/config', data=enc_data, verify=False, timeout=100, proxies=PROXY)
            else:
                resp = requests.post(TARGET + '/config', data=enc_data, verify=False, timeout=100)
            if resp.status_code == 200:
                result = json.loads(resp.text)
                if result['code'] == '-1':
                    exit_print(result['data'])
                return_data = result['data']
                return return_data
            return None
        except Exception as ex:
            retry += 1
            if retry <= 3:
                print(f'[*] 请求服务器失败，正在重试...{retry}/3')
                time.sleep(1)
                continue
            else:
                exit_print('请求服务器失败，请检查网络或重试。')

def print_menu():
    print(f'''
[*] 当前目标: {TARGET}
[*] 1. 查看配置
[*] 2. 添加账户
[*] 3. 删除账户
[*] 4. 添加内测码
[*] 5. 删除内测码
[*] 6. 设置内测码状态（0允许，1禁止）
[*] 7. 设置密码
[*] 8. 更改MGT密码
[*] 0. 退出
''')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AliDown-MGT')
    parser.add_argument('-t', '--target', default=None ,help='设置目标地址')
    parser.add_argument('-p', '--proxy', help='设置代理地址')
    args = parser.parse_args()
    print(BANNER)
    if args.target:
        TARGET = args.target
    else:
        exit_print('请设置目标地址')
    if args.proxy:
        PROXY = {
            'http': args.proxy,
            'https': args.proxy
        }
    load_key()
    while True:
        ## 打印菜单menu
        print_menu()
        choice = input('[*] 请输入选项: ')
        result = ''
        if choice == '1':
            data = post_data('get_config', {})
            result = json.dumps(data, indent=4, ensure_ascii=False)
        elif choice == '2':
            refresh_token = input('[*] 请输入refresh_token: ')
            if refresh_token.find(',') > -1:
                refresh_token = refresh_token.split(',')
            if not isinstance(refresh_token, list):
                data = post_data('add_account', {"refresh_token": refresh_token})
            else:
                accounts = []
                for token in refresh_token:
                    accounts.append({"refresh_token": token})
                data = post_data('add_accounts', accounts)
            result = data
        elif choice == '3':
            index = input('[*] 请输入要删除的账户序号: ')
            data = post_data('del_account', {"index": index})
            result = data
        elif choice == '4':
            id = input('[*] 请输入内测码个人ID: ')
            data = post_data('add_code', {"id": id})
            result = data
        elif choice == '5':
            code = input('[*] 请输入要删除的内测码: ')
            data = post_data('del_code', {"code": code})
            result = data
        elif choice == '6':
            code = input('[*] 请输入要设置的内测码: ')
            status = input('[*] 请输入状态（0允许，1禁止）: ')
            if status not in ['0', '1']:
                exit_print('状态错误')
            data = post_data('set_code_status', {"code":code, "status": status})
            result = data
        elif choice == '7':
            passwd = input('[*] 请输入密码: ')
            data = post_data('set_passwd', {"passwd": passwd})
            result = data
        elif choice == '8':
            data = post_data('change_key', {})
            save_key(data,True)
            load_key()
            result = 'success'
        elif choice == '0':
            exit_print('退出成功')
        else:
            print('[*] 选项错误')
            continue
        print(f'\n[*] 返回结果: {result}')
        input('[*] 按回车键继续...')
        os.system('clear')



