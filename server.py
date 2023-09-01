#encoding=utf-8
from flask import Flask,request
from Crypto.Cipher import AES
import base64
import requests
import json
from threading import Timer,Lock,Thread
import random
import string
import time
import hashlib
import os
## 导入uuid
import uuid
import ecdsa
import logging
import traceback
import sqlite3
import re
import rsa
import argparse
requests.packages.urllib3.disable_warnings()
app = Flask(__name__)

# 配置日志，保存到文件，文件名为当前时间
logging.basicConfig(filename=time.strftime('alidown-%Y-%m-%d',time.localtime(time.time()))+'.log',level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s',datefmt='%Y-%m-%d %H:%M:%S %p')
## 配置日志，输出到控制台
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s',datefmt='%Y-%m-%d %H:%M:%S %p')
console.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(console)
# sqlite3数据库文件名
DB_NAME = "secret/alidown.db"
# 数据库表名
TABLE_NAME = "files"
# 任务表名
TASK_TABLE_NAME = "tasks"
# 下载链接表名
LINK_TABLE_NAME = "links"
# 数据库锁
DB_LOCK = Lock()
# 数据库任务表锁
TASK_LOCK = Lock()
# 数据库下载链接表锁
LINK_LOCK = Lock()
# 队列锁
QUEUE_LOCK = Lock()
# 切换账户锁
ACCOUNT_LOCK = Lock()
# 内测码锁
CODE_LOCK = Lock()
# 通用间隔时间，单位秒，用于延迟
INTERVAL = 1
# 通用重试次数
RETRY_TIME = 5
# task数据库缓存时间
TASK_CACHE_TIME = 21600
# 下载链接数据库缓存时间
LINK_CACHE_TIME = 500
# 文件信息数据库缓存时间
FILE_CACHE_TIME = 3600
# 私钥
PRIVATE_KEY = ""
CONFIG_PATH = "secret/config.json"
# 配置信息
CONFIG = {
    "accounts":[
        {
            "refresh_token":"",
        }
    ],
    "passwd":"alidown",
    "code":{},
    "url": "",
}
# 当前账户索引
CUR_ACCOUNT_INDEX = 0
ENC_KEY = ""
ECC_PRIS = []
BETA_USER_RETURN_COUNT = 3
# 当前服务器版本
CURRENT_VERSION = "2.0"
# 最低支持的客户端版本
MIN_VERSION = "2.0"

# 从数据库中通过file_id获取子文件列表，分页查询
def get_files_from_db_by_folder(file_id, page=1,page_size=100, all=False):
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # 查询数据
        if all:
            c.execute(f"SELECT * FROM {TABLE_NAME} WHERE parent_file_id=? ORDER BY update_time DESC", (file_id,))
        else:
            c.execute(f"SELECT * FROM {TABLE_NAME} WHERE parent_file_id=? ORDER BY update_time DESC LIMIT ? OFFSET ?", (file_id, page_size, (page - 1) * page_size))
        rows = c.fetchall()
        files = []
        if rows:
            for row in rows:
                file = {}
                for i in range(len(c.description)):
                    file[c.description[i][0]] = row[i]
                # logger.info(f'file_info: {file}, type: {type(file)}')
                update_time = file.get("update_time","")
                if update_time != "" and update_time != None:
                    # logger.info("update_time: " + update_time)
                    if time.time() - time.mktime(time.strptime(update_time, '%Y-%m-%d %H:%M:%S')) > TASK_CACHE_TIME:
                        continue
                files.append(file)
        else:
            return None
        return files
    except Exception as e:
        logger.info("Failed to get file ex: " + str(e))
        logger.info("Failed to get file: " + file_id)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()
    return []

def get_file_info_from_db(share_id,file_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # 查询数据
        c.execute(f"SELECT * FROM {TABLE_NAME} WHERE share_id=? AND file_id=?", (share_id,file_id))
        row = c.fetchone()
        if row:
            file = {}
            for i in range(len(c.description)):
                file[c.description[i][0]] = row[i]
            update_time = file.get("update_time","")
            if update_time != "" and update_time != None:
                if time.time() - time.mktime(time.strptime(file["update_time"], '%Y-%m-%d %H:%M:%S')) > FILE_CACHE_TIME:
                    return None
            return file
        else:
            return None
    except Exception as e:
        logger.info("Failed to get file ex: " + str(e))
        logger.info("Failed to get file: " + file_id)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()
    return None

# 从数据库中通过task_id获取任务
def get_task_from_db(task_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # 查询数据
        c.execute(f"SELECT * FROM {TASK_TABLE_NAME} WHERE task_id=?", (task_id,))
        row = c.fetchone()
        if row:
            task = {}
            for i in range(len(c.description)):
                task[c.description[i][0]] = row[i]
            return task
        else:
            return None
    except Exception as e:
        logger.info("Failed to get task ex: " + str(e))
        logger.info("Failed to get task: " + task_id)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()
    return None

# 从数据库中通过file_id获取task_id,如果不存在则返回None
def get_task_id_from_db(file_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # 查询数据，status为success或者running的任务,根据update_time降序排列
        c.execute(f"SELECT task_id,update_time FROM {TASK_TABLE_NAME} WHERE file_id=? AND (status='success' OR status='running') ORDER BY update_time DESC", (file_id,))
        row = c.fetchone()
        if row:
            # 判断链接是否过期，过期则返回None
            if time.time() - time.mktime(time.strptime(row[1], '%Y-%m-%d %H:%M:%S')) > TASK_CACHE_TIME:
                return None
            return row[0]
        else:
            return None
    except Exception as e:
        logger.info("Failed to get task ex: " + str(e))
        logger.info("Failed to get task: " + file_id)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()
# 数据库更新插入或更新任务表状态
def update_task_status(task_id, file_id, status, info, lock):
    conn = None
    try:
        lock.acquire()
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # 检查任务表是否存在
        c.execute(f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{TASK_TABLE_NAME}'")
        table_exists = c.fetchone()[0] == 1
        if not table_exists:
            # 创建任务表
            c.execute(f"CREATE TABLE {TASK_TABLE_NAME} (task_id TEXT PRIMARY KEY, status TEXT, file_id TEXT, info TEXT, create_time TEXT, update_time TEXT)")
        # 查询数据
        c.execute(f"SELECT * FROM {TASK_TABLE_NAME} WHERE task_id=?", (task_id,))
        row = c.fetchone()
        if row:
            # 更新数据
            # 判断状态是否相等，相等则不更新
            if row[1] != status:
                c.execute(f"UPDATE {TASK_TABLE_NAME} SET status=?,info=?,update_time=? WHERE task_id=?", (status, info, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())), task_id))
        else:
            # 插入数据
            c.execute(f"INSERT INTO {TASK_TABLE_NAME} VALUES (?,?,?,?,?,?)", (task_id, status, file_id, info, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())), time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))))
        conn.commit()
    except Exception as e:
        logger.info("Failed to update task ex: " + str(e))
        logger.info("Failed to update task: " + task_id)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()
        lock.release()

# 数据库更新插入或更新链接表
def update_link_to_db(file_id, link, lock):
    conn = None
    try:
        lock.acquire()
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # 检查链接表是否存在
        c.execute(f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{LINK_TABLE_NAME}'")
        table_exists = c.fetchone()[0] == 1
        if not table_exists:
            # 创建链接表
            c.execute(f"CREATE TABLE {LINK_TABLE_NAME} (file_id TEXT PRIMARY KEY, link TEXT, create_time TEXT, update_time TEXT)")
        # 查询数据
        c.execute(f"SELECT * FROM {LINK_TABLE_NAME} WHERE file_id=?", (file_id,))
        row = c.fetchone()
        if row:
            # 更新数据
            # 判断链接是否相等，相等则不更新
            if row[1] != link:
                c.execute(f"UPDATE {LINK_TABLE_NAME} SET link=?,update_time=? WHERE file_id=?", (link, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())), file_id))
        else:
            # 插入数据
            c.execute(f"INSERT INTO {LINK_TABLE_NAME} VALUES (?,?,?,?)", (file_id, link, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())), time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))))
        conn.commit()
    except Exception as e:
        logger.info("Failed to update link ex: " + str(e))
        logger.info("Failed to update link: " + file_id)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()
        lock.release()

# 根据file_id获取链接
def get_link_from_db(file_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # 查询link和更新时间
        c.execute(f"SELECT link,update_time FROM {LINK_TABLE_NAME} WHERE file_id=?", (file_id,))
        row = c.fetchone()
        if row:
            # 判断链接是否过期，过期则返回None
            if time.time() - time.mktime(time.strptime(row[1], '%Y-%m-%d %H:%M:%S')) > LINK_CACHE_TIME:
                return None
            return row[0]
        else:
            return None
    except Exception as e:
        logger.info("Failed to get link ex: " + str(e))
        logger.info("Failed to get link: " + file_id)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()
    return None

# 将文件数据存储到SQLite数据库中
def save_file_to_db(file,lock):
    conn = None
    # 获取线程锁，确保同一时间只有一个线程在操作数据库
    lock.acquire()
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # 检查表是否存在
        c.execute(f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{TABLE_NAME}'")
        table_exists = c.fetchone()[0] == 1
        if not table_exists:
            # 动态创建tasks表,file_id为主键,字符串类型
            create_table_sql = f"CREATE TABLE {TABLE_NAME} (file_id TEXT PRIMARY KEY"
            for field_name in file.keys():
                if field_name != "file_id":
                    create_table_sql += f", {field_name} TEXT"
            create_table_sql += ")"
            c.execute(create_table_sql)
            logger.info("Create table: " + create_table_sql)
        # 插入或更新数据
        insert_sql = f"INSERT OR REPLACE INTO {TABLE_NAME} (file_id"
        values = [file["file_id"]]
        for field_name in file.keys():
            if field_name != "file_id":
                insert_sql += f", {field_name}"
                value = file[field_name]
                if isinstance(value, list) or isinstance(value, dict):
                    file[field_name] = json.dumps(value)
                if isinstance(value, int):
                    file[field_name] = str(value)
                values.append(file[field_name])
        insert_sql += ") VALUES (" + ",".join(["?" for _ in values]) + ")"
        try:
            c.execute(insert_sql, tuple(values))
        except sqlite3.OperationalError as e:
            exception = e
            retry = 0
            while retry < 10:
                # 检查异常信息是否是由于缺少某个列而导致的
                missing_column = re.search(r"no column named (\w+)", str(exception))
                if missing_column:
                    try:
                        # 如果缺少列，则动态添加该列
                        column_name = missing_column.group(1)
                        logger.info("Add column: " + column_name)
                        c.execute(f"ALTER TABLE {TABLE_NAME} ADD COLUMN {column_name} TEXT")
                        conn.commit()
                        # 重新执行插入操作
                        c.execute(insert_sql, tuple(values))
                        break
                    except sqlite3.OperationalError as e:
                        exception = e
                        # 如果还是报错，则继续循环，直到插入成功
                        retry += 1
                        continue
                else:
                    logger.info("Failed to insert task ex: " + str(exception))
                    logger.info("Failed to insert task: " + str(file))
                    traceback.print_exc()
                break
    except Exception as e:
        logger.info("Failed to insert task ex: " + str(e))
        logger.info("Failed to insert task: " + str(file))
        traceback.print_exc()
    finally:
        if conn:
            conn.commit()
            conn.close()
        lock.release()
# 将文件数据存储到SQLite数据库中
def save_files_to_db(files,lock):
    for file in files:
        file["update_time"] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        save_file_to_db(file,lock)
## Ebcrypt类，用于加密解密
## Crypto需要使用 `pip3 install pycryptodome` 安装
class Encrypt:
    def __init__(self, key, iv):
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')
    # @staticmethod
    def pkcs7padding(self, text):
        """
        明文使用PKCS7填充
        """
        bs = 16
        length = len(text)
        bytes_length = len(text.encode('utf-8'))
        padding_size = length if (bytes_length == length) else bytes_length
        padding = bs - padding_size % bs
        padding_text = chr(padding) * padding
        self.coding = chr(padding)
        return text + padding_text
    def aes_encrypt(self, content):
        """
        AES加密
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        # 处理明文
        content_padding = self.pkcs7padding(content)
        # 加密
        encrypt_bytes = cipher.encrypt(content_padding.encode('utf-8'))
        # 重新编码
        result = str(base64.b64encode(encrypt_bytes), encoding='utf-8')
        return result
    def aes_decrypt(self, content):
        """                
        AES解密
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        content = base64.b64decode(content)
        text = cipher.decrypt(content).decode('utf-8')
        return text.rstrip(self.coding)
# RSA加解密
class RSA:
    def __init__(self, key):
        self.key = key
    def decrypt(self, text):
        text = base64.b64decode(text)
        return rsa.decrypt(text, self.key).decode('utf-8')

def gen_key():
    (pubkey, privkey) = rsa.newkeys(2048)
    return pubkey, privkey
def save_key(pubkey, privkey):
    with open('private.pem', 'w+') as f:
        f.write(privkey.save_pkcs1().decode('utf-8'))
    with open('public.pem', 'w+') as f:
        f.write(pubkey.save_pkcs1().decode('utf-8'))
def load_key():
    global PRIVATE_KEY
    # 判断是否存在密钥文件
    if not os.path.exists('private.pem'):
        pubkey, privkey = gen_key()
        save_key(pubkey, privkey)
    with open( 'private.pem', 'r') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read().encode('utf-8'))
    PRIVATE_KEY = privkey

def print_exit(msg):
    logger.info(msg)
    os._exit(0)

# 读取配置文件
def load_config():
    global CONFIG,ENC_KEY,CONFIG_PATH
    # 判断文件是否存在
    if not os.path.exists(CONFIG_PATH):
        # 创建目录和文件
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH,'w',encoding='utf-8') as f:
            f.write(json.dumps(CONFIG,indent=4,ensure_ascii=False))
        print_exit("配置文件不存在, 已生成默认配置文件，请修改配置文件后重启程序")
    with open(CONFIG_PATH,'r',encoding='utf-8') as f:
        CONFIG = json.loads(f.read())
    if CONFIG.get("url","") == "":
        print_exit("请先配置URL信息")
    if CONFIG.get("accounts","") == "":
        print_exit("请先配置账号信息")
    if CONFIG['accounts'][0].get("refresh_token","") == "":
        print_exit("账号信息必须包含refresh_token")
    if CONFIG.get("passwd","") == "":
        CONFIG["passwd"] = "alidown"
    if CONFIG.get("code","") == "":
        CONFIG["code"] = {}
    h = hashlib.sha256()
    h.update(CONFIG["passwd"].encode("utf-8"))
    sha = h.hexdigest()
    ENC_KEY = sha[:4] + sha[8:12] + sha[16:20] + sha[24:28] + sha[32:36] + sha[40:44] + sha[48:52] + sha[56:60]

# 保存配置文件
def save_config():
    global CONFIG,CONFIG_PATH
    save_config = {}
    save_config["accounts"] = []
    save_config["passwd"] = CONFIG["passwd"]
    save_config["code"] = CONFIG["code"]
    save_config["url"] = CONFIG["url"]
    for account in CONFIG["accounts"]:
        save_config["accounts"].append({
            "refresh_token":account["refresh_token"],
            "user_id":account.get("user_id",""),
            "is_normal":account.get("is_normal",1),
        })
    with open(CONFIG_PATH,'w',encoding='utf-8') as f:
        f.write(json.dumps(save_config,indent=4,ensure_ascii=False))

# 刷新token
def refresh_token():
    global CONFIG
    index = 0
    try:
        for index in range(len(CONFIG["accounts"])):
            refresh_token_by_index(index)
        save_config()
    except Exception as ex:
        logger.info(ex)
        logger.info(f"刷新第{index+1}个账号失败，请检查refresh_token是否正确")

def refresh_token_by_index(index,single=False):
    global CONFIG
    try:
        refresh_token = CONFIG["accounts"][index]["refresh_token"]
        post_data = {
            "refresh_token":refresh_token
        }
        response = requests.post("https://api.aliyundrive.com/token/refresh",json=post_data,verify=False)
        json_result = json.loads(response.text)
        refresh_token = json_result["refresh_token"]
        access_token = json_result["access_token"]
        drive_id = json_result["default_drive_id"]
        userId = json_result["user_id"]
        appId = json_result["device_id"]
        CONFIG["accounts"][index]["refresh_token"] = refresh_token
        CONFIG["accounts"][index]["access_token"] = access_token
        CONFIG["accounts"][index]["drive_id"] = drive_id
        CONFIG["accounts"][index]["user_id"] = userId
        CONFIG["accounts"][index]["app_id"] = appId
        CONFIG["accounts"][index]["is_normal"] = 0
        if single:
            save_config()
    except Exception as ex:
        CONFIG["accounts"][index]["is_normal"] = 1
        logger.info(ex)
        logger.info(f"刷新第{index+1}个账号失败，请检查网络或配置文件")
        return False
    return True
# 初始化签名
def init_sign_config():
    global CONFIG
    index = 0
    try:
        for index in range(len(CONFIG["accounts"])):
            init_sign_config_by_index(index)
    except Exception as ex:
        logger.info(ex)
        print_exit(f"初始化签名第{index+1}个账号失败")
# 初始化指定账号签名
def init_sign_config_by_index(index):
    global CONFIG,ECC_PRIS
    try:
        if CONFIG["accounts"][index].get("app_id","") == "":
            CONFIG["accounts"][index]["app_id"] = "5dde4e1bdf9e4966b387ba58f4b3fdc3"
        CONFIG["accounts"][index]["device_id"] = str(uuid.uuid1())
        CONFIG["accounts"][index]["private_key"] = random.randint(1, 2**256-1)
        ECC_PRIS.append(ecdsa.SigningKey.from_secret_exponent(CONFIG["accounts"][index]["private_key"], curve=ecdsa.SECP256k1))
        CONFIG["accounts"][index]["ecc_pub"] = ECC_PRIS[index].get_verifying_key()
        CONFIG["accounts"][index]["public_key"] = "04"+CONFIG["accounts"][index]["ecc_pub"].to_string().hex()
        CONFIG["accounts"][index]["nonce"] = 0
    except Exception as ex:
        logger.info(ex)
        print_exit(f"初始化签名第{index+1}个账号失败")
# 签名预处理
def sign_handle(appId: str, deviceId: str, userId: str, nonce: int) -> str:
    return f"{appId}:{deviceId}:{userId}:{nonce}"
# 生成签名
def gen_sign(index) -> str:
    global CONFIG,ECC_PRIS
    account = CONFIG["accounts"][index]
    sign_dat = ECC_PRIS[index].sign(sign_handle(account["app_id"], account["device_id"], account["user_id"], account["nonce"]).encode('utf-8'), entropy=None,
                            hashfunc=hashlib.sha256)
    account["nonce"] += 1
    CONFIG["accounts"][index] = account
    return sign_dat.hex()+"01"
# 获取签名
def get_sign(index):
    global CONFIG
    try:
        headers = {
            "authorization": "Bearer {0}".format(CONFIG["accounts"][index]["access_token"]),
            "origin": "https://www.aliyundrive.com",
            "referer": "https://www.aliyundrive.com/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.41",
            "x-canary": "client=web,app=adrive,version=v3.17.0",
            "x-device-id": CONFIG["accounts"][index]["device_id"],
        }
        sign = gen_sign(index)
        headers["x-signature"] = sign
        if CONFIG["accounts"][index]["nonce"] == 1:
            resp = requests.post(
                "https://api.aliyundrive.com/users/v1/users/device/create_session",json={
                    "deviceName": "Edge浏览器",
                    "modelName": "Windows网页版",
                    "pubKey": CONFIG["accounts"][index]["public_key"],
                },headers=headers)
            logger.info(f"创建session,返回结果：{resp.text}")
        else:
            resp = requests.post("https://api.aliyundrive.com/users/v1/users/device/renew_session",json={},headers=headers)
            logger.info(f"刷新session,返回结果：{resp.text}")
        return sign
    except Exception as ex:
        logger.info(ex)
        logger.info("获取签名失败")

def check_code(data):
    global CONFIG,CODE_LOCK
    CODE_LOCK.acquire()
    try:
        code = data.get('code','')
        if code != '':
            code_obj = CONFIG["code"].get(code,None)
            if code_obj != None:
                if code_obj.get("status",1) == 0:
                    code_obj["last_use_time"] = time.time()
                    code_obj["use_count"] = code_obj.get("use_count",0) + 1
                    CONFIG["code"][code] = code_obj
                    return True
            return False
        else:
            return False
    except Exception as ex:
        logger.info(ex)
        return False
    finally:
        CODE_LOCK.release()
## 分享链接类，处理分享链接文件的方法
class ShareLink:
    headers={}
    share_id = ""
    share_pwd = ""
    account_index = 0
    share_token = None
    ## Init
    def __init__(self,share_id,share_pwd):
        self.share_id = share_id
        self.share_pwd = share_pwd
        self.switch_account()
    def switch_account(self):
        global CONFIG,CUR_ACCOUNT_INDEX,ACCOUNT_LOCK
        ACCOUNT_LOCK.acquire()
        retry = 0
        while True:
            CUR_ACCOUNT_INDEX = (CUR_ACCOUNT_INDEX + 1) % len(CONFIG["accounts"])
            if CONFIG["accounts"][CUR_ACCOUNT_INDEX]["is_normal"] == 0:
                break
            retry += 1
            if retry >= len(CONFIG["accounts"]):
                CUR_ACCOUNT_INDEX = 0
                break
        self.account_index = CUR_ACCOUNT_INDEX
        self.share_token = self.get_share_token()
        ACCOUNT_LOCK.release()
        logger.info(f"切换账号到{self.account_index}")
    def get_headers(self):
        global CONFIG
        headers = self.headers
        headers["Authorization"] = "Bearer {0}".format(CONFIG["accounts"][self.account_index]["access_token"])
        headers["X-Share-Token"] = self.share_token
        headers["x-device-id"] = CONFIG["accounts"][self.account_index]["device_id"]
        headers["x-signature"] = get_sign(self.account_index)
        return headers
    ## 获取share_token
    def get_share_token(self):
        global RETRY_TIME,INTERVAL
        json_data = {
            "share_id":self.share_id,
            "share_pwd":self.share_pwd
        }
        retry = 0
        while retry < RETRY_TIME:
            try:
                response = requests.post("https://api.aliyundrive.com/v2/share_link/get_share_token",json=json_data,headers=self.get_headers(),verify=False)
                json_result = json.loads(response.text)
                logger.info(f'获取share_token成功，{response.text}')
                return json_result["share_token"]
            except Exception as ex:
                logger.info(f'获取share_token失败，{ex}')
                pass
            retry += 1
            time.sleep(INTERVAL)
            if retry == RETRY_TIME:
                logger.info("获取share_token失败")
                traceback.print_exc()
            continue
        return None
    ## 获取file_id信息
    def get_file_info(self,file_id):
        global DB_LOCK,RETRY_TIME,INTERVAL
        json_data = {
            "share_id":self.share_id,
            "file_id":file_id,
            "fields":"*",
            "image_thumbnail_process":"image/resize,w_400/format,jpeg",
            "image_url_process":"image/resize,w_375/format,jpeg",
            "video_thumbnail_process":"video/snapshot,t_1000,f_jpg,ar_auto,w_375"
        }
        retry = 0
        while retry < RETRY_TIME:
            try:
                response = requests.post("https://api.aliyundrive.com/adrive/v2/file/get_by_share",json=json_data,headers=self.get_headers(),verify=False)
                json_result = json.loads(response.text)
                if json_result.get("file_id",None) != None:
                    if json_result.get("share_id","") == "":
                        json_result["share_id"] = self.share_id
                    json_result["update_time"] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
                    Thread(target=save_file_to_db,args=(json_result,DB_LOCK,)).start()
                    return json_result
                if json_result.get("code",None) != None:
                    refresh_token_by_index(self.account_index,single=True)
            except Exception as ex:
                pass
            retry += 1
            time.sleep(INTERVAL)
            if retry == RETRY_TIME:
                logger.info("获取file_id信息失败")
                traceback.print_exc()
            continue
        return None
    # 从数据库中获取file_id信息
    def get_file_info_from_db(self,file_id):
        file_info = get_file_info_from_db(self.share_id,file_id)
        if file_info == None:
            file_info = self.get_file_info(file_id)
        return file_info
    ## 获取文件夹列表
    def get_list_of_folder(self,file_id,task_id=None):
        global DB_LOCK,RETRY_TIME,INTERVAL
        json_data = {
            "share_id":self.share_id,
            "parent_file_id":file_id,
            "limit":100,
            "marker":"",
            "image_thumbnail_process":"image/resize,w_160/format,jpeg",
            "image_url_process":"image/resize,w_1920/format,jpeg",
            "video_thumbnail_process":"video/snapshot,t_1000,f_jpg,ar_auto,w_300",
            "order_by":"name",
            "order_direction":"DESC"
        }
        result = []
        retry = 0
        while retry < RETRY_TIME:
            try:
                response = requests.post("https://api.aliyundrive.com/adrive/v3/file/list",json=json_data,headers=self.get_headers(),verify=False)
                json_result = json.loads(response.text)
                # logger.info(f'获取文件夹列表：{response.text}')
                if json_result.get("items",None) == None:
                    retry += 1
                    time.sleep(INTERVAL)
                    self.switch_account()
                    if retry == RETRY_TIME:
                        if task_id:
                            update_task_status(task_id,file_id,"failed",json_result,TASK_LOCK)
                        logger.info("获取文件夹列表失败")
                    continue
                result = result + json_result["items"]
                if(json_result["next_marker"] != "" and task_id != None):
                    json_data["marker"] = json_result["next_marker"]
                    retry = 0
                else:
                    break
            except Exception as ex:
                if task_id:
                    update_task_status(task_id,file_id,"failed",str(ex),TASK_LOCK)
                return result
        # logger.info(f'获取文件夹列表成功，共{len(result)}个文件, {result}')
        thread = Thread(target=save_files_to_db,args=(result,DB_LOCK,))
        thread.start()
        if task_id:
            ## 等待线程结束
            thread.join()
            update_task_status(task_id,file_id,"success",'',TASK_LOCK)
        return result
    
    ## 线程任务，获取文件夹列表
    def get_list_of_folder_task(self,file_id):
        global TASK_LOCK
        task_id = get_task_id_from_db(file_id)
        try:
            if task_id:
                return task_id
            task_id = str(uuid.uuid1())
            update_task_status(task_id,file_id,"running",'',TASK_LOCK)
            Thread(target=self.get_list_of_folder,args=(file_id,task_id,)).start()
            return task_id
        except Exception as ex:
            logger.info("线程任务，获取文件夹列表失败")
            traceback.print_exc()
    
    ## 通过task_id判断任务状态，如果任务完成，返回文件列表
    def get_list_of_folder_by_task_id(self,task_id):
        global TASK_LOCK
        task_info = get_task_from_db(task_id)
        if task_info == None:
            return None
        if task_info["status"] == "success":
            files = get_files_from_db_by_folder(task_info["file_id"],all=True)
            if files == None or len(files) == 0:
                update_task_status(task_id,task_info["file_id"],"failed","获取文件列表失败",TASK_LOCK)
                return None
            return files
        return 'wait'

    ## 获取下载地址
    def get_download_url(self,file_id):
        global RETRY_TIME,INTERVAL,DB_LOCK
        json_data = {
            "share_id":self.share_id,
            "file_id":file_id,
            "expire_sec":600
        }
        retry = 0
        while retry < RETRY_TIME:
            try:
                response = requests.post("https://api.aliyundrive.com/v2/file/get_share_link_download_url",json=json_data,headers=self.get_headers(),verify=False)
                json_result = json.loads(response.text)
                # logger.info(json_result)
                file_url = ""
                if json_result.get("download_url",None) != None:
                    file_url = json_result["download_url"]
                if json_result.get("url",None) != None:
                    file_url = json_result["url"]
                if file_url != "":
                    update_link_to_db(file_id,file_url,DB_LOCK)
                return file_url
            except:
                retry += 1
                time.sleep(INTERVAL)
                if retry == RETRY_TIME:
                    logger.info("获取下载地址失败")
                    traceback.print_exc()
                continue
    
    ## 从数据库中获取文件下载地址
    def get_download_url_from_db(self,file_id):
        global QUEUE_LOCK,CUR_ACCOUNT_INDEX,CONFIG
        QUEUE_LOCK.acquire()
        time.sleep(0.1)
        link = get_link_from_db(file_id)
        if link == None:
            thread = Thread(target=self.get_download_url,args=(file_id,))
            thread.start()
            thread.join()
            link = get_link_from_db(file_id)
        QUEUE_LOCK.release()
        return link
    # 分享链接搜索内容
    def search(self,query):
        global DB_LOCK,RETRY_TIME,INTERVAL
        json_data = {
            "share_id":self.share_id,
            "image_thumbnail_process":"image/resize,w_160/format,jpeg",
            "image_url_process":"image/resize,w_1920/format,jpeg",
            "limit":100,
            "marker":"",
            "order_by":"name",
            "order_direction":"DESC",
            "keyword":query,
            "video_thumbnail_process":"video/snapshot,t_1000,f_jpg,ar_auto,w_300"
        }
        # result = []
        # retry = 0
        # while retry < RETRY_TIME:
        response = requests.post("https://api.aliyundrive.com/recommend/v1/shareLink/search",json=json_data,headers=self.get_headers(),verify=False)
        json_result = json.loads(response.text)
        if json_result.get("items",None) != None:
            return json_result["items"]
        return json_result
        # return result

## 文件类，个人网盘文件操作方法
class File:
    account_index = 0
    access_token = ""
    drive_id = ""
    def __init__(self,account_index=0):
        global CONFIG
        self.account_index = account_index
        self.access_token = CONFIG["accounts"][self.account_index]["access_token"]
        self.drive_id = CONFIG["accounts"][self.account_index]["drive_id"]
    def get_headers(self):
        global CONFIG
        headers = {
            "Authorization":"Bearer {0}".format(self.access_token),
            "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/95.0.1020.40",
            "Content-Type":"application/json",
            "Referer":"https://www.aliyundrive.com/",
            "X-Canary":"client=web,app=adrive,version=v4.3.1",
            "x-device-id": CONFIG["accounts"][self.account_index]["device_id"],
            "x-signature": get_sign(self.account_index)
        }
        return headers
    ## 云盘文件搜索
    def search(self,query):
        global RETRY_TIME,INTERVAL
        headers = self.get_headers()
        json_data = {
            "drive_id": self.drive_id,
            "limit": 100,
            "query": query,
            "image_thumbnail_process": "image/resize,w_200/format,jpeg",
            "image_url_process": "image/resize,w_1920/format,jpeg",
            "video_thumbnail_process": "video/snapshot,t_0,f_jpg,ar_auto,w_300",
            "order_by": "updated_at DESC"
        }
        # print(headers)
        response = requests.post("https://api.aliyundrive.com/adrive/v3/file/search",json=json_data,headers=headers,verify=False)
        # print(response.status_code)
        if(response.status_code == 200):
            json_result = json.loads(response.text)
            items = json_result["items"]
            files = []
            for i in items:
                if(i["type"] == "folder"):
                    continue
                file = {
                    "name":i["name"],
                    "type":i["type"],
                    "category":i["category"],
                    "file_extension":i["file_extension"],
                    "mime_type":i["mime_type"],
                    "size":i["size"]
                }
                if i.get("download_url",None) != None:
                    file["download_url"] = i["download_url"]
                else:
                    file["download_url"] = i.get("url",None)
                files.append(file)
            return files
        else:
            return None
    ## 搜索全部文件
    def search_all(self,keyword):
        query = "name match \"{0}\"".format(keyword)
        return self.search(query)
    ## 搜索图片
    def search_image(self,keyword):
        query = "name match \"{0}\" and category = \"image\"".format(keyword)
        return self.search(query)
    ## 搜索视频
    def search_video(self,keyword):
        query = "name match \"{0}\" and category = \"video\"".format(keyword)
        return self.search(query)
    ## 搜索文件夹
    def search_folder(self,keyword):
        query = "name match \"{0}\" and category = \"folder\"".format(keyword)
        return self.search(query)
    ## 搜索文档
    def search_doc(self,keyword):
        query = "name match \"{0}\" and category = \"doc\"".format(keyword)
        return self.search(query)
    ## 搜索音频
    def search_audio(self,keyword):
        query = "name match \"{0}\" and category = \"audio\"".format(keyword)
        return self.search(query)

class Resp:
    code = 0
    data = ""
    def __init__(self,code = 0,data = ""):
        self.code = code
        self.data = data
    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
    def to_dict(self):
        return {
            "code":self.code,
            "data":self.data
        }
    def set_code(self,code):
        self.code = code
    def set_data(self,data):
        self.data = data
## 检查版本
def check_ver(return_data, enc_data):
    global CURRENT_VERSION, MIN_VERSION
    client_ver = float(enc_data["ver"])
    server_ver = float(CURRENT_VERSION)
    min_ver = float(MIN_VERSION)
    if (client_ver < min_ver or client_ver > server_ver):
        return_data.set_code('-1')
        return_data.set_data(f"服务端版本：{server_ver}，兼容最小版本：{min_ver}，当前客户端版本：{client_ver}，请更新客户端！")
    elif client_ver < server_ver:
        return_data.set_data(f"服务端版本：{server_ver}，当前客户端版本：{client_ver}，存在新客户端，如有需要请升级！")
    else:
        return_data.set_data(f"服务端版本：{server_ver}，当前客户端版本：{client_ver}，版本正常！")
    return return_data

def file_search(return_data:Resp, enc_data,f:File) -> Resp:
    s_type = enc_data["type"]
    s_keyword = enc_data["keyword"]
    result = ""
    if s_type == "image":
        result = f.search_image(s_keyword)
    elif s_type == "doc":
        result = f.search_doc(s_keyword)
    elif s_type == "video":
        result = f.search_video(s_keyword)
    elif s_type == "folder":
        result = f.search_folder(s_keyword)
    elif s_type == "audio":
        result = f.search_audio(s_keyword)
    else:
        result = f.search_all(s_keyword)
    return_data.set_data(result)
    return return_data

# 配置信息
@app.route("/info",methods=["GET"])
def info():
    global CONFIG,CURRENT_VERSION,MIN_VERSION
    logger.info("获取配置信息")
    return_data = Resp()
    info = {
        "version":CURRENT_VERSION,
        "min_version":MIN_VERSION,
        "config":{
            "pwd":"",
            "url":CONFIG["url"],
            "code":""
        }
    }
    return_data.set_data(info)
    return return_data.to_dict()

## 接收数据相关操作接口
@app.route("/data",methods=["POST"])
def data():
    global CONFIG,ENC_KEY
    json_data = request.get_json()
    modul = json_data.get("modul",json_data.get("model",""))
    enc_data = json_data["data"]
    return_data = Resp()
    if CONFIG["passwd"] != "":
        try:
            # print(ENC_KEY)
            e = Encrypt(key=ENC_KEY[16:],iv=ENC_KEY[:16])
            e.coding = json_data["coding"]
            enc_data = json.loads(e.aes_decrypt(enc_data))
        except Exception as ex:
            logger.info("解密失败！")
            traceback.print_exc()
            return_data.set_code('-1')
            return_data.set_data("密码错误！")
            return return_data.to_dict()
    else:
        enc_data = json.loads(enc_data)
    try:
        logger.info("接收到数据：" + str(enc_data))
        is_beta = check_code(enc_data)
        if modul == "check":
            func = enc_data["func"]
            if func == "ver":
                return_data = check_ver(return_data,enc_data)
                return return_data.to_dict()
        # if modul == "file":
        #     f = File()
        #     func = enc_data["func"]
        #     if func == "search":
        #         if is_beta:
        #             result = file_search(return_data,enc_data,f)
        #             return_data.set_data(result)
        #             return return_data.to_dict()
        #         else:
        #             return_data.set_code('-1')
        #             result = "内测功能，没有配置内测码或内测码无效！"
        if modul == "slink":
            sid = enc_data["sid"]
            spwd = enc_data["spwd"]
            sl = ShareLink(sid,spwd)
            func = enc_data["func"]
            fid = enc_data["fid"]
            result = ""
            if func == "get_file_info":  
                result = sl.get_file_info_from_db(fid)
            if func == "get_download_url":
                result = sl.get_download_url_from_db(fid)
                # logger.info("从数据库获取下载链接：" + str(result))
            if func == "get_list_of_folder":
                if fid == "root":
                    result = json.dumps(sl.get_list_of_folder(fid))
                else:
                    return_data.set_code('-1')
                    result = "参数错误，请更新客户端！"
            if func == "get_list_of_folder_task":
                if True:
                    result = sl.get_list_of_folder_task(fid)
                else:
                    return_data.set_code('-1')
                    result = "内测功能，没有配置内测码或内测码无效！"
            if func == "get_list_of_folder_by_task_id":
                if True:
                    task_id = enc_data.get("task_id",None)
                    if task_id is None:
                        return_data.set_code('-1')
                        result = "task_id不能为空！"
                    else:
                        files_data = sl.get_list_of_folder_by_task_id(task_id)
                        if files_data is None:
                            return_data.set_code('-1')
                            result = "task_id无效或任务出现异常，请重新获取！"
                        else:
                            result = files_data
                else:
                    return_data.set_code('-1')
                    result = "内测功能，没有配置内测码或内测码无效！"
            # if func == "get_download_url_by_accounts":
            #     result = []
            #     return_user_count = 1
            #     total_count = len(CONFIG["accounts"])
            #     if is_beta:
            #         return_user_count = total_count if BETA_USER_RETURN_COUNT > total_count else BETA_USER_RETURN_COUNT
            #     # 随机取return_user_count个用户的索引
            #     indexs = random.sample(range(0,total_count),return_user_count)
            #     for i in indexs:
            #         sl = ShareLink(sid,spwd,i)
            #         download_url = sl.get_download_url(fid)
            #         if download_url != "":
            #             result.append(download_url)
            #     if len(result) == 0:
            #         result = ""
            if func == "search":
                if is_beta:
                    result = sl.search(enc_data["keyword"])
                else:
                    return_data.set_code('-1')
                    result = "内测功能，没有配置内测码或内测码无效！"
            return_data.set_data(result)
            return return_data.to_dict()
        return_data.set_code('-1')
        return_data.set_data("无效调用！")
    except Exception as ex:
        logger.info("调用错误：" + str(ex))
        # 打印异常调用栈
        traceback.print_exc()
        return_data.set_code('-1')
        return_data.set_data("服务器发生错误！")
    return return_data.to_dict()

## mgt接口
@app.route("/config",methods=["POST"])
def config():
    global CONFIG,QUEUE_LOCK,CONFIG_PATH
    return_data = Resp()
    result = ''
    try:
        # 请求体数据是rsa加密的内容，不是json，获取之后先解密
        # 获取请求的请求体原始内容
        enc_data = request.get_data()
        # 解密
        e = RSA(PRIVATE_KEY)
        data = e.decrypt(enc_data)
        # 转换成json
        json_data = json.loads(data)
        logger.info("mgt请求：" + str(json_data))
        if json_data["func"] == "get_config":
            save_config()
            config_json = None
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                config_json = json.load(f)
            result = config_json
        if json_data["func"] == "add_account":
            account = json_data["data"]
            if account.get("refresh_token",None) is None:
                return_data.set_code('-1')
                result = "refresh_token不能为空！"
            else:
                account = {
                    "refresh_token":account["refresh_token"]
                }
                QUEUE_LOCK.acquire()
                try:
                    CONFIG["accounts"].append(account)
                    account_index = len(CONFIG["accounts"])-1
                    if refresh_token_by_index(account_index,True):
                        init_sign_config_by_index(account_index)
                        result = "success"
                    else:
                        result = "refresh_token无效！"
                except Exception as ex:
                    logger.info("添加账号错误：" + str(ex))
                    result = "添加账号错误！"
                finally:
                    QUEUE_LOCK.release()
        if json_data["func"] == "add_accounts":
            accounts = json_data["data"]
            if len(accounts) == 0:
                return_data.set_code('-1')
                result = "accounts不能为空！"
            else:
                for account in accounts:
                    if account.get("refresh_token",None) is None:
                        return_data.set_code('-1')
                        result = "refresh_token不能为空！"
                        break
                    else:
                        account = {
                            "refresh_token":account["refresh_token"]
                        }
                        QUEUE_LOCK.acquire()
                        try:
                            CONFIG["accounts"].append(account)
                            account_index = len(CONFIG["accounts"])-1
                            if refresh_token_by_index(account_index,True):
                                init_sign_config_by_index(account_index)
                                result += f"{account_index}: success\n"
                            else:
                                result = f"{account_index}: refresh_token无效\n"
                        except Exception as ex:
                            logger.info("添加账号错误：" + str(ex))
                            result = "添加账号错误！"
                            break
                        finally:
                            QUEUE_LOCK.release()
                        time.sleep(0.5)
        if json_data["func"] == "del_account":
            index = json_data["data"].get("index",None)
            if index is None:
                return_data.set_code('-1')
                result = "index不能为空！"
            else:
                index = int(index)
                if index < 0 or index >= len(CONFIG["accounts"]):
                    return_data.set_code('-1')
                    result = "index无效！"
                CONFIG["accounts"].pop(index)
                save_config()
                result = "success"
        if json_data["func"] == "add_code":
            id = json_data["data"].get("id",None)
            if id is None:
                return_data.set_code('-1')
                result = "id不能为空"
            else:
                # 判断id是否重复
                is_repeat = False
                for code in CONFIG["code"].values():
                    if code.get("id","") == id:
                        is_repeat = True
                        break
                if is_repeat:
                    return_data.set_code('-1')
                    result = "id重复"
                else:
                    # 判断是否重复
                    while True:
                        # 随机生成一个内测码，长度为10，由数字和字母组成，字母区分大小写
                        code = ''.join(random.sample(string.ascii_letters + string.digits, 10))
                        if CONFIG["code"].get(code,None) is None:
                            break
                    CONFIG["code"][code] = {
                        "id":id,
                        "create_time":time.time(),
                        "last_use_time":time.time(),
                        "use_count":0,
                        "status":0,
                        "lmit":0
                    }
                    save_config()
                    result = code
        if json_data["func"] == "del_code":
            code = json_data["data"].get("code",None)
            if code is None:
                return_data.set_code('-1')
                result = "code不能为空"
            else:
                for code_key in CONFIG["code"].keys():
                    if code_key == code:
                        CONFIG["code"].pop(code)
                        save_config()
                        result = "success"
                        break
                else:
                    return_data.set_code('-1')
                    result = "code不存在"
        if json_data["func"] == "set_code_status":
            code = json_data["data"].get("code",None)
            status = json_data["data"].get("status",None)
            if code is None:
                return_data.set_code('-1')
                result = "code不能为空"
            elif status is None:
                return_data.set_code('-1')
                result = "status不能为空"
            else:
                for code_key in CONFIG["code"].keys():
                    if code_key == code:
                        CONFIG["code"][code]["status"] = int(status)
                        save_config()
                        result = CONFIG["code"][code]
                        break
                else:
                    return_data.set_code('-1')
                    result = "code不存在"
        if json_data["func"] == "set_passwd":
            passwd = json_data["data"].get("passwd",None)
            if passwd is None:
                return_data.set_code('-1')
                result = "passwd不能为空"
            else:
                CONFIG["passwd"] = passwd
                save_config()
                result = "success"
        if json_data["func"] == "change_key":
            pubkey, privkey = gen_key()
            result = pubkey.save_pkcs1().decode('utf-8')
            save_key(pubkey, privkey)
            load_key()
    except Exception as ex:
        logger.info("调用错误：" + str(ex))
        # 打印异常调用栈
        traceback.print_exc()
        return_data.set_code('-1')
        return_data.set_data("服务器发生错误！")
    return_data.set_data(result)
    return return_data.to_dict()

# 执行任务
class Cron:
    def refresh_token(self,loop=True):
        refresh_token()
        if loop:
            Timer(7000, Cron().refresh_token).start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # 增加说明
    parser.description = 'AliDown-Server'
    # 服务设置
    server_group = parser.add_argument_group('server')
    server_group.add_argument('--port', type=int, default=5000, help='服务监听端口，默认 5000')
    server_group.add_argument('--host', type=str, default='127.0.0.1', help='服务监听地址，默认 127.0.0.1')
    # 调试设置
    debug_group = parser.add_argument_group('debug')
    debug_group.add_argument('--debug', type=bool, default=False, help='是否开启 debug 模式，默认 False')
    # 服务配置
    config_group = parser.add_argument_group('config')
    config_group.add_argument('--config', type=str, default='', help='配置文件路径，默认 secret/config.json')
    config_group.add_argument('--db', type=str, default='', help='数据库文件路径，默认 secret/alidown.db')
    # 解析参数
    args = parser.parse_args()
    # 加在参数
    if args.config != '':
        CONFIG_PATH = args.config
    if args.db != '':
        DB_NAME= args.db
    load_config()
    Cron().refresh_token()
    init_sign_config()
    save_config()
    load_key()
    # 启动服务
    app.run(host=args.host, port=args.port, debug=args.debug)