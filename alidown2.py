import requests
import json
from threading import Timer
import os
import argparse
import re
import time
import hashlib
from Crypto.Cipher import AES
import base64
import sys
import threading
import logging
import copy
requests.packages.urllib3.disable_warnings()
# 程序版本
VERSION = '2.0'
# 程序作者
AUTHOR = 'Soft98'
# 程序运行时的banner
BANNER = rf'''
 ___  ___  ___ _____ ___ ___ 
/ __|/ _ \| __|_   _/ _ ( _ )
\__ \ (_) | _|  | | \_, / _ \
|___/\___/|_|   |_|  /_/\___/
    AliDown {VERSION} By {AUTHOR}    
       QQ群: 775916840
'''
# 链接配置
CONFIG = {
    'passwd': '',
    'code': '',
    'targets': [],
    'cur_target': ''
}
# 密钥
ENC_KEY = None
# 是否开启调试模式
DEBUG = False
# 日志
LOGGER = logging.getLogger(__name__)
# 获取程序所在目录
BASE_PATH = os.path.dirname(sys.executable) + '/'
## 判断如果是py文件运行，则获取py文件所在目录
if os.path.basename(sys.executable) in ['python.exe', 'python3.exe', 'python', 'python3']:
    BASE_PATH = os.path.dirname(os.path.abspath(__file__)) + '/'
# 下载目录
DOWNLOAD_PATH = BASE_PATH + 'Downloads/'
CHUNK_SIZE = 1024
DOWNLOAD_CHUNK_SIZE = 1024 * 200
MAX_DOWNLOAD_ERROR = 20
MAX_DOWNLOAD_THREAD = 20
RETRY_COUNT = 5
TIME_OUT = 10
SELECT_FLAG = False
PROXY = None

# AES加解密类
class Encrypt:
    # 初始化
    def __init__(self, key, iv):
        self.key = key.encode('utf-8')
        self.iv = iv.encode('utf-8')
    # 明文使用PKCS7填充
    def pkcs7padding(self, text):
        bs = 16
        length = len(text)
        bytes_length = len(text.encode('utf-8'))
        padding_size = length if bytes_length == length else bytes_length
        padding = bs - padding_size % bs
        padding_text = chr(padding) * padding
        self.coding = chr(padding)
        return text + padding_text
    # AES加密
    def aes_encrypt(self, content):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        content_padding = self.pkcs7padding(content)
        encrypt_bytes = cipher.encrypt(content_padding.encode('utf-8'))
        result = str((base64.b64encode(encrypt_bytes)), encoding='utf-8')
        return result
    # AES解密
    def aes_decrypt(self, content):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        content = base64.b64decode(content)
        text = cipher.decrypt(content).decode('utf-8')
        return text.rstrip(self.coding)
###########################配置相关###########################
# 调试输出
def debug_print(msg, ex=None):
    if DEBUG:
        out_str = f'[*] {msg}'
        if ex:
            try:
                out_str = ','.join([out_str, f'ex: {str(ex)}', f'line: {sys.exc_info()[2].tb_lineno}'])
            except Exception as ex:
                out_str = ','.join([out_str, f'ex: {str(ex)}'])
            # import traceback
            # # 调试输出错误，和错误代码行
            # traceback.print_exc()
        LOGGER.info(out_str)
# 退出输出
def exit_print(msg):
    msg = f'[*] {msg}\n[*] 如有疑问请添加QQ群:775916840'
    print(msg)
    os._exit(0)
# 加载配置
def load_config():
    global CONFIG, ENC_KEY
    config_path = BASE_PATH + 'config.json'
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as (cfile):
                json_data = json.load(cfile)
            CONFIG['passwd'] = json_data['passwd']
            CONFIG['targets'] = json_data['targets']
            CONFIG['cur_target'] = json_data['cur_target']
            CONFIG['code'] = json_data.get('code', '')
            h = hashlib.sha256()
            h.update(CONFIG['passwd'].encode('utf-8'))
            sha = h.hexdigest()
            ENC_KEY = sha[:4] + sha[8:12] + sha[16:20] + sha[24:28] + sha[32:36] + sha[40:44] + sha[48:52] + sha[56:60]
        except Exception as ex:
            # 调试输出错误，和错误代码行
            debug_print('load_config error', ex)
            exit_print('配置文件格式错误，请修改。')
    else:
        save_config()
        exit_print('配置文件不存在，已生成配置文件，请进行编写配置。')
# 保存配置
def save_config():
    global CONFIG
    config_path = BASE_PATH + 'config.json'
    try:
        with open(config_path, 'w', encoding='utf-8') as (cfile):
            json.dump(CONFIG, cfile, indent=4)
    except Exception as ex:
        debug_print('save_config error', ex)
        exit_print('配置文件保存失败，请检查是否有权限。')
# 打印配置
def print_config():
    global CONFIG
    exit_print('当前配置如下:\n' + json.dumps(CONFIG, indent=4))
# 检查配置
def check_config():
    global CONFIG
    index = 0
    while CONFIG['cur_target'] == '':
        if index >= len(CONFIG['targets']):
            exit_print('没有可用的目标，请检查配置文件。')
        switch_target(index, False)
        index += 1
# 远程获取配置
def get_target_info(target):
    url = target + '/info'
    debug_print(f'get_target_info url: {url}')
    if PROXY:
        resp = requests.get(url, proxies=PROXY)
    else:
        resp = requests.get(url)
    debug_print(f'get_target_info resp: {resp.text}')
    if resp.status_code == 200:
        json_data = json.loads(resp.text)
        if int(json_data['code']) == -1:
            exit_print(json_data['data'])
        return json_data['data']
    else:
        exit_print('获取配置失败，请检查目标是否可用。')

# 设置远程配置
def set_target_info(target, pwd=None, code=None):
    info = get_target_info(target)
    if info:
        config_info = info.get('config', None)
        if config_info:
            if pwd:
                config_info['pwd'] = pwd
            if code:
                config_info['code'] = code
            index = -1
            for i in range(len(CONFIG['targets'])):
                if CONFIG['targets'][i]['url'] == config_info['url']:
                    CONFIG['targets'][i] = config_info
                    index = i
            if index == -1:
                CONFIG['targets'].append(config_info)
                index = len(CONFIG['targets']) - 1
            switch_target(index)

# 切换目标
def switch_target(index, show=True):
    global CONFIG
    if index >= 0 and index < len(CONFIG['targets']):
        target = CONFIG['targets'][index]
        CONFIG['cur_target'] = target.get('url', '')
        CONFIG['code'] = target.get('code', '')
        CONFIG['passwd'] = target.get('pwd', '')
        save_config()
        if show:
            print_config()
    else:
        exit_print('切换失败，没有这个目标')

###########################操作相关##########################
# 请求数据
def post_data(model, data):
    retry = 0
    while True:
        try:
            data['code'] = CONFIG['code']
            data = json.dumps(data)
            req_data = {
                'model': model,
                'coding': None,
                'data' : data
            }
            debug_print(f'req: {model}||{data}')
            if ENC_KEY:
                encrypt = Encrypt(key=ENC_KEY[16:], iv=ENC_KEY[:16])
                req_data['data'] = encrypt.aes_encrypt(data)
                req_data['coding'] = encrypt.coding
            if PROXY:
                resp = requests.post(CONFIG['cur_target'] + '/data', json=req_data, verify=False, timeout=100, proxies=PROXY)
            else:
                resp = requests.post(CONFIG['cur_target'] + '/data', json=req_data, verify=False, timeout=100)
            if resp.status_code == 200:
                result = json.loads(resp.text)
                if result['code'] == '-1':
                    exit_print(result['data'])
                debug_print(f'res: {model}||{result}')
                return_data = result['data']
                debug_print(f'res_data: {type(return_data)}||{return_data}')
                return return_data
            return None
        except Exception as ex:
            retry += 1
            if retry <= 3:
                print(f'[*] 请求服务器失败，正在重试...{retry}/3')
                debug_print(f'post_data error, retry {retry}', ex)
                time.sleep(1)
                continue
            else:
                debug_print('post_data error', ex)
                exit_print('请求服务器失败，请检查网络或重试。')

def check_version():
    req_data = {
        'func': 'ver',
        'ver': VERSION
    }
    result = post_data('check', req_data)
    if result:
        print(f'[*] {result}')

def select_object(data:list):
    if len(data) == 0:
        return []
    print('[*] 请选择目标序号(输入0退出):')
    for i in range(len(data)):
        print(f'[{i + 1}] [{data[i]["type"]}] {data[i]["name"]} {data[i]["file_id"]}')
    while True:
        index = input(f'请输入目标序号(1-{len(data)}), 多选用(,)隔开:')
        if index == '0':
            return []
        if index.find('all') != -1:
            return data
        indexs = index.split(',')
        try:
            indexs = [int(i) - 1 for i in indexs]
            if max(indexs) >= len(data) or min(indexs) < 0:
                exit_print('输入下标错误。')
            indexs = [data[i] for i in indexs]
            return indexs
        except Exception as ex:
            debug_print('select_object error', ex)
        return []

###########################Model###########################
class AliFile:
    sid = ''
    fid = ''
    spwd = None
    name = ''
    size = 0
    type = ''
    sub_files = []
    download_size = 0
    error_indexs = {}
    max_done_index = 0
    threads = []
    start_time = time.time()
    end_time = time.time()
    last_time = 0
    last_download_size = 0
    # 初始化
    def __init__(self, sid, fid, spwd=None):
        self.sid = sid
        self.fid = fid
        self.spwd = spwd
    # 设置信息
    def set_info(self, info):
        self.name = info['name']
        size = info.get('size', 0)
        if size is None:
            size = 0
        self.size = int(size)
        self.type = info['type']
    # 获取信息
    def get_info(self):
        req_data = {
            'func':'get_file_info',
            'sid':self.sid,
            'fid':self.fid,
            'spwd':self.spwd
        }
        result = post_data('slink', req_data)
        if result:
            self.set_info(result)
            return True
        return False
    def process_info(self):
        # 显示下载进度，进度条
        download_size = self.download_size
        self.end_time = time.time()
        end_time = self.end_time
        percent = download_size / self.size
        percent_num = int(percent * 100)
        num_arrow = int(percent * 50)
        num_line = 50 - num_arrow
        out_str = '\r' + '[下载进度]:[' + '>' * num_arrow + '-' * num_line + ']' + f' {percent_num:.2f}' + '%' + f' {download_size}/{self.size}'
        if self.last_download_size != 0:
            # 下载速度
            start_time = self.last_time if self.last_time != 0 else self.start_time
            down_time = end_time - start_time
            if down_time > 1 or download_size >= self.size:
                time_size = (download_size - self.last_download_size) / down_time
                time_kb_size = time_size / 1024
                time_kb_size = time_kb_size if time_kb_size > 0 else 0
                time_mb_size = time_kb_size / 1024
                time_mb_size = time_mb_size if time_mb_size > 0 else 0
                time_gb_size = time_mb_size / 1024
                time_gb_size = time_gb_size if time_gb_size > 0 else 0
                if time_gb_size > 1:
                    speed = f'{time_gb_size:.2f}GB/s'
                elif time_mb_size > 1:
                    speed = f'{time_mb_size:.2f}MB/s'
                elif time_kb_size > 1:
                    speed = f'{time_kb_size:.2f}KB/s'
                else:
                    speed = f'{time_size:.2f}B/s'
                out_str += f' {speed}'
                self.last_time = end_time
                out_str += f' {self.end_time - self.start_time:.2f}s'
                print(out_str, end='', flush=True)
        else:
            self.last_time = end_time
        self.last_download_size = download_size
    # 枚举文件夹
    def list_folder(self,select_flag=False):
        # req_data = {
        #     'func':'get_list_of_folder',
        #     'sid':self.sid,
        #     'fid':self.fid,
        #     'spwd':self.spwd
        # }
        # result = post_data('slink', req_data)
        # if result:
        #     if type(result) == str:
        #         result = json.loads(result)
        #     return result
        # return False
        if self.fid == 'root':
            req_data = {
                'func':'get_list_of_folder',
                'sid':self.sid,
                'fid':self.fid,
                'spwd':self.spwd
            }
            result = post_data('slink', req_data)
            if result:
                if type(result) == str:
                    result = json.loads(result)
                if select_flag:
                    result = select_object(result)
                return result
            return False
        else:
            step1_req = {
                'func':'get_list_of_folder_task',
                'sid':self.sid,
                'fid':self.fid,
                'spwd':self.spwd
            }
            step1_result = post_data('slink', step1_req)
            if step1_result:
                while True:
                    step2_req = {
                        'func':'get_list_of_folder_by_task_id',
                        'sid':self.sid,
                        'fid':self.fid,
                        'spwd':self.spwd,
                        'task_id':step1_result
                    }
                    step2_result = post_data('slink', step2_req)
                    if step2_result == 'wait':
                        time.sleep(1)
                        continue
                    if select_flag and step2_result:
                        step2_result = select_object(step2_result)
                    return step2_result
            return False
    def query_file(self, keyword):
        try:
            req_data = {
                'func':'search',
                'keyword':keyword,
                'sid':sid,
                'fid':fid,
                'spwd':spwd
            }
            result = post_data('slink', req_data)
            if result:
                result = select_object(result)
            return result
        except Exception as ex:
            debug_print('query_slink_file error', ex)
            exit_print('文件搜索失败，请检查网络或配置。')

    # 获取下载地址
    def get_download_url(self):
        req_data = {
            'func':'get_download_url_by_accounts',
            'sid':self.sid,
            'fid':self.fid,
            'spwd':self.spwd
        }
        result = post_data('slink', req_data)
        if result:
            return result
        return None
    # 获取下载记录
    def check_download_record(self,filepath):
        global MAX_DOWNLOAD_THREAD
        # 列举文件夹下所有已下载的分段文件
        file_dir = os.path.dirname(filepath)
        part_indexs = []
        if os.path.exists(file_dir):
            for file in os.listdir(file_dir):
                # 判断是否为分段文件,.part1 .part2
                if file.startswith(os.path.basename(filepath) + '.part'):
                    # 获取分段文件序号
                    part_index = int(file.split('.')[-1].replace('part',''))
                    part_indexs.append(part_index)
        # 获取已下载的分段文件序号，从小到大排序
        part_indexs.sort()
        # 遍历已下载的分段文件，中间有缺失加入到错误列表，最后一个分段文件序号为最大已下载序号，中断序号相差2倍线程最大数，停止遍历
        error_indexs = []
        max_index = 0
        pre_index = -1
        count_index = 0
        for i in part_indexs:
            if i - pre_index > 1:
                middle_indexs = list(range(pre_index + 1,i))
                if len(middle_indexs) > 2*MAX_DOWNLOAD_THREAD:
                    break
                error_indexs += middle_indexs
            pre_index = i
            max_index = i
            count_index += 1
        download_size = count_index * DOWNLOAD_CHUNK_SIZE
        self.download_size = download_size
        download_error = {}
        for error_index in error_indexs:
            download_error[str(error_index)] = 1
        self.error_indexs = download_error
        self.max_done_index = max_index
    # 下载分片
    def download_chunk(self, filepath, download_url, start, end, index):
        global DOWNLOAD_CHUNK_SIZE, CHUNK_SIZE
        donwload_index = 0
        current_url = download_url
        url_number = 1
        if type(download_url) == list:
            current_url = download_url[0]
            url_number = len(download_url)
        headers = {
            'Referer':'https://www.aliyundrive.com/',
            'Range':f'bytes={start}-{end}'
        }
        if start > end:
            return None
        # debug_print(f'下载分片{index} {start}-{end}')
        chunk_size = min(CHUNK_SIZE, end - start + 1, DOWNLOAD_CHUNK_SIZE)
        response = None
        # 如果存在分片文件，跳过
        if os.path.exists(filepath + f'.part{index}'):
            self.download_size += os.path.getsize(filepath + f'.part{index}')
            self.process_info()
            return None
        try:
            while donwload_index < url_number:
                try:
                    response = requests.get(current_url, headers=headers, verify=False, stream=True, timeout=TIME_OUT)
                except Exception as ex:
                    debug_print("download_chunk error1", ex)
                    response = None
                if response == None or response.status_code not in [200, 206]:
                    donwload_index += 1
                    if donwload_index >= url_number:
                        debug_print(f"下载分片{index}失败")
                        self.error_indexs[str(index)] = self.error_indexs.get(str(index), 0) + 1
                        return None
                    current_url = download_url[donwload_index]
                    debug_print(f"下载分片{index}失败，响应：{response}，切换下载地址{donwload_index}")
                    continue
                if response == None:
                    return None
                write_size = 0
                try:
                    # debug_print(f"下载分片{index}，响应：{response}")
                    # debug_print(f"chunk_size:{chunk_size}")
                    with open(filepath + f'.part{index}', 'wb') as file:
                        for data in response.iter_content(chunk_size=chunk_size):
                            # debug_print(f"下载分片{index}，写入数据{data.__len__()}")
                            file.write(data)
                            self.download_size += chunk_size
                            write_size += chunk_size
                    if self.error_indexs.get(str(index), 0) != 0:
                        self.error_indexs.pop(str(index))
                    self.max_done_index = max(self.max_done_index, index)
                    self.process_info()
                except Exception as ex:
                    self.error_indexs[str(index)] = self.error_indexs.get(str(index), 0) + 1
                    self.download_size -= write_size
                    debug_print('write_chunck error',ex)
                    if os.path.exists(filepath + f'.part{index}'):
                        os.remove(filepath + f'.part{index}')
                    return None
                return None
        except Exception as ex:
            self.error_indexs[str(index)] = self.error_indexs.get(str(index), 0) + 1
            debug_print("download_chunk error2", ex)
            return None
    # 下载文件
    def download(self, path:str, select_flag = False):
        global CONFIG, RETRY_COUNT, DOWNLOAD_CHUNK_SIZE, CHUNK_SIZE, TIME_OUT
        try:
            if not os.path.exists(path):
                os.mkdir(path)
            if self.type == 'folder':
                sub_files =  self.list_folder(select_flag)
                if sub_files:
                    download_dir = path + '/' + self.name
                    if not os.path.exists(download_dir):
                        os.mkdir(download_dir)
                    for info in sub_files:
                        ali_file = AliFile(self.sid,info['file_id'],self.spwd)
                        ali_file.set_info(info)
                        ali_file.download(download_dir)
            if self.type == 'file':
                try:
                    path = path.replace('//', '/')
                    filepath = path + '/' + self.name
                    if os.path.exists(filepath):
                        print(f'[*] 文件已存在: {filepath}')
                        return None
                    retry = 0
                    while retry < RETRY_COUNT:
                        req_data = {
                            'func':'get_download_url',
                            'sid':self.sid,
                            'fid':self.fid,
                            'spwd':self.spwd
                        }
                        download_urls = post_data('slink', req_data)
                        self.start_time = time.time()
                        out_str = []
                        out_str.append('\n[*] **************************************************')
                        out_str.append('[*] 文件名: ' + self.name)
                        out_str.append('[*] 文件夹: ' + path)
                        out_str.append('[*] 文件大小: {:.2f} MB'.format(self.size / 1024 / 1024))
                        out_str.append('[*] **************************************************')
                        print('\n'.join(out_str))
                        try:
                            self.check_download_record(filepath)
                            start_chunk = 0
                            if len(self.error_indexs) > 0:
                                # 复制一份避免遍历时修改
                                error_keys = list(self.error_indexs.keys())
                                debug_print('错误处理：'+ str(error_keys))
                                for index in error_keys:
                                    index = int(index)
                                    error_file_path = filepath + '.part' + str(index)
                                    if os.path.exists(error_file_path):
                                        self.download_size -= os.path.getsize(error_file_path)
                                        os.remove(error_file_path)
                                    # if len(self.error_indexs) >= MAX_DOWNLOAD_ERROR:
                                    #     debug_print('下载错误次数过多，下载失败。')
                                    #     break
                                    while len(self.threads) >= MAX_DOWNLOAD_THREAD:
                                        debug_print(f'错误处理：下载线程过多，当前线程数{len(self.threads)}，清理线程池。')
                                        time.sleep(0.5)
                                        for sub_thread in self.threads:
                                            if sub_thread.is_alive() == False:
                                                self.threads.remove(sub_thread)
                                        debug_print(f'错误处理：线程池清理完成，当前线程数{len(self.threads)}。')
                                        continue
                                    start = index * DOWNLOAD_CHUNK_SIZE
                                    end = min((index + 1) * DOWNLOAD_CHUNK_SIZE - 1, self.size - 1)
                                    self.error_indexs.pop(str(index))
                                    thread = threading.Thread(target=(self.download_chunk), args=(filepath,download_urls,start,end,index))
                                    self.threads.append(thread)
                                    thread.start()
                            last_chunk = self.max_done_index * DOWNLOAD_CHUNK_SIZE
                            if last_chunk > 0:
                                start_chunk = min(last_chunk + DOWNLOAD_CHUNK_SIZE, self.size)
                            for i in range(start_chunk, self.size, DOWNLOAD_CHUNK_SIZE):
                                # print(i,content_size,thread_chunk_size)
                                start = i
                                end = min(i + DOWNLOAD_CHUNK_SIZE - 1, self.size - 1)
                                # 如果线程数过多，会导致下载失败，所以这里限制一下
                                if len(self.error_indexs) >= MAX_DOWNLOAD_ERROR:
                                    # debug_print('下载错误次数过多，下载失败。')
                                    break
                                while len(self.threads) >= MAX_DOWNLOAD_THREAD:
                                    debug_print(f'下载线程过多，当前线程数{len(self.threads)}，清理线程池。')
                                    time.sleep(0.5)
                                    for sub_thread in self.threads:
                                        if sub_thread.is_alive() == False:
                                            self.threads.remove(sub_thread)
                                    debug_print(f'线程池清理完成，当前线程数{len(self.threads)}。')
                                    continue
                                thread = threading.Thread(target=(self.download_chunk), args=(filepath,download_urls,start,end,i // DOWNLOAD_CHUNK_SIZE))
                                self.threads.append(thread)
                                thread.start()
                            for thread in self.threads:
                                thread.join()
                            if len(self.error_indexs) > 0 or self.download_size < self.size:
                                debug_print('下载错误次数过多，下载失败。')
                                retry += 1
                                print('\n[*] 下载失败，重试中。')
                                continue
                            # 合成之前检查分片完整性
                            print('\n[*] 检查文件完整性中...')
                            for i in range(0, self.size, DOWNLOAD_CHUNK_SIZE):
                                index = i // DOWNLOAD_CHUNK_SIZE
                                part_file = filepath + f'.part{index}'
                                size_error = False
                                part_file_size = 0
                                if os.path.exists(part_file):
                                    part_file_size = os.path.getsize(part_file)
                                    # 如果不是最后一片，判断大小是否正确
                                    if i + DOWNLOAD_CHUNK_SIZE < self.size:
                                        if part_file_size != DOWNLOAD_CHUNK_SIZE:
                                            size_error = True
                                    # 如果是最后一片，判断大小是否正确
                                    elif part_file_size != self.size - i:
                                            size_error = True
                                else:
                                    size_error = True           
                                if size_error:
                                    self.error_indexs[str(index)] = self.error_indexs.get(str(index), 0) + 1
                                    self.download_size -= part_file_size
                                    # 删除下载失败的分片
                                    if os.path.exists(part_file):
                                        print('[*] 分片{}文件大小异常，删除重试'.format(index))
                                        os.remove(part_file)
                            if len(self.error_indexs) > 0:
                                retry += 1
                                print('\n[*] 下载失败，重试中。')
                                continue
                            with open(filepath, 'wb+') as file:
                                for i in range(0, self.size, DOWNLOAD_CHUNK_SIZE):
                                    part_file = filepath + f'.part{i//DOWNLOAD_CHUNK_SIZE}'
                                    with open(part_file, 'rb') as part:
                                        file.write(part.read())
                                    os.remove(part_file)
                            if os.path.exists(filepath + '.download'):
                                os.remove(filepath + '.download')
                            return True
                        except Exception as ex:
                            retry += 1
                            debug_print('download error', ex)
                            print('[*] 下载失败，重试中。')
                    if retry >= RETRY_COUNT:
                        print('[*] 下载失败，重试次数过多。')
                        return False
                except Exception as ex:
                    debug_print('download file retry error', ex)
                    exit_print('下载失败，请检查网络。')
                    return False
        except Exception as ex:
            debug_print('download error', ex)
            exit_print('下载失败，请检查网络。')
            return False
        return False
    
# 下载分享链接
def download_slink(sid, fid, spwd):
    try:
        ali_file = AliFile(sid, fid, spwd)
        if ali_file.get_info():
            ali_file.download(DOWNLOAD_PATH,SELECT_FLAG)
    except Exception as ex:
        debug_print('download_slink error', ex)
        exit_print('文件下载失败，请检查网络或配置，可以尝试重新下载。')

def query_slink_file(sid, fid, spwd, keyword):
    try:
        ali_file = AliFile(sid, fid, spwd)
        sub_files =  ali_file.query_file(keyword)
        if sub_files:
            if not os.path.exists(DOWNLOAD_PATH):
                os.mkdir(DOWNLOAD_PATH)
            for info in sub_files:
                sub_file = AliFile(sid,info['file_id'],spwd)
                sub_file.set_info(info)
                sub_file.download(DOWNLOAD_PATH)
    except Exception as ex:
        debug_print('query_slink_file error', ex)
        exit_print('文件查询失败，请检查网络或配置。')

if os.name == 'nt':
    import ctypes
    from ctypes import windll, wintypes
    from uuid import UUID

    class GUID(ctypes.Structure):
        _fields_ = [
            (
                'Data1', wintypes.DWORD),
            (
                'Data2', wintypes.WORD),
            (
                'Data3', wintypes.WORD),
            (
                'Data4', wintypes.BYTE * 8)]

        def __init__(self, uuidstr):
            uuid = UUID(uuidstr)
            ctypes.Structure.__init__(self)
            self.Data1, self.Data2, self.Data3, self.Data4[0], self.Data4[1], rest = uuid.fields
            for i in range(2, 8):
                self.Data4[i] = rest >> (8 - i - 1) * 8 & 255

    SHGetKnownFolderPath = windll.shell32.SHGetKnownFolderPath
    SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(GUID), wintypes.DWORD,
        wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]

    def _get_known_folder_path(uuidstr):
        pathptr = ctypes.c_wchar_p()
        guid = GUID(uuidstr)
        if SHGetKnownFolderPath(ctypes.byref(guid), 0, 0, ctypes.byref(pathptr)):
            raise ctypes.WinError()
        return pathptr.value

    FOLDERID_Download = '{374DE290-123F-4565-9164-39C4925E467B}'

    def get_download_folder():
        return _get_known_folder_path(FOLDERID_Download)

else:

    def get_download_folder():
        home = os.path.expanduser('~')
        return os.path.join(home, 'Downloads')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='阿里云盘分享链接下载工具')
    parser.add_argument('-u', '--url', type=str,
                        default=None, help='需要下载的分享链接')
    parser.add_argument('-s', '--sid', type=str,
                        default=None, help='需要下载的share_id')
    parser.add_argument('-sp', '--spwd', type=str,
                        default=None, help='需要下载的分享链接密码')
    parser.add_argument('-f', '--fid', type=str,
                        default='root', help='需要下载的file_id')
    parser.add_argument('-q', '--query', type=str,
                        default=None, help='搜索分享链接中的文件')
    parser.add_argument('--select', action='store_true',
                        default=False, help='选择下载文件')
    parser.add_argument('--folder', type=str, default=None, help='保存文件的位置')
    parser.add_argument('-v', action='store_true',
                        default=False, help='查看相关信息')
    parser.add_argument('-t', '--target', type=str,
                        default=None, help='切换服务器地址，自动获取配置信息')
    parser.add_argument('-p', '--pwd', type=str,
                        default=None, help='获取远程配置信息时，配置链接密码，需要结合-t参数使用')
    parser.add_argument('--code', type=str,
                        default=None, help='获取远程配置信息时，配置内测码，需要结合-t参数使用')
    parser.add_argument('-ti', '--tindex', type=int,
                        default=None, help='切换目标地址')
    # parser.add_argument('--debug', action='store_true',
    #                     default=False, help='DEBUG模式, 会显示调试信息, 默认为False')
    parser.add_argument('-n', type=int,
                    default=20, help='分段并发下载数, 默认为20')
    parser.add_argument('--chunk', type=int,
                        default=200, help='分段大小, 默认为300')
    parser.add_argument('-ct', '--chunktype', type=str,
                        default='KB', help='分段单位, 可选B, KB, MB, 默认为KB')
    parser.add_argument('--retry', type=int,
                        default=5, help='下载失败重试次数, 默认为5')
    parser.add_argument('--timeout', type=int,
                        default=10, help='下载超时时间, 默认为10, 单位为秒')
    parser.add_argument('--proxy', type=str,
                        default='', help='设置代理, 默认为空')
    args = parser.parse_args()
    url = args.url
    sid = args.sid
    fid = args.fid
    spwd = args.spwd
    # DEBUG = args.debug
    SELECT_FLAG = args.select
    if args.chunktype == 'B':
        DOWNLOAD_CHUNK_SIZE = args.chunk
    elif args.chunktype == 'KB':
        DOWNLOAD_CHUNK_SIZE = args.chunk * 1024
    elif args.chunktype == 'MB':
        DOWNLOAD_CHUNK_SIZE = args.chunk * 1024 * 1024
    else:
        DOWNLOAD_CHUNK_SIZE = 200 * 1024
    MAX_DOWNLOAD_THREAD = args.n
    RETRY_COUNT = args.retry
    TIME_OUT = args.timeout
    if args.proxy != '':
        PROXY = {'http': args.proxy, 'https': args.proxy}
    print(BANNER)
    load_config()
    if DEBUG:
        debug_print('DEBUG模式开启')
        # 配置日志，保存到文件，文件名为当前时间
        logging.basicConfig(filename=time.strftime('alidown-client-%Y-%m-%d',time.localtime(time.time()))+'.log',level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s',datefmt='%Y-%m-%d %H:%M:%S %p')
    if args.v:
        print_config()
    if args.target is not None:
        set_target_info(args.target, args.pwd, args.code)
    if args.tindex is not None:
        switch_target(args.tindex)
    check_config()
    check_version()
    if args.folder:
        if args.folder.endswith('/'):
            DOWNLOAD_PATH = args.folder
        else:
            DOWNLOAD_PATH = args.folder + '/'
    else:
        DOWNLOAD_PATH = get_download_folder() + '/'
    if not os.path.exists(DOWNLOAD_PATH):
        exit_print(f'下载目录不存在，请检查。{DOWNLOAD_PATH}')
    DOWNLOAD_PATH = DOWNLOAD_PATH + 'AliDown/'
    if url:
        try:
            slink = re.search('https://www.aliyundrive.com/s/(.*)/folder/(.*)', url)
            if slink:
                sid = slink.group(1)
                fid = slink.group(2)
            else:
                slink = re.search('https://www.aliyundrive.com/s/(.*)', url)
                if slink:
                    sid = slink.group(1)
                else:
                    exit_print('分享链接格式错误，请检查。')
        except Exception as ex:
            exit_print('分享链接格式错误，请检查。')
    if sid and fid:
        if args.query:
            query_slink_file(sid, fid, spwd, args.query)
        else:
            download_slink(sid, fid, spwd)
    else:
        exit_print('缺少参数，请检查。')