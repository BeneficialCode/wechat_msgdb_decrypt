import os
from typing import Union,List
from Crypto.Cipher import AES
import hashlib
import hmac
import binascii
import sqlite3

SQLITE_FILE_HEADER = b"SQLite format 3\x00"

KEY_SIZE = 32
DEFAULT_PAGESIZE = 1024
DEFAULT_ITER = 4000


# 通过密钥解密数据库
def decrypt(key: str, db_path, out_path):
    """
    通过密钥解密数据库
    :param key: 密钥 7位16进制字符串
    :param db_path:  待解密的数据库路径(必须是文件)
    :param out_path:  解密后的数据库输出路径(必须是文件)
    :return:
    """
    if not os.path.exists(db_path) or not os.path.isfile(db_path):
        raise Exception("db_path must be a file")

    with open(db_path,"rb") as file:
        blist = file.read()

    # 每一个数据库文件的开头16字节都保存了一段唯一且随机的盐值，作为HMAC的验证和数据的解密
    salt = blist[:16]
    byteKey = hashlib.pbkdf2_hmac('sha1',key.encode(),salt,DEFAULT_ITER,dklen=KEY_SIZE)
    first = blist[16:DEFAULT_PAGESIZE]
    if len(salt) != 16:
        raise Exception("salt must be 16 bytes")

    block_sz = 16

    reserve_sz = 0
    # iv size
    iv_sz = 16
    # hmac size
    hmac_sz = 20

    reserve_sz = iv_sz
    reserve_sz += hmac_sz
    if reserve_sz % block_sz != 0:
        reserve_sz = ((reserve_sz // block_sz) + 1) * block_sz
    print("reserve_sz:",reserve_sz)

    reserve_sz = iv_sz
    if reserve_sz % block_sz != 0:
        reserve_sz = ((reserve_sz // block_sz) + 1) * block_sz

    print("reserve_sz:",reserve_sz)

    newblist = [blist[i:i + DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(blist), DEFAULT_PAGESIZE)]

    with open(out_path,"wb") as deFile:
        deFile.write(SQLITE_FILE_HEADER)
        # 第一页前16字节为盐值,紧接着是992字节的加密数据段和16字节的保留段
        iv = first[-16:]
        t = AES.new(byteKey, AES.MODE_CBC, iv)
        decrypted = t.decrypt(first[:-16])
        deFile.write(decrypted)
        deFile.write(first[-16:])

        # 后续页均是1008字节长度的加密数据段和16字节的保留段
        for i in newblist:
            iv = i[-16:]
            t = AES.new(byteKey, AES.MODE_CBC, iv)
            decrypted = t.decrypt(i[:-16])
            deFile.write(decrypted)
            deFile.write(i[-16:])
    
    return True,[db_path,out_path]


def get_msgdb_key(uin,imei):
    key = imei + uin
    md5 = hashlib.md5()
    md5.update(key.encode('utf-8'))
    key = md5.hexdigest()[:7].lower()
    print("key:",key)
    return key

def parse_contract(db_path):
    if not os.path.exists(db_path):
        print("DB not found: ", db_path)
        return False
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    users = c.execute("SELECT username, alias, nickname from rcontact WHERE type=1 OR type=8388611")
    for user in users:
        username = user[0]
        alias = user[1]
        nickname = user[2]
        # 忽略微信团队和文件助手
        if username == "weixin" or username == "filehelper":
            continue
        print(user)
    return True

imei = "1234567890ABCDEF"
uin = "1146048721"
key = get_msgdb_key(uin,imei)

ret = decrypt(key,"EnMicroMsg.db","EnMicroMsg.decrypted.db")

parse_contract("EnMicroMsg.decrypted.db")




    
