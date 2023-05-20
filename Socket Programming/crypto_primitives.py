import time

from fastecdsa.curve import Curve
from fastecdsa import keys, curve

from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto import Random
from Crypto.Cipher import AES

import hashlib

def Hash(*dataListByte):
    h = hashlib.new('sha256')
    Mydata=b""
    for data in dataListByte:
        #print("Data: ",data)
        Mydata = Mydata + data.to_bytes(32, 'big')
    h.update(Mydata)
    HashResult=h.hexdigest()
    HashInt=int(HashResult,16)
    Hash_value=HashInt%P256.q
    return Hash_value

def FPUF(Challenge):
    h = hashlib.new('sha256')
    h.update(Challenge.to_bytes(32, 'big'))
    HashResult=h.hexdigest()
    HashInt=int(HashResult,16)
    Response=HashInt%P256.q
    time.sleep(2.2/1000)
    return Response

def DPUF(Challenge, state):
    h = hashlib.new('sha256')
    h.update(Challenge.to_bytes(32, 'big')+state.to_bytes(32, 'big'))
    HashResult=h.hexdigest()
    HashInt=int(HashResult,16)
    Response=HashInt%P256.q
    time.sleep(3.3/1000)
    return Response