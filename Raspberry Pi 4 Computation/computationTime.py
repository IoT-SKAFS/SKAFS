# The 256-bit hash function
from Crypto.Hash import SHA256
import hashlib

# The HMAC function
from Crypto.Hash import HMAC
from scipy.spatial.distance import hamming
import numpy as np
import argparse

import hmac



# The Advanced Encryption System  CBC Mode(Symmetric Encryption)
from Crypto.Cipher import AES
from Crypto import Random

#The random number generation
import os

# The public key encrypton (RSA)
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# The bilinear pairing
from bplib import bp

# The elliptic curve
from fastecdsa.curve import P256
from fastecdsa.point import Point

import time

import json

from mod import Mod

from fuzzy_extractor import FuzzyExtractor

parser=argparse.ArgumentParser()
parser.add_argument("iterations", type=int, help="number of iterations to run")
data=[]
args=parser.parse_args()
n_iterations=args.iterations

#Getting the  hash start time
hashStartTime=time.time()

h = hashlib.sha256()
h.update(b'rfvsjbnbkf nikvfabnbrnkbnbknv NBRNTENBBFKEDANKENG KNKFDANKGRNKBGKNBFKTFNBFR  KFBDNKBNFRK BFD BLKBNRFNRF KFNBKEG DNBNRKORMVFS BKRNKRNGRNNB;KNBRNRF KBFRNRJFEM  KFRNBFNKNG NVFRL;SBFBJGERINHKTNBNBITNERKNAKNKVFNKNRAFNKNGRKF;FEKPKEGR  GRGKFM FV;LRMGR;MV,MV;LGRMLGRNV ,;FKDGRMV;MSK NGFAKBRKB FKVNBDKFGTNFVM CXFKNRKADN CNKGRNFD ,VCSNFRKK DDSKTENFKZVFDNVD.NGTLKNMGFD  VFGRAMDCMRJNDNMVSC  MDCSJNF DCDCNSL.N.M NDDDDDDDNCDCJMD,C  ,M ,M ,M ,M ,M ,M ,M ,M ,MDSCJN MDSV CM J DCCMDANFKJN VDNDCKLNVDS DV SJCBJBDSJCBBDJJGRBJBGRJKBKJBGERWBJKJVDBRJVFBLCBVECBFRWVC U V  DCBSKDJEWNFRWBJFRBVFDFENCXBKSANDMXNLKJNEDSAFHFUEDWHGUGFBVBVBVBVBVBVLKENFDLKLKLKLK.NDSA MNSLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKDC S,M,M,M,M,M,M,MJEWEWEWEWEWEWEWEWEWEWEW,Msaddddrehjjhq.JE.JE.JE.JE.JE.JE.JE.JE.JE.JEaf,nnnnnnn cxzzzzzzbewjkewrioooipoiiiiiiiiipcdklbdjcbsnccds<M,sDCAnDCSnmdb.vdjj dcms.fedn dcnjdcskbjkfbedjbfrjbdjvfbjdcbcbdckjbkjdcbjdcdcjdkjcbjdcbbcdckjbjbdjjbdcjkdsx m mxX<Mmnc.,mcdcmnmdcm,m<MNCXnC<,mnNN<,m<MNXZnxnNnmXnNXnnnxnxnnxmnnxxnbnXNBnxXkjdsbjkeds <MZ')
#loop #some computations
for i in range(n_iterations):
    digest=h.hexdigest()


hashEndTime=time.time()

hashExecutionTime=hashEndTime-hashStartTime
averageHashExecutionTime=hashExecutionTime/n_iterations
dataSize= 1024

computation = {"computation": "SHA-256",
               "iterations":n_iterations,
               "Data size in bytes": dataSize,
               "Total Execution time": hashExecutionTime,
               "Average Execution time": averageHashExecutionTime,
               "Average Execution time(msec)": averageHashExecutionTime*1000}

data.append(computation)


# The HMAC function (SHA256)
secret = b'Swordfish'
msg = b'rfvsjbnbkf nikvfabnbrnkbnbknv NBRNTENBBFKEDANKENG KNKFDANKGRNKBGKNBFKTFNBFR  KFBDNKBNFRK BFD BLKBNRFNRF KFNBKEG DNBNRKORMVFS BKRNKRNGRNNB;KNBRNRF KBFRNRJFEM  KFRNBFNKNG NVFRL;SBFBJGERINHKTNBNBITNERKNAKNKVFNKNRAFNKNGRKF;FEKPKEGR  GRGKFM FV;LRMGR;MV,MV;LGRMLGRNV ,;FKDGRMV;MSK NGFAKBRKB FKVNBDKFGTNFVM CXFKNRKADN CNKGRNFD ,VCSNFRKK DDSKTENFKZVFDNVD.NGTLKNMGFD  VFGRAMDCMRJNDNMVSC  MDCSJNF DCDCNSL.N.M NDDDDDDDNCDCJMD,C  ,M ,M ,M ,M ,M ,M ,M ,M ,MDSCJN MDSV CM J DCCMDANFKJN VDNDCKLNVDS DV SJCBJBDSJCBBDJJGRBJBGRJKBKJBGERWBJKJVDBRJVFBLCBVECBFRWVC U V  DCBSKDJEWNFRWBJFRBVFDFENCXBKSANDMXNLKJNEDSAFHFUEDWHGUGFBVBVBVBVBVBVLKENFDLKLKLKLK.NDSA MNSLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKDC S,M,M,M,M,M,M,MJEWEWEWEWEWEWEWEWEWEWEW,Msaddddrehjjhq.JE.JE.JE.JE.JE.JE.JE.JE.JE.JEaf,nnnnnnn cxzzzzzzbewjkewrioooipoiiiiiiiiipcdklbdjcbsnccds<M,sDCAnDCSnmdb.vdjj dcms.fedn dcnjdcskbjkfbedjbfrjbdjvfbjdcbcbdckjbkjdcbjdcdcjdkjcbjdcbbcdckjbjbdjjbdcjkdsx m mxX<Mmnc.,mcdcmnmdcm,m<MNCXnC<,mnNN<,m<MNXZnxnNnmXnNXnnnxnxnnxmnnxxnbnXNBnxXkjdsbjkeds <MZ'
HMACStartTime=time.time()
h = hmac.new(secret,msg, hashlib.sha256)

#loop #some computations
for i in range (n_iterations):
    digestHMAC=h.hexdigest()
HMACEndTime=time.time()

HMACExecutionTime=HMACEndTime-HMACStartTime
averageHMACExecutionTime=HMACExecutionTime/n_iterations

computation = {"computation": "HMAC-SHA256",
               "Data size in bytes": dataSize,
               "Total Execution time": HMACExecutionTime,
               "Average Execution time": averageHMACExecutionTime,
               "Average Execution time(msec)": 1000*averageHMACExecutionTime}

data.append(computation)



#The random number generation
RandomStartTime=time.time()
for i in range (n_iterations):
    random = os.urandom(1024)
    
RandomEndTime=time.time()

RandomExecutionTime=RandomEndTime-RandomStartTime
AverageRandomExecutionTime=RandomExecutionTime/n_iterations

computation = {"computation": "Random generation",
               "Data size in bytes": dataSize,
               "Total Execution time": RandomExecutionTime,
               "Average Execution time": AverageRandomExecutionTime,
               "Average Execution time(msec)": 1000*AverageRandomExecutionTime}

data.append(computation)


# The AES encryption procedures
key = b'Sixteen byte key'
#print (key)
iv = Random.new().read(AES.block_size)
#print (iv)
AESencryptionStartTime=time.time()

aes = AES.new(key, AES.MODE_CBC, iv)
message = b'rfvsjbnbkf nikvfabnbrnkbnbknv NBRNTENBBFKEDANKENG KNKFDANKGRNKBGKNBFKTFNBFR  KFBDNKBNFRK BFD BLKBNRFNRF KFNBKEG DNBNRKORMVFS BKRNKRNGRNNB;KNBRNRF KBFRNRJFEM  KFRNBFNKNG NVFRL;SBFBJGERINHKTNBNBITNERKNAKNKVFNKNRAFNKNGRKF;FEKPKEGR  GRGKFM FV;LRMGR;MV,MV;LGRMLGRNV ,;FKDGRMV;MSK NGFAKBRKB FKVNBDKFGTNFVM CXFKNRKADN CNKGRNFD ,VCSNFRKK DDSKTENFKZVFDNVD.NGTLKNMGFD  VFGRAMDCMRJNDNMVSC  MDCSJNF DCDCNSL.N.M NDDDDDDDNCDCJMD,C  ,M ,M ,M ,M ,M ,M ,M ,M ,MDSCJN MDSV CM J DCCMDANFKJN VDNDCKLNVDS DV SJCBJBDSJCBBDJJGRBJBGRJKBKJBGERWBJKJVDBRJVFBLCBVECBFRWVC U V  DCBSKDJEWNFRWBJFRBVFDFENCXBKSANDMXNLKJNEDSAFHFUEDWHGUGFBVBVBVBVBVBVLKENFDLKLKLKLK.NDSA MNSLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKLKDC S,M,M,M,M,M,M,MJEWEWEWEWEWEWEWEWEWEWEW,Msaddddrehjjhq.JE.JE.JE.JE.JE.JE.JE.JE.JE.JEaf,nnnnnnn cxzzzzzzbewjkewrioooipoiiiiiiiiipcdklbdjcbsnccds<M,sDCAnDCSnmdb.vdjj dcms.fedn dcnjdcskbjkfbedjbfrjbdjvfbjdcbcbdckjbkjdcbjdcdcjdkjcbjdcbbcdckjbjbdjjbdcjkdsx m mxX<Mmnc.,mcdcmnmdcm,m<MNCXnC<,mnNN<,m<MNXZnxnNnmXnNXnnnxnxnnxmnnxxnbnXNBnxXkjdsbjkeds ' # <- 16 bytes
for i in range (n_iterations):
    encd = aes.encrypt(message)
#print (encd)
AESencryptionEndTime=time.time()
AESEncryptionTime=AESencryptionEndTime-AESencryptionStartTime
AverageAESEncryptionTime=AESEncryptionTime/n_iterations

computation = {"computation": "AES-128-CBC enc",
               "Data size in bytes": dataSize,
               "Total Execution time": AESEncryptionTime,
               "Average Execution time": AverageAESEncryptionTime,
               "Average Execution time(msec)": 1000*AverageAESEncryptionTime}

data.append(computation)


FHDStartTime=time.time()
values1 = [10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40, 10, 20, 30, 40]
values2 = [10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50, 10, 20, 30, 50]
for i in range (n_iterations):
   #calculate Hamming distance between the two binary arrays
   hamming_distance = hamming(values1, values2)
   count= np.count_nonzero(hamming_distance)
   FHD=count/ len(values1)
   
   
FHDEndTime=time.time()
HammingTime=FHDEndTime-FHDStartTime
AverageHammingTime=HammingTime/n_iterations
   
computation = {"computation": "FHD",
               "Total Execution time": HammingTime,
               "Average Hamming time": AverageHammingTime,
               "Average Hamming time(msec)": 1000*AverageHammingTime}

data.append(computation)

# The elliptic curve operations
xs = 0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9
ys = 0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256
S = Point(xs, ys, curve=P256)

xt = 0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b
yt = 0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316
T = Point(xt, yt, curve=P256)
     
ECCadditionStartTime=time.time()
for i in range (n_iterations):
    S + T
ECCadditionEndTime=time.time()
ECCadditionTime=ECCadditionEndTime-ECCadditionStartTime
AverageECCadditionTime=ECCadditionTime/n_iterations
   
computation = {"computation": "ECCaddition",
               "Total Execution time": ECCadditionTime,
               "Average ECC addition time": AverageECCadditionTime,
               "Average ECC addition time (msec)": 1000*AverageECCadditionTime}
data.append(computation)
     
d = 0xc51f
ECCscalarMultiplicationStartTime=time.time()
for i in range (n_iterations):
    R = d * S
ECCscalarMultiplicationEndTime=time.time()
ECCscalarMultiplicationTime=ECCscalarMultiplicationEndTime-ECCscalarMultiplicationStartTime
AverageECCscalarMultiplicationTime=ECCscalarMultiplicationTime/n_iterations
   
computation = {"computation": "ECC scalar Multiplication",
               "Total Execution time": ECCscalarMultiplicationTime,
               "Average ECC scalar Multiplication time": AverageECCscalarMultiplicationTime,
               "Average ECC scalar Multiplication time(msec)": 1000*AverageECCscalarMultiplicationTime}
data.append(computation)


BPTimeStartTime=time.time()
G = bp.BpGroup()
g1, g2 = G.gen1(), G.gen2()
for i in range (n_iterations):    
    gt = G.pair(g1, g2)
BPTimeEndTime=time.time()
BPTime=BPTimeEndTime-BPTimeStartTime
AverageBPTime=BPTime/n_iterations
   
computation = {"computation": "Bilinear Pairing",
               "iterations": n_iterations,
               "Total Execution time": BPTime,
               "Average Bilinear pairing time": AverageBPTime,
               "Average Bilinear pairing time (msec)": 1000*AverageBPTime}
data.append(computation)

# Writing to JSON file
with open(f'PrimitiveComputationTime {n_iterations}.txt', 'w') as json_file:
  json.dump(data, json_file, indent =4)
