from fastecdsa.curve import Curve
from fastecdsa import keys, curve

from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto import Random
from Crypto.Cipher import AES

import hashlib
import os 
import sys
import time


def Hash(*dataListByte):
    h = hashlib.new('sha256')
    Mydata=b""
    for data in dataListByte:
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

#################################################
##########The registration of the IoT device
#################################################

# The fixed challenges generation in bytes for the PUF (Simulated as Hash function)
C_F0 = int.from_bytes(os.urandom(1024),'big')%P256.q
C_F1 = int.from_bytes(os.urandom(1024),'big')%P256.q

# The DPUF challenge and state 
IoT_C_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
state= int.from_bytes(os.urandom(1024),'big')%P256.q

#The Generation of the IoT identity
IoT_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q

# The Generation of the long-term Key K on the CA side
K = int.from_bytes(os.urandom(1024),'big')%P256.q
IoT_T_j=K ^ FPUF(C_F0) ^ FPUF(C_F1)

# The Initialization parameter on the CA
CA_K_before_previous = int.from_bytes(os.urandom(1024),'big')%P256.q
CA_K_previous = int.from_bytes(os.urandom(1024),'big')%P256.q
CA_K_current = DPUF(IoT_C_1,state)

# The initialization of the parameters on the IoT device
IoT_K_previous=CA_K_previous

#####################################################
###### The registration of the Gateway ##############
#####################################################

#The Generation of the gateway identity
Gateway_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q
CA_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q

#The Generation of the Master Key between the gateway and the CA
CA_MK_G_CA = int.from_bytes(os.urandom(1024),'big')%P256.q
CA_Sync_K_G_CA_previous = int.from_bytes(os.urandom(1024),'big')%P256.q
CA_r_1_previous = int.from_bytes(os.urandom(1024),'big')%P256.q

# The Initialization parameter on the CA
CA_Sync_K_G_CA = Hash(CA_Sync_K_G_CA_previous,CA_r_1_previous)

# The Initialization parameters on the IoT device
G_MK_G_CA=CA_MK_G_CA
G_Sync_K_G_CA_previous= CA_Sync_K_G_CA_previous
G_r_1_previous=CA_r_1_previous
G_Sync_K_G_CA=Hash(G_Sync_K_G_CA_previous,G_r_1_previous)


###############################################################
#########  The Authentication process  ########################
###############################################################

########   The IoT device computation  ########################

G_r_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
IoT_r_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
IoT_r_3 = int.from_bytes(os.urandom(1024),'big')%P256.q

IoT_ID_obfusacted=IoT_Identity^Hash(G_r_1,IoT_r_2)
IoT_K_i=DPUF(IoT_C_1,state)
IoT_K_i_obfuscated=IoT_K_i^IoT_K_previous
IoT_M_1=Hash(IoT_K_i,G_r_1,IoT_r_3)
IoT_r_2_obfuscated=FPUF(C_F0)^IoT_r_2
IoT_r_2_obfuscated=IoT_r_2_obfuscated^FPUF(C_F1)^IoT_T_j
IoT_r_3_obfuscated=IoT_r_3^IoT_K_i

############ The gateway computation ##########################
G_nonce = int.from_bytes(os.urandom(1024),'big')%P256.q
G_sigma_1=Hash(G_MK_G_CA,Gateway_Identity,G_nonce)
G_sigma_2=Hash(G_Sync_K_G_CA,Gateway_Identity,G_nonce)

iv = Random.new().read(AES.block_size)
h = hashlib.new('sha256')
h.update(G_Sync_K_G_CA.to_bytes(32, 'big'))
HashResult=bytes(h.hexdigest(),'utf-8')

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_1_1=ENC.encrypt(IoT_ID_obfusacted.to_bytes(32,'big'))

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_1_2=ENC.encrypt(IoT_r_2_obfuscated.to_bytes(32,'big'))

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_1_3=ENC.encrypt(IoT_r_3_obfuscated.to_bytes(32,'big'))

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_1_4=ENC.encrypt(G_r_1.to_bytes(32,'big'))

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_1_5=ENC.encrypt(IoT_K_i_obfuscated.to_bytes(32,'big'))

############### The CA computation  ################
h1 = hashlib.new('sha256')
h1.update(CA_Sync_K_G_CA.to_bytes(32, 'big'))
HashResult=bytes(h1.hexdigest(),'utf-8')

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
IoT_ID_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_1), 'big')

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
IoT_r_2_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_2),'big')

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
IoT_r_3_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_3),'big')
      
DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
G_r_1_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_4),'big')

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
IoT_K_i_Decrypted=int.from_bytes(DEC.decrypt(Epison_1_5),'big')

assert G_sigma_1 ==Hash(CA_MK_G_CA,Gateway_Identity,G_nonce), "The authentication of the Gateway by the CA has failed"

if G_sigma_2==Hash(CA_Sync_K_G_CA_previous,Gateway_Identity,G_nonce):
    D_sync_CA_G=-1
elif G_sigma_2 == Hash(CA_Sync_K_G_CA,Gateway_Identity,G_nonce):
    D_sync_CA_G=0
CA_r_2_retrieved=IoT_r_2_Decrypted^K

CA_IoT_ID_retrieved=IoT_ID_Decrypted^Hash(G_r_1_Decrypted,CA_r_2_retrieved)
CA_sigma_3=Hash(CA_MK_G_CA,CA_Identity,D_sync_CA_G,G_nonce+1)

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_2_1=ENC.encrypt(CA_K_before_previous.to_bytes(32,'big'))

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_2_2=ENC.encrypt(CA_K_previous.to_bytes(32,'big'))

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_2_3=ENC.encrypt(CA_K_current.to_bytes(32,'big'))

ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_2_4=ENC.encrypt(CA_r_1_previous.to_bytes(32,'big'))

##################### The Gateway Computation ##############

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
G_K_before_previous=int.from_bytes(DEC.decrypt(Epison_2_1),'big')

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
G_K_previous=int.from_bytes(DEC.decrypt(Epison_2_2),'big')

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
G_K_current=int.from_bytes(DEC.decrypt(Epison_2_3),'big')

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
G_r_1_previous=int.from_bytes(DEC.decrypt(Epison_2_4),'big')

if D_sync_CA_G==-1:
    G_Sync_K_G_CA=Hash(G_Sync_K_G_CA_previous,G_r_1_previous)

assert CA_sigma_3==Hash(G_MK_G_CA,CA_Identity,D_sync_CA_G,G_nonce+1), "The authentication of the CA on the gateway side has failed"
if IoT_K_i_obfuscated^G_K_previous==G_K_current:
    assert IoT_M_1==Hash(G_K_current,G_r_1,IoT_r_3), "The K_c has not been used in the first authentication message"
    Sync_IoT_G=0
    G_K_a = G_K_current
    G_r_3=IoT_r_3_obfuscated^G_K_current
elif IoT_K_i_obfuscated^G_K_before_previous==G_K_previous:
    assert (IoT_M_1==Hash(G_K_previous,G_r_1,IoT_r_3)), "The K_p has not been used in the generation of the authentication message"
    Sync_IoT_G=-1
    G_K_a = G_K_previous
    G_r_3=IoT_r_3_obfuscated^G_K_previous
G_M_2=Hash(G_K_a,Sync_IoT_G,G_r_1,G_r_3)


##########################    The IoT computation  #########################

assert G_M_2==Hash(IoT_K_i,Sync_IoT_G,G_r_1,IoT_r_3), "The authentication of the Gateway on the IoT device has failed"
if Sync_IoT_G==-1:
    IoT_C_1=Hash(IoT_C_1)
    state=Hash(state)
IoT_K_i=DPUF(IoT_C_1,state)
IoT_K_i_next=DPUF(Hash(IoT_C_1),Hash(state))
IoT_K_i_next_obfuscated=IoT_K_i_next^IoT_K_i
IoT_K_s=Hash(G_r_1,IoT_r_3,IoT_K_i)
print("The IoT session key:",IoT_K_s)
######################      The Gateway computation  #####################
G_IoT_K_i_next=IoT_K_i_next_obfuscated^G_K_a
ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
Epison_3_1=ENC.encrypt(G_IoT_K_i_next.to_bytes(32,'big'))

#######################     The CA computation   ##########################

DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
CA_IoT_K_i_next=int.from_bytes(DEC.decrypt(Epison_3_1),'big')

##### Update the IoT synchronization keys ##############
CA_K_before_previous=CA_K_previous
CA_K_previous=CA_K_current
CA_K_current=CA_IoT_K_i_next
CA_r_1_previous=G_r_1_Decrypted

##### Update the gateway & CA synchronization keys ###########
CA_Sync_K_G_CA_previous=CA_Sync_K_G_CA
CA_Sync_K_G_CA=Hash(CA_Sync_K_G_CA,G_r_1_Decrypted)

M_3=Hash(CA_K_before_previous,CA_K_previous,CA_K_current,CA_Sync_K_G_CA)

################################# The gateway computation ##############
G_K_s=Hash(G_r_1,IoT_r_3,G_K_current)
print("The IoT Gateway session key:",G_K_s)

####### Update the synchronization keys  ###############################
G_K_before_previous=G_K_previous
G_K_previous=G_K_current
G_K_current=IoT_K_i_next
G_r_1_previous=G_r_1

##### Update the gateway & CA synchronization keys ###########
G_Sync_K_G_CA_previous=G_Sync_K_G_CA
G_Sync_K_G_CA=Hash(G_Sync_K_G_CA,G_r_1)

assert M_3==Hash(G_K_before_previous,G_K_previous,G_K_current,G_Sync_K_G_CA), "The synchronization keys of the gateway and the CA have not been updated on the Gateway"
M_4=Hash(G_K_s,G_r_1,IoT_r_3)


################ The IoT computation   #######################
assert M_4 == Hash(IoT_K_s,G_r_1,IoT_r_3), "The synchronization keys between the IoT device and the gateway have not been updated on the IoT device"
IoT_C_1=Hash(IoT_C_1)
IoT_K_previous=IoT_K_i
state=Hash(state)