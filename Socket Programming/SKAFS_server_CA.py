###   To Connect to the laptop server from the raspberry pi,run: 
###
###   python client.py -c 169.254.69.248
###
###   To Connect to the raspberry pi server from the laptop, run: 
###
###   python client.py -c 169.254.232.12

import argparse
import socket, pickle
import os
# The elliptic curve
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.curve import Curve
from fastecdsa import keys, curve
from ecdsa.util import PRNG
from ecdsa import SigningKey

import hashlib
import time

from crypto_primitives import *

#Identity from registration.py
CA_Identity= 46579844848554959339853780073501818311333011659385775622580556906392721096590
K= 53493793430918351993050431433857390972363452288460865537986695568195450305147
CA_MK_G_CA= 1159271140786686176441844293055059612874238751727527131886619586251662372606
CA_Sync_K_G_CA_previous= 33931604500771325315349620475168180167086521637799650438157775622534247950473
CA_r_1_previous= 31117325389844503084244712533611686457352293220259477778503853065508984899608
CA_Sync_K_G_CA= 31551912937363746602456966393987354119641925636358327385722398856783474291213
CA_K_before_previous = 91289531547633314789640143076649403445524859162380902182454388259509213812777
CA_K_previous= 31117325389844503084244712533611686457352293220259477778503853065508984899608
CA_K_current= 6215023898619450942669055423149822016701696788684213924828826919701330385338


# The Socket programming
parser = argparse.ArgumentParser(description = 'Server CA for IoT Simulation')
args = parser.parse_args()

def ca_server_program():

    

    host = '0.0.0.0'
    port = 5001  # socket server port number

    ca_server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    ca_server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    ca_server_socket.listen(10)
    

    while True:
    
        conn, address = ca_server_socket.accept()  # accept new connection
        print("Connection from: " + str(address))
        message = ""
        #Step 1: Receive Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5 from the gateway
        data = conn.recv(2048)         
        print('CA: step 1: received from gateway: ')
        print(pickle.loads(data))  # show in terminal

        #do the IoT computation 2 and send the authentication token to the gateway
        # Message contains: P_1, P_2, P_3, sigma_t, T_1, T_2, s_1, s_2

        ReturnData = RetrieveR_2_ID(pickle.loads(data))
        message=ReturnData[:6]
        HashResult=ReturnData[6]
        G_r_1_Decrypted=ReturnData[7]
        iv=ReturnData[8]

        #Step 2: Send the sigma_3 epson2 D_CA_G to the IoT gateway
        conn.send(pickle.dumps(message))
        # print('CA: Step 2: sent to gateway: ' + str(message))     

        #Step 3: Receive the Epison_3_1 from the IoT gateway
        data = conn.recv(2048) 
        # print('CA: step 3: received from gateway: ')
        # print(pickle.loads(data))  # show in terminal
        message=updatingSynchronizationKeys(pickle.loads(data), HashResult,iv,G_r_1_Decrypted,CA_K_previous,CA_K_current,CA_Sync_K_G_CA)

        #Step 4: Send M_3 to the IoT gateway
        conn.send(pickle.dumps(message))
        # print('CA: Step 4: sent to gateway: ' + str(message))

        #conn.close()  # close the connection

def RetrieveR_2_ID(data):
    # Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5, iv
    Gateway_Identity= data[0]
    G_nonce= data[1]
    G_sigma_1= data[2]
    G_sigma_2= data[3]
    Epison_1_1= data[4]
    Epison_1_2= data[5]
    Epison_1_3= data[6]
    Epison_1_4= data[7]
    Epison_1_5= data[8]
    iv= data[9]

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
        D_sync_CA_G=1 #it was -1
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

    return CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4, D_sync_CA_G, HashResult, G_r_1_Decrypted, iv

def updatingSynchronizationKeys(Epison_3_1,HashResult,iv,G_r_1_Decrypted,CA_K_previous,CA_K_current,CA_Sync_K_G_CA):
        
    DEC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    CA_IoT_K_i_next=int.from_bytes(DEC.decrypt(Epison_3_1),'big')

    ##### Update the IoT synchronization keys ##############
    CA_K_before_previous=CA_K_previous
    CA_K_previous=CA_K_current
    CA_K_current=CA_IoT_K_i_next
    global CA_r_1_previous
    CA_r_1_previous=G_r_1_Decrypted

    ##### Update the gateway & CA synchronization keys ###########
    global CA_Sync_K_G_CA_previous
    CA_Sync_K_G_CA_previous=CA_Sync_K_G_CA
    CA_Sync_K_G_CA=Hash(CA_Sync_K_G_CA,G_r_1_Decrypted)
    M_3=Hash(CA_K_before_previous,CA_K_previous,CA_K_current,CA_Sync_K_G_CA)
    return M_3

if __name__ == '__main__':
    ca_server_program()
