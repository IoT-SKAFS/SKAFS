import argparse
import socket, pickle
import os
import hashlib

# The elliptic curve
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.curve import Curve
from fastecdsa import keys, curve
from ecdsa.util import PRNG
from ecdsa import SigningKey
import hashlib
import time

# The HMAC function
from Crypto.Hash import HMAC
import hmac

from crypto_primitives import *

#Identity from registration.py
CA_Identity= 46579844848554959339853780073501818311333011659385775622580556906392721096590
Gateway_Identity= 86435257210596399642414507776986316715309341655253547362665956092651043226837
G_MK_G_CA= 1159271140786686176441844293055059612874238751727527131886619586251662372606
G_Sync_K_G_CA_previous= 33931604500771325315349620475168180167086521637799650438157775622534247950473
G_r_1_previous= 25987635929841083546691414601148870947453149543849025278881379581648406719593
G_Sync_K_G_CA= 31551912937363746602456966393987354119641925636358327385722398856783474291213


parser = argparse.ArgumentParser(description = 'Client for IoT Simulation')
parser.add_argument('-c', '--connect', default="127.0.0.1", help='CA server to connect to') 
args = parser.parse_args()


def server_program():
    # get the hostname
    bind_address = '0.0.0.0'
    port = 5000  # initiate port no above 1024
    host = args.connect # CA server

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((bind_address, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(10)



    while True:
        
        conn, address = server_socket.accept()  # accept new connection
        print("Connection from: " + str(address))
        ca_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ca_client_socket.connect((host, 5001))
        # step 1: receive (Hello Msg)
        IoT_HelloMsg = conn.recv(2048)
        if not IoT_HelloMsg:
            # if data is not received break
            break
        # print("Gateway :Step 1: received Hello Msg from the IoT device")

        # Generate the r_1 after receiving the Hello message from the IoT device
        G_r_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
        
        # Step 2: send the generated r_1 to the IoT device 
        conn.send(pickle.dumps(G_r_1))  
        # print('Gateway: Step 2: sent to r_1 the IoT device:' + str(G_r_1))
        
        # Step 3: receive M_1, ID*, r_2*, K_i*, r_3* from the IoT device
        IoT_M1 = conn.recv(2048)
        if not IoT_M1:
            break
        # print("Gateway: Step3: received from the IoT device: " + str(pickle.loads(IoT_M1)))

        # Generate N_g, \sigma_1,\sigma_2, E1 after receiving M1
        G_nonce = int.from_bytes(os.urandom(1024),'big')%P256.q
        returnData=generateSigma1Sigma2Epison1(G_nonce,G_MK_G_CA,Gateway_Identity,G_Sync_K_G_CA, G_r_1, IoT_M1)        
        iv = returnData[9]
        HashResult=returnData[10]
        message=returnData[:10]
        
        # Step 4: Send Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5, iv to the CA
        ca_client_socket.send(pickle.dumps(message))
        # print("Gateway: Step 4: sent Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5, iv to the CA:" + str(message))

        # Step 5: Receive CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4, D_sync_CA_G from the CA
        message = ca_client_socket.recv(2048)
        if not message:
            break
        # print("Gateway: Step 5: received from the CA: " + str(pickle.loads(message)))
        ReturnData=checkingSynchronizationBetGatewayIoT(pickle.loads(message), G_nonce, pickle.loads(IoT_M1), G_r_1, iv, HashResult)
        message=ReturnData[:2]
        G_K_a=ReturnData[2]
        G_K_previous=ReturnData[3]
        G_K_current=ReturnData[4]
        G_r_3=ReturnData[5]

        # Step 6: Send G_M_2, Sync_IoT_G to the IoT device
        # print("Gateway: Step 6: send to the IoT device: ", message)
        conn.send(pickle.dumps(message))
        

        # Step 7: Receive IoT_K_i_next_obfuscated from the IoT device
        message = conn.recv(2048)
        if not message:
            break
        # print("Gateway: Step 7: received from the IoT device: " + str(pickle.loads(message)))
        returnData=gettingEncryptingNextSessionKey(pickle.loads(message), iv, HashResult, G_K_a)
        message=returnData[0]
        G_IoT_K_i_next=returnData[1]

        # Step 8: Send Epison_3_1 to the CA
        ca_client_socket.send(pickle.dumps(message))
        # print("Gateway: Step 8: send to the IoT device: ", message)

        # Step 9: Receive M_3 from the CA
        CA_M3 = ca_client_socket.recv(2048)
        if not CA_M3:
            break
        # print("Gateway: Step 9: received from the CA: " + str(pickle.loads(CA_M3)))
        message=updatingSynchronizationKeys(pickle.loads(CA_M3), G_r_1, G_r_3, G_K_previous, G_K_current, G_IoT_K_i_next,G_Sync_K_G_CA)

        # Step 10: send M_4 to the IoT device
        conn.send(pickle.dumps(message))
        # print("Gateway: Step 10: send to the IoT device: " + str(message))
        #conn.close()  # close the connection
        ca_client_socket.close()

def generateSigma1Sigma2Epison1(G_nonce,G_MK_G_CA,Gateway_Identity,G_Sync_K_G_CA, G_r_1, IoT_M1):
    G_sigma_1=Hash(G_MK_G_CA,Gateway_Identity,G_nonce)
    G_sigma_2=Hash(G_Sync_K_G_CA,Gateway_Identity,G_nonce)

    iv = Random.new().read(AES.block_size)
    h = hashlib.new('sha256')
    h.update(G_Sync_K_G_CA.to_bytes(32, 'big'))
    HashResult=bytes(h.hexdigest(),'utf-8')

    IoT_ID_obfusacted=IoT_M1[1]
    IoT_r_2_obfuscated=IoT_M1[2]
    IoT_r_3_obfuscated=IoT_M1[4]
    IoT_K_i_obfuscated=IoT_M1[3]

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

    return Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5, iv, HashResult
    
def checkingSynchronizationBetGatewayIoT(data, G_nonce, IoT_M_1, G_r_1, iv,HashResult):
    #CA_sigma_3, Epison_2_1, Epison_2_2, Epison_2_3, Epison_2_4, D_sync_CA_G
    CA_sigma_3= data[0]
    Epison_2_1= data[1]
    Epison_2_2= data[2]
    Epison_2_3= data[3]
    Epison_2_4= data[4]
    D_sync_CA_G= data[5]
    IoT_K_i_obfuscated= IoT_M_1[3]
    IoT_A_M_1= IoT_M_1[0]
    IoT_r_3_obfuscated= IoT_M_1[4]

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
        Sync_IoT_G=0
        G_K_a = G_K_current
        G_r_3=IoT_r_3_obfuscated^G_K_current
        assert IoT_A_M_1==Hash(G_K_current,G_r_1,G_r_3), "The K_c has not been used in the first authentication message"
    elif IoT_K_i_obfuscated^G_K_before_previous==G_K_previous:
        Sync_IoT_G=-1
        G_K_a = G_K_previous
        G_r_3=IoT_r_3_obfuscated^G_K_previous
        assert (IoT_A_M_1==Hash(G_K_previous,G_r_1,G_r_3)), "The K_p has not been used in the generation of the authentication message"
    else:
        print("didnt match stuff")
    G_M_2=Hash(G_K_a,Sync_IoT_G,G_r_1,G_r_3)

    return G_M_2, Sync_IoT_G, G_K_a, G_K_previous, G_K_current, G_r_3

def gettingEncryptingNextSessionKey(IoT_K_i_next_obfuscated, iv, HashResult, G_K_a):
    # IoT_K_i_next_obfuscated
    G_IoT_K_i_next=IoT_K_i_next_obfuscated^G_K_a
    ENC = AES.new(HashResult[:16], AES.MODE_CBC, iv)
    Epison_3_1=ENC.encrypt(G_IoT_K_i_next.to_bytes(32,'big'))

    return Epison_3_1, G_IoT_K_i_next

def updatingSynchronizationKeys(CA_M3, G_r_1, IoT_r_3, G_K_previous,G_K_current,G_IoT_K_i_next,G_Sync_K_G_CA):
    

    G_K_s=Hash(G_r_1,IoT_r_3,G_K_current)
    print("The session key on the gateway:",G_K_s)

    ####### Update the synchronization keys ###############################
    G_K_before_previous=G_K_previous
    G_K_previous=G_K_current
    G_K_current=G_IoT_K_i_next
    G_r_1_previous=G_r_1

    ##### Update the gateway & CA synchronization keys ###########
    G_Sync_K_G_CA_previous=G_Sync_K_G_CA
    G_Sync_K_G_CA=Hash(G_Sync_K_G_CA,G_r_1)

    assert CA_M3==Hash(G_K_before_previous,G_K_previous,G_K_current,G_Sync_K_G_CA), "The synchronization keys of the gateway and the CA have not been updated on the Gateway"
    M_4=Hash(G_K_s,G_r_1,IoT_r_3)

    return M_4

if __name__ == '__main__':
    server_program()
