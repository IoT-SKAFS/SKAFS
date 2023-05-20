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
import time
from crypto_primitives import *
import json

#Identity from registration.py
IoT_Identity= 82035478971259123442476348655689178763265947662226951356770556462596085405261
C_F0 = 23463903806953807842431617969019732927618817648364579493088905949190648809248
C_F1 = 56130256727970922694153193637085342496720701146161205257150377645439802282776
IoT_T_j= 95265415477471203397570617911574964654953060590569413853346805591915253533514

IoT_C_1= 96660611014739447327655946229167953636372761059426846278304971566265805594760
state= 7914639113350599556765007708874217835310467035816774076625498702666207416659
IoT_K_previous= 31117325389844503084244712533611686457352293220259477778503853065508984899608

# The Socket programming
parser = argparse.ArgumentParser(description = 'Client for IoT Simulation')
parser.add_argument('-c', '--connect', default="127.0.0.1", help='server to connect to') 
parser.add_argument('-i', '--iterations', default=1, help='how many tim to run') 
args = parser.parse_args()

def client_program():
    host = args.connect # as both code is running on same pc
    iterations = int(args.iterations) # how many time to run
    port = 5000  # socket server port number
    global IoT_C_1
    global state
    global IoT_K_previous


    i = 0

    while(i < iterations):

        client_socket = socket.socket()  # instantiate
        client_socket.connect((host, port))  # connect to the server

        message = ""
        # while message.lower().strip() != 'bye':
        StartTime=time.time() 
        # Step 1: Send hello
        message = "hello"
        client_socket.send(pickle.dumps(message))  # send message
        # print('IoT device: step 1: sent to gateway: ' + str(message))
        
        #Step 2: Receive the gateway authentication token # data contains: W, X_w_pub_key, Y_w_pub_key, sigmaZ
        data = client_socket.recv(2048)         
        # print('IoT device: step 2: received from gateway: ')
        # print(pickle.loads(data))  # show in terminal
        G_r_1 = pickle.loads(data)

        #do the IoT computation 2 and send the authentication token to the gateway
        # Message contains: P_1, P_2, P_3, sigma_t, T_1, T_2, s_1, s_2
        message, IoT_r_3, IoT_K_i = IoTobfuscationForR_2_ID(pickle.loads(data))

        
        #Step 3: Send the M_1,ID*,r_2*,K_i*,r_3* to the IoT gateway
        client_socket.send(pickle.dumps(message))
        # print('IoT device: Step 3: sent to gateway: ' + str(message))

        #Step 4: Receive the G_M_2, Sync_IoT_G from the IoT gateway
        data = client_socket.recv(2048)  
        # print("IoT device: Step 4: received from the gateway: " + str(pickle.loads(data)))
        message, IoT_K_s, state, IoT_C_1=computeNextSessionKey(pickle.loads(data), G_r_1, IoT_r_3, IoT_K_i,IoT_C_1,state)

        

        #Step 5: Send IoT_K_i_next_obfuscated to the IoT gateway
        client_socket.send(pickle.dumps(message))
        # print("IoT device: Step 5: send to the IoT gateway: ",message)

        #Step 6: Receive M_4 from the IoT gateway
        data = client_socket.recv(2048)
        # print("IoT device: Step 6: received from the gateway: " + str(pickle.loads(data)))
        IoT_K_previous,IoT_C_1,state=updatingChallengeDPUFconfiguration(pickle.loads(data),IoT_K_s,G_r_1,IoT_r_3,IoT_K_previous,IoT_K_i,IoT_C_1,state) 
        
        EndTime=time.time() 
        print("roundTime=", EndTime-StartTime)
        i = i + 1
        #end iterations
        client_socket.close()  # close the connection

        data = {
            "roundTime": EndTime-StartTime,
            "Session key": IoT_K_s
        }
        
        with open("output.json", "a") as f:
           json.dump(data, f)

def IoTobfuscationForR_2_ID(G_r_1):
    IoT_r_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
    IoT_r_3 = int.from_bytes(os.urandom(1024),'big')%P256.q

    IoT_ID_obfusacted=IoT_Identity^Hash(G_r_1,IoT_r_2)
    IoT_K_i=DPUF(IoT_C_1,state)
    IoT_K_i_obfuscated=IoT_K_i^IoT_K_previous
    IoT_A_M_1=Hash(IoT_K_i,G_r_1,IoT_r_3)
    IoT_r_2_obfuscated=FPUF(C_F0)^IoT_r_2
    IoT_r_2_obfuscated=IoT_r_2_obfuscated^FPUF(C_F1)^IoT_T_j
    IoT_r_3_obfuscated=IoT_r_3^IoT_K_i

    return (IoT_A_M_1, IoT_ID_obfusacted, IoT_r_2_obfuscated, IoT_K_i_obfuscated, IoT_r_3_obfuscated), IoT_r_3, IoT_K_i

def computeNextSessionKey(data, G_r_1, IoT_r_3, IoT_K_i, IoT_C_1, state):
    #G_M_2, Sync_IoT_G
    G_M_2 = data[0]
    Sync_IoT_G = data[1]

    assert G_M_2==Hash(IoT_K_i,Sync_IoT_G,G_r_1,IoT_r_3), "The authentication of the Gateway on the IoT device has failed"
    if Sync_IoT_G==-1:
        IoT_C_1=Hash(IoT_C_1)
        state=Hash(state)
    IoT_K_i=DPUF(IoT_C_1,state)
    IoT_K_i_next=DPUF(Hash(IoT_C_1),Hash(state))
    IoT_K_i_next_obfuscated=IoT_K_i_next^IoT_K_i
    IoT_K_s=Hash(G_r_1,IoT_r_3,IoT_K_i)
    print("The IoT session Key:",IoT_K_s)
    return IoT_K_i_next_obfuscated, IoT_K_s, state, IoT_C_1

def updatingChallengeDPUFconfiguration(M_4,IoT_K_s,G_r_1,IoT_r_3,IoT_K_previous,IoT_K_i,IoT_C_1,state):
    assert M_4 == Hash(IoT_K_s,G_r_1,IoT_r_3), "The synchronization keys between the IoT device and the gateway have not been updated on the IoT device"
    IoT_C_1 = Hash(IoT_C_1)
    IoT_K_previous=IoT_K_i
    state=Hash(state)  
    return  IoT_K_previous,IoT_C_1,state

if __name__ == '__main__':
    client_program()
