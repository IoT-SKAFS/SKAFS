# SKAFS
This is a python implementation of our protocol SKAFS: Symmetric Key Authentication Protocol with Forward Secrecy for Edge Computing. Our implementation consists of three parts.
## The Cryptographic Overhead Timing
A Python program to calculate the cryptographic overhead time, which comes from the cryptographic primitives in our protocol, such as the SHA-256 hash function, HMAC function, random number generation, AES-CBC mode encryption, fractional Hamming distance, EC point addition, EC scalar multiplication, and bilinear pairing. The measurements were reported based on the performance on two platforms: the Raspberry Pi 1 Model B+ with 512 MB of RAM and 0.7 GHz, and the Raspberry Pi 4 equipped with a 1.5 GHz 64-bit Quad-core ARM Cortex-A72 processor running Raspbian GNU/Linux 11 (bullseye). It was tested with Python 3.9.2.

### Running on The Raspberry Pi 4 and Pi 1
First, install the requirements:
```
pip3 install -r requirements.txt
```

Run the cryptographic primitives on the Raspberry Pi 4. The results will be stored in `PrimitiveComputationTime {iteration}.txt`

```
cd "Raspberry Pi 4 Computation"
python computationTime.py <# of iterations>
```

Run the cryptographic primitives on the Raspberry Pi 1. The results will be stored in `PrimitiveComputationTime {iteration}.txt`

```
cd "Raspberry Pi 1 Computation"
python computationTime.py <# of iterations>
```


## The Protocol Implementation
A Python implementation of the protocol where the registration for the IoT device and the IoT gateway are done. Afterwards, the protocol is executed between the IoT device, the IoT gateway, and the CA where the IoT device sends authentication request to the IoT gateway. This implementation shows the completeness of our the protocol and the agreement on the session key on both the IoT device and the IoT gateway.

run the protocol on the Laptop:
```
cd "SKAFS Implementation"
python SKAF.py
```

### Running The Protocol Implementation

Start the protocol on the Laptop:
```
cd "Socket Programming"
python SKAFS_server_CA.py
```

## The Socket Programming
A Python socket programming implementation of SKAFS to simulate the flow of our protocol messages between the IoT device, IoT gateway, and the cloud admin in a real-time experiment and to measure the end-to-end latency. The Raspberry Pi $1$ of $0.7$ GHz ARM11 processor and $512$ MB of RAM represents the IoT device while the Raspberry Pi $4$ represents the IoT gateway, and an Intel laptop 11th Gen Core i7-11800H clocked at 2.3 GHz with 16 GB RAM, acts as the server.
### Running The Socket Programming
Start the server on the Laptop. The CA will listen on port 5001:
```
cd "Socket Programming"
python SKAFS_server_CA.py
```
Start the gateway on the Raspberry Pi 4. The gateway will listen on port 5000. The IP address of the CA must be passed with the `-c` argument.
```
cd "Socket Programming"
python SKAFS_Server_Gateway.py -c <ip of CA>
```
Run the script file to start the IoT device on the Raspberry Pi 1. The end-to-end-latency for 100 iterations will be stored in the log file "output.log". Edit `python_args="-c 192.168.88.254"` in `run_iterations.sh` to reflect the IP address of the gateway. 
```
cd "Socket Programming"
sh run_iterations.sh
```
 
