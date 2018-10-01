import socket
from cypher import AESCipher
import hashlib,random
from diffiehellman.diffiehellman import DiffieHellman


#testar mig fram
alice = DiffieHellman()
alice.generate_public_key()
UDP_IP = "127.0.0.1"
UDP_PORT = 5005


print("UDP target IP:",UDP_IP)
print("UDP target port:",UDP_PORT)
print("Public key: ", alice.public_key)

#sock setup
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((UDP_IP, 13000))

#Handshake
sock.sendto(("Handshake,"+str(alice.public_key)).encode(), (UDP_IP, UDP_PORT))
data, addr = sock.recvfrom(4096)
test = int(data.decode())
alice.generate_shared_secret(test,echo_return_key=True)
print(alice.shared_key)
aesciph = AESCipher(alice.shared_key)
session = random.getrandbits(128)
print(session)





