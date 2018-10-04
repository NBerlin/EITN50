import socket
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import random
from diffiehellman.diffiehellman import DiffieHellman


#testar mig fram
alice = DiffieHellman()
alice.generate_public_key()
UDP_IP = "127.0.0.1"
UDP_PORT = 5005


print("UDP target IP:",UDP_IP)
print("UDP target port:",UDP_PORT)
print("Public key: ", alice.public_key)

# Code stolen from: https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
#--------------------------------------------------------------------------------------------------------
BS=16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

def encrypt(raw):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(hash, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw.encode("utf8")))
#--------------------------------------------------------------------------------------------------------

#sock setup
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((UDP_IP, 13000))

#Handshake
sock.sendto(("Handshake,"+str(alice.public_key)).encode(), (UDP_IP, UDP_PORT))
data, addr = sock.recvfrom(4096)
test = int(data.decode())
alice.generate_shared_secret(test,echo_return_key=True)
print(alice.shared_key)
hash = SHA256.new()
hash.update(str(alice.shared_key).encode())
hash = hash.digest()
session = random.getrandbits(128)
print(session)
test = pad(str(session))
iv = Random.new().read( AES.block_size )
obj = AES.new(hash,AES.MODE_CBC, iv)
encrypted_message = base64.b64encode(iv + obj.encrypt(test.encode("utf8")))
print(encrypted_message)
sock.sendto(encrypted_message, (UDP_IP, UDP_PORT))
session_number=1
while True:
    message = input("Send message")
    newstr=",".join((str(session),message,str(session_number)))
    sock.sendto(encrypt(newstr), (UDP_IP, UDP_PORT))
    session_number += 1





