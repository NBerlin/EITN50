import socket
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from diffiehellman.diffiehellman import DiffieHellman
import base64
UDP_IP = "127.0.0.1"
UDP_PORT = 5005
bob = DiffieHellman()
bob.generate_public_key()

#Sätter upp socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

#sessionkey
session = "aaaaaaaaaaaaaa"

#encrypt, decrypt, pad och unpad funktion tagen från
#https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
def decrypt( enc ):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(hash, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc[16:] ))
def encrypt(raw):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(hash, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

#pad och unpad
BS=16
unpad = lambda s : s[:-ord(s[len(s)-1:])]
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
while True:
    #ta emot nytt meddelande
    data, addr = sock.recvfrom(4096)
    temp=data.decode()

    #handshake
    if temp.startswith("Handshake,"):
        data =temp.split(",")[1]
        sock.sendto(str(bob.public_key).encode(),(UDP_IP, 13000))
        print("Public key of Server:",bob.public_key)
        print("Public key of Client:",data)
        test = int(data)
        bob.generate_shared_secret(test,echo_return_key=True)
        hash = SHA256.new()
        hash.update(str(bob.shared_key).encode())
        hash = hash.digest()
        print("Symmetric shared key: ",bob.shared_key)
        session, addr = sock.recvfrom(4096)
        session = decrypt(session)
        print("Sesssion number:",session.decode('utf-8'))
        session_number = 1

    else:
        print("------------------------------------")
        print("Meddelande innan decode: ",data.decode('utf-8'))
        data = decrypt(data)
        if data.startswith(session):
            session_number_msg = str(data.decode('utf-8')).split(",")[2]
            if session_number==int(session_number_msg):
                message = str(data.decode('utf-8')).split(",")[1]
                print("Meddelandet: ",str(message))
                print("Session nummer: ",str(session_number))
                print("------------------------------------")
                session_number += 1




