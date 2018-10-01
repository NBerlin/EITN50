import socket
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome import Random
from diffiehellman.diffiehellman import DiffieHellman
import base64
UDP_IP = "127.0.0.1"
UDP_PORT = 5005
bob = DiffieHellman()
bob.generate_public_key()

#pad och unpad
BS=16
unpad = lambda s : s[:-ord(s[len(s)-1:])]
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

#Sätter upp socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

#sessionkey
session = "aaaaaaaaaaaaaa"

#decrypt funktion
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

while True:
    #ta emot nytt meddelande
    data, addr = sock.recvfrom(4096)
    temp=data.decode()

    #handshake
    if temp.startswith("Handshake,"):
        data=temp.split(",")[1]
        sock.sendto(str(bob.public_key).encode(),(UDP_IP, 13000))
        print("received message:",data)
        test = int(data)
        bob.generate_shared_secret(test,echo_return_key=True)
        hash = SHA256.new()
        hash.update(str(bob.shared_key).encode())
        hash = hash.digest()
        print(bob.shared_key)
        session, addr = sock.recvfrom(4096)
        notenc = decrypt(session)
        print(str(notenc))
        session=str(notenc)
    else:
        print("--------------------------------")
        print("Meddelande innan decode: ")
        print(data.decode('utf-8'))
        print("--------------------------------")
        data = decrypt(data)
        if data.startswith(session):
            data=str(data.decode('utf-8')).split(",")[1]
            print("--------------------------------")
            print("Meddelandet: ")
            print(str(data))
            print("--------------------------------")




