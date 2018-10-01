import socket
from cypher import AESCipher
from diffiehellman.diffiehellman import DiffieHellman
UDP_IP = "127.0.0.1"
UDP_PORT = 5005
bob = DiffieHellman()
bob.generate_public_key()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(4096)
    data=data.decode()
    if data.startswith("Handshake,"):
        data=data.split(",")[1]
        sock.sendto(str(bob.public_key).encode(),(UDP_IP, 13000))
        print("received message:",data)
        test = int(data)
        bob.generate_shared_secret(test,echo_return_key=True)
        print(bob.shared_key)
        aescipher = AESCipher(bob.shared_key)
        session, addr = sock.recvfrom(4096)
        session = aescipher.decrypt(session)
        print(session)





