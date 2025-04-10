import hashlib
import os.path
import pickle
import socket
import threading


from tcp_by_size import recv_by_size, send_with_size
import random
from TCP_AES import recv_with_AES, send_with_AES
from rsa_lib import RSA_CLASS


server_sock = socket.socket()
server_sock.bind(("127.0.0.1", 8553))
server_sock.listen(5)

DEFAULT_IV = bytes.fromhex("c2dbc239dd4e91b46729d73a27fb57e9")
print(len(DEFAULT_IV))

def hash_password(username, password, salt):
    return hashlib.sha256(bytes(f"{username}${password}${salt}".encode() )).digest()

#username: (hashed_pass, salt)
if os.path.isfile("users.pkl"):
    with open("users.pkl", "rb") as f:
        users = pickle.load(f)
else:
    hash_pwd = hash_password("nadav", "123", bytes(12387))
    users = {
        "nadav": (hash_pwd, bytes(12387))
    }
    with open("users.pkl", "wb+") as f:
        pickle.dump(users, f)

def send_encrypted(s, enc_type,  message : bytes | bytearray, aes_key = None,  rsa_key = None,):
    print(f"sending: {message}")

    match enc_type:

        case "none":
            send_with_size(s, message)
        case "aes":
            send_with_AES(s, message, aes_key, DEFAULT_IV)
        case "rsa":
            send_with_size(s, rsa_key.encrypt_RSA(message))


def recv_encrypted(s, enc_type, aes_key = None,rsa_key = None):
    match enc_type:
        case "none":
            return recv_by_size(s)
        case "aes":
            return recv_with_AES(s, aes_key, DEFAULT_IV)
        case "rsa":
            return rsa_key.decrypt_RSA(recv_by_size(s))


def exchange_keys(sock : socket.socket) ->int:
    # server sends the public params first
    p = 23
    g = 5

    send_with_size(sock, str(p))
    send_with_size(sock, str(g))

    a = random.randint(3, 96)
    A = (g ** a) % p
    # print(f"a:{a}")
    # print(f"A:{A}")

    send_with_size(sock, str(A))

    B = int(recv_by_size(sock))
    # print(f"B:{B}")

    s = (B ** a) % p
    # print("key:", s)
    return s

def handle_log_in(username, password) -> bool:
    salt = users[username][1]
    if users[username][0] != hash_password(username, password, salt):
        return False
    return True

def handle_sign_up(username, password) -> bool:
    salt = hashlib.sha256(bytes(random.randint(0,10000000000))).digest()
    hashed_password = hash_password(username, password, salt)
    if username not in users.keys():
        users[username] = (hashed_password, salt)
        with open("users.pkl", "wb+") as f1:
            pickle.dump(users, f1)
        return True
    return False

def handle_client(sock: socket.socket):
    key = 0
    rsa = 0

    print("connection")
    enc_type = recv_by_size(client).decode()
    print(f"enc_type = {enc_type}")

    if enc_type != "none":
        key = exchange_keys(sock)
        key = hashlib.sha256(bytes(key)).digest()
        print(key)
    if enc_type == "rsa":
        rsa = RSA_CLASS()
        send_encrypted(sock, "aes",  rsa.public_key, aes_key= key)
        other_public = recv_encrypted(sock,  "aes", aes_key = key)
        print(other_public)
        rsa.set_other_public(other_public)
        enc_type = "rsa"


    uname, password = recv_encrypted(sock, enc_type, aes_key= key,rsa_key= rsa ).decode().split('~')
    print(uname)
    print(password)

    send_encrypted(sock,enc_type, str(handle_log_in(uname, password)).lower().encode(), aes_key=key, rsa_key=rsa )
    print("main loop")
    while True:
        data = recv_encrypted(sock, enc_type, aes_key= key,rsa_key= rsa )
        if data == b"":
            return
        print(f"{uname}->{data}")

while True:
    client, addr = server_sock.accept()
    thread = threading.Thread(target=handle_client, args=(client,))
    thread.start()
