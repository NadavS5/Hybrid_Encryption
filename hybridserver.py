import hashlib
import os.path
import pickle
import socket
import threading
from os import urandom

from AsyncMessages import AsyncMessages
from tcp_by_size import recv_by_size, send_with_size
import random
from TCP_AES import recv_with_AES, send_with_AES
from rsa_lib import RSA_CLASS

import base64

server_sock = socket.socket()
server_sock.bind(("127.0.0.1", 8553))
server_sock.listen(5)

DEFAULT_IV = bytes.fromhex("c2dbc239dd4e91b46729d73a27fb57e9")


asmgs = AsyncMessages()

def hash_password(username, password, salt):
    return hashlib.sha256(bytes(f"{username}${password}${salt}".encode() )).digest()

#users: username: (hashed_pass, salt)
if os.path.isfile("users.pkl"):
    with open("users.pkl", "rb") as f:
        users = pickle.load(f)
else:
    salt1 = hashlib.sha256(urandom(256)).digest()
    salt2 = hashlib.sha256(urandom(256)).digest()

    hash_pwd = hash_password("nadav", "123", salt1)
    hash_pwd2 = hash_password("elay", "123", salt2)
    users = {
        "nadav": (hash_pwd, salt1),
        "elay":  (hash_pwd2, salt2)
    }
    with open("users.pkl", "wb+") as f:
        pickle.dump(users, f)


def send_encrypted(s, enc_type,  message : bytes | bytearray, aes_key = None,  rsa_key = None,):

    match enc_type:

        case "none":
            send_with_size(s, message)
        case "aes":
            send_with_AES(s, message, aes_key, DEFAULT_IV)
        case "rsa":
            send_with_size(s, rsa_key.encrypt_RSA(message))


def recv_encrypted(s, enc_type, aes_key = None,rsa_key = None):
        try:
            match enc_type:
                case "none":
                    return recv_by_size(s)
                case "aes":

                    data = recv_with_AES(s, aes_key, DEFAULT_IV)

                    return data
                case "rsa":
                    try:
                        data = recv_by_size(s)
                        if data == b"" or data == "":
                            return b""
                        return rsa_key.decrypt_RSA(data)
                    except ConnectionError:
                        return b""
        except ConnectionError:
            return b""


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

    if username in users.keys():

        salt = users[username][1]
        if users[username][0] != hash_password(username, password, salt):
            return False
        return True
    else:
        return False

def handle_sign_up(username, password) -> bool:
    salt = hashlib.sha256(hashlib.sha256(urandom(256)).digest()).digest()
    hashed_password = hash_password(username, password, salt)

    if username not in users.keys():

        users[username] = (hashed_password, salt)

        # print("dumping to users.pkl")
        # print(users)
        with open("users.pkl", "wb+") as f1:
            pickle.dump(users, f1)
        return True
    return False
def handle_message_code(fields, username):
    code = fields[0]
    # print(fields)
    match code:
        case "SEND":
            pass
            target = fields[1]
            message = base64.b64decode(fields[2]).decode()
            print(f"{username} -> {target}: {message}")
            asmgs.put_msg_by_user(target, f"RECV~{username}~{fields[2]}".encode())
        case "BROD":
            message = base64.b64decode(fields[1]).decode()
            print(f"{username} sending to everyone: {message}")
            asmgs.put_msg_to_all(f"BROD~{username}~{fields[1]}")
    
    
    
def handle_client(sock: socket.socket):
    key = 0
    rsa = 0

    # print("connection")
    enc_type = recv_by_size(client).decode()
    # print(f"enc_type = {enc_type}")

    if enc_type != "none":
        key = exchange_keys(sock)
        key = hashlib.sha256(bytes(key)).digest()
        # print(key)
    if enc_type == "rsa":
        rsa = RSA_CLASS()
        send_encrypted(sock, "aes",  rsa.public_key, aes_key= key)
        other_public = recv_encrypted(sock,  "aes", aes_key = key)
        # print(other_public)
        rsa.set_other_public(other_public)
        enc_type = "rsa"

    action, uname, password = recv_encrypted(sock, enc_type, aes_key= key,rsa_key= rsa ).decode().split('~')
    match action:
        case "LOGN":

            # print(uname)
            # print(password)
            status = handle_log_in(uname, password)
            send_encrypted(sock, enc_type, str(status).lower().encode(), aes_key=key,
                           rsa_key=rsa)
            if not status:
                return
            print(f"{uname} logged in")
        case "SIGN": #sign up
            print("signing up")
            status = handle_sign_up(uname, password)
            send_encrypted(sock, enc_type, str(status).lower().encode(), aes_key=key,
                           rsa_key=rsa)

            if not status:
                return
            print(f"{uname} signed up")

    #anounce to everyone that a new user is connected
    asmgs.put_msg_to_all(f"NEWU~{uname}")

    asmgs.add_new_user(uname)
    #send all online users to clients
    # print("sending to user all online users:")
    for user in asmgs.async_msgs.keys():
        if user != uname:
            send_encrypted(sock, enc_type, f"NEWU~{user}".encode(), aes_key=key,
                           rsa_key=rsa)

    while True:
        sock.settimeout(0.1)
        try:
            data = recv_encrypted(sock, enc_type, aes_key= key,rsa_key= rsa ).decode()
            if data == "":
                print(f"{uname} left")
                asmgs.delete_user(uname)
                asmgs.put_msg_to_all(f"REMU~{uname}".encode())
                return

            fields = data.split('~')
            handle_message_code(fields, uname)
        except socket.timeout:
            msgs = asmgs.get_async_messages_to_send(uname)
            if msgs != []:
                for message in msgs:
                    send_encrypted(sock, enc_type, message, aes_key=key,rsa_key=rsa)
            continue
        # print(f"{uname}->{data}")

while True:
    client, addr = server_sock.accept()
    thread = threading.Thread(target=handle_client, args=(client,))
    thread.start()
