import math
import socket

def main():
    ip = '0.0.0.0'
    port = 1234

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.bind((ip, port))
    srv_sock.listen(5)

    cli_sock, addr = srv_sock.accept()
    p = 23
    g = 5

    cli_sock.send(str(p).encode())
    cli_sock.send(str(g).encode())

    a = 3
    A = int(math.pow(g,a) % p)

    cli_sock.send(str(A).encode())
    B = int(cli_sock.recv(1024).decode())

    key = math.pow(B,a) % p
    print(key)

if __name__ == '__main__':
    main()
