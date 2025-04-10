import socket, math


def main():
    ip = '127.0.0.1'
    port = 1234
    sock = socket.socket()

    sock.connect((ip,port))

    p = int(sock.recv(1024).decode())
    g = int(sock.recv(1024).decode())

    b = 4
    B = int(math.pow(g,b) % p)

    sock.send(str(B).encode())
    A = int(sock.recv(1024).decode())

    key = math.pow(A,b) % p
    print(key)
if __name__ == '__main__':
    main()
