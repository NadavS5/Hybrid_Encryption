import random
import base64
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QLineEdit, QGridLayout, QWidget, \
    QRadioButton, QTextBrowser, QComboBox
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
import socket
import threading
from PyQt6 import QtCore

from rsa_lib import RSA_CLASS
from tcp_by_size import send_with_size, recv_by_size
import threading
import hashlib
from TCP_AES import send_with_AES, recv_with_AES
import traceback

sock = socket.socket()
PORT = 8553

app = QApplication([])

isconnected = False

enc_type = ""
pkey = None

rsa = RSA_CLASS()

DEFAULT_IV = bytes.fromhex("c2dbc239dd4e91b46729d73a27fb57e9")
print(len(DEFAULT_IV))

def send_encrypted(s, message):
    print(f"enc: {enc_type} sending: {message}")
    global  pkey
    global rsa

    match enc_type:
        case "none":
            send_with_size(s, message)
        case "aes":
            send_with_AES(sock, message, pkey, DEFAULT_IV)
        case "rsa":
            send_with_size(s, rsa.encrypt_RSA(message))
def recv_encrypted(s):
    match enc_type:
        case "none":
            return recv_by_size(s)
        case "aes":
            return recv_with_AES(s, pkey, DEFAULT_IV)
        case "rsa":
            return rsa.decrypt_RSA(recv_by_size(sock))

def log(message):
    formatted_text = f'<span style="color: black;">{message}</span>'
    win.log_box.append(formatted_text)


def err(message):
    formatted_text = f'<span style="color: red;">{message}</span>'
    win.log_box.append(formatted_text)


def green(message):
    formatted_text = f'<span style="color: green;">{message}</span>'
    win.log_box.append(formatted_text)


def text_print(message):
    win.message_box.append(f'<span style="color: blue;">you-> {message}</span>')


def connect_to_server(address):
    global enc_type
    global pkey
    global rsa
    global isconnected
    log("connecting...")
    try:
        sock.connect(("127.0.0.1", PORT))

    except Exception as ex:
        err(f"couldnt connect to server {err}")
        print(err)
        return
    enc_type = win.dropdown.currentText()
    send_with_size(sock, enc_type)
    try:
        if enc_type != "none":
            pkey = exchange_keys()
            pkey = hashlib.sha256(bytes(pkey)).digest()
            print(pkey)
        if enc_type == "rsa":
            enc_type = "aes"
            other_public = recv_encrypted(sock)
            # print("other public", other_public)
            rsa.set_other_public(other_public)
            print("-------------------------")
            print(rsa.public_key)
            send_encrypted(sock, rsa.public_key)
            enc_type = "rsa"

    except Exception as Ex:
        err(f"couldn't exchange keys")
        print("couldn't exchange keys")
        traceback.print_exc()
        sock.close()
        return

    try:
        if login(win.username.text(), win.password.text()):

            print(address)
            win.connect_button.setText("Disconnect")
            win.address_box.setEnabled(False)
            win.input_box.setEnabled(True)
            win.listener()

            isconnected = True

        else:
            sock.close()
    except Exception as ex:
        print("login failed")
        print(traceback.format_exc())

    # win.message_box.setText("connecting...")


def disconnect_from_server(address):
    print("disconnecting...")
    isconnected = False
    sock.close()
    win.connect_button.setText("Connect To Server")

def send_to(target: str, message : str):
    
    b64_message = base64.b64encode(message.encode()).decode()
    
    if target == 'everyone':
            send_encrypted(sock, f"BROD~{b64_message}")
    else:
        send_encrypted(sock, f"SEND~{target}~{b64_message}")

def toggle_password_visible(checked: bool):
    global password_visible

    if checked:
        win.password.setEchoMode(QLineEdit.EchoMode.Password)

    else:
        win.password.setEchoMode(QLineEdit.EchoMode.Normal)


def login(name, password):
    send_encrypted(sock, f"{name}~{password}")
    success = recv_encrypted(sock).decode()
    if success == "true":
        green("login succeeded")
        return True
    else:
        err("name or password not currect")
        return False


def exchange_keys():
    global pkey
    p = int(recv_by_size(sock))
    g = int(recv_by_size(sock))
    A = int(recv_by_size(sock))
    print("p,g,A",p,g,A)
    b = random.randint(0,p)
    B = (g**b) % p
    send_with_size(sock,str(B))

    s = (A **b) % p
    pkey = s
    return s


@QtCore.pyqtSlot()
def handle_send_message():
    message = win.input_box.text()
    target = win.users.currentText()
    send_to(target,message)
    win.input_box.setText("")
    win.text_print(message)


class Window(QMainWindow):
    log_box_signal = pyqtSignal(str)
    text_box_signal = pyqtSignal(str)

    def __init__(self):
        window = QMainWindow()
        window.show()
        super().__init__()

        self.layout = QGridLayout()

        self.address_box = QLineEdit()
        self.address_box.setPlaceholderText("server address")
        self.address_box.setText("127.0.0.1")
        self.layout.addWidget(self.address_box, 0, 0)

        self.username = QLineEdit()
        self.username.setPlaceholderText("username")
        self.layout.addWidget(self.username, 0, 1)

        self.password_visible = QRadioButton()
        self.password_visible.clicked.connect(toggle_password_visible)
        self.layout.addWidget(self.password_visible, 0, 3)
        self.password_visible.setChecked(True)

        self.password = QLineEdit()
        self.password.setPlaceholderText("password")
        self.layout.addWidget(self.password, 0, 2)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        super().setMinimumSize(500, 100)
        super().setWindowTitle("Hybrid Encryption Client")

        # self.button1 = QPushButton("exchange keys")
        # self.button1.setFixedSize(100,50)
        # self.button1.clicked.connect(lambda _: print("exchange keys"))
        # self.layout.addWidget(self.button1, 1,1, Qt.AlignmentFlag.AlignCenter)

        self.dropdown = QComboBox()
        self.dropdown.addItems(["none", "aes", "rsa"])
        self.layout.addWidget(self.dropdown, 1, 2, Qt.AlignmentFlag.AlignCenter)

        self.connect_button = QPushButton("Connect")
        self.connect_button.setFixedSize(100, 50)
        self.connect_button.clicked.connect(lambda _: connect_to_server(
        address=self.address_box.text() if not isconnected else disconnect_from_server(self.address_box.text())))
        self.layout.addWidget(self.connect_button, 1, 0, Qt.AlignmentFlag.AlignLeft)

        self.sign_up = QPushButton("Sign Up")
        self.sign_up.setFixedSize(100, 50)
        # self.sign_up.clicked.connect(lambda _: connect_to_server(
        # address=self.address_box.text() if not isconnected else disconnect_from_server(self.address_box.text())))
        self.layout.addWidget(self.sign_up, 1, 1, Qt.AlignmentFlag.AlignLeft)

        self.message_box = QTextBrowser()
        self.layout.addWidget(self.message_box, 2, 1)

        self.users = QComboBox()
        self.users.addItems(["everyone", "nadav", "elay"])
        self.layout.addWidget(self.users, 3, 0, Qt.AlignmentFlag.AlignCenter)


        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("enter a message")
        # self.input_box.returnPressed.connect(lambda _:send_message(self.input_box.text()))
        # self.input_box.returnPressed.connect(lambda x: send_message(self.input_box.text()))
        self.input_box.returnPressed.connect(handle_send_message)
        self.input_box.setText("")
        self.input_box.setEnabled(False)

        self.layout.addWidget(self.input_box, 3, 1)

        self.log_box = QTextBrowser()
        self.log_box.setStyleSheet("background-color: #dddddd;")
        self.layout.addWidget(self.log_box, 2, 2)

        self.center_widget = QWidget()
        self.center_widget.setLayout(self.layout)
        super().setCentralWidget(self.center_widget)

        self.log_box_signal.connect(log)
        self.text_box_signal.connect(text_print)
        print("signal ready")

    def log(self, message):
        self.log_box_signal.emit(message)

    def text_print(self, message):
        self.text_box_signal.emit(message)

    def start_listener(self):
        print("starting listener thread")
        t = threading.Thread(target=self.listener)
        t.start()

    def listener(self):
        self.log("hello from listener")
        while True:
            sock.settimeout(0.1)
            try:
                data = recv_encrypted(sock)
            except socket.timeout:
                continue
            except Exception:
                traceback.print_exc()

win = Window()
win.show()
app.aboutToQuit.connect(lambda: exit())

app.exec()
app.exec()
