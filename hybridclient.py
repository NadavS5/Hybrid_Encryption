import random
import base64
from tabnanny import process_tokens
from time import sleep

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



connected_users = ["everyone"]

def disable_buttons():
    win.connect_button.setText("Disconnect")
    win.address_box.setEnabled(False)
    win.input_box.setEnabled(True)
    win.sign_up.setVisible(False)

    win.username.setEnabled(False)
    win.password.setEnabled(False)
    win.dropdown.setEnabled(False)

    set_users(["everyone"])
def enable_buttons():
    win.connect_button.setText("Connect")
    win.address_box.setEnabled(True)
    win.input_box.setEnabled(True)
    win.sign_up.setVisible(True)

    win.username.setEnabled(True)
    win.password.setEnabled(True)
    win.dropdown.setEnabled(True)

    set_users(["everyone"])

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
    try:
        match enc_type:
            case "none":
                return recv_by_size(s)
            case "aes":
                return recv_with_AES(s, pkey, DEFAULT_IV)
            case "rsa":
                return rsa.decrypt_RSA(recv_by_size(sock))
    except ConnectionAbortedError:
        return  b""

def log(message):
    formatted_text = f'<span style="color: black;">{message}</span>'
    win.log_box_signal.emit(formatted_text)


def err(message):
    formatted_text = f'<span style="color: red;">{message}</span>'
    win.log_box.append(formatted_text)


def green(message):
    formatted_text = f'<span style="color: green;">{message}</span>'
    win.log_box.append(formatted_text)


def text_print(message):
    win.text_box_signal.emit(f'<span style="color: Aqua;">{message}</span>')

def set_users(users: list[str]):
    win.online_users_signal.emit(users)
#action: "signup" | "login"
def connect_to_server(address, action: str):
    global enc_type
    global pkey
    global rsa
    global isconnected
    global sock
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
        match action:
            case "login":
                if login(win.username.text(), win.password.text()):

                    print(address)
                    disable_buttons()

                    isconnected = True

                else:
                    sock.close()
                    sock = socket.socket()
                    return
            case "signup":
                if sign_up(win.username.text(), win.password.text()):
                    disable_buttons()

                    isconnected = True
                else:
                    sock.close()
                    sock = socket.socket()
                    return

        win.start_listener()
    except Exception as ex:
        print("login failed")
        print(traceback.format_exc())

    # win.message_box.setText("connecting...")


def disconnect_from_server():
    global sock
    global isconnected
    print("disconnecting...")
    isconnected = False
    sock.close()
    sock = socket.socket()
    enable_buttons()

def send_to(target: str, message : str):
    
    b64_message = base64.b64encode(message.encode()).decode()
    print(f"sending message to {target} message: {message} b64_message: {b64_message}")
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
    send_encrypted(sock, f"LOGN~{name}~{password}")
    success = recv_encrypted(sock).decode()
    if success == "true":
        green("login succeeded")
        return True
    else:
        err("name or password not currect")
        return False

def sign_up(name, password):
    send_encrypted(sock, f"SIGN~{name}~{password}")
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
    text_print(f"you->{target}: {message}")


def handle_server_message(fields : list[str]):
    code = fields[0]
    match code:
        case "RECV":
            from_user, message = fields[1:]
            message = base64.b64decode(message).decode()
            text_print(f"{from_user}->me: {message}")
        case "BROD":
            from_user, message = fields[1:]
            message = base64.b64decode(message).decode()
            text_print(f"{from_user}->everyone: {message}")
        case "NEWU":
            new_user = fields[1]
            connected_users.append(new_user)
            set_users(connected_users)
            text_print(f"{new_user} connected")
        case "REMU":
            removed_user = fields[1]
            connected_users.remove(removed_user)
            set_users(connected_users)
            text_print(f"{removed_user} diconnected")



class Window(QMainWindow):
    log_box_signal = pyqtSignal(str)
    text_box_signal = pyqtSignal(str)
    online_users_signal = pyqtSignal(list)

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
        self.connect_button.clicked.connect(lambda _: connect_to_server( address=self.address_box.text(),action="login") if not isconnected else disconnect_from_server())
        self.layout.addWidget(self.connect_button, 1, 0, Qt.AlignmentFlag.AlignLeft)

        self.sign_up = QPushButton("Sign Up")
        self.sign_up.setFixedSize(100, 50)
        self.sign_up.clicked.connect(lambda _: connect_to_server( address=self.address_box.text(),action="signup") if not isconnected else disconnect_from_server())
        self.layout.addWidget(self.sign_up, 1, 1, Qt.AlignmentFlag.AlignLeft)

        self.message_box = QTextBrowser()
        self.layout.addWidget(self.message_box, 2, 1)

        self.users = QComboBox()
        self.users.addItems(["everyone"])
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

        self.log_box_signal.connect(self._log)
        self.text_box_signal.connect(self._text_print)
        self.online_users_signal.connect(self._set_users)
        print("signal ready")

    def _log(self, message):
        self.log_box.append(message)
    def _set_users(self, users : list[str]):
        current = self.users.currentText()
        self.users.clear()
        self.users.addItems(users)
        if current in users:
            self.users.setCurrentText(current)



    def _text_print(self, message):
        self.message_box.append(message)

    def start_listener(self):
        print("starting listener thread")
        t = threading.Thread(target=self.listener)
        t.start()
    def listener(self):
        global isconnected
        log("listener thread started")
        while isconnected:
            data = recv_encrypted(sock)
            if data ==b"":
                return
            handle_server_message(data.decode().split("~"))


win = Window()
win.show()
app.aboutToQuit.connect(lambda: exit())

app.exec()
app.exec()
