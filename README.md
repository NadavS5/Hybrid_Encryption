School Project.
# Hybrid Encryption
Hybrid Encryption is a fully encrypted client chat program that allows you to chat with other users securely.
it has RSA / AES. keys are transfered with dippie hellman.

The default server port is: 8553
if you want to change it, modify line 22 client and line 17 server

to run the code
1. install dependencies
~~~
pip install -r requirements.txt
~~~
2. run the server
~~~
python hybridserver.py
~~~
3. run the client
~~~
python hybridclient.py
~~~
