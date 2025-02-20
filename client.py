import socket
import hashlib
import pickle
from getpass import getpass

def login(sock: socket.socket, master_pass: str) -> bool:
    salt = pickle.loads(sock.recv(1024))['salt']
    hex = hashlib.pbkdf2_hmac('sha256', master_pass.encode(), salt, 862780).hex()
    master_pass = 0
    master_pass_dict = pickle.dumps({"master_pw": hex})

    sock.send(master_pass_dict)

    sock.settimeout(15)
    success_or_fail = sock.recv(1024)
    return bool.from_bytes(success_or_fail), hex, salt
        

def set_password(sock: socket.socket, set_pass: str, master_pass_hex: str, username: str):
    new_hex = (hashlib.pbkdf2_hmac('sha256', set_pass.encode(), username.encode(), 862780) + bytes.fromhex(master_pass_hex)).hex()
    print(new_hex)
    data = pickle.dumps({username: new_hex})
    print("sending password")
    sock.send(data)

def retrieve_password(pw_key: dict, master_pass: str):
    pass

def main():
    sock = socket.socket()
    sock.connect(("127.0.0.1", 1234))
    master_pass = getpass("Enter master password: ")

    is_login_valid, hex, salt = login(sock, master_pass)
    master_pass = 0
    if is_login_valid:
        print("login complete")
        username = input("Enter a username for the password: ")
        set_pass = getpass("Enter a password to store: ")
        set_password(sock, set_pass, hex, username)

if __name__ == '__main__':
    main()