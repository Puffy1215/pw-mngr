import socket
import hashlib
import pickle
import base64
from getpass import getpass
from typing import Tuple
from cryptography.fernet import Fernet


def login(sock: socket.socket, master_pass: str) -> Tuple[bool, bytes]:
    salt = pickle.loads(sock.recv(1024))["salt"]
    master_pass_bytes = hashlib.pbkdf2_hmac(
        "sha256", master_pass.encode(), salt, 862780
    )
    master_pass = 0
    master_pass_dict = pickle.dumps({"master_pw": master_pass_bytes.hex()})

    sock.send(master_pass_dict)

    sock.settimeout(15)
    success_or_fail = sock.recv(1024)
    return bool.from_bytes(success_or_fail), master_pass_bytes


def set_password(sock: socket.socket, set_pass: str, username: str, fern: Fernet):
    token = fern.encrypt(set_pass.encode())
    print(f"TOKEN: {token}")

    data = pickle.dumps({username: token})
    print("sending password")
    sock.send(data)


def retrieve_password(sock: socket.socket, username: str, fern: Fernet):
    sock.send(username.encode())
    token = sock.recv(1024)
    print(f"RECIEVED TOKEN: {token}")
    print(fern.decrypt(token).decode())


def main():
    sock = socket.socket()
    sock.connect(("127.0.0.1", 1234))
    master_pass = getpass("Enter master password: ")

    is_login_valid, master_pass_bytes = login(sock, master_pass)
    master_pass = 0
    if is_login_valid:
        print("login complete")
        fern = Fernet(base64.urlsafe_b64encode(master_pass_bytes))
        username = input("Enter a username for the password: ")
        set_pass = getpass("Enter a password to store: ")
        set_password(sock, set_pass, username, fern)
        retrieve_password(sock, username, fern)
    else:
        print("login failed")
        sock.close()


if __name__ == "__main__":
    main()
