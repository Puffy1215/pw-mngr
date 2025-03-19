import secrets
import socket
import hashlib
import pickle
from constants import Action, MasterPasswordStatus
from getpass import getpass
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _generate_master_pass(sock: socket.socket, password: str, salt: bytes):
    master_pw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 862780)
    obj = pickle.dumps({"hex": master_pw.hex()})
    sock.send(obj)


def login(sock: socket.socket) -> Tuple[bool, bytes]:
    obj_bytes = sock.recv(2)
    if obj_bytes.decode() == MasterPasswordStatus.EMPTY.value:
        salt = sock.recv(1024)
        print("Password is not set")
        master_pass = getpass("Set master password: ")
        _generate_master_pass(sock, master_pass, salt)

    master_pass = getpass("Enter master password to login: ")

    salt = sock.recv(1024)
    master_pass_bytes = hashlib.pbkdf2_hmac(
        "sha256", master_pass.encode(), salt, 862780
    )
    master_pass = 0
    master_pass_dict = pickle.dumps({"master_pw": master_pass_bytes.hex()})

    sock.send(master_pass_dict)

    success_or_fail = sock.recv(1024)
    return bool.from_bytes(success_or_fail), master_pass_bytes


def set_password(sock: socket.socket, set_pass: str, username: str, crypt: AESGCM):
    sock.send(Action.SET.value.encode())
    nonce = secrets.token_bytes(12)
    token = crypt.encrypt(nonce, set_pass.encode(), None)
    print(f"TOKEN: {token}")

    data = pickle.dumps({username: token, "nonce": nonce})
    print("sending password")
    sock.send(data)


def retrieve_password(sock: socket.socket, username: str, crypt: AESGCM):
    sock.send(Action.RETRIEVE.value.encode())
    sock.send(username.encode())
    obj = pickle.loads(sock.recv(1024))
    print(f"RECIEVED TOKEN: {obj["token"]}")
    print(crypt.decrypt(obj["nonce"], obj["token"], None).decode())


def main():
    sock = socket.socket()
    sock.settimeout(15)
    sock.connect(("127.0.0.1", 1234))

    is_login_valid, master_pass_bytes = login(sock)
    if is_login_valid:
        print("login complete")
        aes = AESGCM(master_pass_bytes)

        user_input = input("[1] Retrieve password [2] Set Password [3] Exit: ")

        if user_input == Action.RETRIEVE.value:
            username = input("Enter a username for the password: ")
            retrieve_password(sock, username, aes)
        elif user_input == Action.SET.value:
            username = input("Enter a username for the password: ")
            set_pass = getpass("Enter a password to store: ")
            set_password(sock, set_pass, username, aes)
        else:
            sock.close()
            exit(0)

    else:
        print("login failed")
        sock.close()


if __name__ == "__main__":
    main()
