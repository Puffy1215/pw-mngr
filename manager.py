import socket
import hashlib
import secrets
import sys
import pickle

HOST = "localhost"
PORT = 1234

passwords = {}
salt = secrets.token_bytes(50)


def validate_login(conn: socket.socket, salt: bytes, master_pass_hex: str) -> bool:
    conn.send(salt)
    hex = pickle.loads(conn.recv(1024))["master_pw"]
    return hex == master_pass_hex


def set_password(conn: socket.socket):
    new_pw_bytes = conn.recv(1024)
    print(new_pw_bytes)
    new_pw = pickle.loads(new_pw_bytes)
    passwords.update(new_pw)
    print(passwords)


def send_password(conn: socket.socket):
    print("howdy")
    username = conn.recv(1024).decode()
    token = passwords.get(username, "")
    print(token)
    conn.send(pickle.dumps({"token": token, "nonce": passwords["nonce"]}))


def main():
    sock = socket.create_server((HOST, PORT))
    sock.listen()
    master_pw_hex = None
    while True:
        conn, _ = sock.accept()
        if master_pw_hex is None:
            conn.send("00".encode())
            conn.send(salt)
            print("Master pass not set")
            obj = pickle.loads(conn.recv(1024))
            print(obj)
            master_pw_hex = obj["hex"]
        else:
            conn.send("01".encode())

        is_login_valid = validate_login(conn, salt, master_pw_hex)
        conn.send(is_login_valid.to_bytes())
        if is_login_valid:
            print("success")
            option = conn.recv(1024).decode()
            print(option)
            if option == "1":
                send_password(conn)
            elif option == "2":
                set_password(conn)


if __name__ == "__main__":
    main()
