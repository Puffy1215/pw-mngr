import socket
import hashlib
import secrets
import sys
import pickle

HOST = "localhost"
PORT = 1234

passwords = {}


def validate_login(conn: socket.socket, salt: bytes, master_pass_hex: str) -> bool:
    conn.send(pickle.dumps({"salt": salt}))
    hex = pickle.loads(conn.recv(1024))["master_pw"]
    return hex == master_pass_hex


def set_password(conn: socket.socket):
    new_pw_bytes = conn.recv(1024)
    print(new_pw_bytes)
    new_pw = pickle.loads(new_pw_bytes)
    passwords.update(new_pw)
    print(passwords)


def send_password(conn: socket.socket):
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
            print("Master pass not set")
            conn.setblocking(True)
            obj = pickle.loads(conn.recv(1024))
            print(obj)
            master_pw_hex, salt = obj['hex'], obj['salt']
        else:
            is_login_valid = validate_login(conn, salt, master_pw_hex)
            conn.send(is_login_valid.to_bytes())
            if is_login_valid:
                print("success")
                set_password(conn)
                send_password(conn)
        


if __name__ == "__main__":
    main()
