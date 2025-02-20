import socket
import hashlib
import os
import sys
import pickle

HOST = 'localhost'
PORT = 1234

passwords = {}

def _generate_master_pass(password: str):
    salt = os.urandom(50)
    master_pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 862780)
    return master_pw.hex(), salt

def validate_login(conn: socket.socket, salt: bytes, master_pass_hex: str) -> bool:
    conn.send(pickle.dumps({"salt": salt}))
    hex = pickle.loads(conn.recv(1024))['master_pw']
    return hex == master_pass_hex

def main():
    master_pw_hex, salt = _generate_master_pass(sys.argv[1])
    sys.argv[1] = 0

    sock = socket.create_server((HOST, PORT))
    sock.listen()
    while True: 
        conn, _ = sock.accept()
        is_login_valid = validate_login(conn, salt, master_pw_hex)
        if is_login_valid:
            conn.send(is_login_valid.to_bytes())
            print("success")
            new_pw_bytes = conn.recv(4096)
            print(new_pw_bytes)
            new_pw = pickle.loads(new_pw_bytes)
            print(new_pw)


if __name__ == '__main__':
    main()