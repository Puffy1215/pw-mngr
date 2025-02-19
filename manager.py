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

def validate_login(master_pass_obj: dict, salt: bytes, master_pass_hex: str) -> bool:
    password = master_pass_obj.get("master_pw", "")
    if password == "":
        return ""
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 862780)
    return password_hash.hex() == master_pass_hex

def main():
    master_pw_hex, salt = _generate_master_pass(sys.argv[1])
    sock = socket.create_server((HOST, PORT))
    sock.listen()
    while True: 
        conn, address = sock.accept()
        obj = pickle.loads(conn.recv(1024))
        print(validate_login(obj, salt, master_pw_hex))



if __name__ == '__main__':
    main()