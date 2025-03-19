import argparse
import socket
import secrets
import pickle
from threading import Thread

from constants import Action, MasterPasswordStatus

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
    username = conn.recv(1024).decode()
    token = passwords.get(username, "")
    print(token)
    conn.send(pickle.dumps({"token": token, "nonce": passwords["nonce"]}))


def set_master_pass(conn: socket.socket, master_pw_hex: str):
    if master_pw_hex is None:
        conn.send(MasterPasswordStatus.EMPTY.value.encode())
        conn.send(salt)
        print("Master pass not set")
        obj = pickle.loads(conn.recv(1024))
        print(obj)
        master_pw_hex = obj["hex"]
    else:
        conn.send(MasterPasswordStatus.SET.value.encode())

    return master_pw_hex


def handle_connections(conn: socket.socket, master_pw_hex: str):
    is_login_valid = validate_login(conn, salt, master_pw_hex)
    conn.send(is_login_valid.to_bytes())
    if is_login_valid:
        print("success")
        option = conn.recv(1024).decode()
        print(option)
        if option == Action.RETRIEVE.value:
            send_password(conn)
        elif option == Action.SET.value:
            set_password(conn)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        help="Port number for manager to run on. Defaults to 1234.",
        default=1234,
    )
    args = parser.parse_args()

    sock = socket.create_server((HOST, args.port))
    sock.listen()
    master_pw_hex = None
    while True:
        conn, _ = sock.accept()
        master_pw_hex = set_master_pass(conn, master_pw_hex)
        connection_thread = Thread(
            target=lambda a, b: handle_connections(a, b),
            args=(conn, master_pw_hex),
        )

        connection_thread.start()


if __name__ == "__main__":
    main()
