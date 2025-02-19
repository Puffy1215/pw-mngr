import socket
import hashlib
import pickle

def login(sock: socket.socket, master_pass: str) -> bool:
    master_pass_dict = pickle.dumps({"master_pw": master_pass})
    sock.send(master_pass_dict)

    sock.settimeout(15)
    success_or_fail, _ = sock.accept()
    
    return False


def set_password(pw_dict: dict, master_pass: str):
    sock = socket.socket()
    sock.connect(("127.0.0.1", 1234))

    if login(sock, master_pass):
        data = pickle.dumps(pw_dict)    
        
        sock.send(data)
        sock.close()

def retrieve_password(pw_key: dict, master_pass: str):
    pass

def main():
    master_pass = input("Enter master password: ")
    set_password({"test": "test1"}, master_pass)

if __name__ == '__main__':
    main()