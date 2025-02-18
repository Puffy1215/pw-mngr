import socket
import pickle

def set_password():
    pass

def retrieve_password():
    pass

def main():
    data = pickle.dumps({"test": "test1"})
    sock = socket.socket()
    sock.connect(("127.0.0.1", 1234))
    sock.send(data)
    sock.close()

if __name__ == '__main__':
    main()