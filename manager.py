import socket
import pickle

HOST = 'localhost'
PORT = 1234

sock = socket.create_server((HOST, PORT))

passwords = {}
def main():
    sock.listen()
    while True: 
        conn, address = sock.accept()
        obj = pickle.loads(conn.recv(1024))
        print(f'Connected with {address[0]}, {obj}')
        
        passwords.update(obj)
        print(passwords)


if __name__ == '__main__':
    main()