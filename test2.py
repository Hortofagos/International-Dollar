import socket
import threading

rendezvous = ('79.31.108.43', 443)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 50001))
sock.sendto(b'0', rendezvous)

while True:
    data = sock.recv(1024).decode()

    if data.strip() == 'ready':
        break

data = sock.recv(1024).decode()
ip, sport, dport = data.split(' ')

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', int(sport)))
sock.sendto(b'0', (ip, int(dport)))

def listen():
    while True:
        data1 = sock.recv(1024)
        print('\rpeer: {}\n> '.format(data1.decode()), end='')

listener = threading.Thread(target=listen, daemon=True)
listener.start()

while True:
    msg = input('> ')
    sock.sendto(msg.encode(), (ip, int(sport) ))

