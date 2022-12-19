import socket
import os
import random
import time
import threading
import base64
import rsa
import ipaddress
import string

already_tried = []
PORT = 443
def connect(indicator, data, ipnl):
    with open('rsa_public_key.txt', 'r') as rsk:
        key = rsk.read()
    start_time = int(time.time())
    while int(time.time()) - start_time <= 20:
        if random.randrange(1000) == 9:
            already_tried.clear()
        SERVER = random.choice(ipnl).replace('.txt', '')
        ADDR = (SERVER, PORT)
        try:
            if SERVER not in already_tried:
                client = socket.create_connection(ADDR, timeout=0.4)
                client.settimeout(4)
                client.sendall(key.encode('utf-8'))
                recv_key = client.recv(1024).decode('utf-8')
                public_key_node = rsa.PublicKey.load_pkcs1(base64.b64decode(recv_key))
                encrypted_data = rsa.encrypt((indicator + data).encode('utf-8'), public_key_node)
                encrypted_data_b64 = base64.b64encode(encrypted_data)
                client.sendall(encrypted_data_b64)
                try:
                    msg = client.recv(512).decode('utf-8')
                    client.close()
                    with open('rsa_private_key.txt', 'r') as rsk:
                        private_key = rsk.read()
                        rsa_pk = rsa.PrivateKey.load_pkcs1(base64.b64decode(private_key))
                    msg_decrypted = rsa.decrypt(base64.b64decode(msg), rsa_pk).decode('utf-8')
                    return msg_decrypted
                except:
                    return 'n'
        except :
            if SERVER not in already_tried:
                already_tried.append(SERVER)
    return 'n'


def connect_udp(sm, ip_range):
    random_port = random.randint(50000, 65000)
    with open('my_public_ip.txt', 'r') as mpi:
        my_ip = mpi.read()
        # try:
        udp_ip = connect('y', str(random_port), ip_range)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.settimeout(5)
        server_socket.bind(('', random_port))
        with open('rsa_public_key.txt', 'r') as p:
            public_key = p.read()
        if ipaddress.ip_address(my_ip).version == 4:
            server_socket.sendto('None'.encode('utf-8'), (udp_ip, random_port))
        else:
            server_socket.sendto('None'.encode('utf-8'), (udp_ip, random_port, 0, 0))
        response = []
        def listen():
            recv_pk = server_socket.recv(1024).decode('utf-8')
            if recv_pk == 'None':
                recv_pk = server_socket.recv(1024).decode('utf-8')
            time.sleep(0.4)
            print(recv_pk)
            pk_node = rsa.PublicKey.load_pkcs1(base64.b64decode(recv_pk))
            full_msg = ''.join(random.choices(string.ascii_uppercase + string.digits, k=9)) + '\n' + sm
            encrypted_data = rsa.encrypt(full_msg.encode('utf-8'), pk_node)
            encrypted_data_b64 = base64.b64encode(encrypted_data)
            if ipaddress.ip_address(my_ip).version == 4:
                server_socket.sendto(encrypted_data_b64, (udp_ip, random_port))
            else:
                server_socket.sendto(encrypted_data_b64, (udp_ip, random_port, 0, 0))
            data = server_socket.recv(1024).decode('utf-8')
            if data:
                data_decrypted = rsa.decrypt(base64.b64decode(data), recv_pk).decode('utf-8')
                response.append(data_decrypted)
            else:
                response.append('n')
        threading.Thread(target=listen).start()
        time.sleep(0.3)
        if ipaddress.ip_address(my_ip).version == 4:
            server_socket.sendto(public_key.encode('utf-8'), (udp_ip, random_port))
        else:
            server_socket.sendto(public_key.encode('utf-8'), (udp_ip, random_port, 0, 0))
        while True:
            time.sleep(0.1)
            if response:
                return response[0]

        # except:
        # pass


def send_bills():
    ipnl1 = os.listdir('ip_folder/1')
    ipnl2 = os.listdir('ip_folder/2')
    while True:
        for transaction in os.listdir('transaction_folder'):
            with open('transaction_folder/' + transaction, 'r') as tm:
                tm = tm.read()
                threading.Thread(target=connect, args=('b', tm, ipnl1)).start()
                for _ in range(2):
                    threading.Thread(target=connect, args=('b', tm, ipnl1 + ipnl2)).start()
                    time.sleep(0.1)
            os.remove('transaction_folder/' + str(transaction))


def public_ip():
    try:
        ipnl = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')
        ip_addr = connect('x', '', ipnl)
        if ip_addr:
            return ip_addr
    except:
        pass


def check_validity(serial_num):
    ipnl = os.listdir('ip_folder/1')
    ipnl2 = os.listdir('ip_folder/2')
    comparison = [' ']
    ct = str(int(time.time()))

    def main_nodes():
        # try:
        holder = connect('c', serial_num, ipnl)
        importance = int(max(0, 1800 - int(ct[0:4])) / 8)
        for x in range(importance):
            if holder != 'n':
                comparison.append((holder.splitlines()[0], holder.splitlines()[1]))
            else:
                comparison.append(" ")
        # except:
        # pass
    def full_nodes():
        # try:
        holder = connect('c', serial_num, ipnl2)
        if holder != 'n':
            comparison.append((holder.splitlines()[0], holder.splitlines()[1]))
        else:
            comparison.append(" ")
        # except:
        # pass
    def small_udp_node():
        holder = connect_udp(serial_num, ipnl + ipnl2)
        if holder != 'n':
            comparison.append((holder.splitlines()[0], holder.splitlines()[1]))
        else:
            comparison.append(" ")

    r1, r2, r3 = 4, 10, 20

    if int(ct[0:4]) < 1790:
        for t in range(r1):
            threading.Thread(target=main_nodes).start()
    for t2 in range(r2):
        threading.Thread(target=full_nodes).start()
    for t3 in range(r3):
        threading.Thread(target=small_udp_node).start()

    time.sleep(7)
    voted_holder = max(set(comparison), key=comparison.count)
    return voted_holder


def update_ip_list():
    # try:
    def new_main_ip():
        comparison_ip = []
        main_ips = os.listdir('ip_folder/1')
        def thrd():
            new_main = connect('u', 'main ip', main_ips)
            comparison_ip.append(new_main)

        for _ in range(len(main_ips)):
            threading.Thread(target=thrd).start()
        time.sleep(10)
        try:
            voted_new_ip = max(set(comparison_ip), key=comparison_ip.count)
            if voted_new_ip != 'n':
                open('ip_folder/1/' + str(voted_new_ip) + '.txt', 'w').close()
        except:
            pass

    if random.randint(0, 27) == 3:
        threading.Thread(target=new_main_ip).start()

    ipnl = os.listdir('ip_folder/2')
    list_ips = connect('u', '', ipnl)

    for c, ip in enumerate(list_ips.splitlines()):
        try:
            if ipaddress.ip_address(ip).version == 4:
                matches0 = 0
                matches1 = 0
                matches2 = 0
                for item_ip in os.listdir('ip_folder/2') + os.listdir('ip_folder/3'):
                    ip_split = item_ip.split('.')
                    if item_ip[0] == ip_split[0]:
                        matches0 += 1
                    if item_ip[0] + item_ip[1] == ip_split[0] + ip_split[1]:
                        matches1 += 1
                    if item_ip[0] + item_ip[1] + item_ip[2] == ip_split[0] + ip_split[1] + ip_split[2]:
                        matches2 += 1
                if matches0 < 32 and matches1 < 4 and matches2 < 1:
                    if (c % 2) == 0:
                        open('ip_folder/2/' + str(ip) + '.txt').close()
                    else:
                        open('ip_folder/3/' + str(ip) + '.txt').close()
        except:
            pass
    # except:
    # pass


def receive_bills():
    # try:
    ipnl = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')
    for wal in os.listdir('wallet_folder'):
        if wal.startswith('wallet_decrypted'):
            with open('wallet_folder/' + wal, 'r') as wa:
                wa.seek(0)
                wallet = wa.readlines()
                address = wallet[0].strip()
            msg = connect('r', address, ipnl)
            new_bills = []
            def confirm_bill(serial_number):
                bill_holder = check_validity(serial_number)
                if bill_holder[0] == address and serial_number + '\n' not in wallet:
                    new_bills.append((serial_number, bill_holder[1]))
            if msg != 'n':
                for sm in msg.splitlines():
                    if sm:
                        threading.Thread(target=confirm_bill, args=(sm,)).start()
                        break
                time.sleep(8)
                for b in new_bills:
                    with open('wallet_folder/' + wal, 'a') as wa2:
                        wa2.write(b[0] + ' ' + b[1] + ' ' + str(int(time.time())) + '\n')
    # except:
    # pass


def ask_for_luck():
    addr = ''
    for w in os.listdir('wallet_folder'):
        if w.startswith('wallet_decrypted'):
            addr += w[18:].replace('.txt', '')
    while True:
        try:
            ADDR = (PORT, random.choice(os.listdir('ip_folder/1')))
            client = socket.create_connection(ADDR, timeout=4)
            client.sendall('l' + addr.encode('utf-8'))
        except:
            pass

