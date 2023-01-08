import time
import rsa
import base64
import socket
import threading
import os
from node_client import new_ip
import ipaddress
import random
import sqlite3
from multiprocessing import Process, Manager
from node_client import download_bills
from hashlib import sha3_256
import confirm_validity
import base58

def udp_node(rfb, rfb_response, potential_conns):
    new_ip('3')

    def access_database(sma):
        random_num1 = str(random.uniform(0.1, 99.9))
        rfb.append((random_num1 + sma))
        time.sleep(0.8)
        for respon in rfb_response:
            if respon[0] == random_num1:
                rfb_response.remove(respon)
                return respon[2:]
        else:
            return

    def handle_client(nef):
        ip, port = nef[0], int(nef[1])
        with open('rsa_public_key.txt', 'r') as rk:
            key = rk.read()
        with open('rsa_private_key.txt', 'r') as rsk:
            private_key = rsk.read()
            rsa_pk = rsa.PrivateKey.load_pkcs1(base64.b64decode(private_key))

        def rsa_process(m, p_key):
            msg_decrypted = rsa.decrypt(base64.b64decode(m), rsa_pk).decode('utf-8')
            mspl = msg_decrypted.splitlines()
            random_verify = mspl[0]
            serial_num = mspl[1]
            with open('full_activation/' + serial_num.split('x')[0] + '.txt', 'r') as fa:
                is_downloaded = fa.read().strip('x')
                if int(is_downloaded) > int(serial_num.split('x')[1]):
                    db = access_database(serial_num)
                    key2 = rsa.PublicKey.load_pkcs1(base64.b64decode(p_key))
                    full_msg = random_verify + '\n' + '\n'.join(db)
                    print(full_msg)
                    encrypted_data = rsa.encrypt(full_msg.encode('utf-8'), key2)
                    encrypted_data_b64 = base64.b64encode(encrypted_data)
                    return encrypted_data_b64
                else:
                    return
        type_ip = ipaddress.ip_address(ip)
        if type_ip.version == 4:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.settimeout(5)
            server_socket.bind(('', port))
            server_socket.sendto('None'.encode('utf-8'), (ip, port))
            def listen():
                public_key = ''
                while True:
                    message = server_socket.recv(1024).decode('utf-8')
                    print(message)
                    if message != 'None' and public_key == '':
                        public_key += message
                    elif message != 'None':
                        encd = rsa_process(message, public_key)
                        if encd:
                            server_socket.sendto(encd.encode('utf-8'), (ip, port))
                        break
            threading.Thread(target=listen).start()
            time.sleep(0.3)
            server_socket.sendto(key.encode('utf-8'), (ip, port))

        elif type_ip.version == 6:
            server_socket2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            server_socket2.settimeout(5)
            server_socket2.bind(('', port, 0, 0))
            server_socket2.sendto('None'.encode('utf-8'), (ip, port, 0, 0))
            def listen():
                public_key = ''
                while True:
                    message = server_socket.recv(1024).decode('utf-8')
                    if message != 'None' and public_key == '':
                        public_key += message
                    elif message != 'None':
                        encd = rsa_process(message, public_key)
                        if encd:
                            server_socket.sendto(encd.encode('utf-8'), (ip, port, 0, 0))
                        break
            threading.Thread(target=listen).start()
            time.sleep(0.3)
            server_socket2.sendto(key.encode('utf-8'), (ip, port, 0, 0))

    while True:
        time.sleep(0.1)
        with open('kill_node.txt', 'r') as kn1:
            if kn1.read() == 'True':
                break
        for new in potential_conns:
            threading.Thread(target=handle_client, args=(new, )).start()
            potential_conns.remove(new)
            
            
def database(rfb, rfb_response, transaction_pool):
    conn1 = sqlite3.connect('node_bills.db')
    c1 = conn1.cursor()
    while True:
        time.sleep(0.1)
        current_time_float = time.time()
        current_time = int(current_time_float)
        with open('kill_node.txt', 'r') as kn1:
            kill_node = kn1.read()
            if kill_node == 'True':
                conn1.close()
                break
        if str(current_time).endswith('999'):
            open('spam_protection.txt', 'w').close()
        for finder in rfb:
            if finder[1].startswith('x'):
                c1.execute("SELECT serial_num FROM bills WHERE address MATCH ? ORDER BY RANDOM() LIMIT 14", (finder[1], ))
                data = c1.fetchall()
                full_return = [finder[0]]
                for item in data:
                    full_return.append(item[0])
                rfb_response.append(tuple(full_return))
            elif finder[1].startswith('!'):
                finder_range = []
                f1 = finder[1][1:].split('x')[0]
                f2 = finder[1].split('x')[1]
                for cou in range(50):
                    finder_range.append(f1 + 'x' + str(int(f2) + cou))
                c1.execute("SELECT * FROM bills WHERE serial_num IN (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(finder_range))
                rfb_response.append(tuple([finder[0]] + c1.fetchall()))
            elif finder[1]:
                c1.execute("SELECT * FROM bills WHERE serial_num MATCH ?", (finder[1],))
                data = c1.fetchone()
                print(data)
                if data:
                    rfb_response.append(tuple([finder[0]]) + data)
            rfb.remove(finder)

        for new_bill in transaction_pool:
            serial_number2 = new_bill[0]
            address = new_bill[1]
            number = new_bill[2]
            dataf = (address, number, serial_number2)
            datag = (serial_number2, address, number)
            c1.execute("SELECT * FROM bills WHERE serial_num MATCH ?", (serial_number2,))
            existing = c1.fetchone()
            if existing:
                c1.execute("UPDATE bills SET address = ?, number = ? WHERE serial_num MATCH ?", dataf)
            else:
                c1.execute("INSERT INTO bills VALUES(?, ?, ?)", datag)
            transaction_pool.remove(new_bill)
        conn1.commit()

                      
def client_udp(rfb, rfb_response, transaction_pool, potential_conns2):

    def access_database(sma):
        random_num1 = str(random.uniform(0.1, 99.9))
        rfb.append((random_num1 + sma))
        time.sleep(0.8)
        for respon in rfb_response:
            if respon[0] == random_num1:
                rfb_response.remove(respon)
                return respon[2:]
        else:
            return

    active_conns = []
    def new_conn(ip):
        try:
            client = socket.create_connection((ip, 8888), timeout=1)
            client.settimeout(120)
            active_conns.append(ip)
            with open('rsa_public_key.txt', 'r') as rsk:
                key = rsk.read()
            client.sendall(key.encode('utf-8'))
            recv_key = client.recv(1024).decode('utf-8')
            public_key_node = rsa.PublicKey.load_pkcs1(base64.b64decode(recv_key))
            encrypted_data = rsa.encrypt('p'.encode('utf-8'), public_key_node)
            encrypted_data_b64 = base64.b64encode(encrypted_data)
            client.sendall(encrypted_data_b64)
            with open('rsa_private_key.txt', 'r') as rsk:
                private_key = rsk.read()
                rsa_pk = rsa.PrivateKey.load_pkcs1(base64.b64decode(private_key))
            while True:
                msg_encrypted = client.recv(512).decode('utf-8')
                msg_decrypted = rsa.decrypt(base64.b64decode(msg_encrypted), rsa_pk).decode('utf-8')
                msg_split = msg_decrypted[1:].split()
                if msg_decrypted[0] == 'n':
                    potential_conns2.append((msg_split[0], msg_split[2]))
                elif msg_decrypted[0] == 'b':
                    msg = msg_decrypted[1:]
                    bill = msg.splitlines(keepends=True)[:5]
                    print(bill)
                    bill_serial_num, bill_number, bill_addr = bill[0].strip(), bill[1].strip(), bill[3].strip()
                    bill_public_key, bill_digital_sig = bill[2].strip(), bill[4].strip()
                    with open('spam_protection.txt', 'r') as sc:
                        sc = sc.read()
                        spam_count = sc.count(bill_serial_num)
                    num_bill = bill_serial_num.split('x')[1]
                    if spam_count < 4 and 0 < int(num_bill) < 50000000:
                        db = access_database(bill_serial_num)
                        if db:
                            addr_old = db[0]
                            number = db[1]
                            hash_key = sha3_256(bill_public_key.encode('utf-8')).digest()
                            hash_key_encode = base58.b58encode(hash_key).decode('utf-8')
                            if hash_key_encode[:30] == addr_old and int(number) + 1 == int(bill_number):
                                v_sig = confirm_validity.verify_ecdsa(bill_digital_sig, ''.join(bill[:4]),
                                                                      bill_public_key)
                                if v_sig == 'valid':
                                    transaction_pool.append((bill_serial_num, bill_addr, bill_number))
        except:
            active_conns.remove(ip)
            client.close()

    while True:
        with open('kill_node.txt', 'r') as kn2:
            if kn2.read() == 'True':
                break
        ip_f = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')
        ip_addr = random.choice(ip_f).replace('.txt', '')
        if len(active_conns) < len(ip_f) / 10 + 1 and ip_addr not in active_conns:
            threading.Thread(target=new_conn, args=(ip_addr,)).start()
        time.sleep(2)

if __name__ == "__main__":
    for f in os.listdir('full_activation'):
        open('full_activation/' + f, 'w').close()
    with Manager() as manager:
        rf1 = manager.list()
        rf2 = manager.list()
        t = manager.list()
        new_connect = manager.list()
        Process(target=database, args=(rf1, rf2, t)).start()
        Process(target=client_udp, args=(rf1, rf2, t, new_connect)).start()
        pos1 = ['1x', '2x', '5x', '10x', '20x', '50x', '100x', '200x']
        pos2 = ['500x', '1000x', '2000x', '5000x', '10000x', '20000x', '50000x', '100000x']
        Process(target=download_bills, args=(pos1, t)).start()
        Process(target=download_bills, args=(pos2, t)).start()
        udp_node(rf1, rf2, new_connect)
