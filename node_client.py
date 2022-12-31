import socket
import threading
import time
import os
import confirm_validity
from hashlib import sha3_256
import base64
import rsa
import random
import requests
import sender_node
import ipaddress
import difflib
import sqlite3
import base58
from multiprocessing import Process, Manager
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PORT = 8888
def new_ip(v):
    try:
        try:
            try:
                public_ip = requests.get('https://www.wikipedia.org').headers['X-Client-IP']
            except:
                public_ip = requests.get('https://checkip.amazonaws.com').text.strip()
        except:
            public_ip = sender_node.public_ip()
    except:
        return
    if ipaddress.ip_address(public_ip).version == 6:
        with open('kill_node.txt', 'w') as kn:
            kn.seek(0)
            kn.truncate()
            kn.write('True')
            return

    ipnl = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')

    with open('my_public_ip.txt', 'r+') as mpi:
        mpi_lines = mpi.readlines()
        my_ip = mpi_lines[0].strip()
        if my_ip != public_ip:
            mpi.seek(0)
            mpi.truncate()
            mpi.write(str(public_ip))
            for _ in range(len(ipnl)):
                threading.Thread(target=sender_node.connect, args=('i', public_ip + '\n' + v, ipnl)).start()


def node_protocol(rfb, rfb_response, transaction_pool, bill_pool):
    new_ip('2')
    active_connections = []
    active_udp_connections = []
    potential_conns_udp = []
    with open('rsa_public_key.txt', 'r') as pk:
        public_key_rsa = pk.read()
    def handle_client(conn, addr):
        try:
            client_public_key = conn.recv(1024).decode('utf-8')
            conn.sendall(public_key_rsa.encode('utf-8'))
            def send(data1):
                key = rsa.PublicKey.load_pkcs1(base64.b64decode(client_public_key))
                encrypted_data = rsa.encrypt(data1.encode('utf-8'), key)
                encrypted_data_b64 = base64.b64encode(encrypted_data)
                conn.sendall(encrypted_data_b64)

            def add_spam(info):
                with open('spam_protection.txt', 'a') as sp:
                    sp.write(info + '\n')

            def access_database(serial_num_address):
                random_num1 = str(random.uniform(0.1, 99.9))
                rfb.append((random_num1, serial_num_address))
                time.sleep(0.8)
                for respon in rfb_response:
                    if respon[0] == random_num1:
                        rfb_response.remove(respon)
                        return respon[2:]
                else:
                    return

            conn.settimeout(120)
            add_spam(addr[0])
            #try:
            with open('kill_node.txt', 'r') as kn4:
                if kn4.read() == 'True':
                    conn.close()
                    return
            msg_encrypted = conn.recv(512).decode('utf-8')
            if not msg_encrypted:
                conn.close()
                return

            with open('rsa_private_key.txt', 'r') as rsk:
                private_key = rsk.read()
                rsa_pk = rsa.PrivateKey.load_pkcs1(base64.b64decode(private_key))

            msg_decrypted = rsa.decrypt(base64.b64decode(msg_encrypted), rsa_pk).decode('utf-8')
            i = msg_decrypted[:1]
            msg = msg_decrypted[1:]
            if i == 'r':
                # send a client his bills
                random_num = str(random.uniform(0.1, 99.9))
                rfb.append((random_num, msg))
                time.sleep(0.8)
                for respor in rfb_response:
                    if respor[0] == random_num:
                        send('\n'.join(respor[1:]))
            elif i == 'b':
                # add a new bill to the database
                bill = msg.splitlines(keepends=True)[:5]
                bill_serial_num,  bill_number, bill_addr = bill[0].strip(), bill[1].strip(), bill[3].strip()
                bill_public_key, bill_digital_sig = bill[2].strip(), bill[4].strip()
                with open('spam_protection.txt', 'r') as sc:
                    sc = sc.read()
                    spam_count1 = sc.count(bill_serial_num)
                num_bill = bill_serial_num.split('x')[1]
                if spam_count1 < 4 and 0 < int(num_bill) < 500000000:
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
                                add_spam(bill_serial_num)
                                bill_pool.append(''.join(bill))
                                transaction_pool.append((bill_serial_num, bill_addr, bill_number))
                                time.sleep(0.5)
                                bill_pool.remove(''.join(bill))
            elif i == 'c':
                # confirm the possesion of a bill
                with open('full_activation/' + msg.split('x')[0] + '.txt', 'r') as fa:
                    is_downloaded = fa.read().strip('x')
                    if int(is_downloaded) > int(msg.split('x')[1]):
                        db2 = access_database(msg)
                        if db2:
                            send('\n'.join(db2))
            elif i == 'u':
                # send node ips to the client
                ip_txt = ''
                if msg == 'main ip':
                    ipf1 = os.listdir('ip_folder/1')
                    ip_txt += difflib.get_close_matches(str(int(time.time()))[-4:-2], ipf1, 1, 0)[0].replace('.txt', '')
                else:
                    ipf2 = os.listdir('ip_folder/2')
                    ipf3 = os.listdir('ip_folder/3')
                    for x in range(8):
                        ip_txt += random.choice(ipf2).replace('.txt', '\n')
                        ip_txt += random.choice(ipf3).replace('.txt', '\n')
                send(ip_txt)
            elif i == 'i':
                # add a new ip address to node network
                ip = msg.splitlines()[0]
                version = msg.splitlines()[1]
                if addr[0] == ip:
                    try:
                        time.sleep(random.uniform(0.0, 3.5))
                        send('test')
                        open('ip_folder/' + version + '/' + ip + '.txt', 'w')
                    except:
                        pass
            elif i == 'y':
                # connect a udp client to a udp node
                random_udp_node = random.choice(active_udp_connections).replace('::ffff:', '')
                if 40000 <= int(msg) <= 65000:
                    potential_conns_udp.append((addr[0].replace('::ffff:', ''), random_udp_node, msg))
                send(random_udp_node)
            elif i == 'p':
                # keep a udp node updated
                if addr[0] not in active_udp_connections:
                    active_udp_connections.append(addr[0])
                    itera = 0
                    while True:
                        if itera == 1150:
                            active_udp_connections.remove(addr[0])
                            break
                        time.sleep(0.1)
                        for nef in potential_conns_udp:
                            if nef[1] == addr[0].replace('::ffff:', ''):
                                send('n' + ' '.join(nef))
                                potential_conns_udp.remove(nef)
                                print('send' + ' '.join(nef))
                        for b in bill_pool:
                            send(b)
                        itera += 1
            elif i == 'x':
                # send client their public ip
                send(addr[0].replace('::ffff:', ''))
                pass
            elif i == 'n':
                # new bills are being added to the database
                bill = msg.splitlines(keepends=True)
                sm = bill[0]
                address = bill[1].strip()
                digtal_sig = bill[2].strip()
                hard_key = 'r*{>Opx@$BqA87pd<&4eK7bp~y;1dtlNplnDT1+52h<CoTd2f{02Egzuc0sKY5=SZlk#TuV|fM6&xQKV'
                v = confirm_validity.verify_ecdsa(digtal_sig, sm + address, hard_key)
                if v == 'valid':
                    full_insert = (sm, '0', address)
                    transaction_pool.append(full_insert)
            elif i == 'd':
                # download service for another node
                key_aes = os.urandom(32)
                iv = os.urandom(16)
                sm1 = msg.split('x')[0]
                sm2 = int(msg.split('x')[1])
                with open('full_activation/' + sm1 + '.txt', 'r') as fa:
                    max_num = int(fa.read().strip('x'))
                if sm2 <= max_num:
                    random_num2 = str(random.uniform(0.1, 99.9))
                    rfb.append((random_num2, '!' + msg))
                    time.sleep(3)
                    for respo in rfb_response:
                        if respo[0] == random_num2:
                            cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv))
                            encryptor = cipher.encryptor()
                            join_list = ''
                            for ite in respo[1:]:
                                join_list += '\n'.join(ite) + '\n'
                            while len(join_list) < 2720:
                                join_list += '!'
                            ct = encryptor.update(join_list.encode('utf-8')) + encryptor.finalize()
                            data_encode = base64.b64encode(iv + key_aes + ct)
                            conn.sendall(data_encode[:1300])
                            time.sleep(0.5)
                            conn.sendall(data_encode[1300:2600])
                            time.sleep(0.5)
                            conn.sendall(data_encode[2600:])
                            rfb_response.remove(respo)
                            break
                    else:
                        conn.sendall('None'.encode('utf-8'))
                else:
                    conn.sendall('None'.encode('utf-8'))
            if i == 'p':
                active_udp_connections.remove(addr[0])
            active_connections.remove(addr[0])
            conn.close()
        except:
            pass

    overload = False
    def ping_own_server():
        global overload
        while True:
            try:
                time.sleep(10)
                c = socket.create_connection(('127.0.0.1', PORT), timeout=1)
                with open('kill_node.txt', 'r') as kn3:
                    kill_node3 = kn3.read()
                    if kill_node3 == 'True':
                        break
                overload = False
                c.close()
            except:
                with open('kill_node.txt', 'r') as kn3:
                    kill_node3 = kn3.read()
                    if kill_node3 == 'True':
                        break
                overload = True

    time.sleep(10)
    ADDR = ('', PORT)
    if socket.has_dualstack_ipv6():
        server = socket.create_server(ADDR, family=socket.AF_INET6, dualstack_ipv6=True)
        server.settimeout(None)
    else:
        return
    server.listen()
    threading.Thread(target=ping_own_server).start()
    while True:
        try:
            conn1, addr1 = server.accept()
            print(conn1, addr1)
            with open('kill_node.txt', 'r') as kn2:
                kill_node = kn2.read()
                if kill_node == 'True':
                    conn1.close()
                    break
            spam_count = active_connections.count(addr1[0])
            if addr1[0] == '::ffff:127.0.0.1':
                conn1.close()
            elif int(spam_count) < 50 and not overload:
                threading.Thread(target=handle_client, args=(conn1, addr1)).start()
                active_connections.append(addr1[0])
            else:
                conn1.close()
        except:
            pass


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
                if data:
                    rfb_response.append(tuple(finder[0]) + data)
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

def download_bills(pos, transaction_pool):

    def thrd(it):
        number = 0
        already_tried = []
        bill_comparison = []

        def down(num, ipnl):
            serial_num_range = it + str(num)
            with open('rsa_public_key.txt', 'r') as rsk:
                key = rsk.read()
            while True:
                if random.randrange(1000) == 9:
                    already_tried.clear()
                SERVER = random.choice(ipnl).replace('.txt', '')

                ADDR = (SERVER, PORT)
                try:
                    client = socket.create_connection(ADDR, timeout=0.3)
                    client.settimeout(6)
                    client.sendall(key.encode('utf-8'))
                    recv_key = client.recv(1024).decode('utf-8')
                    public_key_node = rsa.PublicKey.load_pkcs1(base64.b64decode(recv_key))
                    encrypted_data = rsa.encrypt(('d' + serial_num_range).encode('utf-8'), public_key_node)
                    encrypted_data_b64 = base64.b64encode(encrypted_data)
                    client.sendall(encrypted_data_b64)
                    full_msg = ''
                    multi = 1
                    s1 = serial_num_range.split('x')
                    ct2 = str(int(time.time()))
                    if SERVER in os.listdir('ip_folder/1'):
                        multi += int(max(0, 1800 - int(ct2[0:4])) / 12)
                    for _ in range(3):
                        full_msg += client.recv(2048).decode('utf-8')
                        if full_msg == 'None':
                            for c in range(50):
                                for _ in range(multi):
                                    bill_comparison.append(('n',  s1[0] + 'x' + str(int(s1[1]) + c), 'n'))
                            return
                    recv_msg_decode = base64.b64decode(full_msg)
                    iv = recv_msg_decode[:16]
                    key_aes = recv_msg_decode[16:48]
                    data = recv_msg_decode[48:]
                    cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv))
                    decryptor = cipher.decryptor()
                    data_decrypted = decryptor.update(data) + decryptor.finalize()
                    data_decoded = data_decrypted.decode('utf-8').strip('!')
                    spl = data_decoded.splitlines()
                    for c in range(50):
                        for _ in range(multi):
                            try:
                                bill_comparison.append((spl[c * 3], spl[c * 3 + 1], spl[c * 3 + 2]))
                            except:
                                bill_comparison.append(('n',  s1[0] + 'x' + str(int(s1[1]) + c), 'n'))
                    client.close()
                    break
                except TimeoutError:
                    if SERVER not in already_tried:
                        already_tried.append(SERVER)

        def thrd2(number1):
            for _ in range(2):
                threading.Thread(target=down, args=(number1, os.listdir('ip_folder/1'))).start()
            for _ in range(3):
                threading.Thread(target=down, args=(number1, os.listdir('ip_folder/2'))).start()

            time.sleep(9)
            sorted_max_list = []
            for c3 in range(50):
                small_comparison = []
                for item in bill_comparison:
                    if item[0] == it + str(number1 + c3) or item[1] == it + str(number1 + c3):
                        small_comparison.append(item)
                        bill_comparison.remove(item)
                sorted_max_list.append(max(set(small_comparison), key=small_comparison.count))
            with open('full_activation/' + it.strip('x') + '.txt', 'r') as d2:
                if d2.read().endswith('x'):
                    return
            for sorted_bill in sorted_max_list:
                if sorted_bill[0] != 'n':
                    transaction_pool.append(sorted_bill)
                else:
                    with open('full_activation/' + it.strip('x') + '.txt', 'w') as fa2:
                        fa2.seek(0)
                        fa2.truncate()
                        fa2.write(sorted_bill[1].split('x')[1] + 'x')
                    return

        while True:
            with open('kill_node.txt', 'r') as kn2:
                kill_node = kn2.read()
                if kill_node == 'True':
                    return
            with open('full_activation/' + it.strip('x') + '.txt', 'r') as d:
                if d.read().endswith('x'):
                    return

            ct = int(str(int(time.time()))[:3]) - 165
            with open('full_activation/' + it.strip('x') + '.txt', 'w') as fa3:
                fa3.seek(0)
                fa3.truncate()
                fa3.write(str(number))
            for _ in range(ct):
                threading.Thread(target=thrd2, args=(number, )).start()
                number += 50
                time.sleep(1)
            time.sleep(10)

    for i in pos:
        time.sleep(10)
        threading.Thread(target=thrd, args=(i, )).start()


def maintain_connections(bill_pool):
    active_conns = []

    def connection(ip, b_pool):
        ADDR = (ip, PORT)
        try:
            client = socket.create_connection(ADDR, timeout=0.5)
            client.settimeout(120)
            with open('rsa_public_key.txt', 'r') as rsk:
                key = rsk.read()
            client.sendall(key.encode('utf-8'))
            recv_key = client.recv(1024).decode('utf-8')
            active_conns.append(ip)
            while True:
                time.sleep(0.1)
                with open('kill_node.txt', 'r') as kn3:
                    if kn3.read() == 'True':
                        break
                if b_pool:
                    pool_rand = random.choice(bill_pool)
                    public_key_node = rsa.PublicKey.load_pkcs1(base64.b64decode(recv_key))
                    encrypted_data = rsa.encrypt(('b' + pool_rand).encode('utf-8'), public_key_node)
                    encrypted_data_b64 = base64.b64encode(encrypted_data)
                    client.sendall(encrypted_data_b64)
                    break
            client.close()
            active_conns.remove(ip)
        except:
            try:
                active_conns.remove(ip)
            except:
                pass

    while True:
        with open('kill_node.txt', 'r') as kn2:
            if kn2.read() == 'True':
                break
        len_folder = len(os.listdir('ip_folder/1')) + len(os.listdir('ip_folder/2'))
        if len(active_conns) < len_folder / 10 + 1:
            try:
                ip_f = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')
                ip_addr = random.choice(ip_f).strip('.txt')
                threading.Thread(target=connection, args=(ip_addr, bill_pool)).start()
            except:
                pass
        time.sleep(0.5)


if __name__ == "__main__":
    for f in os.listdir('full_activation'):
        open('full_activation/' + f, 'w').close()
    with Manager() as manager:
        rf1 = manager.list()
        rf2 = manager.list()
        t = manager.list()
        bp = manager.list()
        pos1 = ['1x', '2x', '5x', '10x', '20x', '50x', '100x', '200x']
        pos2 = ['500x', '1000x', '2000x', '5000x', '10000x', '20000x', '50000x', '100000x']
        Process(target=database, args=(rf1, rf2, t)).start()
        Process(target=maintain_connections, args=(bp, )).start()
        Process(target=download_bills, args=(pos1, t)).start()
        Process(target=download_bills, args=(pos2, t)).start()
        node_protocol(rf1, rf2, t, bp)

