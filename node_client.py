import socket
import threading
import time
import os
import confirm_validity
from hashlib import sha3_256
import base64
import rsa
import random
import sender_node
import ipaddress
import difflib
import sqlite3
import base58
from multiprocessing import Process, Manager
# most modules come preinstalled
# if you miss modules, execute pip install -r ./requirements.txt in the local directory (cmd)

PORT = 8888
def new_ip(v):
    # this function registers a new ip address with the rest of the node network
    public_ip = sender_node.public_ip()
    print(public_ip)
    if public_ip:
        # ipv6 addresses are rejected
        if ipaddress.ip_address(public_ip).version == 6:
            with open('kill_node.txt', 'w') as kn:
                kn.seek(0)
                kn.truncate()
                kn.write('True')
                return

        ipnl = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')

        with open('my_public_ip.txt', 'r+') as mpi:
            mpi_lines = mpi.readlines()
            def newi():
                mpi.seek(0)
                mpi.truncate()
                mpi.write(str(public_ip))
                # let every node know that you entered the node network
                for _ in range(len(ipnl)):
                    threading.Thread(target=sender_node.connect, args=('i', public_ip + '\n' + v, ipnl)).start()
            try:
                my_ip = mpi_lines[0].strip()
                if my_ip != public_ip:
                    newi()
            except:
                newi()

def node_protocol(rfb, rfb_response, transaction_pool, bill_pool):
    new_ip('2')
    with open('rsa_public_key.txt', 'r') as pk:
        public_key_rsa = pk.read()

    def handle_client(conn, addr):
        # this function handles a client thread
        try:
            # send and receive public key
            client_public_key = conn.recv(1024).decode('utf-8')
            conn.sendall(public_key_rsa.encode('utf-8'))

            def send(data1):
                # this function encrypts and sends data to the client
                key = rsa.PublicKey.load_pkcs1(base64.b64decode(client_public_key))
                encrypted_data = rsa.encrypt(data1.encode('utf-8'), key)
                encrypted_data_b64 = base64.b64encode(encrypted_data)
                conn.sendall(encrypted_data_b64)

            def add_spam(info):
                with open('spam_protection.txt', 'a') as sp:
                    sp.write(info + '\n')

            def access_database(serial_num_address):
                # access the database for 1 serial number
                random_number = str(random.uniform(0.1, 99.9))
                rfb.append((random_number, serial_num_address))
                time.sleep(0.8)
                try:
                    item_response_dtbse1 = rfb_response.pop(random_number)
                    return item_response_dtbse1[1:]
                except:
                    return

            conn.settimeout(120)
            # receive a encrypted message
            msg_encrypted = conn.recv(512).decode('utf-8')
            # use your private key to decrypt the message
            with open('rsa_private_key.txt', 'r') as rsk:
                private_key = rsk.read()
                rsa_pk = rsa.PrivateKey.load_pkcs1(base64.b64decode(private_key))
            msg_decrypted = rsa.decrypt(base64.b64decode(msg_encrypted), rsa_pk).decode('utf-8')
            i = msg_decrypted[:1]
            # i = indicator (indicates what the client wants from the node)
            msg = msg_decrypted[1:]
            if i == 'r':
                # r = receive (the client wants to receive a list of serial numbers, from bills that belong to him)
                # send a client his bills
                random_num = str(random.uniform(0.1, 99.9))
                rfb.append((random_num, msg))
                time.sleep(0.8)
                item_response = rfb_response.pop(random_num)
                send('\n'.join(item_response))
            elif i == 'b':
                # b = bill (a new bill is being sent around the network)
                # add a new bill to the database
                bill = msg.splitlines(keepends=True)[:5]
                bill_serial_num,  bill_number, bill_addr = bill[0].strip(), bill[1].strip(), bill[3].strip()
                bill_public_key, bill_digital_sig = bill[2].strip(), bill[4].strip()
                with open('spam_protection.txt', 'r') as sc:
                    sc = sc.read()
                    spam_count1 = sc.count(bill_serial_num)
                num_bill = bill_serial_num.split('x')[1]
                # check if bill has been transacted less than 6 times in the last 16 minutes (spam protection)
                # check if the serial_num of the bill is in the allowed range of under 50 million
                if spam_count1 < 6 and 0 < int(num_bill) < 100000000:
                    db = access_database(bill_serial_num)
                    if db:
                        addr_old = db[0]
                        number = db[1]
                        # create a sha3 256 hash of the senders public key
                        hash_key = sha3_256(bill_public_key.encode('utf-8')).digest()
                        hash_key_encode = base58.b58encode(hash_key).decode('utf-8')
                        # check if the base58 encoded version of the hash matches the address noted in the database
                        # this ensures, the bill belongs to the sender.
                        # check also wich transaction iteration this bill has gone through (bill_number)
                        if hash_key_encode[:30] == addr_old and int(number) + 1 == int(bill_number):
                            # access the verify_ecdsa function at confirm_validity.py
                            v_sig = confirm_validity.verify_ecdsa(bill_digital_sig, ''.join(bill[:4]),
                                                                  bill_public_key)
                            if v_sig == 'valid':
                                # if the signature is valid, we add the serial_num to the spam count
                                add_spam(bill_serial_num)
                                # we append the entire bill to the bill_pool and transaction_pool
                                # this ensures we continue to send the bill to other nodes, in case they
                                # haven't received it yet. Also add the bill to our own database (transaction_pool)
                                bill_pool.append(''.join(bill))
                                transaction_pool.append((bill_serial_num, bill_addr, bill_number))
                                time.sleep(0.5)
                                bill_pool.remove(''.join(bill))
            elif i == 'c':
                # c = confirm (the possession of a bill)
                msg_spl = msg.splitlines()
                random_nums = []
                # check each serial_num
                for bill_sm in msg_spl:
                    with open('full_activation/' + bill_sm.split('x')[0] + '.txt', 'r') as fa:
                        is_downloaded = fa.read()
                    if int(is_downloaded) >= int(bill_sm.split('x')[1]):
                        random_num1 = str(random.uniform(0.1, 99.9))
                        # rfb = request from base (send a request to the sqlite3 database)
                        rfb.append((random_num1, bill_sm))
                        random_nums.append(random_num1)
                time.sleep(1)
                send_b = ''
                for rndm in random_nums:
                    try:
                        # look for a response from the database
                        item_response_dtbse = rfb_response.pop(rndm)
                        send_b += '\n'.join(item_response_dtbse) + '\n'
                    except:
                        # if nothing is found send the serial num with 'x', the client will see this as a no vote
                        send_b += msg_spl[random_nums.index(rndm)] + '\nx\nx'
                send(send_b)

            elif i == 'u':
                # u = user ip request
                # send node ips to the client
                ip_txt = ''
                if msg == 'main ip':
                    ipf1 = os.listdir('ip_folder/1')
                    # strange method of getting consensus and variation at the same time
                    # this is only important if your node is considered a main node or a number '1'
                    ip_txt += difflib.get_close_matches(str(int(time.time()))[-4:-2], ipf1, 1, 0)[0].replace('.txt', '')
                else:
                    ipf2 = os.listdir('ip_folder/2')
                    ipf3 = os.listdir('ip_folder/3')
                    for x in range(8):
                        ip_txt += random.choice(ipf2).replace('.txt', '\n')
                        ip_txt += random.choice(ipf3).replace('.txt', '\n')
                send(ip_txt)
            elif i == 'i':
                # i = ip (a new ipv4 address node)
                ip = msg.splitlines()[0]
                version = msg.splitlines()[1]
                if addr[0].replace('::ffff:', '') == ip and ipaddress.ip_address(ip).version == 4:
                    open('ip_folder/' + version + '/' + ip + '.txt', 'w').close()

            elif i == 'x':
                # send client their public ip
                send(addr[0].replace('::ffff:', ''))
                pass
            elif i == 'd':
                # d = download request (from another node, that has started to download your fresh database)
                # this is a request of 10 thousand bills at once
                # we highly optimized this so speed should not be an issue (in database)
                sm1 = msg.split('x')[0]
                sm2 = int(msg.split('x')[1])
                with open('full_activation/' + sm1 + '.txt', 'r') as fa:
                    max_num = int(fa.read())
                if sm2 <= max_num:
                    random_num2 = str(random.uniform(0.1, 99.9))
                    rfb.append((random_num2, '!' + msg))
                    time.sleep(2)
                    item_respo = rfb_response.pop(random_num2)
                    join_list = ''
                    for ite in item_respo:
                        join_list += '\n'.join(ite) + '\n'
                    # send ip packets 1300 bytes each (300 - 400)
                    parts = [join_list[ium:ium + 1300] for ium in range(0, len(join_list), 1300)]
                    for send_data in parts:
                        conn.sendall(send_data.encode('utf-8'))
                        time.sleep(0.1)
                    conn.sendall('END'.encode('utf-8'))
            conn.close()
        except:
            conn.close()

    time.sleep(10)
    ADDR = ('', PORT)
    if socket.has_dualstack_ipv6():
        # a dualstack TCP socket in blocking mode
        server = socket.create_server(ADDR, family=socket.AF_INET6, dualstack_ipv6=True)
        server.settimeout(None)
    else:
        return
    server.listen()
    connections = []
    while True:
        try:
            # conn1 = full connection addr1 = (ip address, port)
            conn1, addr1 = server.accept()
            # clear spam every 10 seconds
            if str(int(time.time())).endswith('9'):
                connections.clear()
            print(conn1, addr1)
            # always check if the node has been turned off, in that case break the loop
            with open('kill_node.txt', 'r') as kn2:
                kill_node = kn2.read()
                if kill_node == 'True':
                    conn1.close()
                    break
            # count how many times a specific ip address is already connected to the node
            spam_count = connections.count(addr1[0])
            if addr1[0] == '::ffff:127.0.0.1':
                conn1.close()
            elif int(spam_count) < 50:
                threading.Thread(target=handle_client, args=(conn1, addr1)).start()
                connections.append(addr1[0])
            else:
                conn1.close()
        except:
            pass


def database(rfb, rfb_response, transaction_pool):
    # the file node_bills.db stores the entire sqlite database
    conn1 = sqlite3.connect('node_bills.db')
    conn1.isolation_level = None
    c1 = conn1.cursor()
    while True:
        time.sleep(0.2)
        c1.execute("BEGIN")
        current_time_float = time.time()
        current_time = int(current_time_float)
        # check if the node has been turned off
        with open('kill_node.txt', 'r') as kn1:
            kill_node = kn1.read()
            if kill_node == 'True':
                conn1.close()
                break
        if str(current_time).endswith('999'):
            # clear spam protection, every 16 minutes
            open('spam_protection.txt', 'w').close()
        # iterate through the database requests
        for finder in rfb:
            try:
                # search for an address, when the client send 'r' request
                if finder[1].startswith('x'):
                    c1.execute("SELECT serial_num FROM bills WHERE address MATCH ? LIMIT 1000", (finder[1], ))
                    data1 = c1.fetchall()
                    data = random.choices(data1, k=14)
                    full_return = []
                    for item in data:
                        full_return.append(item[0])
                    rfb_response[finder[0]] = full_return
                # get a 10000 chunk from database, this happens when another node sends 'd' request (download)
                elif finder[1].startswith('!'):
                    f1 = finder[1][1:].split('x')[0]
                    f2 = finder[1].split('x')[1]
                    plusf = {'1':0, '2':10000, '5':20000, '10':30000, '20':40000, '50':50000, '100':60000, '200':70000,
                             '500':80000, '1000':90000, '2000':100000, '5000':110000, '10000':120000, '20000':130000,
                             '50000':140000, '100000':150000}
                    serial_range = plusf[f1] + (160000 * int(int(f2) / 10000))
                    c1.execute("SELECT * FROM bills WHERE rowid >= ? LIMIT 10000", (serial_range + 1, ))
                    rfb_response[finder[0]] = c1.fetchall()
                # search for a serial number, this is the case in multiple client requests
                elif finder[1]:
                    c1.execute("SELECT * FROM bills WHERE serial_num MATCH ?", (finder[1],))
                    data = c1.fetchone()
                    if data:
                        rfb_response[finder[0]] = data
                rfb.remove(finder)
            except:
                try:
                    rfb.remove(finder)
                except:
                    pass
        # create an entire copy of the transaction pool
        trans_pool_copy = transaction_pool[:]
        # clear the transaction pool
        transaction_pool[:] = []
        # iterate over the transaction pool copy

        datag = []
        for new_bill in trans_pool_copy:
            try:
                plusf = {'1': 0, '2': 10000, '5': 20000, '10': 30000, '20': 40000, '50': 50000, '100': 60000, '200': 70000,
                         '500': 80000, '1000': 90000, '2000': 100000, '5000': 110000, '10000': 120000, '20000': 130000,
                         '50000': 140000, '100000': 150000}
                serial_number2 = new_bill[0]
                f1 = serial_number2.split('x')[0]
                f2 = serial_number2.split('x')[1]
                address = new_bill[1]
                number = new_bill[2]
                try:
                    add_sm = int(f2[-4:])
                except:
                    add_sm = int(f2)
                # the database is structured like this:
                # 1x0 -> 1x9999 2x0 -> 2x9999 5x0 -> 5x9999 ....... 100000x0 -> 100000x9999 1x10000 -> 1x19999
                datag.append((add_sm + plusf[f1] + (160000 * int(int(f2) / 10000)), serial_number2, address, number))
            except:
                pass
        c1.executemany("INSERT OR REPLACE INTO bills(rowid, serial_num, address, number) VALUES(?, ?, ?, ?)", datag)
        # commit changes
        c1.execute("COMMIT")


def download_bills(pos, transaction_pool):

    def thrd(it):
        number = 0
        already_tried = []
        bill_comparison = {}

        def down(num, ipnl):
            serial_num_range = it + str(num)
            with open('rsa_public_key.txt', 'r') as rsk:
                key = rsk.read()
            start_time = int(time.time())
            while int(time.time()) - start_time <= 9:
                if random.randrange(1000) == 9:
                    already_tried.clear()
                SERVER = ipnl
                if SERVER not in already_tried:
                    ADDR = (SERVER, PORT)
                    try:
                        # TCP socket with node
                        client = socket.create_connection(ADDR, timeout=5)
                        # set a timeout of 10 seconds after connection has been established
                        client.settimeout(45)
                        # send the node your public key
                        client.sendall(key.encode('utf-8'))
                        # receive the nodes public key
                        recv_key = client.recv(1024).decode('utf-8')
                        public_key_node = rsa.PublicKey.load_pkcs1(base64.b64decode(recv_key))
                        encrypted_data = rsa.encrypt(('d' + serial_num_range).encode('utf-8'), public_key_node)
                        encrypted_data_b64 = base64.b64encode(encrypted_data)
                        # send the node the encrypted request
                        client.sendall(encrypted_data_b64)
                        full_msg = ''
                        multi = 1
                        ct2 = str(int(time.time()))
                        # strengthen the importance of the opinion of number '1' main nodes (controlled by founder)
                        # only in the early stages, until enough other nodes have entered the network
                        if SERVER in os.listdir('ip_folder/1'):
                            multi += int(max(0, 1800 - int(ct2[0:4])) / 12)
                        # receive 300 - 400 1300 byte packages from the node, containing the (serial_num, address,
                        # number) for 10000 bills
                        for _ in range(432):
                            recvv = client.recv(2048)
                            if recvv == 'END':
                                break
                            full_msg += recvv.decode('utf-8')
                        spl = full_msg.splitlines()
                        # append the 10,000 bills to 'bill_comparison'
                        for c in range(10000):
                            for _ in range(multi):
                                bill_comparison[it + str(int(num) + c)].append((spl[c * 3], spl[c * 3 + 1], spl[c * 3 + 2]))
                        client.close()
                        break
                    except TimeoutError:
                        if SERVER not in already_tried:
                            already_tried.append(SERVER)
        def thrd2(number1):
            # this thread will start the main download process
            ipf_1 = os.listdir('ip_folder/1')
            ipf_2 = os.listdir('ip_folder/2')
            used = []
            # connect to every known number '1' and '2' node known
            with open('my_public_ip.txt', 'r') as whip:
                my_ip = whip.read()
            for count, ip in enumerate(ipf_1 + ipf_2):
                if ip not in used and ip.replace('.txt', '') != my_ip:
                    threading.Thread(target=down, args=(str(number1), ip.replace('.txt', ''))).start()
                used.append(ip)
            # wait for all different opinions of the nodes
            time.sleep(48)
            sorted_max_list = []
            # get a consensus based on the majority, for each individual bill
            for key_item in bill_comparison.values():
                sorted_max_list.append(max(set(key_item), key=key_item.count))
            # add the bills to the transaction_pool (database entry)
            transaction_pool.extend(sorted_max_list)

        # this loop breaks when max of the database has been downloaded
        # this could take a couple of hours
        # until 2024 the max download is up to 10 million per serial number starter in pos
        while True:
            current_time = int(str(int(time.time()))[:3])
            if number == 10000000:
                break
            # check if the node has been turned off
            with open('kill_node.txt', 'r') as kn2:
                kill_node = kn2.read()
                if kill_node == 'True':
                    return
            # update the corresponding .txt file in full activation folder. This will allow the node
            # you are running, to know the status of your download. Therefore it wont give the client
            # old information.
            with open('full_activation/' + it.strip('x') + '.txt', 'w') as fa3:
                fa3.seek(0)
                fa3.truncate()
                fa3.write(str(number))
            # create 10,000 new keys in the bill comparison dictionary
            for appnd_dict in range(20000):
                bill_comparison[it + str(number + appnd_dict)] = []
            #######
            for new_thrd in range(2):
                threading.Thread(target=thrd2, args=(number, )).start()
                number += 10000
            time.sleep(50)
            #######
            bill_comparison.clear()

    # start a thread for every serial number starter (1x, 2x, 5x, ...)
    for i in pos:
        time.sleep(10)
        threading.Thread(target=thrd, args=(i, )).start()


def maintain_connections(bill_pool):
    # this function maintains connections with other TCP number '2' nodes and sends them new bills
    def connection(ip):
        ADDR = (ip, PORT)
        try:
            client = socket.create_connection(ADDR, timeout=4)
            client.settimeout(120)
            with open('rsa_public_key.txt', 'r') as rsk:
                key = rsk.read()
            client.sendall(key.encode('utf-8'))
            recv_key = client.recv(1024).decode('utf-8')
            # this while loop only breaks after node has been shut off, or set timeout(120 seconds)
            while True:
                time.sleep(0.1)
                if bill_pool:
                    # send a random bill in the bill pool
                    # note that other threads and other nodes will also send random bills
                    # this makes it very unlikely that a bill doesnt reach every node
                    pool_rand = random.choice(bill_pool)
                    public_key_node = rsa.PublicKey.load_pkcs1(base64.b64decode(recv_key))
                    encrypted_data = rsa.encrypt(('b' + pool_rand).encode('utf-8'), public_key_node)
                    encrypted_data_b64 = base64.b64encode(encrypted_data)
                    client.sendall(encrypted_data_b64)
                    break
            client.close()
        except:
            pass

    while True:
        with open('kill_node.txt', 'r') as kn2:
            if kn2.read() == 'True':
                break
        ip_f = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')
        # choose a random ip
        with open('my_public_ip.txt', 'r') as mp:
            my_ip = mp.read()
        ip_addr = random.choice(ip_f).strip('.txt')
        if ip_addr != my_ip:
            threading.Thread(target=connection, args=(ip_addr, )).start()
            time.sleep(4)
        time.sleep(0.2)


def udp_rendezvous(bill_pool):
    # udp rendezvous server socket
    udp_nodes = []
    def ipv4_sock():
        dest_port = 8888
        # UDP socket bound to 8888
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 8888))
        while True:
            time.sleep(0.1)
            try:
                # check if node is shut off
                with open('kill_node.txt', 'r') as kn2:
                    kill_node = kn2.read()
                    if kill_node == 'True':
                        break
                data, address = sock.recvfrom(128)
                data_d = data.decode('utf-8')

                if data_d == 'node':
                    udp_nodes.append(address)

                    def node_communication():
                        # this function checks the bill_pool, and if there is a new bill it sends it, to the udp node
                        iteration = 0
                        while iteration <= 200:
                            time.sleep(0.3)
                            iteration += 1
                            for b1 in bill_pool:
                                sock.sendto(b1.encode('utf-8'), address)
                        udp_nodes.remove(address)
                    threading.Thread(target=node_communication).start()
                elif data_d == 'client':
                    # choose a random udp node to pair up with client
                    c2 = random.choice(udp_nodes)
                    c2_addr, c2_port = c2
                    if len(c2) >= 1:
                        # comb = combination of address and destination port
                        comb = '\n'.join(str(a) for a in address) + '\n' + str(dest_port)
                        sock.sendto(b'ready', c2)
                        sock.sendto('{} {} {}'.format(c2_addr, c2_port, dest_port).encode('utf-8'), address)
                        sock.sendto(comb.encode('utf-8'), c2)
            except:
                pass
    def ipv6_sock():
        dest_port = 8887
        # UDP ipv6 socket bound to PORT 8887
        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock6.bind(('', 8887))
        while True:
            time.sleep(0.1)
            try:
                # check if node is shut off
                with open('kill_node.txt', 'r') as kn2:
                    kill_node = kn2.read()
                    if kill_node == 'True':
                        break
                data, address = sock6.recvfrom(128)
                c2 = random.choice(udp_nodes)
                c2_addr, c2_port = c2
                if len(c2) >= 1:
                    # comb = combination of address and destination port
                    comb = '\n'.join(str(a) for a in address) + '\n' + str(dest_port)
                    sock6.sendto(b'ready', c2)
                    # send node info to client
                    sock6.sendto('{} {} {}'.format(c2_addr, c2_port, dest_port).encode('utf-8'), address)
                    # send client info to node
                    sock6.sendto(comb.encode('utf-8'), c2)
            except:
                pass
    # start 2 sockets, one socket for IPv4 clients & nodes
    # the other one for ipv6 clients
    threading.Thread(target=ipv4_sock).start()
    threading.Thread(target=ipv6_sock).start()

if __name__ == "__main__":
    for f in os.listdir('full_activation'):
        open('full_activation/' + f, 'w').close()
    print('node is starting...')
    with Manager() as manager:
        # rf1 = rfb (find item in database request)
        rf1 = manager.list()
        # rf2 = rfb_response (database response)
        rf2 = manager.dict()
        # t = transaction_pool (add or update bills in the database)
        t = manager.list()
        # bp = bill_pool (send bills to other nodes)
        bp = manager.list()
        pos1 = ['1x', '2x', '5x', '10x', '20x', '50x', '100x', '200x']
        pos2 = ['500x', '1000x', '2000x', '5000x', '10000x', '20000x', '50000x', '100000x']
        # 6 different processes taking up 6 cores
        # on idle the node should not be taking up more than a few percent of the cp
        Process(target=database, args=(rf1, rf2, t)).start()
        Process(target=maintain_connections, args=(bp, )).start()
        Process(target=download_bills, args=(pos1, t)).start()
        Process(target=download_bills, args=(pos2, t)).start()
        Process(target=udp_rendezvous, args=(bp, ))
        node_protocol(rf1, rf2, t, bp)

