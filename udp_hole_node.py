import time
import ipaddress
import socket
import threading
import os
import random
from multiprocessing import Process, Manager
from node_client import download_bills, database, new_ip
from hashlib import sha3_256
import confirm_validity
import base58


def udp_node(rfb, rfb_response, potential_conns):
    # register a new ip with the node network. The '3' indicates that this is a udp node
    new_ip('3')

    # this function accesses the sqlite database known as 'node_bills.db'
    def access_database(sml):
        random_nums = []
        for bill_sm in sml:
            with open('full_activation/' + bill_sm.split('x')[0] + '.txt', 'r') as fa:
                is_downloaded = fa.read()
            # check download status
            if int(is_downloaded) >= int(bill_sm.split('x')[1]):
                random_num1 = str(random.uniform(0.1, 99.9))
                rfb.append((random_num1, bill_sm))
                random_nums.append(random_num1)
        # wait for database to respond
        time.sleep(1)
        send_b = ''
        # iterate through random_nums and index + remove from database response
        for rndm in random_nums:
            try:
                item_response_dtbse = rfb_response.pop(rndm[0])
                send_b += '\n'.join(item_response_dtbse) + '\n'
            except:
                send_b = sml[random_nums.index(rndm)] + '\nx\nx'
        # return a list of bills in string format
        return send_b

    # this function handles a udp client
    def handle_client(nef):
        ip_version = ipaddress.ip_address(nef[0]).version
        if ip_version == 4:
            # for IPv4 clients
            ip, s_port, d_port = nef[0], int(nef[1]), int(nef[2])
            sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock4.settimeout(5)
            # we bind to the destination port and send to the source port while the client does the opposite
            sock4.bind(('', d_port))
            # punching a hole in the NAT
            sock4.sendto(b'0', (ip, s_port))
            message = sock4.recv(1024).decode('utf-8')
            db = access_database(message.splitlines()[1:])
            # the random verify prohibits ip spoofing
            random_verify = message.splitlines()[0]
            full_msg = random_verify + '\n' + db
            sock4.sendto(full_msg.encode('utf-8'), (ip, s_port))
        elif ip_version == 6:
            # for IPv6 clients
            ip, s_port, d_port = nef[0], int(nef[1]), int(nef[2])
            sock4 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock4.settimeout(5)
            # we bind to the destination port and send to the source port while the client does the opposite
            sock4.bind(('', d_port))
            # punching a hole in the NAT
            sock4.sendto(b'0', (ip, s_port, 0, 0))
            message = sock4.recv(1024).decode('utf-8')
            db = access_database(message.splitlines()[1:])
            # the random verify prohibits ip spoofing
            random_verify = message.splitlines()[0]
            full_msg = random_verify + '\n' + db
            sock4.sendto(full_msg.encode('utf-8'), (ip, s_port, 0, 0))

    while True:
        time.sleep(0.1)
        with open('kill_node.txt', 'r') as kn1:
            if kn1.read() == 'True':
                break
        for new in potential_conns:
            threading.Thread(target=handle_client, args=(new,)).start()
        potential_conns[:] = []


def client_udp(rfb, rfb_response, transaction_pool, potential_conns2):
    # search for only 1 serial num in database 'node_bills.db'
    def access_database(serial_num_address):
        random_num1 = str(random.uniform(0.1, 99.9))
        rfb.append((random_num1, serial_num_address))
        time.sleep(0.8)
        try:
            item_response_dtbse = rfb_response.pop(random_num1)
            return item_response_dtbse[1:]
        except:
            return

    # this function establishes a socket connection with a number '2' node, known as the rendezvous server
    # the rendezvous server exchanges information between udp node and a client.
    # it also updates the udp server with new bills
    def new_conn(ip):
        rendezvous = (ip, 8888)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(60)
        sock.sendto(b'node', rendezvous)
        while True:
            msg = sock.recv(1024).decode('utf-8')
            # a client is ready to exchange information
            if msg == 'ready':
                data = sock.recv(248).decode('utf-8')
                ip, sport, dport = data.splitlines()
                potential_conns2.append((ip, int(sport), int(dport)))
            else:
                # divide bill
                bill = msg.splitlines(keepends=True)[:5]
                bill_serial_num, bill_number, bill_addr = bill[0].strip(), bill[1].strip(), bill[3].strip()
                bill_public_key, bill_digital_sig = bill[2].strip(), bill[4].strip()
                with open('spam_protection.txt', 'r') as sc:
                    sc = sc.read()
                    spam_count = sc.count(bill_serial_num)
                num_bill = bill_serial_num.split('x')[1]
                # check if spam count is under 6 and check if number of bill is below max of 50 million
                if spam_count < 6 and 0 < int(num_bill) < 10000000:
                    db = access_database(bill_serial_num)
                    if db:
                        addr_old = db[0]
                        number = db[1]
                        hash_key = sha3_256(bill_public_key.encode('utf-8')).digest()
                        hash_key_encode = base58.b58encode(hash_key).decode('utf-8')
                        # check if sha3 256 hash of the sender public key equals his address, in the database.
                        # check if number (how many times a bill has been sent) correlates to number in the database
                        if hash_key_encode[:30] == addr_old and int(number) + 1 == int(bill_number):
                            v_sig = confirm_validity.verify_ecdsa(bill_digital_sig, ''.join(bill[:4]),
                                                                  bill_public_key)
                            if v_sig == 'valid':
                                with open('spam_protection.txt', 'a') as sp:
                                    sp.write(bill_serial_num + '\n')
                                transaction_pool.append((bill_serial_num, bill_addr, bill_number))
    # connect to all '2' nodes saved in the ip_folder/2
    while True:
        with open('kill_node.txt', 'r') as kn2:
            if kn2.read() == 'True':
                break
        ip_f = os.listdir('ip_folder/2')
        for ip_address in ip_f:
            threading.Thread(target=new_conn, args=(ip_address.replace('.txt', ''),)).start()
            time.sleep(0.2)
        time.sleep(61)


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
        # start 2 download processes on 2 cores
        #Process(target=download_bills, args=(pos1, t)).start()
        #Process(target=download_bills, args=(pos2, t)).start()
        udp_node(rf1, rf2, new_connect)
