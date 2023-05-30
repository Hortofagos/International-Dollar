import socket
import os
import random
import time
import threading
import base64
import rsa
import ipaddress
import string
import requests
# most modules come preinstalled
# if you miss modules, execute pip install -r ./requirements.txt in the local directory (cmd)

already_tried = []
PORT = 8888

def connect(indicator, data, ipnl):
    # connect to TCP nodes
    with open('rsa_public_key.txt', 'r') as rsk:
        key = rsk.read()
    start_time = int(time.time())
    # search for a connection for max 20 seconds
    while int(time.time()) - start_time <= 20:
        if random.randrange(1000) == 9:
            already_tried.clear()
        # choose a random ip address from list
        SERVER = random.choice(ipnl).replace('.txt', '')
        ADDR = (SERVER, PORT)
        try:
            # check if there already has been a failed connection to the node
            if SERVER not in already_tried:
                # establish a TCP connection to a number '2' node
                client = socket.create_connection(ADDR, timeout=2)
                client.settimeout(4)
                # send the node your public key
                client.sendall(key.encode('utf-8'))
                # get public key of node
                recv_key = client.recv(1024).decode('utf-8')
                # use the RSA algorithm to encrypt your data
                public_key_node = rsa.PublicKey.load_pkcs1(base64.b64decode(recv_key))
                encrypted_data = rsa.encrypt((indicator + data).encode('utf-8'), public_key_node)
                encrypted_data_b64 = base64.b64encode(encrypted_data)
                # send the encrypted data in base64 encoding
                client.sendall(encrypted_data_b64)
                try:
                    # wait for server response, blocking mode
                    msg = client.recv(512).decode('utf-8')
                    client.close()
                    with open('rsa_private_key.txt', 'r') as rsk:
                        private_key = rsk.read()
                        rsa_pk = rsa.PrivateKey.load_pkcs1(base64.b64decode(private_key))
                    # decrypt the response from the node with our ptivate key
                    msg_decrypted = rsa.decrypt(base64.b64decode(msg), rsa_pk).decode('utf-8')
                    return msg_decrypted
                except:
                    return 'n'
        except :
            if SERVER not in already_tried:
                already_tried.append(SERVER)
    # if all connection fail, function will return 'n'
    return 'n'



def public_ip():
    # we designed it this way to minimize load on the node network
    try:
        try:
            try:
                # get your ip by connecting to wikipedia
                my_ip = requests.get('https://www.wikipedia.org').headers['X-Client-IP']
                return my_ip
            except:
                # if wikipedia doesnt work look up amazon
                my_ip = requests.get('https://checkip.amazonaws.com').text.strip()
                return my_ip
        except:
            # if both dont work get your public ip, from a node
            ipnl = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')
            my_ip = connect('x', '', ipnl)
            if my_ip != 'n' and my_ip:
                return my_ip
    except:
        return
    

def connect_udp(sm):
    # connect to udp nodes, via simple udp hole punching technique
    ipf_2 = os.listdir('ip_folder/2')
    my_ip = public_ip()
    ip_version = ipaddress.ip_address(my_ip).version
    if ip_version == 4:
        # connect to a number '2' node with open ports, to establish a IPv4 udp connection
        rendezvous = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rendezvous.settimeout(5)
        rendezvous.sendto('client'.encode('utf-8'), (random.choice(ipf_2).replace('.txt', ''), 8888))
        # receive the address and port information
        msg_peer = rendezvous.recv(248).decode('utf-8').split(' ')
        ip, sport, dport = msg_peer[0], int(msg_peer[1]), int(msg_peer[2])
        # create a p2p socket designed to punch a hole through the NAT and connect to a node also behind a NAT
        sock_p2p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_p2p.settimeout(5)
        # bind to the source port (of the node) and send to the destination port (8888)
        sock_p2p.bind(('', sport))
        ########
        # UDP HOLE PUNCH
        sock_p2p.sendto(b'0', (ip, dport))
        ########
        # create a random string, and include in full msg
        key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=9))
        full_msg = key + '\n' + sm
        sock_p2p.sendto(full_msg, (ip, dport))
        data = sock_p2p.recv(1024).decode('utf-8')
        dta_spl = data.splitlines(keepends=True)
        # By checking the random key string we generated, with the key we received, we prevent IP spoofing
        if dta_spl[0].strip() == key:
            # return the bill in string format
            return ''.join(dta_spl[1:])
    else:
        # create a IPv6 UDP socket
        rendezvous = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        rendezvous.settimeout(5)
        rendezvous.sendto(b'0', (random.choice(ipf_2).replace('.txt', ''), 8887))
        # receive the address and port information
        msg_peer = rendezvous.recv(248).decode('utf-8').split(' ')
        ip, sport, dport = msg_peer[0], msg_peer[1], msg_peer[2]
        # p2p UDP connection IPv6 similar to IPv4 above
        sock_p2p = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock_p2p.settimeout(5)
        sock_p2p.bind(('', sport))
        sock_p2p.sendto(b'0', (ip, dport, 0, 0))
        key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=9))
        full_msg = key + '\n' + sm
        sock_p2p.sendto(full_msg, (ip, dport, 0, 0))
        data = sock_p2p.recv(1024).decode('utf-8')
        dta_spl = data.splitlines(keepends=True)
        if dta_spl[0].strip() == key:
            return ''.join(dta_spl[1:])

def send_bills():
    # this function will take all signed transaction files in the transaction_folder and send them to the node network
    ipnl1 = os.listdir('ip_folder/1')
    ipnl2 = os.listdir('ip_folder/2')
    for transaction in os.listdir('transaction_folder'):
        with open('transaction_folder/' + transaction, 'r') as tm:
            tm = tm.read()
            # send the same transaction to 3 different nodes (ensure distribution)
            threading.Thread(target=connect, args=('b', tm, ipnl1)).start()
            for _ in range(2):
                threading.Thread(target=connect, args=('b', tm, ipnl2)).start()
                time.sleep(0.1)
        os.remove('transaction_folder/' + str(transaction))


def check_validity(serial_num_list):
    # this is the most important function
    # it reaches a consensus on the ownership of bills

    # the ip_folder stores the ip addresses of the nodes in the network (offline and online)
    ipnl1 = os.listdir('ip_folder/1')
    ipnl2 = os.listdir('ip_folder/2')
    # the comparison dictionary uses each serial_number as a key
    comparison = {}
    for serm in serial_num_list:
        comparison[serm] = []
    ct = str(int(time.time()))
    serial_num_list_join = '\n'.join(serial_num_list)
    def main_nodes(ipnl):
        # this function will only connect to main nodes (number '1')
        holder = connect('c', serial_num_list_join, ipnl)
        # importance variable is a number that determines the voting power of the main nodes
        # this number decreases over time until main nodes hold no more special weight
        importance = int(max(0, 1800 - int(ct[0:4])) / 4)
        hdlr_spl = holder.splitlines()
        # split the message from the node in multiple parts of 3 [serial_num, address, number]
        parts_holder = [hdlr_spl[ium:ium + 3] for ium in range(0, len(hdlr_spl), 3)]
        # iterate through the bills and append them to the comparison dictionary
        for bill in parts_holder:
            for x in range(importance):
                comparison[bill[0]].append(tuple(bill))
    def full_nodes(ipnl):
        # this function only connects to secondary nodes (number '2')
        # these nodes are operated by normal users, with open 8888 & 8887 ports TCP & UDP
        holder = connect('c', serial_num_list_join, ipnl)
        hdlr_spl = holder.splitlines()
        # split the message from the node in multiple parts of 3 [serial_num, address, number]
        parts_holder = [hdlr_spl[ium:ium + 3] for ium in range(0, len(hdlr_spl), 3)]
        # iterate through the bills and append them to the comparison dictionary
        for bill in parts_holder:
            comparison[bill[0]].append(tuple(bill))
    def small_udp_node():
        # this function only connects to UDP nodes (usually behind NAT number '3' nodes)
        holder = connect_udp(serial_num_list_join)
        hdlr_spl = holder.splitlines()
        # split the message from the node in multiple parts of 3 [serial_num, address, number]
        parts_holder = [hdlr_spl[ium:ium + 3] for ium in range(0, len(hdlr_spl), 3)]
        # iterate through the bills and append them to the comparison dictionary
        for bill in parts_holder:
            comparison[bill[0]].append(tuple(bill))

    # split all number '1' IPs into 8 equal parts
    r1 = [ipnl1[ium:ium + 8] for ium in range(0, len(ipnl1), 8)]
    # split all number '2' IPs into 8 equal parts
    r2 = [ipnl2[ium:ium + 8] for ium in range(0, len(ipnl2), 8)]
    # udp connections
    r3 = 10
    # randomize ip lists
    random.shuffle(r1)
    random.shuffle(r2)
    # check if main nodes (number '1') still have voting power. It depends on how much time has passed
    if int(ct[0:4]) < 1790:
        # iterate through every single main node
        for t in r1:
            threading.Thread(target=main_nodes, args=(t, )).start()
    # iterate through max 20 blocks of number '2' nodes... Note that each block has 8 ips, but only 1 will be chosen
    # this means at max there will come in 20 votes from number '2' nodes, more likely than not its going to be less,
    # since not every IP block contains an online node
    for c, t2 in enumerate(r2):
        if c == 20:
            break
        threading.Thread(target=full_nodes, args=(t2, )).start()
    # get max 20 votes from udp nodes, again some connections will fail so its more in the range of 10 - 15 votes
    for t3 in range(r3):
        threading.Thread(target=small_udp_node).start()
    # wait 7 seconds for all the responses from nodes
    time.sleep(7)
    full_bills_voted_holders = []
    # iterate through all serial numbers in the dictionary, and append the majority consensus for each bill to
    # the list full_bill_voted_holder.
    for key_dict in comparison:
        get_items = comparison.get(key_dict)
        voted_holder = max(set(get_items), key=get_items.count)
        full_bills_voted_holders.append(voted_holder)
    # return example: [('10x9', 'x2345678901234567890123456789x', '2'), ('5x9', 'x2345678901234567890123456789x', '7')]
    return full_bills_voted_holders


def update_ip_list():
    # this function is responsible for updating your ip_folder with new nodes
    def new_main_ip():
        # this function will only add main number '1' ips through a majority selection processes
        # only other number '1' nodes can give a vote
        comparison_ip = []
        main_ips = os.listdir('ip_folder/1')
        def thrd():
            new_main = connect('u', 'main ip', main_ips)
            comparison_ip.append(new_main)
        # iterate thorugh every known number '1' main node (172.86.121.72)
        for _ in range(len(main_ips)):
            threading.Thread(target=thrd).start()
        time.sleep(10)
        # reach a consensus on 1 new main ip
        try:
            voted_new_ip = max(set(comparison_ip), key=comparison_ip.count)
            if voted_new_ip != 'n':
                open('ip_folder/1/' + str(voted_new_ip) + '.txt', 'w').close()
        except:
            pass

    if random.randint(0, 27) == 3:
        threading.Thread(target=new_main_ip).start()

    ##############

    ipnl = os.listdir('ip_folder/2')
    # get a list of different ips, both number '2' and number '3' (UDP) nodes
    list_ips = connect('u', '', ipnl)

    for c, ip in enumerate(list_ips.splitlines()):
        try:
            # only IPv4 addresses will be accepted and added to the ip_folder
            if ipaddress.ip_address(ip).version == 4:
                # we need to check if multiple ip addresses come from the same block
                # this makes it impossible for an entity, to gain voting majority by buying their way to the top
                matches0 = 0
                matches1 = 0
                matches2 = 0
                ip_split = ip.split('.')
                # check all IPs that are already saved, split the IP [172, 86, 121, 72]
                for ii in os.listdir('ip_folder/2') + os.listdir('ip_folder/3'):
                    item_ip = ii.split('.')
                    if item_ip[0] == ip_split[0]:
                        matches0 += 1
                    if item_ip[:2] == ip_split[:2]:
                        matches1 += 1
                    if item_ip[:3] == ip_split[:3]:
                        matches2 += 1
                # Class A block: max of 32 addresses
                # Class B block: max 4 addresses
                # Class C block: max 1 address
                if matches0 < 32 and matches1 < 4 and matches2 < 1:
                    if (c % 2) == 0:
                        open('ip_folder/2/' + str(ip) + '.txt', 'w').close()
                    else:
                        open('ip_folder/3/' + str(ip) + '.txt', 'w').close()
        except:
            pass


def receive_bills():
    # this function is responsible for invoking the check_validity function and add the new bills to the wallet file
    ipnl = os.listdir('ip_folder/1') + os.listdir('ip_folder/2')
    # find the decrypted wallet file
    for wal in os.listdir('wallet_folder'):
        if wal.startswith('wallet_decrypted'):
            # get wallet info like address
            with open('wallet_folder/' + wal, 'r') as wa:
                wa.seek(0)
                wallet = wa.readlines()
                address = wallet[0].strip()
            # connect to 5 random nodes requesting a sample of serial numbers you own
            full_msgs = []

            def thrd_recv():
                msg = connect('r', address, ipnl)
                full_msgs.extend(msg.splitlines())
            for iteration in range(5):
                threading.Thread(target=thrd_recv).start()
            time.sleep(5)
            print(full_msgs)
            def confirm_bill(serial_numbers):
                # this function invokes the above check_validity function
                bill_holder = check_validity(serial_numbers)
                list_new_bills = []
                print(list_new_bills)
                # iterate through list of bills, and check if the node consensus agrees with your address
                for new_b in bill_holder:
                    if new_b[1] == address:
                        list_new_bills.append(new_b)
                return list_new_bills

            # look though bills that are already in wallet, to avoid unnecessary load
            bills_in_wallet = []
            for b in wallet[4:]:
                bills_in_wallet.append(b.split()[0])
            bills_to_confirm = []
            # check all serial numbers that you this wallet address supposedly owns
            csm = []
            for sm in full_msgs:
                if int(sm.split('x')[1]) < 10000000 and sm.strip() not in bills_in_wallet and sm not in csm:
                    csm.append(sm)
                    bills_to_confirm.append(sm)
            # split list of bills in multiple parts that contain 4 serial numbers each
            parts_b = [bills_to_confirm[ium:ium + 4] for ium in range(0, len(bills_to_confirm), 4)]
            # format list = [['1x9', '2x9', '5x9', '10x9'], ['1x99', ....]]
            for p in parts_b:
                new_bills = confirm_bill(p)
                # append the new bills to the wallet
                with open('wallet_folder/' + wal, 'a') as wa2:
                    for b in new_bills:
                        wa2.write(b[0] + ' ' + b[2] + ' ' + str(int(time.time())) + '\n')


def ask_for_luck():
    # this function asks the main nodes for free bills
    for w in os.listdir('wallet_folder'):
        if w.startswith('wallet_decrypted'):
            addr = w[17:].replace('.txt', '')
            ipf = os.listdir('ip_folder/1')
            connect('l', addr, ipf)
