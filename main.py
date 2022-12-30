import base64
import hashlib
import os
import subprocess
import sys
import threading
import time
from tkinter import *
from tkinter import filedialog

import ecdsa
import qrcode
from PIL import ImageTk, Image
import cv2
from pyzbar.pyzbar import decode
from tkinterdnd2 import *
import getpass
import rsa
from datetime import datetime
import random
from tkextrafont import Font

from print import full_bill, only_qr
import sender_node
import wallet_decryption
import wallet_encryption

try:
    os.mkdir('transaction_folder')
    os.mkdir('wallet_folder')
except:
    pass

root = Tk()
root.title('International Dollar')
root.tk.call('tk', 'scaling', 1.36)
height_screen = root.winfo_screenheight()
try:
    font = Font(file="ind_font.ttf", family="ind")
except:
    pyglet.resource.add_font('ind_font.ttf')

if height_screen >= 4000:
    res = '8'
elif height_screen >= 1600:
    res = '4'
else:
    res = ''

try:
    reso = int(int(res) / 2)
except Exception:
    reso = 1

try:
    path = os.path.expanduser('~/wallet_folder_backup')
    try:
        os.mkdir(path)
    except:
        pass
    for file_w in os.listdir('wallet_folder'):
        if not file_w.startswith('wallet_decrypted'):
            with open('wallet_folder/' + file_w, 'r') as fw:
                wallet = fw.read()
            with open(path + '/' + file_w, 'w') as fw2:
                fw2.seek(0)
                fw2.truncate()
                fw2.write(wallet)
except:
    pass


path, path_purchase, path_info = 'img/home' + res + '.png', 'img/purchase' + res + '.png','img/info' + res + '.png'
path_node_terminal = 'img/_terminal' + res + '.png'
path_sign_in, path_wallet = 'img/sign_in' + res + '.png', 'img/wallet' + res + '.png'
path_button_generate_wallet = 'img/generate_wallet' + res + '.png'
path_button_sign_in = 'img/different_buttons/sign_in_button' + res + '.png'
path_button_send = 'img/different_buttons/send_button' + res + '.png'
path_button_confirm = 'img/different_buttons/confirm_button' + res + '.png'
path_claim_bill = 'img/pop_up/claim_bill' + res + '.png'
path_button_lucky = 'img/different_buttons/button_lucky' + res + '.png'
path_button_print = 'img/different_buttons/print_button' + res + '.png'
path_button_only_qr = 'img/different_buttons/only_qr_button' + res + '.png'
path_button_add_bill = 'img/different_buttons/add_bill_button' + res + '.png'
path_qr_overlay = 'img/pop_up/qr_overlay' + res + '.png'
path_button_next = 'img/different_buttons/next_button' + res + '.png'
path_button_previous = 'img/different_buttons/previous_button' + res + '.png'
path_button_tf = 'img/different_buttons/tf_button' + res + '.png'
path_button_r = 'img/different_buttons/r_button' + res + '.png'
path_success = 'img/pop_up/success' + res + '.png'
path_button_participate = 'img/different_buttons/button_participate' + res + '.png'
path_button_not_participate = 'img/different_buttons/button_not_participate' + res + '.png'
path_button_log_in = 'img/different_buttons/log_in_button' + res + '.png'
path_button_show = 'img/different_buttons/show_button' + res + '.png'
path_button_show2 = 'img/different_buttons/show2_button' + res + '.png'
path_button_start = 'img/different_buttons/start' + res + '.png'
path_button_end = 'img/different_buttons/end' + res + '.png'
path_button_receive = 'img/different_buttons/reload_button' + res + '.png'
path_generate_address_button = 'img/different_buttons/generate_address_button' + res + '.png'
path_generate_wallet_button = 'img/different_buttons/generate_wallet_button' + res + '.png'
path_button_show3 = 'img/different_buttons/show3_button' + res + '.png'
path_plus_bills_button = 'img/different_buttons/plus_bills_button' + res + '.png'
path_button_close_amount = 'img/different_buttons/close_amount' + res + '.png'
path_button_close = 'img/pop_up/close' + res + '.png'
path_checkbox = 'img/different_buttons/checkbox' + res + '.png'
path_checkmark = 'img/different_buttons/checkmark' + res + '.png'
path_button_validity, path_valid = 'img/different_buttons/check_validity_button' + res + '.png', 'img/pop_up/valid' + res + '.png'
path_w1,path_w2,path_w5 = 'img/wallet_bills/_1' + res + '.png','img/wallet_bills/_2' + res + '.png','img/wallet_bills/_5' + res + '.png'
path_w10,path_w20,path_w50 = 'img/wallet_bills/_10' + res + '.png','img/wallet_bills/_20' + res + '.png','img/wallet_bills/_50' + res + '.png'
path_w100,path_w200,path_w500 = 'img/wallet_bills/_100' + res + '.png','img/wallet_bills/_200' + res + '.png','img/wallet_bills/_500' + res + '.png'
path_w1000,path_w2000 = 'img/wallet_bills/_1000' + res + '.png','img/wallet_bills/_2000' + res + '.png',
path_w5000,path_w10000 = 'img/wallet_bills/_5000' + res + '.png','img/wallet_bills/_10000' + res + '.png',
path_w20000,path_w50000 = 'img/wallet_bills/_20000' + res + '.png','img/wallet_bills/_50000' + res + '.png'
path_w100000 = 'img/wallet_bills/_100000' + res + '.png'
path_w1c,path_w2c,path_w5c = 'img/wallet_bills/_1c' + res + '.png','img/wallet_bills/_2c' + res + '.png','img/wallet_bills/_5c' + res + '.png'
path_w10c,path_w20c,path_w50c = 'img/wallet_bills/_10c' + res + '.png','img/wallet_bills/_20c' + res + '.png','img/wallet_bills/_50c' + res + '.png'
path_w100c,path_w200c = 'img/wallet_bills/_100c' + res + '.png','img/wallet_bills/_200c' + res + '.png'
path_w500c,path_w1000c = 'img/wallet_bills/_500c' + res + '.png','img/wallet_bills/_1000c' + res + '.png'
path_w2000c,path_w5000c = 'img/wallet_bills/_2000c' + res + '.png','img/wallet_bills/_5000c' + res + '.png'
path_w10000c,path_w20000c = 'img/wallet_bills/_10000c' + res + '.png','img/wallet_bills/_20000c' + res + '.png'
path_w50000c,path_w100000c = 'img/wallet_bills/_50000c' + res + '.png','img/wallet_bills/_100000c' + res + '.png'

def update_wallet():
    for x in os.listdir('wallet_folder'):
        if x.startswith('wallet_decrypted'):
            with open('wallet_folder/' + x, 'r+') as d:
                dr_w = d.readlines()
                num_lines_w = sum(1 for _ in dr_w)
                return dr_w, num_lines_w

try:
    dr, num_lines = update_wallet()
except:
    pass

international_dollar = Text(root, font=('ind', 45 * reso), bg='black', fg='white', bd=0, highlightthickness=0)
international_dollar.insert(1.0, 'International Dollar')
international_dollar.place(x=150 * reso, y=45 * reso, height=90 * reso, width=410 * reso)
international_dollar.config(state='disabled', cursor='arrow')


def generate_new_keys():
    public_key_rsa, private_key_rsa = rsa.newkeys(2048)
    with open('rsa_public_key.txt', 'w') as rk:
        rk.write(base64.b64encode(public_key_rsa.save_pkcs1('PEM')).decode('utf-8'))
    with open('rsa_private_key.txt', 'w') as rk2:
        rk2.write(base64.b64encode(private_key_rsa.save_pkcs1('PEM')).decode('utf-8'))

with open('rsa_public_key.txt', 'r') as r:
    f = r.read()
if not f:
    generate_new_keys()
elif random.randrange(9) == 3:
    generate_new_keys()

try:
    wa_sliced = dr[0]
    address_qr = qrcode.QRCode(version=1, box_size=6, border=1, error_correction=qrcode.constants.ERROR_CORRECT_H)
    address_qr.add_data(wa_sliced)
    qr_make = address_qr.make_image(fill_color='black', back_color='#D3D3D3')
    qr_resize = qr_make.resize((250 * reso, 250 * reso), Image.Resampling.LANCZOS)
    qr_img = ImageTk.PhotoImage(qr_resize)
    qr = Label(root, image=qr_img, bd=0, highlightthickness=0)
    address_txt = Text(root, font=('ind', 19 * reso), bg='black', fg='white', bd=0, highlightthickness=0)
except Exception:
    pass

root.configure(background='white')
img = PhotoImage(file=path)
panel = Label(root, image=img)
panel.pack(fill='none', expand=True)
node_terminal_img = PhotoImage(file=path_node_terminal)
node_terminal = Label(root, image=node_terminal_img)
info_img = PhotoImage(file=path_info)
info = Label(root, image=info_img)
purchse_img = PhotoImage(file=path_purchase)
purchase = Label(root, image=purchse_img)
wallet_img = PhotoImage(file=path_wallet)
wallet = Label(root, image=wallet_img)
sign_in_img = PhotoImage(file=path_sign_in)
sign_in = Label(root, image=sign_in_img)
generate_wallet_img = PhotoImage(file=path_button_generate_wallet)
generate_wallet = Label(root, image=generate_wallet_img)
receiver = Entry(root, font=('ind', 20 * reso), bg='light grey')
frame_w = Frame(root, bg='black')
root.resizable(False, False)

with open('node_class.txt', 'r') as ncl:
    l1 = ncl.readlines()
    l2 = l1[0].strip()
    l3 = l1[1].strip()
    l4 = l1[2].strip()

class_var = StringVar(root)
node_class_selector = OptionMenu(root, class_var, 'FULL NODE', 'SMALL NODE')
node_class_selector.config(font=('ind', 24 * reso, 'bold'), cursor='hand2', bg='black', fg='white')
ncss = root.nametowidget(node_class_selector.menuname)
ncss.config(font=('ind', 20 * reso))
class_var.set(l2)

ron_var = StringVar(root)
ron = OptionMenu(root, ron_var, 'YES', 'NO')
ron.config(font=('ind', 24 * reso, 'bold'), cursor='hand2', bg='black', fg='white')
rons = root.nametowidget(ron.menuname)
rons.config(font=('ind', 20 * reso))
ron_var.set(l3)

bak_var = StringVar(root)
bak = OptionMenu(root, bak_var, 'YES', 'NO')
bak.config(font=('ind', 24 * reso, 'bold'), cursor='hand2', bg='black', fg='white')
baks = root.nametowidget(bak.menuname)
baks.config(font=('ind', 20 * reso))
bak_var.set(l4)
try:
    USER_NAME = getpass.getuser()
    disk = os.path.realpath(__file__)[0]
    bat_path = disk + r':\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' % USER_NAME
except Exception:
    pass

def start():
    with open('node_class.txt', 'w') as nc:
        nc.seek(0)
        nc.truncate()
        nc.write(str(class_var.get()) + '\n')
        nc.write(str(ron_var.get()) + '\n')
        nc.write(str(bak_var.get()))

    if ron_var.get() == 'YES':
        try:
            if class_var.get() == 'FULL NODE':
                file_path = str(os.path.dirname(os.path.realpath(__file__))) + '/node_client.py'
                file_path2 = str(os.path.dirname(os.path.realpath(__file__))) + '/client_node.py'
            else:
                file_path = str(os.path.dirname(os.path.realpath(__file__))) + '/udp_hole_node.py'
                file_path2 = str(os.path.dirname(os.path.realpath(__file__))) + '/udp_hole_client.py'
            with open(bat_path + '\\' + 'server1.bat', 'w+') as bat_file:
                bat_file.write(r'start "" "%s"' % file_path)
            with open(bat_path + '\\' + 'server2.bat', 'w+') as bat_file2:
                bat_file2.write(r'start "" "%s"' % file_path2)
        except:
            pass

    with open('kill_node.txt', 'w') as kn:
        kn.seek(0)
        kn.truncate()
    start_button.place_forget()
    end_button.place(x=977 * reso, y=190 * reso)

    if class_var.get() == 'FULL NODE':
        subprocess.Popen([sys.executable, 'node_client.py'])
        time.sleep(0.5)
    else:
        subprocess.Popen([sys.executable, 'udp_hole_node.py'])
        time.sleep(0.5)

    def thrd2():
        time.sleep(5)
        for _ in range(3):
            sender_node.update_ip_list()

    threading.Thread(target=thrd2).start()

def end():
    with open('kill_node.txt', 'w') as kn1:
        kn1.seek(0)
        kn1.write('True')
    end_button.place_forget()
    start_button.place(x=977 * reso, y=190 * reso)
    time.sleep(1)

b = Text(root, font=('ind', 37 * reso), bg='black', fg='white', bd=0, highlightthickness=0)
balance_top = Text(root, font=('ind', 26 * reso), bg='black', fg='white', bd=0, highlightthickness=0)

start_button_img = PhotoImage(file=path_button_start)
start_button = Button(root, image=start_button_img, bd=0, highlightthickness=0, cursor='hand2', command=start)
end_button_img = PhotoImage(file=path_button_end)
end_button = Button(root, image=end_button_img, bd=0, highlightthickness=0, cursor='hand2', command=end)


a = Entry(root, font=('ind', 22 * reso), bg='light grey')
receiver_history = Text(root, font=('ind', 22 * reso), bg='black', fg='light grey', bd=0, highlightthickness=0)
receiver_history.bind("<Key>", lambda e: "break")

def request_luck():
    with open('last_luck.txt', 'r+') as lt:
        last_timestamp = lt.read()
        lt.seek(0)
        lt.truncate()
        lt.write(str(int(time.time())))
    if int(time.time()) - int(last_timestamp) > 86400:
        button_lucky.config(cursor='watch')
        sender_node.ask_for_luck()
        b1 = b.get("1.0", END).strip('$')
        receive_bills()
       
def print_bills():
    root.config(cursor='watch')
    button_print.config(cursor='watch')
    def t():
        full_bill(list(filter(None, selected_bills_text.get(1.0, END).splitlines())))
        root.config(cursor='arrow')
        button_print.config(cursor='hand2')

    threading.Thread(target=t).start()

def print_only_qr():
    root.config(cursor='watch')
    button_only_qr.config(cursor='watch')
    def t():
        only_qr(selected_bills_text.get(1.0, END).splitlines())
        root.config(cursor='arrow')
        button_only_qr.config(cursor='hand2')

    threading.Thread(target=t).start()


button_lucky_img = PhotoImage(file=path_button_lucky)
button_lucky = Button(root, image=button_lucky_img, bd=0, highlightthickness=0, cursor='hand2', command=request_luck)
button_print_img = PhotoImage(file=path_button_print)
button_print = Button(root, image=button_print_img, bd=0, highlightthickness=0, cursor='hand2', command=print_bills)
only_qr_img = PhotoImage(file=path_button_only_qr)
button_only_qr = Button(root, image=only_qr_img, bd=0, highlightthickness=0, cursor='hand2', command=print_only_qr)
all_bills_text = Text(root, font=('ind', 22 * reso), bg='black', fg='light grey')
selected_bills_text = Text(root, font=('ind', 22 * reso), bg='#181818', fg='light grey')
asl_text = Text(root, font=('ind', 26 * reso), bg='black', fg='light grey', bd=0)
asl_text.insert(1.0, 'Copy bills\t\t   Paste bills')
asl_text.config(state='disabled')

def node_terminal_button():
    close()
    button.config(bg='white', fg='black'),button2.config(bg='black', fg='white'), button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white'), button_log_in.config(bg='black', fg='black')
    with open('kill_node.txt', 'r') as kn:
        if kn.read() == 'True':
            start_button.place(x=977 * reso, y=190 * reso)
        else:
            end_button.place(x=977 * reso, y=190 * reso)
    node_class_selector.place(x=450 * reso,  y=255 * reso, width=230 * reso, height=45 * reso)
    ron.place(x=450 * reso,  y=395 * reso, width=230 * reso, height=45 * reso)
    bak.place(x=450 * reso,  y=535 * reso, width=230 * reso, height=45 * reso)
    node_terminal.place(x=0, y=0)

def sign_in_button():
    close()
    button.config(bg='black', fg='white'),button2.config(bg='black', fg='white'),button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white'),button_log_in.config(bg='white', fg='black')
    button_generate_wallet.config(bg='black', fg='white')
    button_log_in.place(x=609 * reso, y=196 * reso, width=322 * reso, height=57 * reso)
    button_generate_wallet.place(x=285 * reso, y=196 * reso, width=322 * reso, height=57 * reso)
    enter_address.place(x=400 * reso, y=355 * reso, width=425 * reso, height=50 * reso)
    enter_key.place(x=370 * reso, y=500 * reso, width=425 * reso, height=50 * reso)
    log_in_button2.place(x=500 * reso, y=650 * reso)
    with open('check_signed_in.txt', 'r') as csi:
        if csi.read() == 'True':
            button_checkmark.place(x=465 * reso, y=602 * reso)
        else:
            button_checkbox.place(x=465 * reso, y=602 * reso)
    button_show.place(x=800 * reso, y=500 * reso)
    sign_in.place(x=0, y=0)

def info_button():
    close()
    button.config(bg='black', fg='white'),button2.config(bg='white', fg='black'),button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white')
    info.place(x=0, y=0)

def win_button():
    close()
    button.config(bg='black', fg='white'),button4.config(bg='black', fg='white'),button2.config(bg='black', fg='white')
    button3.config(bg='white', fg='black')
    button_lucky.place(x=60 * reso, y=650 * reso)
    button_print.place(x=640 * reso, y=650 * reso)
    button_only_qr.place(x=950 * reso, y=650 * reso)
    all_bills_text.place(x=640 * reso, y=310 * reso, width=240 * reso, height=300 * reso)
    selected_bills_text.place(x=900 * reso, y=310 * reso, width=240 * reso, height=300 * reso)
    asl_text.place(x=640 * reso, y=260 * reso, width=480 * reso, height=48 * reso)
    only_sm = ''
    for bsm in dr[4:]:
        if not bsm.startswith('-'):
            only_sm += bsm.split()[0] + '\n'
    all_bills_text.insert(1.0, only_sm[:-1])
    purchase.place(x=0, y=0)
def wallet_button():
    close()
    button.config(bg='black', fg='white'),button2.config(bg='black', fg='white'),button3.config(bg='black', fg='white')
    button4.config(bg='white', fg='black')
    plus_bills_button.place(x=435 * reso, y=725 * reso)
    receiver.place(x=853 * reso, y=238 * reso, width=343 * reso, height=36 * reso)
    send.place(x=1075 * reso, y=365 * reso)
    b.place(x=340 * reso, y=187 * reso, width=480 * reso, height=60 * reso)
    balance_top.place(x=660 * reso, y=30 * reso, width=450 * reso, height=40 * reso)
    frame_w.place(x=18 * reso, y=170 * reso, width=305 * reso, height=595 * reso)
    close_amount.place(x=1157 * reso, y=324 * reso)
    receiver_button.place(x=747 * reso, y=190 * reso)
    a.place(x=853 * reso, y=320 * reso, width=343 * reso, height=36 * reso)
    next_button.place(x=720 * reso, y=730 * reso)
    receiver_history.place(x=343 * reso, y=310 * reso, width=480 * reso, height=450 * reso)
    wallet.place(x=0, y=0)
    try:
        qr.place(x=898 * reso, y=468 * reso)
        tf_button.place(x=1155 * reso, y=570 * reso)
        qr.lift()
        address_txt.delete(1.0, END)
        address_txt.tag_configure('center', justify='center')
        address_txt.insert(1.0, wa_sliced.strip())
        address_txt.tag_add('center', '1.0', 'end')
        address_txt.config(state='disabled')
        address_txt.place(x=861 * reso, y=730 * reso, width=325 * reso, height=35 * reso)
        address_txt.lift()
    except Exception:
        pass

def generate_wallet_button():
    button_show.place_forget(),enter_key.place_forget(),log_in_button2.place_forget()
    enter_address.place_forget(),sign_in.place_forget(), button_checkmark.place_forget(), button_checkbox.place_forget()
    button_generate_wallet.config(bg='white', fg='black')
    button_log_in.config(bg='black', fg='white')
    generate_address_text.place(x=380 * reso, y=318 * reso, width=370 * reso, height=40 * reso)
    generate_address_button.place(x=760 * reso, y=318 * reso)
    public_key.place(x=340 * reso, y=420 * reso, width=550 * reso, height=30 * reso)
    private_key.place(x=380 * reso, y=500 * reso, width=420 * reso, height=30 * reso)
    button_show2.place(x=810 * reso, y=500 * reso)
    choose_password.place(x=380 * reso, y=600 * reso, width=415 * reso, height=40 * reso)
    generate_wallet_button2.place(x=505 * reso, y=660 * reso)
    button_show3.place(x=805 * reso, y=600 * reso)
    generate_wallet.place(x=0, y=0)

tf_text = Text(font=('ind', 28 * reso), bg='black', fg='white', bd=0)
def transfer_wallet():
    try:
        data_wallet = ''.join(dr[:4])
        wallet_qr = qrcode.QRCode(version=1, box_size=4, border=1,
                                  error_correction=qrcode.constants.ERROR_CORRECT_L)
        wallet_qr.add_data(data_wallet)
        wqr_make_security = wallet_qr.make_image(fill_color='#F5F5F5', back_color='white')
        wqr_resize_security = wqr_make_security.resize((250 * reso, 250 * reso), Image.Resampling.LANCZOS)
        wqr_security_img = ImageTk.PhotoImage(wqr_resize_security)
        qr.wqr_security_img = wqr_security_img
        qr.config(image=wqr_security_img)
        qr.config(text='SECURITY RISK', font=('ind', 36 * reso, 'bold'), fg='red', compound='center')
        tf_text.delete(1.0, END)
        tf_text.insert(1.0, 'Transfer wallet')
        tf_text.place(x=935 * reso, y=420 * reso, width=190 * reso, height=45 * reso)
        tf_button.place_forget()
    except Exception:
        pass

    def config_normal():
        time.sleep(5)
        r_button.place(x=850 * reso, y=570 * reso)
        wqr_make = wallet_qr.make_image(fill_color='black', back_color='#D3D3D3')
        wqr_resize = wqr_make.resize((250 * reso, 250 * reso), Image.Resampling.LANCZOS)
        wqr_img = ImageTk.PhotoImage(wqr_resize)
        qr.wqr_img = wqr_img
        qr.config(image=wqr_img, text=' ')
    threading.Thread(target=config_normal).start()

def receive_qr():
    r_button.place_forget()
    tf_button.place(x=1155 * reso, y=570 * reso)
    tf_text.place_forget()
    qr.config(image=qr_img)

tf_button_img = PhotoImage(file=path_button_tf)
tf_button = Button(root, image=tf_button_img, bd=0, highlightthickness=0, cursor='hand2', command=transfer_wallet)
r_button_img = PhotoImage(file=path_button_r)
r_button = Button(root, image=r_button_img, bd=0, highlightthickness=0, cursor='hand2', command=receive_qr)

page_wallet = 1
place_next_button = 0
def page():
    global place_next_button
    try:
        conf = ''
        num_of_bills = 0
        try:
            dr_new, _ = update_wallet()
            for t in reversed(dr_new[4:]):
                conf += t.split()[0] + '\t\t        ' + str(datetime.fromtimestamp(int(t.split()[2])).strftime('%Y-%m-%d   %H:%M')) + '\n\n'
                num_of_bills += 1
        except Exception:
            pass
        if place_next_button != 0:
            next_button.place(x=720 * reso, y=730 * reso)
            place_next_button -= 1
        if page_wallet > 1:
            previous_button.place(x=345 * reso, y=730 * reso)
        else:
            previous_button.place_forget()
        if page_wallet * 4 >= num_of_bills:
            next_button.place_forget()
            place_next_button += 1

        conf_split = '\n'.join(conf.splitlines()[((page_wallet-1) * 12):(12*page_wallet)])
        receiver_history.delete(1.0, END)
        receiver_history.insert(1.0, conf_split)

        num_paragraph = 0
        for paragraph in conf_split.splitlines():
            if paragraph.startswith('-'):
                receiver_history.tag_add('red', str(num_paragraph) + '.end', str(num_paragraph + 1) + '.end')
                receiver_history.tag_config('red', foreground='red')
            num_paragraph += 1
    except:
        pass


def next_():
    global page_wallet
    page_wallet += 1
    page()
def previous():
    global page_wallet
    page_wallet -= 1
    page()


next_button_img = PhotoImage(file=path_button_next)
next_button = Button(root, image=next_button_img, bd=0, highlightthickness=0, cursor='hand2', command=next_)
previous_button_img = PhotoImage(file=path_button_previous)
previous_button = Button(root, image=previous_button_img, bd=0, highlightthickness=0, cursor='hand2', command=previous)
page()

w1c_img = PhotoImage(file=path_w1c)
w2c_img = PhotoImage(file=path_w2c)
w5c_img = PhotoImage(file=path_w5c)
w10c_img = PhotoImage(file=path_w10c)
w20c_img = PhotoImage(file=path_w20c)
w50c_img = PhotoImage(file=path_w50c)
w100c_img = PhotoImage(file=path_w100c)
w200c_img = PhotoImage(file=path_w200c)
w500c_img = PhotoImage(file=path_w500c)
w1000c_img = PhotoImage(file=path_w1000c)
w2000c_img = PhotoImage(file=path_w2000c)
w5000c_img = PhotoImage(file=path_w5000c)
w10000c_img = PhotoImage(file=path_w10000c)
w20000c_img = PhotoImage(file=path_w20000c)
w50000c_img = PhotoImage(file=path_w50000c)
w100000c_img = PhotoImage(file=path_w100000c)
w1_img = PhotoImage(file=path_w1)
w2_img = PhotoImage(file=path_w2)
w5_img = PhotoImage(file=path_w5)
w10_img = PhotoImage(file=path_w10)
w20_img = PhotoImage(file=path_w20)
w50_img = PhotoImage(file=path_w50)
w100_img = PhotoImage(file=path_w100)
w200_img = PhotoImage(file=path_w200)
w500_img = PhotoImage(file=path_w500)
w1000_img = PhotoImage(file=path_w1000)
w2000_img = PhotoImage(file=path_w2000)
w5000_img = PhotoImage(file=path_w5000)
w10000_img = PhotoImage(file=path_w10000)
w20000_img = PhotoImage(file=path_w20000)
w50000_img = PhotoImage(file=path_w50000)
w100000_img = PhotoImage(file=path_w100000)

amount = 0
bills_w1, bills_w2, bills_w5, bills_w10, bills_w20, bills_w50, bills_w100, bills_w200, bills_w500 = 0, 0, 0, 0, 0, 0, 0, 0, 0
bills_w1000, bills_w2000, bills_w5000, bills_w10000, bills_w20000, bills_w50000, bills_w100000 = 0, 0, 0, 0, 0, 0, 0
selected_w1, selected_w2, selected_w5, selected_w10, selected_w20 = 0, 0, 0, 0, 0
selected_w50, selected_w100, selected_w200, selected_w500, selected_w1000 = 0, 0, 0, 0, 0
selected_w2000, selected_w5000, selected_w10000, selected_w20000 = 0, 0, 0, 0
selected_w50000, selected_w100000 = 0, 0
def update_balance():
    global first_iteration, amount, count_selected
    global bills_w1, bills_w2, bills_w5, bills_w10, bills_w20, bills_w50, bills_w100, bills_w200, bills_w500
    global bills_w1000, bills_w2000, bills_w5000, bills_w10000, bills_w20000, bills_w50000, bills_w100000
    try:
        dr_new2, _ = update_wallet()
    except:
        pass
    bills_w1 = bills_w2 = bills_w5 = bills_w10 = bills_w20 = bills_w50 = bills_w100 = bills_w200 = bills_w500 = 0
    bills_w1000 = bills_w2000 = bills_w5000 = bills_w10000 = bills_w20000 = bills_w50000 = bills_w100000 = 0
    try:
        for az in dr_new2:
            if az.startswith('1x'):
                bills_w1 += 1
            elif az.startswith('2x'):
                bills_w2 += 1
            elif az.startswith('5x'):
                bills_w5 += 1
            elif az.startswith('10x'):
                bills_w10 += 1
            elif az.startswith('20x'):
                bills_w20 += 1
            elif az.startswith('50x'):
                bills_w50 += 1
            elif az.startswith('100x'):
                bills_w100 += 1
            elif az.startswith('200x'):
                bills_w200 += 1
            elif az.startswith('500x'):
                bills_w500 += 1
            elif az.startswith('1000x'):
                bills_w1000 += 1
            elif az.startswith('2000x'):
                bills_w2000 += 1
            elif az.startswith('5000x'):
                bills_w5000 += 1
            elif az.startswith('10000x'):
                bills_w10000 += 1
            elif az.startswith('20000x'):
                bills_w20000 += 1
            elif az.startswith('50000x'):
                bills_w50000 += 1
            elif az.startswith('100000x'):
                bills_w100000 += 1
    except Exception:
        pass
    balance = bills_w1+(bills_w2*2)+(bills_w5*5)+(bills_w10*10)+(bills_w20*20)+(bills_w50*50)+(bills_w100*100) \
               + (bills_w200*200)+(bills_w500*500)+(bills_w1000*1000)+(bills_w2000*2000)+(bills_w5000*5000) \
               + (bills_w10000*10000)+(bills_w20000*20000)+(bills_w50000*50000)+(bills_w100000*100000)
    balance_format = f'{balance:,}'
    balance_top_format = f'{balance:,}'
    balance_top.bind("<Key>", lambda e: "break")
    balance_top.tag_configure('tag-right', justify='right')
    balance_top.delete(1.0, END)
    balance_top.insert(1.0, str(balance_top_format) + '$', 'tag-right')
    b.delete(1.0, END)
    b.insert(1.0, 'Balance:  ' + str(balance_format) + '$')
    b.bind("<Key>", lambda e: "break")
    count_selected = False
    start_bills()

count_selected = False
def amount_config():
    amount_format = f'{amount:,}'
    a.delete(0, END)
    a.insert(0, str(amount_format) + '$')
    a.bind("<Key>", lambda e: "break")

def add_1():
    global selected_w1, amount, count_selected
    if bills_w1 - selected_w1 > 0:
        if count_selected:
            selected_w1 += 1
            amount += 1
        w1.config(text='       ' + str(bills_w1 - selected_w1), cursor='hand2', state='normal',
                  image=w1c_img)
    if bills_w1 - selected_w1 == 0:
        w1.config(cursor='', image=w1_img, state='disabled')
    amount_config()
w1 = Button(frame_w, image=w1_img, bd=0, command=add_1, state='disabled',
            font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_2():
    global selected_w2, amount, count_selected
    if bills_w2 - selected_w2 > 0:
        if count_selected:
            selected_w2 += 1
            amount += 2
        w2.config(text='       ' + str(bills_w2 - selected_w2), cursor='hand2', state='normal',
                  image=w2c_img)
    if bills_w2 - selected_w2 == 0:
        w2.config(cursor='', image=w2_img, state='disabled')
    amount_config()
w2 = Button(frame_w, image=w2_img, bd=0, command=add_2, state='disabled',
            font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_5():
    global selected_w5, amount, count_selected
    if bills_w5 - selected_w5 > 0:
        if count_selected:
            selected_w5 += 1
            amount += 5
        w5.config(text='       ' + str(bills_w5 - selected_w5), cursor='hand2', state='normal',
                  image=w5c_img)
    if bills_w5 - selected_w5 == 0:
        w5.config(cursor='', image=w5_img, state='disabled')
    amount_config()
w5 = Button(frame_w, image=w5_img, bd=0, command=add_5, state='disabled',
            font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_10():
    global selected_w10, amount, count_selected
    if bills_w10 - selected_w10 > 0:
        if count_selected:
            selected_w10 += 1
            amount += 10
        w10.config(text='       ' + str(bills_w10 - selected_w10), cursor='hand2', state='normal',
                   image=w10c_img)
    if bills_w10 - selected_w10 == 0:
        w10.config(cursor='', image=w10_img, state='disabled')
    amount_config()
w10 = Button(frame_w, image=w10_img, bd=0, command=add_10, state='disabled',
             font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_20():
    global selected_w20, amount, count_selected
    if bills_w20 - selected_w20 > 0:
        if count_selected:
            selected_w20 += 1
            amount += 20
        w20.config(text='       ' + str(bills_w20 - selected_w20), cursor='hand2', state='normal',
                   image=w20c_img)
    if bills_w20 - selected_w20 == 0:
        w20.config(cursor='', image=w20_img, state='disabled')
    amount_config()
w20 = Button(frame_w, image=w20_img, bd=0, command=add_20, state='disabled',
             font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_50():
    global selected_w50, amount, count_selected
    if bills_w50 - selected_w50 > 0:
        if count_selected:
            selected_w50 += 1
            amount += 50
        w50.config(text='       ' + str(bills_w50 - selected_w50), cursor='hand2', state='normal',
                   image=w50c_img)
    if bills_w50 - selected_w50 == 0:
        w50.config(cursor='', image=w50_img, state='disabled')
    amount_config()
w50 = Button(frame_w, image=w50_img, bd=0, command=add_50, state='disabled',
             font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_100():
    global selected_w100, amount, count_selected
    if bills_w100 - selected_w100 > 0:
        if count_selected:
            selected_w100 += 1
            amount += 100
        w100.config(text='       ' + str(bills_w100 - selected_w100), cursor='hand2', state='normal',
                    image=w100c_img)
    if bills_w100 - selected_w100 == 0:
        w100.config(cursor='', image=w100_img, state='disabled')
    amount_config()
w100 = Button(frame_w, image=w100_img, bd=0, command=add_100, state='disabled',
              font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_200():
    global selected_w200, amount, count_selected
    if bills_w200 - selected_w200 > 0:
        if count_selected:
            selected_w200 += 1
            amount += 200
        w200.config(text='       ' + str(bills_w200 - selected_w200), cursor='hand2', state='normal',
                    image=w200c_img)
    if bills_w200 - selected_w200 == 0:
        w200.config(cursor='', image=w200_img, state='disabled')
    amount_config()
w200 = Button(frame_w, image=w200_img, bd=0, command=add_200, state='disabled',
              font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_500():
    global selected_w500, amount, count_selected
    if bills_w500 - selected_w500 > 0:
        if count_selected:
            selected_w500 += 1
            amount += 500
        w500.config(text='       ' + str(bills_w500 - selected_w500), cursor='hand2', state='normal',
                    image=w500c_img)
    if bills_w500 - selected_w500 == 0:
        w500.config(cursor='', image=w500_img, state='disabled')
    amount_config()
w500 = Button(frame_w, image=w500_img, bd=0, command=add_500, state='disabled',
              font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_1000():
    global selected_w1000, amount, count_selected
    if bills_w1000 - selected_w1000 > 0:
        if count_selected:
            selected_w1000 += 1
            amount += 1000
        w1000.config(text='       ' + str(bills_w1000 - selected_w1000), cursor='hand2', state='normal',
                     image=w1000c_img)
    if bills_w1000 - selected_w1000 == 0:
        w1000.config(cursor='', image=w1000_img, state='disabled')
    amount_config()
w1000 = Button(frame_w, image=w1000_img, bd=0, command=add_1000, state='disabled',
               font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_2000():
    global selected_w2000, amount, count_selected
    if bills_w2000 - selected_w2000 > 0:
        if count_selected:
            selected_w2000 += 1
            amount += 2000
        w2000.config(text='       ' + str(bills_w2000 - selected_w2000), cursor='hand2', state='normal',
                     image=w2000c_img)
    if bills_w2000 - selected_w2000 == 0:
        w2000.config(cursor='', image=w2000_img, state='disabled')
    amount_config()
w2000 = Button(frame_w, image=w2000_img, bd=0, command=add_2000, state='disabled',
               font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_5000():
    global selected_w5000, amount, count_selected
    if bills_w5000 - selected_w5000 > 0:
        if count_selected:
            selected_w5000 += 1
            amount += 5000
        w5000.config(text='       ' + str(bills_w5000 - selected_w5000), cursor='hand2', state='normal',
                     image=w5000c_img)
    if bills_w5000 - selected_w5000 == 0:
        w5000.config(cursor='', image=w5000_img, state='disabled')
    amount_config()
w5000 = Button(frame_w, image=w5000_img, bd=0, command=add_5000, state='disabled',
               font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_10000():
    global selected_w10000, amount, count_selected
    if bills_w10000 - selected_w10000 > 0:
        if count_selected:
            selected_w10000 += 1
            amount += 10000
        w10000.config(text='       ' + str(bills_w10000 - selected_w10000), cursor='hand2', state='normal',
                      image=w10000c_img)
    if bills_w10000 - selected_w10000 == 0:
        w10000.config(cursor='', image=w10000_img, state='disabled')
    amount_config()
w10000 = Button(frame_w, image=w10000_img, bd=0, command=add_10000, state='disabled',
                font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_20000():
    global selected_w20000, amount, count_selected
    if bills_w20000 - selected_w20000 > 0:
        if count_selected:
            selected_w20000 += 1
            amount += 20000
        w20000.config(text='       ' + str(bills_w20000 - selected_w20000), cursor='hand2', state='normal',
                      image=w20000c_img)
    if bills_w20000 - selected_w20000 == 0:
        w20000.config(cursor='', image=w20000_img, state='disabled')
    amount_config()
w20000 = Button(frame_w, image=w20000_img, bd=0, command=add_20000, state='disabled',
                font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_50000():
    global selected_w50000, amount, count_selected
    if bills_w50000 - selected_w50000 > 0:
        if count_selected:
            selected_w50000 += 1
            amount += 50000
        w50000.config(text='       ' + str(bills_w50000 - selected_w50000), cursor='hand2', state='normal',
                      image=w50000c_img)
    if bills_w50000 - selected_w50000 == 0:
        w50000.config(cursor='', image=w50000_img, state='disabled')
    amount_config()
w50000 = Button(frame_w, image=w50000_img, bd=0, command=add_50000, state='disabled',
                font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def add_100000():
    global selected_w100000, amount, count_selected
    if bills_w100000 - selected_w100000 > 0:
        if count_selected:
            selected_w100000 += 1
            amount += 100000
        w100000.config(text='       ' + str(bills_w100000 - selected_w100000), cursor='hand2', state='normal',
                       image=w100000c_img)
    if bills_w100000 - selected_w100000 == 0:
        w100000.config(cursor='', image=w100000_img, state='disabled')
    amount_config()
w100000 = Button(frame_w, image=w100000_img, bd=0, command=add_100000, state='disabled',
                 font=('ind', 30 * reso), fg='white', bg='black', compound='center')

def start_bills():
    global count_selected
    add_1(), add_2(), add_5(), add_10(), add_20(), add_50(), add_100(), add_200(), add_500(), add_1000(), add_2000()
    add_5000(), add_10000(), add_20000(), add_50000(), add_100000()
    count_selected = True
start_bills()
update_balance()

w1.place(x=0, y=0, width=139 * reso, height=59 * reso)
w2.place(x=0, y=70 * reso, width=139 * reso, height=59 * reso)
w5.place(x=0, y=140 * reso, width=139 * reso, height=59 * reso)
w10.place(x=0, y=210 * reso, width=139 * reso, height=59 * reso)
w20.place(x=0, y=280 * reso, width=139 * reso, height=59 * reso)
w50.place(x=160 * reso, y=0, width=139 * reso, height=59 * reso)
w100.place(x=160 * reso, y=70 * reso, width=139 * reso, height=59 * reso)
w200.place(x=160 * reso, y=140 * reso, width=139 * reso, height=59 * reso)
w500.place(x=160 * reso, y=210 * reso, width=139 * reso, height=59 * reso)
w1000.place(x=160 * reso, y=280 * reso, width=139 * reso, height=59 * reso)
w2000.place(x=0, y=370 * reso, width=149 * reso, height=64 * reso)
w5000.place(x=0, y=445 * reso, width=149 * reso, height=64 * reso)
w10000.place(x=0, y=520 * reso, width=149 * reso, height=64 * reso)
w20000.place(x=152 * reso, y=370 * reso, width=149 * reso, height=64 * reso)
w50000.place(x=152 * reso, y=445 * reso, width=149 * reso, height=64 * reso)
w100000.place(x=152 * reso, y=520 * reso, width=149 * reso, height=64 * reso)


def receive_bills():
    root.config(cursor='watch')
    receiver_button.config(cursor='watch')
    def thrd():
        sender_node.update_ip_list()
        sender_node.receive_bills()
        time.sleep(10)
        update_balance()
        page()
        root.config(cursor='arrow')
        receiver_button.config(cursor='hand2')
    threading.Thread(target=thrd).start()

receiver_button_img = PhotoImage(file=path_button_receive)
receiver_button = Button(root, image=receiver_button_img, cursor='hand2', command=receive_bills, bd=0,
                         highlightthickness=0)

show = 0
def show_key_s():
    global show
    show += 1
    if (show % 2) != 0:
        enter_key.config(show='')
    else:
        enter_key.config(show='*')
show2 = 0
def show_key_p():
    global show2
    show2 += 1
    if (show2 % 2) != 0:
        private_key.config(show='')
    else:
        private_key.config(show='*')
show3 = 0
def show_password():
    global show3
    show3 += 1
    if (show3 % 2) != 0:
        choose_password.config(show='*')
    else:
        choose_password.config(show='')


def stay_signed():
    with open('check_signed_in.txt', 'r+') as csig:
        checkmark = csig.read()
        csig.seek(0)
        csig.truncate()
        if checkmark == 'False':
            button_checkbox.place_forget()
            button_checkmark.place(x=465 * reso, y=602 * reso)
            csig.write('True')
        else:
            button_checkmark.place_forget()
            button_checkbox.place(x=465 * reso, y=602 * reso)
            csig.write('False')

def log_in():
    with open('passphrase.txt', 'w') as ps:
        ps.seek(0)
        ps.truncate(0)
        ps.write(str(enter_key.get()) + '\n')
        ps.write(str(address_variable.get()))
    wallet_decryption.wallet_decrypt()

    def check_decrypted():
        global decrypted
        for decrypted_wallet in os.listdir('wallet_folder'):
            if decrypted_wallet.startswith('wallet_decrypted'):
                root.destroy()
                subprocess.Popen([sys.executable, 'main.py'])
                break
    check_decrypted()

address_variable = StringVar(root)
options_addr = ['                                                                        ']
for s in os.listdir('wallet_folder'):
    wallet_raw = s.replace('wallet_encrypted_', '').replace('wallet_decrypted_', '').replace('.txt', '')
    if wallet_raw not in options_addr:
        options_addr.append(wallet_raw)
if len(options_addr) == 1:
    men = 0
else:
    men = 1
enter_address = OptionMenu(root, address_variable, *options_addr[men:])
enter_address.config(font=('ind', 21 * reso, 'bold'), cursor='hand2', bg='black', fg='white')
eadrr = root.nametowidget(enter_address.menuname)
eadrr.config(font=('ind', 20 * reso))

enter_key = Entry(root, font=('ind', 26 * reso), show='*', bg='light grey')
log_in_button2_img = PhotoImage(file=path_button_log_in)
log_in_button2 = Button(root, image=log_in_button2_img, cursor='hand2', command=log_in)
button_show_img = PhotoImage(file=path_button_show)
button_show = Button(root, image=button_show_img, cursor='hand2', command=show_key_s, bd=0, highlightthickness=0)
button_show3_img = PhotoImage(file=path_button_show3)
button_show3 = Button(root, image=button_show3_img, cursor='hand2', command=show_password, bd=0, highlightthickness=0)
button_checkbox_img = PhotoImage(file=path_checkbox)
button_checkbox = Button(root, image=button_checkbox_img, cursor='hand2', command=stay_signed, bd=0,
                         highlightthickness=0)
button_checkmark_img = PhotoImage(file=path_checkmark)
button_checkmark = Button(root, image=button_checkmark_img, cursor='hand2', command=stay_signed, bd=0,
                          highlightthickness=0)

def gen_ad():
    def t():
        open('hashing.txt', 'w').close()
        generate_address_text.config(state='normal'),public_key.config(state='normal'),private_key.config(state='normal')
        generate_address_text.delete(0, END),public_key.delete(0, END),private_key.delete(0, END)
        root.config(cursor='watch')
        generate_address_button.config(cursor='watch')
        subprocess.run("python generate_address.py", shell=True)
        with open('hashing.txt', 'r') as hs:
            ha = hs.readlines()
        h_address = ha[0].strip()
        h_private_key = ha[1].strip()
        h_public_key = ha[2].strip()
        generate_address_text.insert(0, h_address),public_key.insert(0, h_public_key)
        private_key.insert(0, h_private_key)
        generate_address_text.config(state='readonly'),public_key.config(state='readonly')
        private_key.config(state='readonly'),generate_address_button.config(cursor='hand2')
        root.config(cursor='arrow')
    threading.Thread(target=t).start()
def generate_wallet_final():
    with open('hashing.txt', 'a+') as hf:
        hf.write(str(choose_password.get()) + '\n')
        hf.seek(0)
        addr_hash = hf.readlines()[0].strip()
    wallet_encryption.wallet_encrypt()
    open('hashing.txt', 'w').close()
    success.place(x=282 * reso, y=193 * reso)
    button_participate.place(x=680 * reso, y=650 * reso)
    button_not_participate.place(x=330 * reso, y=650 * reso)
    success.lift()
    button_participate.lift()
    button_not_participate.lift()
    address_variable.set(addr_hash)
    sign_in_button()

def particpate():
    def t():
        time.sleep(40)
        request_luck()
    threading.Thread(target=t).start()
    success.place_forget()
    button_participate.place_forget()
    button_not_participate.place_forget()
    start()
def not_participate():
    success.place_forget()
    button_participate.place_forget()
    button_not_participate.place_forget()

success_img = PhotoImage(file=path_success)
success = Label(root, image=success_img, bd=0, highlightthickness=0)
participate_img = PhotoImage(file=path_button_participate)
button_participate = Button(root, image=participate_img, command=particpate, bd=0, highlightthickness=0, cursor='hand2')
not_participate_img = PhotoImage(file=path_button_not_participate)
button_not_participate = Button(root, image=not_participate_img, command=not_participate, bd=0, highlightthickness=0,
                                cursor='hand2')
generate_address_text = Entry(root, font=('ind', 21 * reso), bd=0, bg='light grey')
generate_address_button_img = PhotoImage(file=path_generate_address_button)
generate_address_button = Button(root, image=generate_address_button_img, command=gen_ad, bd=0,
                                 highlightthickness=0, cursor='hand2')
public_key = Entry(root, font=('ind', 18 * reso), bd=0, bg='light grey')
private_key = Entry(root, font=('ind', 18 * reso), bd=0, show='*', bg='light grey')
button_show2_img = PhotoImage(file=path_button_show2)
button_show2 = Button(root, image=button_show2_img, cursor='hand2', command=show_key_p, bd=0, highlightthickness=0)
choose_password = Entry(root, font=('ind', 22 * reso), bd=0, bg='light grey')
generate_wallet_button_img = PhotoImage(file=path_generate_wallet_button)
generate_wallet_button2 = Button(root, image=generate_wallet_button_img, cursor='hand2', command=generate_wallet_final)

button_log_in = Button(root, font=('ind', 30 * reso), text='Sign In', bd=0, highlightthickness=0, cursor='hand2',
                       bg='black', fg='white', command=sign_in_button)
button_generate_wallet = Button(root, font=('ind', 30 * reso), text='Generate Wallet', bd=0, highlightthickness=0,
                                cursor='hand2', bg='black', fg='white', command=generate_wallet_button)

def send_bills(serial_num_start):
    for w in os.listdir('wallet_folder'):
        if w.startswith('wallet_decrypted'):
            with open('wallet_folder/' + w, 'r+') as o:
                of = o.readlines()
                o.seek(0)
                o.truncate()

                for wb in of:
                    if wb.split('x')[0] + 'x' in serial_num_start:
                        serial_num_start.remove(wb.split('x')[0] + 'x')
                        try:
                            full_transaction = wb.split()[0] + '\n' + str(int(wb.split()[1]) + 1) + '\n' + of[2]
                            full_transaction += receiver.get() + '\n'
                            read_tn = full_transaction.encode('utf-8')
                            private_key_decode = base64.b85decode(of[1].strip())
                            sk = ecdsa.SigningKey.from_string(private_key_decode, curve=ecdsa.SECP256k1,
                                                              hashfunc=hashlib.sha3_256)
                            sign = sk.sign(read_tn)
                            signature = base64.b85encode(sign).decode('utf-8')
                            full_transaction += str(signature)
                            o.write('-' + wb.split()[0] + ' ' + str(int(wb.split()[1]) + 1) + ' ' + str(int(time.time())) + '\n')
                            t = str(len(os.listdir('transaction_folder')) + 1)
                            with open('transaction_folder/transaction_' + t + '.txt', 'w') as tn:
                                tn.seek(0)
                                tn.truncate()
                                tn.write(str(full_transaction))
                        except:
                            o.write(wb)
                    else:
                        o.write(wb)

def confirm_transaction():
    global selected_w1,selected_w2,selected_w5,selected_w10,selected_w20
    global selected_w50,selected_w100,selected_w200,selected_w500,selected_w1000
    global selected_w2000,selected_w5000,selected_w10000,selected_w20000,selected_w50000
    global selected_w100000, function_call

    if len(os.listdir('transaction_folder')) != 0:
        sender_node.send_bills()

    starts_with = []
    while True:
        if selected_w1 > 0:
            starts_with.append('1x')
            selected_w1 -= 1
        elif selected_w2 > 0:
            starts_with.append('2x')
            selected_w2 -= 1
        elif selected_w5 > 0:
            starts_with.append('5x')
            selected_w5 -= 1
        elif selected_w10 > 0:
            starts_with.append('10x')
            selected_w10 -= 1
        elif selected_w20 > 0:
            starts_with.append('20x')
            selected_w20 -= 1
        elif selected_w50 > 0:
            starts_with.append('50x')
            selected_w50 -= 1
        elif selected_w100 > 0:
            starts_with.append('100x')
            selected_w100 -= 1
        elif selected_w200 > 0:
            starts_with.append('200x')
            selected_w200 -= 1
        elif selected_w500 > 0:
            starts_with.append('500x')
            selected_w500 -= 1
        elif selected_w1000 > 0:
            starts_with.append('1000x')
            selected_w1000 -= 1
        elif selected_w2000 > 0:
            starts_with.append('2000x')
            selected_w2000 -= 1
        elif selected_w5000 > 0:
            starts_with.append('5000x')
            selected_w5000 -= 1
        elif selected_w10000 > 0:
            starts_with.append('10000x')
            selected_w10000 -= 1
        elif selected_w20000 > 0:
            starts_with.append('20000x')
            selected_w20000 -= 1
        elif selected_w50000 > 0:
            starts_with.append('50000x')
            selected_w50000 -= 1
        elif selected_w100000 > 0:
            starts_with.append('100000x')
            selected_w100000 -= 1
        else:
            break

    send_bills(starts_with)
    threading.Thread(target=sender_node.send_bills).start()
    receiver.delete(0, END)
    close_amount()
    update_balance()
    page()

def send_button():
    try:
        for _ in range(3):
            sender_node.update_ip_list()
        if len(receiver.get()) == 30 and amount != 0 and receiver.get() != dr[0].strip():
            confirm_transaction()
    except:
        pass
def close():
    claim_bills_amount.place_forget(), webcam_scanner.place_forget(), private_key_entry.place_forget()
    claim_bill.place_forget(),close_button.place_forget(), next_button.place_forget(), end_button.place_forget()
    serial_num.place_forget(), public_key_entry.place_forget(), check_validity_button.place_forget()
    send.place_forget(), receiver.place_forget(), a.place_forget(), frame_w.place_forget()
    b.place_forget(), close_amount.place_forget(),plus_bills_button.place_forget(), r_button.place_forget()
    previous_button.place_forget(), start_button.place_forget(), receiver_history.place_forget()
    panel.pack_forget(), purchase.place_forget(), wallet.place_forget(), receiver_button.place_forget()
    sign_in.place_forget(), log_in_button2.place_forget(), button_log_in.place_forget(), enter_address.place_forget()
    enter_key.place_forget(), button_generate_wallet.place_forget(), generate_wallet.place_forget()
    button_show.place_forget(), generate_address_text.place_forget(), generate_address_button.place_forget()
    public_key.place_forget(), private_key.place_forget(), button_show2.place_forget(), choose_password.place_forget()
    generate_wallet_button2.place_forget(), node_terminal.place_forget(), tf_button.place_forget()
    button_show3.place_forget(), button_checkmark.place_forget(), button_lucky.place_forget()
    button_checkbox.place_forget(), info.place_forget(), tf_text.place_forget(), button_print.place_forget()
    add_bill_button.place_forget(), node_class_selector.place_forget()
    ron.place_forget(), bak.place_forget(), asl_text.place_forget(), all_bills_text.place_forget()
    selected_bills_text.place_forget(), button_only_qr.place_forget()
    try:
        qr.place_forget(), address_txt.place_forget()
    except Exception:
        pass
def close_amount():
    global selected_w1, selected_w2, selected_w5, selected_w10, selected_w20
    global selected_w100, selected_w200, selected_w500, selected_w1000, selected_w2000
    global selected_w5000, selected_w10000, selected_w20000, selected_w50000, selected_w100000
    global selected_w50, amount, count_selected
    selected_w1 = selected_w2 = selected_w5 = selected_w10 = selected_w20 = 0
    selected_w50 = selected_w100 = selected_w200 = selected_w500 = selected_w1000 = 0
    selected_w2000 = selected_w5000 = selected_w10000 = selected_w20000 = 0
    selected_w50000 = selected_w100000 = amount = 0
    count_selected = False
    start_bills()
def close_bill_claimer():
    serial_num.place_forget(), public_key_entry.place_forget(), check_validity_button.place_forget()
    claim_bills_amount.place_forget(), webcam_scanner.place_forget(), close_button.place_forget()
    claim_bill.place_forget(), add_bill_button.place_forget(), private_key_entry.place_forget()

send_img = PhotoImage(file=path_button_send)
send = Button(root, image=send_img, bd=0, cursor='hand2', command=send_button)
close_img = PhotoImage(file=path_button_close)
close_button = Button(root, image=close_img, bd=0, highlightthickness=0, cursor='hand2', command=close_bill_claimer)
close_amount_img = PhotoImage(file=path_button_close_amount)
close_amount = Button(root, image=close_amount_img, bd=0, highlightthickness=0, cursor='hand2', command=close_amount)

def plus_bills():
    claim_bill.place(x=335 * reso, y=154 * reso)
    claim_bills_amount.place()
    close_button.place(x=785 * reso, y=163 * reso)
    close_button.lift()
    check_validity_button.place(x=366 * reso, y=727 * reso)
    add_bill_button.place(x=605 * reso, y=727 * reso)
    serial_num.place(x=364 * reso, y=295 * reso, width=440 * reso, height=40 * reso)
    public_key_entry.place(x=364 * reso, y=390 * reso, width=440 * reso, height=40 * reso)
    private_key_entry.place(x=364 * reso, y=482 * reso, width=440 * reso, height=40 * reso)
    webcam_scanner.place(x=364 * reso, y=538 * reso)
    claim_bills_amount.place(x=655 * reso, y=460 * reso, width=160 * reso, height=183 * reso)
    claim_bills_amount.bind("<Key>", lambda e: "break")
    webcam_scanner.lift()

plus_bills_button_img = PhotoImage(file=path_plus_bills_button)
plus_bills_button = Button(root, image=plus_bills_button_img, command=plus_bills, bd=0, highlightthickness=0,
                           cursor='hand2')
claim_bill_img = PhotoImage(file=path_claim_bill)
claim_bill = Label(root, image=claim_bill_img, bd=0, highlightthickness=0)
claim_bills_amount = Entry(root, font=('ind', 26 * reso, 'bold'), fg='white', bg='black', bd=0)
claim_bills_amount.insert(0, '0$')

used_codes = []
num_of_times_clicked = 0
def claim_bills():
    t_num2 = 1
    for bill in used_codes:
        split = bill.splitlines()
        sm = split[0]
        privk = split[1]
        pubk = split[2]
        for w in os.listdir('wallet_folder'):
            if w.startswith('wallet_decrypted'):
                full_transaction = sm + '\n' + '1' + '\n' + pubk + '\n' + w[17:].replace('.txt', '') + '\n'
                read_tn = full_transaction.encode('utf-8')
                private_key_decode = base64.b85decode(privk)
                sk = ecdsa.SigningKey.from_string(private_key_decode, curve=ecdsa.SECP256k1,
                                                  hashfunc=hashlib.sha3_256)
                sign = sk.sign(read_tn)
                signature = base64.b85encode(sign).decode('utf-8')
                full_transaction += str(signature)
                with open('transaction_folder/transaction_' + str(t_num2) + '.txt', 'w') as tn:
                    tn.seek(0)
                    tn.truncate()
                    tn.write(str(full_transaction))
                    t_num2 += 1
    sender_node.send_bills()
    balance1 = b.get("1.0", END).strip('$')
    receive_bills()
    balance_combined = str(int(b.get("1.0", END).strip('$')) - int(balance1)) + '$'
    claimed_amount = Text(root, font=('ind', 30 * reso, 'bold'), fg='white', bd=0)
    if balance_combined != claim_bills_amount.get():
        claimed_amount.config(bg='#c1272d')
        claimed_amount.insert(1.0, 'Insufficient amount:\n' + balance_combined + ' claimed')
        not_valid.place(x=335 * reso, y=154 * reso)
    else:
        claimed_amount.config(bg='#006837')
        claimed_amount.insert(1.0, 'Everything\n' + balance_combined + ' claimed')
        valid.place(x=335 * reso, y=154 * reso)

    claimed_amount.place(x=500 * reso, y=400 * reso, width=200 * reso, height=80 * reso)
    time.sleep(5)
    valid.place_forget()
    not_valid.place_forget()

def add_bill():
    global used_codes
    full_code = serial_num.get() + '\n' + private_key_entry.get() + '\n' + public_key_entry.get() + '\n'
    if full_code not in used_codes:
        used_codes.appned(full_code)
        am = int(claim_bills_amount.get().strip('$'))
        claim_bills_amount.delete(0, END)
        claim_bills_amount.insert(0, str(am + int(serial_num.get().split('x')[0])) + '$')

check_validity_button_img = PhotoImage(file=path_button_validity)
check_validity_button = Button(root, image=check_validity_button_img, bd=0, highlightthickness=0, cursor='hand2',
                               command=claim_bills)
add_bill_button_img = PhotoImage(file=path_button_add_bill)
add_bill_button = Button(root, image=add_bill_button_img, bd=0, highlightthickness=0, cursor='hand2', command=add_bill)
valid_img = PhotoImage(file=path_valid)
valid = Label(root, image=valid_img, bd=0, highlightthickness=0)
not_valid_img = PhotoImage(file=path_valid)
not_valid = Label(root, image=not_valid_img, bd=0, highlightthickness=0)
serial_num = Entry(root, font=('ind', 22 * reso), bg='light grey')
public_key_entry = Entry(root, font=('ind', 22 * reso), bg='light grey')
private_key_entry = Entry(root, font=('ind', 22 * reso), bg='light grey')

def qr_decoder(qrimage):
    global used_codes
    for code in decode(qrimage):
        decoded_qrcode = code.data.decode('utf-8')
        if decoded_qrcode not in used_codes:
            if decoded_qrcode.startswith('x'):
                receiver.delete(0, END)
                receiver.insert(0, decoded_qrcode)
            else:
                used_codes.append(decoded_qrcode)
                serial_num.delete(0, END)
                serial_num.insert(0, decoded_qrcode.splitlines()[0])
                private_key_entry.delete(0, END)
                private_key_entry.insert(0, decoded_qrcode.splitlines()[1])
                public_key_entry.delete(0, END)
                public_key_entry.insert(0, decoded_qrcode.splitlines()[2])
                am = int(claim_bills_amount.get().strip('$'))
                claim_bills_amount.delete(0, END)
                claim_bills_amount.insert(0, str(int(decoded_qrcode.split('x')[0]) + am) + '$')


def qr_scan():
    global num_of_times_clicked, cap
    num_of_times_clicked += 1
    webcam_scanner.config(cursor='watch')
    if (num_of_times_clicked % 2) != 0:
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        webcam_scanner.config(cursor='hand2')

    def loop():
        try:
            _, frame = cap.read()
            cropped = frame[0:0+177 * reso, 0:0+280 * reso]
            cv2image = cv2.cvtColor(cropped, cv2.COLOR_BGR2RGBA)
            qr_pic = Image.fromarray(cv2image)
            imgtk = ImageTk.PhotoImage(image=qr_pic)
            webcam_scanner.imgtk = imgtk
            webcam_scanner.config(image=imgtk)
            qr_decoder(frame)
            if (num_of_times_clicked % 2) != 0:
                webcam_scanner.after(10, loop)
        except Exception:
            filename = filedialog.askopenfilename(title='Find QR image', initialdir='quickaccess',
                                                  filetypes=(('png files', '*.png'), ('all files', '*.*')))
            img_e = Image.open(filename)
            img_explorer_resize = img_e.resize((280 * reso, 177 * reso), Image.Resampling.LANCZOS)
            img_explorer = ImageTk.PhotoImage(img_explorer_resize)
            webcam_scanner.config(image=img_explorer)
            webcam_scanner.img_explorer = img_explorer
            qr_decoder(img_e)
    if (num_of_times_clicked % 2) != 0:
        loop()
    else:
        webcam_scanner.config(image=webcam_scanner_img, cursor='hand2')
        cap.release()
        cv2.destroyAllWindows()

webcam_scanner_img = ImageTk.PhotoImage(Image.open(path_qr_overlay))
webcam_scanner = Button(root, image=webcam_scanner_img, cursor='hand2', highlightthickness=0, bd=0, command=qr_scan)


def drop(event):
    qr_path = event.data.strip('{}')
    qr_path_tk = Image.open(qr_path)
    resized = qr_path_tk.resize((280 * reso, 177 * reso), Image.Resampling.LANCZOS)
    drag_and_drop_img = ImageTk.PhotoImage(resized)
    webcam_scanner.drag_and_drop_img = drag_and_drop_img
    webcam_scanner.config(image=drag_and_drop_img)
    qr_decoder(qr_path_tk)

webcam_scanner.drop_target_register(DND_FILES)
webcam_scanner.dnd_bind('<<Drop>>', drop)

button = Button(root, command=node_terminal_button, text='Node Terminal', bg='black', fg='white',
                font=('ind', 24 * reso), cursor='hand2', bd=0, activebackground='white', highlightthickness=0,)
button.place(x=577 * reso, y=100 * reso, width=169 * reso, height=50 * reso)

button2 = Button(root, command=info_button, text='Information', bg='black', fg='white', font=('ind', 24 * reso),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
button2.place(x=750 * reso, y=100 * reso, width=169 * reso, height=50 * reso)

button3 = Button(root, command=win_button, text='Win/Print', bg='black', fg='white', font=('ind', 24 * reso),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
button3.place(x=923 * reso, y=100 * reso, width=169 * reso, height=50 * reso)

button4 = Button(root, command=wallet_button, text='Wallet', bg='black', fg='white', font=('ind', 24 * reso),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
button4.place(x=1096 * reso, y=100 * reso, width=114 * reso, height=50 * reso)

button_sign_in = PhotoImage(file=path_button_sign_in)
button6 = Button(root, command=sign_in_button, image=button_sign_in, bd=0, highlightthickness=0, cursor='hand2')
button6.place(x=1120 * reso, y=18 * reso)
international_dollar.lift()

def on_closing():
    try:
        with open('node_class.txt', 'r') as nc:
            lines = nc.readlines()
            run_in_background = lines[2].strip()
            run_on_startup = lines[1].strip()
        if run_in_background == 'NO':
            with open('kill_node.txt', 'w') as kn1:
                kn1.seek(0)
                kn1.truncate()
                kn1.write('True')
        with open('check_signed_in.txt', 'r') as csi:
            if csi.read() == 'False':
                for wal in os.listdir('wallet_folder'):
                    if wal.startswith('wallet_decrypted'):
                        with open('wallet_folder/' + wal, 'r') as wallet2:
                            w = wallet2.read()
                        with open('hashing.txt', 'w') as hashz:
                            hashz.seek(0)
                            hashz.truncate()
                            hashz.write(w)
                        os.remove('wallet_folder/wallet_encrypted_' + wal[17:])
                        wallet_encryption.wallet_encrypt()
                        os.remove('wallet_folder/' + wal)
                        open('hashing.txt', 'w').close()
        if run_on_startup == 'NO':
            os.remove(bat_path + '/server1.bat')
            os.remove(bat_path + '/server2.bat')
    except:
        pass
    root.destroy()

root.protocol('WM_DELETE_WINDOW', on_closing)
mainloop()
