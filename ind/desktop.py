import importlib
import os
import shutil
import subprocess
import sys
import threading
import time
import json
from pathlib import Path
from tkinter import *
from tkinter import filedialog, messagebox
from tkinter import font as tkfont

from tkinterdnd2 import *
import getpass
from datetime import datetime

import platform
from . import runtime as runtime_json
from . import settings as ind_settings
# most modules come preinstalled
# if you miss modules, execute pip install -r ./requirements.txt in the local directory (cmd)

BASE_DIR = Path(__file__).resolve().parent.parent
os.chdir(BASE_DIR)
APP_FONT_FAMILY = 'Teko Light'
FONT_PATH = BASE_DIR / 'Teko-Light.ttf'
RUNTIME_DIRS = runtime_json.RUNTIME_DIRS
RUNTIME_FILES = {
    'files/security_settings.json': ind_settings.default_settings_json(),
}


class LazyModule:
    def __init__(self, module_name, on_load=None):
        self.module_name = module_name
        self.on_load = on_load
        self.module = None

    def _load(self):
        if self.module is None:
            self.module = importlib.import_module(self.module_name)
            if self.on_load:
                self.on_load(self.module)
        return self.module

    def __getattr__(self, name):
        return getattr(self._load(), name)


qrcode = LazyModule('qrcode')
Image = LazyModule('PIL.Image')
ImageTk = LazyModule('PIL.ImageTk')
cv2 = LazyModule('cv2')
pyglet = LazyModule('pyglet')
sender_node = LazyModule('ind.sender_node', lambda module: module.ensure_runtime_files())
ind_token = LazyModule('ind.token')
wallet_decryption = LazyModule('ind.wallet_decryption')
wallet_encryption = LazyModule('ind.wallet_encryption')
wallet_services = LazyModule('ind.wallet_services')
print_tools = LazyModule('ind.print_tools')


def decode(qrimage):
    from pyzbar.pyzbar import decode as decode_qr_codes

    return decode_qr_codes(qrimage)


def ensure_runtime_files_light():
    runtime_json.ensure_runtime_files()
    for path, default in RUNTIME_FILES.items():
        if not os.path.exists(path):
            with open(path, 'w') as handle:
                handle.write(default)


ensure_runtime_files_light()


def copy_font_if_needed(font_path, target):
    if not target.exists() or target.stat().st_size != font_path.stat().st_size:
        shutil.copy2(font_path, target)
    return target


def install_windows_font(font_path, font_family):
    installed_path = font_path
    try:
        local_app_data = os.environ.get('LOCALAPPDATA')
        fonts_dir = (
            Path(local_app_data) / 'Microsoft' / 'Windows' / 'Fonts'
            if local_app_data
            else Path.home() / 'AppData' / 'Local' / 'Microsoft' / 'Windows' / 'Fonts'
        )
        fonts_dir.mkdir(parents=True, exist_ok=True)
        installed_path = copy_font_if_needed(font_path, fonts_dir / font_path.name)

        import winreg
        registry_path = r'Software\Microsoft\Windows NT\CurrentVersion\Fonts'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE) as font_key:
            winreg.SetValueEx(font_key, font_family + ' (TrueType)', 0, winreg.REG_SZ, str(installed_path))
    except Exception:
        installed_path = font_path

    try:
        import ctypes
        ctypes.windll.gdi32.AddFontResourceExW(str(installed_path), 0, 0)
        ctypes.windll.gdi32.AddFontResourceExW(str(font_path), 0x10, 0)
        ctypes.windll.user32.SendMessageW(0xFFFF, 0x001D, 0, 0)
    except Exception:
        pass


def load_custom_font(font_path, font_family):
    font_path = Path(font_path)
    if not font_path.exists():
        return

    try:
        pyglet.font.add_file(str(font_path))
    except Exception:
        try:
            pyglet.resource.add_font(str(font_path))
        except Exception:
            pass

    system = platform.system()
    if system == 'Windows':
        install_windows_font(font_path, font_family)
    elif system == 'Darwin':
        try:
            fonts_dir = Path.home() / 'Library' / 'Fonts'
            fonts_dir.mkdir(parents=True, exist_ok=True)
            copy_font_if_needed(font_path, fonts_dir / font_path.name)
        except Exception:
            pass
    elif system == 'Linux':
        try:
            fonts_dir = Path.home() / '.local' / 'share' / 'fonts'
            fonts_dir.mkdir(parents=True, exist_ok=True)
            copy_font_if_needed(font_path, fonts_dir / font_path.name)
            subprocess.run(['fc-cache', '-f', str(fonts_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def schedule_custom_font_load():
    try:
        if APP_FONT_FAMILY in tkfont.families(root):
            return
    except Exception:
        pass
    root.after_idle(lambda: load_custom_font(FONT_PATH, APP_FONT_FAMILY))


def hide_root_window():
    try:
        root.withdraw()
        root.update_idletasks()
    except Exception:
        pass


def show_root_when_ready():
    try:
        root.update_idletasks()
        root.deiconify()
        root.lift()
    except Exception:
        pass


def start_new_app_process():
    subprocess.Popen([sys.executable, str(BASE_DIR / 'main.py')], cwd=str(BASE_DIR))


def relaunch_application():
    hide_root_window()
    start_new_app_process()
    root.destroy()


APP_BASE_WIDTH = 1214
APP_BASE_HEIGHT = 771
APP_HIDPI_SCALE = 2
HEADER_BUTTON_X_NUDGE = -1
HEADER_BUTTON_Y_NUDGE = -2
SIGN_IN_PAGE_Y_NUDGE = -2


def enable_high_dpi_awareness():
    if platform.system() != 'Windows':
        return

    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def choose_app_scale(screen_width, screen_height):
    if (
        screen_width >= APP_BASE_WIDTH * APP_HIDPI_SCALE
        and screen_height >= APP_BASE_HEIGHT * APP_HIDPI_SCALE
    ):
        return APP_HIDPI_SCALE
    return 1


# the main.py file is more or less just the tkinter GUI implementation
# transactions can also be made and sent manually in the command line, for example:
# python -c "import sender_node; sender_node.send_bills()"

# everything builds on this main root
enable_high_dpi_awareness()
root = Tk()
root.withdraw()
root.configure(background='black')
root.title('International Dollar')
# ensure right scaling of text even when user has different zoom settings (laptop)
root.tk.call('tk', 'scaling', 1.36)

# reso determines the high-resolution GUI multiplier.
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
reso = choose_app_scale(screen_width, screen_height)
res = '4' if reso == APP_HIDPI_SCALE else ''
root.geometry(f'{APP_BASE_WIDTH * reso}x{APP_BASE_HEIGHT * reso}')
try:
    root.iconbitmap(str(BASE_DIR / 'img' / 'logo.ico'))
except Exception:
    pass
schedule_custom_font_load()

IND_GREEN = '#009846'
IND_RED = '#ed1c24'
IND_ORANGE = '#f15a24'
IND_BLACK = '#000000'
IND_WHITE = '#ffffff'
IND_MUTED = '#bfbfbf'
WALLET_SEND_Y_OFFSET = 30
INFO_MAX_SUPPLY = f'{ind_token.MASTER_SUPPLY_NUMBER} Billion'

GUI_TEXT = {
    'app_title': 'International Dollar',
    'home_code_prefix': 'print',
    'home_code_open': '(',
    'home_code_body': '"Hello World!"',
    'home_code_suffix': ')',
    'node_labels': ('Node class:', 'Run on startup:', 'Run in background:'),
    'node_forwarding': (
        'If you are running a full node make sure to\n'
        'forward TCP port 8888 to your local machine\n'
        'via your router terminal.'
    ),
    'node_ipv4': 'Only IPv4 addresses are supported\ndue to their limited availability.',
    'info_features': (
        'No miner voting',
        '33 Billion max supply',
        'Bearer bills',
        'Signed transfers',
        'Receipt gossip',
        'Double-spend proofs',
    ),
    'info_title': 'IND Basics',
    'info_body': (
        'IND is a fixed-supply bearer-token network. There is no mining,\n'
        'staking, or blockchain consensus.\n\n'
        f'Supply is capped at {INFO_MAX_SUPPLY} IND. Genesis defines the full\n'
        'supply map with an issuer-signed manifest, while bills can remain lazy\n'
        'until they first move.\n\n'
        'Each bill has its own owner history. Transfers are signed with\n'
        'secp256k1 over canonical SHA3-256 data, and receivers verify every hop\n'
        'from genesis to the current owner.\n\n'
        'Desktop nodes gossip transfers, receipts, and double-spend proofs.\n'
        'Nodes do not vote on balances; conflicting spends make only that bill\n'
        'invalid locally. Wait for the finality buffer before treating IND as settled.'
    ),
    'info_blockchain': 'Blockchain',
    'info_supply_amount': INFO_MAX_SUPPLY,
    'info_supply_label': 'max supply',
    'info_inflation': '0%\ninflation',
    'print_title': 'Print bills from your wallet!',
    'wallet_send_title': 'Send IND',
    'wallet_receiver_label': 'Receiver address:',
    'wallet_amount_label': 'Amount (select bills):',
    'wallet_receive_title': 'Receive IND',
    'signin_wallet_label': 'Enter wallet address',
    'signin_password_label': 'Enter wallet password',
    'signin_stay_label': 'Remember sign-in choice',
    'generate_wallet_address': 'Wallet address',
    'generate_public_key': 'Public key',
    'generate_private_key': 'Private key',
    'generate_password': 'Choose password',
    'settings_title': 'Security Settings',
    'settings_peer_servers': 'Peer ping servers',
    'settings_finality': 'Accept bills after (s)',
    'settings_timeout': 'Peer timeout (s)',
    'settings_require_log': 'Require Merkle log',
    'settings_root_domains': 'Trusted root domains',
    'settings_root_mirrors': 'Merkle root mirrors',
    'settings_operator_url': 'Operator URL',
    'settings_operator_key': 'Operator public key',
    'settings_root_lag': 'Max root lag (s)',
    'settings_min_mirrors': 'Min mirrors',
    'claim_title': 'Claim new bills',
    'claim_serial': 'Serial number:',
    'claim_public': 'Public key:',
    'claim_private': 'Private key:',
    'qr_drop': 'Drop QR image\nor use webcam',
    'success_title': 'Success!',
    'success_body': (
        'A new wallet has successfully been generated!\n'
        'Make sure to remember your password and\n'
        'keep your encrypted wallet folder safe.'
    ),
}


def px(value):
    return int(value * reso)


def place_scaled(widget, x, y, width=None, height=None, x_nudge=0, y_nudge=0):
    options = {
        'x': px(x + x_nudge),
        'y': px(y + y_nudge),
    }
    if width is not None:
        options['width'] = px(width)
    if height is not None:
        options['height'] = px(height)
    widget.place(**options)


def place_header_button(widget, x, y, width, height):
    place_scaled(
        widget,
        x,
        y,
        width,
        height,
        x_nudge=HEADER_BUTTON_X_NUDGE,
        y_nudge=HEADER_BUTTON_Y_NUDGE,
    )


def place_sign_in_control(widget, x, y, width, height):
    place_scaled(widget, x, y, width, height, y_nudge=SIGN_IN_PAGE_Y_NUDGE)


def app_font(size, weight=None):
    font = (APP_FONT_FAMILY, px(size))
    if weight:
        font += (weight,)
    return font


def canvas_text(canvas, x, y, text, size, fill=IND_WHITE, anchor='nw', justify='left', weight=None,
                width=None):
    kwargs = {
        'text': text,
        'fill': fill,
        'font': app_font(size, weight),
        'anchor': anchor,
        'justify': justify,
    }
    if width is not None:
        kwargs['width'] = px(width)
    return canvas.create_text(px(x), px(y), **kwargs)


def make_icon_button(text, command, font_size=18, bg=IND_BLACK, fg=IND_WHITE):
    return make_text_button(text, command, font_size=font_size, bg=bg, fg=fg, bd=1, relief=SOLID)


class GuiScreen(Canvas):
    def __init__(self, master, screen_name, width=APP_BASE_WIDTH, height=APP_BASE_HEIGHT):
        super().__init__(
            master,
            width=px(width),
            height=px(height),
            bg=IND_BLACK,
            bd=0,
            highlightthickness=0,
        )
        self.screen_name = screen_name
        self.draw()

    def line(self, x1, y1, x2, y2, color=IND_WHITE, width=2):
        self.create_line(px(x1), px(y1), px(x2), px(y2), fill=color, width=px(width))

    def checkmark(self, x, y, color='#35c758'):
        points = (
            (x + 1, y + 29),
            (x + 10, y + 20),
            (x + 23, y + 33),
            (x + 55, y - 8),
            (x + 64, y),
            (x + 25, y + 51),
        )
        coordinates = []
        for point_x, point_y in points:
            coordinates.extend((px(point_x), px(point_y)))
        self.create_polygon(*coordinates, fill=color, outline=color)

    def rect(self, x1, y1, x2, y2, fill='', outline=IND_WHITE, width=2):
        self.create_rectangle(px(x1), px(y1), px(x2), px(y2), fill=fill, outline=outline, width=px(width))

    def draw_header(self):
        self.rect(1, 1, APP_BASE_WIDTH - 1, APP_BASE_HEIGHT - 1, fill=IND_BLACK, width=2)
        self.rect(570, 94, APP_BASE_WIDTH - 2, 151, fill=IND_WHITE, outline=IND_WHITE, width=1)
        self.line(0, 151, APP_BASE_WIDTH, 151, width=4)

    def draw(self):
        self.draw_header()
        draw_method = getattr(self, f'draw_{self.screen_name}', None)
        if draw_method:
            draw_method()

    def draw_home(self):
        canvas_text(self, 438, 420, GUI_TEXT['home_code_prefix'], 45, fill='#7a4ca8')
        canvas_text(self, 532, 420, GUI_TEXT['home_code_open'], 45, fill=IND_WHITE)
        canvas_text(self, 550, 420, GUI_TEXT['home_code_body'], 45, fill='#64a982')
        canvas_text(self, 781, 420, GUI_TEXT['home_code_suffix'], 45, fill=IND_WHITE)

    def draw_node_terminal(self):
        for y, label in zip((260, 400, 540), GUI_TEXT['node_labels']):
            canvas_text(self, 52, y, label, 34)
        canvas_text(self, 832, 260, GUI_TEXT['node_forwarding'], 20, width=330)
        canvas_text(self, 832, 405, GUI_TEXT['node_ipv4'], 20, width=330)

    def draw_info(self):
        self.line(362, 152, 362, APP_BASE_HEIGHT)
        self.line(981, 152, 981, APP_BASE_HEIGHT)
        y = 215
        for feature in GUI_TEXT['info_features']:
            self.checkmark(20, y)
            canvas_text(self, 85, y, feature, 35)
            y += 90
        canvas_text(self, 682, 175, GUI_TEXT['info_title'], 42, anchor='n', justify='center')
        canvas_text(self, 382, 235, GUI_TEXT['info_body'], 18, fill=IND_WHITE, width=575)
        self.create_oval(px(1003), px(184), px(1183), px(364), outline=IND_RED, width=px(16))
        self.line(1030, 330, 1159, 210, color=IND_RED, width=14)
        canvas_text(self, 1093, 254, GUI_TEXT['info_blockchain'], 28, anchor='n', justify='center')
        self.create_oval(px(1003), px(402), px(1183), px(582), outline='#35c758', width=px(16))
        canvas_text(self, 1093, 449, GUI_TEXT['info_supply_amount'], 22, anchor='n', justify='center')
        canvas_text(self, 1093, 492, GUI_TEXT['info_supply_label'], 24, anchor='n', justify='center')
        canvas_text(self, 1093, 620, GUI_TEXT['info_inflation'], 43, anchor='n', justify='center')

    def draw_print_page(self):
        canvas_text(self, 637, 195, GUI_TEXT['print_title'], 40)

    def draw_wallet(self):
        self.line(825, 151, 825, APP_BASE_HEIGHT)
        canvas_text(self, 1020, 135 + WALLET_SEND_Y_OFFSET, GUI_TEXT['wallet_send_title'], 32, anchor='n',
                    justify='center')
        canvas_text(self, 852, 180 + WALLET_SEND_Y_OFFSET, GUI_TEXT['wallet_receiver_label'], 24)
        canvas_text(self, 852, 261 + WALLET_SEND_Y_OFFSET, GUI_TEXT['wallet_amount_label'], 24)
        canvas_text(self, 1024, 420, GUI_TEXT['wallet_receive_title'], 32, anchor='n', justify='center')

    def draw_settings(self):
        canvas_text(self, 62, 176, GUI_TEXT['settings_title'], 42)
        canvas_text(self, 62, 245, GUI_TEXT['settings_peer_servers'], 22)
        self.rect(60, 280, 520, 410, fill='#101010', outline=IND_MUTED, width=1)
        canvas_text(self, 62, 475, GUI_TEXT['settings_finality'], 22)
        canvas_text(self, 62, 529, GUI_TEXT['settings_timeout'], 22)
        canvas_text(self, 62, 583, GUI_TEXT['settings_require_log'], 22)
        self.line(575, 170, 575, 716, color=IND_MUTED, width=1)
        canvas_text(self, 620, 176, GUI_TEXT['settings_root_domains'], 22)
        self.rect(618, 210, 1142, 292, fill='#101010', outline=IND_MUTED, width=1)
        canvas_text(self, 620, 312, GUI_TEXT['settings_root_mirrors'], 22)
        self.rect(618, 346, 1142, 438, fill='#101010', outline=IND_MUTED, width=1)
        canvas_text(self, 620, 460, GUI_TEXT['settings_operator_url'], 22)
        canvas_text(self, 620, 512, GUI_TEXT['settings_operator_key'], 22)
        self.rect(618, 546, 1142, 612, fill='#101010', outline=IND_MUTED, width=1)
        canvas_text(self, 620, 632, GUI_TEXT['settings_root_lag'], 20)
        canvas_text(self, 860, 632, GUI_TEXT['settings_min_mirrors'], 20)

    def draw_sign_in_panel(self, generate=False):
        self.rect(282, 190, 933, 740, fill=IND_BLACK, outline=IND_WHITE, width=3)
        self.rect(282, 190, 933, 253, fill=IND_WHITE, outline=IND_WHITE, width=1)
        if generate:
            canvas_text(self, 607, 276, GUI_TEXT['generate_wallet_address'], 28, anchor='n', justify='center')
            canvas_text(self, 607, 386, GUI_TEXT['generate_public_key'], 21, anchor='n', justify='center')
            canvas_text(self, 607, 467, GUI_TEXT['generate_private_key'], 21, anchor='n', justify='center')
            canvas_text(self, 607, 549, GUI_TEXT['generate_password'], 29, anchor='n', justify='center')
        else:
            canvas_text(self, 607, 303, GUI_TEXT['signin_wallet_label'], 28, anchor='n', justify='center')
            canvas_text(self, 607, 448, GUI_TEXT['signin_password_label'], 28, anchor='n', justify='center')
            canvas_text(self, 607, 598, GUI_TEXT['signin_stay_label'], 18, anchor='n', justify='center')

    def draw_sign_in(self):
        self.draw_sign_in_panel(generate=False)

    def draw_generate_wallet(self):
        self.draw_sign_in_panel(generate=True)


class ModalCanvas(Canvas):
    def __init__(self, master, modal_name, width, height, bg=IND_BLACK):
        super().__init__(
            master,
            width=px(width),
            height=px(height),
            bg=bg,
            bd=0,
            highlightthickness=0,
        )
        self.modal_name = modal_name
        self.width = width
        self.height = height
        self.draw()

    def draw(self):
        self.create_rectangle(px(1), px(1), px(self.width - 1), px(self.height - 1), outline=IND_WHITE,
                              width=px(2), fill=self['bg'])
        if self.modal_name == 'claim':
            canvas_text(self, 246, 32, GUI_TEXT['claim_title'], 34, anchor='n', justify='center')
            canvas_text(self, 30, 108, GUI_TEXT['claim_serial'], 28)
            canvas_text(self, 30, 200, GUI_TEXT['claim_public'], 28)
            canvas_text(self, 30, 292, GUI_TEXT['claim_private'], 28)
            self.create_rectangle(px(28), px(382), px(309), px(560), fill=IND_WHITE, outline=IND_WHITE)
        elif self.modal_name == 'success':
            self.create_rectangle(px(1), px(1), px(self.width - 1), px(self.height - 1), outline=IND_GREEN,
                                  width=px(2), fill='#007a3b')
            canvas_text(self, 326, 14, GUI_TEXT['success_title'], 58, anchor='n', justify='center',
                        weight='bold')
            canvas_text(self, 46, 123, GUI_TEXT['success_body'], 29)
        elif self.modal_name == 'valid':
            canvas_text(self, self.width / 2, self.height / 2, 'Valid', 44, anchor='center', justify='center')
        elif self.modal_name == 'not_valid':
            canvas_text(self, self.width / 2, self.height / 2, 'Not valid', 44, anchor='center',
                        justify='center')


def make_text_button(text, command, font_size=24, bg=IND_GREEN, fg='white', font_weight=None, bd=0,
                     relief=FLAT):
    font = (APP_FONT_FAMILY, font_size * reso) if font_weight is None else (APP_FONT_FAMILY, font_size * reso, font_weight)
    return Button(
        root,
        text=text,
        command=command,
        font=font,
        bg=bg,
        fg=fg,
        activebackground=bg,
        activeforeground=fg,
        bd=bd,
        highlightthickness=0,
        cursor='hand2',
        relief=relief,
        overrelief=relief,
        padx=0,
        pady=0,
    )


def control_image_path(folder, name):
    scaled_path = BASE_DIR / 'img' / folder / f'{name}{res}.png'
    if scaled_path.exists():
        return scaled_path
    return BASE_DIR / 'img' / folder / f'{name}.png'


def make_asset_button(folder, name, command, fallback_text, font_size=18, bg=IND_BLACK, fg=IND_WHITE):
    try:
        image = PhotoImage(file=str(control_image_path(folder, name)))
        button = Button(
            root,
            image=image,
            command=command,
            bd=0,
            highlightthickness=0,
            cursor='hand2',
            relief=FLAT,
            overrelief=FLAT,
        )
        button.image = image
        return button
    except Exception:
        return make_text_button(fallback_text, command, font_size=font_size, bg=bg, fg=fg, bd=1, relief=SOLID)


# make a backup copy of all wallets in the wallet folder, in case program is uninstalled, these will remain
try:
    path = os.path.expanduser('~/wallet_folder_backup')
    try:
        os.mkdir(path)
    except:
        pass
    for wallet_path in runtime_json.iter_encrypted_wallet_files():
        shutil.copyfile(wallet_path, os.path.join(path, wallet_path.name))
except:
    pass

def update_wallet():
    # this function will return a update of the decrypted wallet file
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        dr_w = runtime_json.read_decrypted_wallet_lines(wallet_path)
        num_lines_w = len(dr_w)
        return dr_w, num_lines_w

try:
    dr, num_lines = update_wallet()
except:
    pass

# main "International Dollar" text in upper left corner of GUI
international_dollar = Text(root, font=app_font(45), bg='black', fg='white', bd=0, highlightthickness=0)
international_dollar.insert(1.0, GUI_TEXT['app_title'])
international_dollar.place(x=150 * reso, y=45 * reso, height=90 * reso, width=410 * reso)
international_dollar.config(state='disabled', cursor='arrow')


# The receive QR is built lazily when the wallet tab is opened.
wa_sliced = None
qr_img = None
qr = None
address_txt = None


def ensure_wallet_qr():
    global wa_sliced, qr_img, qr, address_txt
    if qr is not None and address_txt is not None:
        return True
    try:
        wallet_lines, _ = update_wallet()
        wa_sliced = wallet_lines[0]
        address_qr = qrcode.QRCode(
            version=1,
            box_size=6,
            border=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
        )
        address_qr.add_data(wa_sliced)
        qr_make = address_qr.make_image(fill_color='black', back_color='#D3D3D3')
        qr_resize = qr_make.resize((250 * reso, 250 * reso), Image.Resampling.LANCZOS)
        qr_img = ImageTk.PhotoImage(qr_resize)
        qr = Label(root, image=qr_img, bd=0, highlightthickness=0)
        address_txt = Text(root, font=(APP_FONT_FAMILY, 19 * reso), bg='black', fg='white', bd=0,
                           highlightthickness=0)
        return True
    except Exception:
        return False

# main Tkinter-drawn screens that replace the old full-window PNG backgrounds
root.configure(background=IND_BLACK)
panel = GuiScreen(root, 'home')
panel.pack(fill='none', expand=True)
node_terminal = GuiScreen(root, 'node_terminal')
info = GuiScreen(root, 'info')
print_page = GuiScreen(root, 'print_page')
wallet = GuiScreen(root, 'wallet')
settings_page = GuiScreen(root, 'settings')
sign_in = GuiScreen(root, 'sign_in')
generate_wallet = GuiScreen(root, 'generate_wallet')
logo = Label(root, text='$', font=app_font(72, 'bold'), bg=IND_BLACK, fg=IND_WHITE, bd=0)
logo.place(x=12 * reso, y=14 * reso, width=126 * reso, height=126 * reso)


def load_logo_image():
    try:
        logo_src = Image.open(BASE_DIR / 'img' / 'logo.ico')
        logo_src = logo_src.resize((px(126), px(126)), Image.Resampling.LANCZOS)
        logo_img = ImageTk.PhotoImage(logo_src)
        logo.config(image=logo_img, text='')
        logo.image = logo_img
    except Exception:
        pass


root.after_idle(load_logo_image)
receiver = Entry(root, font=(APP_FONT_FAMILY, 20 * reso), bg='light grey')
frame_w = Frame(root, bg='black')
# disable window resize
root.resizable(False, False)


l2, l3, l4 = runtime_json.read_node_config()

# Node Terminal notice. Nodes must be reachable over TCP; UDP hole punching is no longer used.
node_port_notice = Text(root, font=(APP_FONT_FAMILY, 19 * reso), bg='black', fg='white', bd=0, highlightthickness=0)
node_port_notice.insert(1.0, 'Open TCP port 8888\non your router/firewall')
node_port_notice.config(state='disabled', cursor='arrow')

# run on startup option
ron_var = StringVar(root)
ron = OptionMenu(root, ron_var, 'YES', 'NO')
ron.config(font=(APP_FONT_FAMILY, 24 * reso, 'bold'), cursor='hand2', bg='black', fg='white')
rons = root.nametowidget(ron.menuname)
rons.config(font=(APP_FONT_FAMILY, 20 * reso))
ron_var.set(l3)

# run in background option
bak_var = StringVar(root)
bak = OptionMenu(root, bak_var, 'YES', 'NO')
bak.config(font=(APP_FONT_FAMILY, 24 * reso, 'bold'), cursor='hand2', bg='black', fg='white')
baks = root.nametowidget(bak.menuname)
baks.config(font=(APP_FONT_FAMILY, 20 * reso))
bak_var.set(l4)

try:
    USER_NAME = getpass.getuser()
    disk = os.path.realpath(__file__)[0]
    bat_path = disk + r':\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' % USER_NAME
except Exception:
    pass

def start():
    # update node class
    runtime_json.write_node_config('FULL NODE', ron_var.get(), bak_var.get())

    # if run on startup is enabled 'YES', write a BAT file
    if ron_var.get() == 'YES':
        try:
            file_path = str(os.path.dirname(os.path.realpath(__file__))) + '/node_client.pyw'
            with open(bat_path + '\\' + 'ind_node.bat', 'w+') as bat_file:
                bat_file.write(r'start "" "%s"' % file_path)
        except:
            pass

    runtime_json.set_kill_node(False)
    start_button.place_forget()
    end_button.place(x=977 * reso, y=190 * reso, width=177 * reso, height=54 * reso)

    # start a subprocess of the TCP gossip node
    def subp():
        if platform.system() != 'Windows':
            subprocess.run("python3 node_client.py", shell=True)
        else:
            subprocess.run("python node_client.py", shell=True)
    threading.Thread(target=subp).start()
    time.sleep(0.5)

    # add more nodes to your ip_folder
    def thrd2():
        time.sleep(5)
        for _ in range(3):
            sender_node.update_ip_list()

    threading.Thread(target=thrd2).start()

# shut the node off
def end():
    runtime_json.set_kill_node(True)
    end_button.place_forget()
    start_button.place(x=977 * reso, y=190 * reso, width=177 * reso, height=54 * reso)
    time.sleep(1)
# b = balance
b = Text(root, font=(APP_FONT_FAMILY, 37 * reso), bg='black', fg='white', bd=0, highlightthickness=0)
balance_top = Text(root, font=(APP_FONT_FAMILY, 26 * reso), bg='black', fg='white', bd=0, highlightthickness=0)

start_button = make_asset_button('different_buttons', 'start', start, 'Start', font_size=32, bg=IND_GREEN)
end_button = make_asset_button('different_buttons', 'end', end, 'End', font_size=32, bg=IND_RED)


def make_settings_text(font_size=16):
    return Text(
        root,
        font=app_font(font_size),
        bg='#101010',
        fg=IND_WHITE,
        insertbackground=IND_WHITE,
        bd=0,
        highlightthickness=0,
        wrap='word',
    )


def make_settings_entry(font_size=18):
    return Entry(
        root,
        font=app_font(font_size),
        bg='light grey',
        fg=IND_BLACK,
        insertbackground=IND_BLACK,
        bd=0,
        highlightthickness=0,
    )


def _text_lines(widget):
    return [line.strip() for line in widget.get('1.0', END).splitlines() if line.strip()]


def _set_text_lines(widget, lines):
    widget.config(state='normal')
    widget.delete('1.0', END)
    widget.insert('1.0', '\n'.join(lines))


def _set_entry_value(widget, value):
    widget.delete(0, END)
    widget.insert(0, str(value))


def _set_settings_status(message, color=IND_WHITE):
    settings_status.config(state='normal', fg=color)
    settings_status.delete('1.0', END)
    settings_status.insert('1.0', message)
    settings_status.config(state='disabled')


def _set_ping_status(message, color=IND_WHITE):
    settings_ping_status.config(state='normal', fg=color)
    settings_ping_status.delete('1.0', END)
    settings_ping_status.insert('1.0', message)
    settings_ping_status.config(state='disabled')


settings_peer_servers = make_settings_text(17)
settings_root_domains = make_settings_text(17)
settings_root_mirrors = make_settings_text(17)
settings_operator_key = make_settings_text(14)
settings_finality_entry = make_settings_entry(19)
settings_timeout_entry = make_settings_entry(19)
settings_operator_url_entry = make_settings_entry(17)
settings_root_lag_entry = make_settings_entry(17)
settings_min_mirrors_entry = make_settings_entry(17)
settings_status = make_settings_text(16)
settings_status.config(state='disabled')
settings_ping_status = make_settings_text(15)
settings_ping_status.config(state='disabled')
settings_require_log_var = StringVar(root)
settings_require_log = OptionMenu(root, settings_require_log_var, 'YES', 'NO')
settings_require_log.config(font=app_font(18, 'bold'), cursor='hand2', bg=IND_BLACK, fg=IND_WHITE,
                            activebackground=IND_WHITE, activeforeground=IND_BLACK, highlightthickness=0)
settings_require_log_menu = root.nametowidget(settings_require_log.menuname)
settings_require_log_menu.config(font=app_font(16))


def load_security_settings_form():
    settings = ind_settings.load_security_settings()
    _set_text_lines(settings_peer_servers, settings['peer_ping_servers'])
    _set_text_lines(settings_root_domains, settings['trusted_root_domains'])
    _set_text_lines(settings_root_mirrors, settings['trusted_root_mirrors'])
    _set_text_lines(settings_operator_key, [settings['transparency_operator_public_key']])
    _set_entry_value(settings_finality_entry, settings['finality_buffer_seconds'])
    _set_entry_value(settings_timeout_entry, settings['peer_request_timeout_seconds'])
    _set_entry_value(settings_operator_url_entry, settings['transparency_operator_url'])
    _set_entry_value(settings_root_lag_entry, settings['max_root_lag_seconds'])
    _set_entry_value(settings_min_mirrors_entry, settings['min_root_mirrors'])
    settings_require_log_var.set('YES' if settings['require_transparency_log'] else 'NO')
    _set_ping_status('')


def collect_security_settings_form():
    return {
        'peer_ping_servers': _text_lines(settings_peer_servers),
        'trusted_root_domains': _text_lines(settings_root_domains),
        'trusted_root_mirrors': _text_lines(settings_root_mirrors),
        'transparency_operator_url': settings_operator_url_entry.get().strip(),
        'transparency_operator_public_key': '\n'.join(_text_lines(settings_operator_key)).strip(),
        'require_transparency_log': settings_require_log_var.get() == 'YES',
        'min_root_mirrors': settings_min_mirrors_entry.get().strip(),
        'max_root_lag_seconds': settings_root_lag_entry.get().strip(),
        'finality_buffer_seconds': settings_finality_entry.get().strip(),
        'peer_request_timeout_seconds': settings_timeout_entry.get().strip(),
    }


def save_security_settings_form():
    try:
        settings = ind_settings.save_security_settings(collect_security_settings_form())
        load_security_settings_form()
        _set_settings_status(
            'Saved. Bills settle after %s seconds; %s Merkle mirror(s) required.'
            % (settings['finality_buffer_seconds'], settings['min_root_mirrors']),
            IND_GREEN,
        )
    except Exception as exc:
        _set_settings_status('Save failed: ' + str(exc), IND_RED)


def reset_security_settings_form():
    try:
        settings = ind_settings.reset_security_settings()
        load_security_settings_form()
        _set_settings_status(
            'Reset to defaults. Bills settle after %s seconds.' % settings['finality_buffer_seconds'],
            IND_ORANGE,
        )
    except Exception as exc:
        _set_settings_status('Reset failed: ' + str(exc), IND_RED)


def ping_security_servers():
    servers = _text_lines(settings_peer_servers)
    if not servers:
        _set_ping_status('No servers configured.', IND_ORANGE)
        return
    settings_ping_button.config(cursor='watch')
    _set_ping_status('Pinging...')

    def worker():
        results = []
        for server in servers[:8]:
            started = time.time()
            try:
                response = sender_node.connect('d', '', [server])
                elapsed = int((time.time() - started) * 1000)
                label = 'OK' if response == 'END' else 'No reply'
                results.append(f'{server}: {label} ({elapsed} ms)')
            except Exception as exc:
                results.append(f'{server}: {exc}')

        def finish():
            settings_ping_button.config(cursor='hand2')
            _set_ping_status('\n'.join(results), IND_GREEN if any('OK' in row for row in results) else IND_ORANGE)

        root.after(0, finish)

    threading.Thread(target=worker, daemon=True).start()


settings_save_button = make_text_button('Save', save_security_settings_form, font_size=24, bg=IND_GREEN)
settings_reset_button = make_text_button('Reset', reset_security_settings_form, font_size=24, bg=IND_ORANGE)
settings_ping_button = make_text_button('Ping', ping_security_servers, font_size=22, bg=IND_BLACK,
                                        fg=IND_WHITE, bd=1, relief=SOLID)
settings_widgets = (
    settings_peer_servers,
    settings_root_domains,
    settings_root_mirrors,
    settings_operator_key,
    settings_finality_entry,
    settings_timeout_entry,
    settings_operator_url_entry,
    settings_root_lag_entry,
    settings_min_mirrors_entry,
    settings_require_log,
    settings_status,
    settings_ping_status,
    settings_save_button,
    settings_reset_button,
    settings_ping_button,
)

# a = amount
a = Entry(root, font=(APP_FONT_FAMILY, 22 * reso), bg='light grey')
receiver_history = Text(root, font=(APP_FONT_FAMILY, 22 * reso), bg='black', fg='light grey', bd=0, highlightthickness=0)
receiver_history.bind("<Key>", lambda e: "break")

def write_transfer_announcement(wallet_lines, wallet_bill_line, recipient_address):
    """Spend one locally stored token and queue its transfer announcement."""

    return wallet_services.spend_wallet_bill(wallet_lines, wallet_bill_line, recipient_address)

address_to_charge = []
def charge_bills():
    """Send selected printed bills to the generated paper-wallet addresses."""

    root.config(cursor='watch')
    charge_bills_button.config(cursor='watch')
    list_sm = list(filter(None, selected_bills_text.get(1.0, END).splitlines()))
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if wallet_path.name.startswith('wallet_decrypted'):
            of = runtime_json.read_decrypted_wallet_lines(wallet_path)
            updated = []
            for wb in of:
                if wb.split()[0] in list_sm:
                    index_item = list_sm.index(wb.split()[0])
                    try:
                        state = write_transfer_announcement(of, wb, address_to_charge[index_item])
                        if state:
                            updated.append('-' + wb.split()[0] + ' ' + str(state.sequence) + ' ' + str(int(time.time())) + '\n')
                        else:
                            updated.append(wb)
                    except:
                        updated.append(wb)
                else:
                    updated.append(wb)
            runtime_json.write_decrypted_wallet_lines(wallet_path, updated)
    sender_node.send_bills()
    charge_bills_button.place_forget()
    button_print.place(x=640 * reso, y=650 * reso, width=291 * reso, height=59 * reso)
    button_only_qr.place(x=950 * reso, y=650 * reso, width=187 * reso, height=59 * reso)
    selected_bills_text.delete(1.0, END)
    root.config(cursor='arrow')
    update_balance()
    page()
    charge_bills_button.config(cursor='hand2')

def print_bills():
    # this function is responsible for creating a pdf file which the user can print
    if len(selected_bills_text.get(1.0, END)) <= 2:
        return
    list_bills = list(filter(None, selected_bills_text.get(1.0, END).splitlines()))
    list_bills_2 = []
    dr, _ = update_wallet()
    # iterate through all bills in the wallet
    for b in runtime_json.wallet_token_lines(dr):
        if b.split()[0] in list_bills:
            list_bills_2.append((b.split()[0], str(int(b.split()[1]) + 1)))
    root.config(cursor='watch')
    button_print.config(cursor='watch')

    def t():
        return_addr = print_tools.full_bill(list_bills_2)

        def finish():
            root.config(cursor='arrow')
            button_print.config(cursor='hand2')
            for re_addr in return_addr:
                address_to_charge.append(re_addr)

        root.after(0, finish)

    threading.Thread(target=t, daemon=True).start()

    def show_charge_button():
        button_print.place_forget()
        button_only_qr.place_forget()
        charge_bills_button.place(x=750 * reso, y=650 * reso, width=267 * reso, height=56 * reso)

    root.after(60000, show_charge_button)

def print_only_qr():
    # this function only prints qr codes, containing private key, public key and number
    if len(selected_bills_text.get(1.0, END)) <= 2:
        return
    list_bills = list(filter(None, selected_bills_text.get(1.0, END).splitlines()))
    list_bills_2 = []
    dr, _ = update_wallet()
    # iterate through all bills in the wallet
    for b in runtime_json.wallet_token_lines(dr):
        if b.split()[0] in list_bills:
            list_bills_2.append((b.split()[0], str(int(b.split()[1]) + 1)))
    root.config(cursor='watch')
    button_print.config(cursor='watch')
    button_only_qr.config(cursor='watch')

    def t():
        return_addr = print_tools.only_qr(list_bills_2)

        def finish():
            root.config(cursor='arrow')
            button_print.config(cursor='hand2')
            button_only_qr.config(cursor='hand2')
            for re_addr in return_addr:
                address_to_charge.append(re_addr)

        root.after(0, finish)

    threading.Thread(target=t, daemon=True).start()

    def show_charge_button():
        button_print.place_forget()
        button_only_qr.place_forget()
        charge_bills_button.place(x=750 * reso, y=650 * reso, width=267 * reso, height=56 * reso)

    root.after(60000, show_charge_button)


button_print = make_asset_button('different_buttons', 'print_button', print_bills, 'Print bills',
                                 font_size=22, bg=IND_GREEN)
button_only_qr = make_asset_button('different_buttons', 'only_qr_button', print_only_qr, 'Print only Qr',
                                   font_size=28, bg=IND_GREEN)
all_bills_text = Text(root, font=(APP_FONT_FAMILY, 22 * reso), bg='black', fg='light grey')
selected_bills_text = Text(root, font=(APP_FONT_FAMILY, 22 * reso), bg='#181818', fg='light grey')
asl_text = Text(root, font=(APP_FONT_FAMILY, 26 * reso), bg='black', fg='light grey', bd=0)
asl_text.insert(1.0, 'Copy bills\t\t   Paste bills to print')
asl_text.config(state='disabled')
charge_bills_button = make_asset_button('different_buttons', 'charge_bills_button', charge_bills, 'Charge bills',
                                        font_size=26, bg=IND_ORANGE)

def node_terminal_button():
    # this button function opens the 'Node terminal' tab in the right upper corner
    # the close function makes previous windows disappear
    close()
    button.config(bg='white', fg='black'),button2.config(bg='black', fg='white'), button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white'), button_log_in.config(bg='black', fg='black')
    button_settings.config(bg='black', fg='white')
    # check if node is already running
    if runtime_json.get_kill_node():
        start_button.place(x=977 * reso, y=190 * reso, width=177 * reso, height=54 * reso)
    else:
        end_button.place(x=977 * reso, y=190 * reso, width=177 * reso, height=54 * reso)
    # Node networking notice and settings like "run in background: YES"
    node_port_notice.place(x=420 * reso,  y=245 * reso, width=360 * reso, height=70 * reso)
    ron.place(x=450 * reso,  y=395 * reso, width=230 * reso, height=45 * reso)
    bak.place(x=450 * reso,  y=535 * reso, width=230 * reso, height=45 * reso)
    node_terminal.place(x=0, y=0)

def sign_in_button():
    # this button function opens the 'Sign in' button window in the right upper corner
    close()
    button.config(bg='black', fg='white'),button2.config(bg='black', fg='white'),button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white'),button_log_in.config(bg='white', fg='black')
    button_settings.config(bg='black', fg='white')
    button_generate_wallet.config(bg='black', fg='white')
    place_sign_in_control(button_log_in, 609, 196, 322, 57)
    place_sign_in_control(button_generate_wallet, 285, 196, 322, 57)
    place_sign_in_control(enter_address, 400, 355, 425, 50)
    place_sign_in_control(enter_key, 400, 500, 360, 50)
    place_sign_in_control(log_in_button2, 500, 650, 213, 58)
    # check if user wants to be signed in permanently
    if runtime_json.get_check_signed_in():
        place_sign_in_control(button_checkmark, 465, 602, 26, 27)
    else:
        place_sign_in_control(button_checkbox, 465, 602, 26, 26)
    place_sign_in_control(button_show, 765, 500, 60, 50)
    sign_in.place(x=0, y=0)

def info_button():
    # this button function opens the 'Information' tab in the right upper corner
    close()
    button.config(bg='black', fg='white'),button2.config(bg='white', fg='black'),button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white')
    button_settings.config(bg='black', fg='white')
    info.place(x=0, y=0)

def print_page_button():
    # this button function opens the Print tab in the right upper corner
    close()
    button.config(bg='black', fg='white'),button4.config(bg='black', fg='white'),button2.config(bg='black', fg='white')
    button3.config(bg='white', fg='black')
    button_settings.config(bg='black', fg='white')
    button_print.place(x=640 * reso, y=650 * reso, width=291 * reso, height=59 * reso)
    button_only_qr.place(x=950 * reso, y=650 * reso, width=187 * reso, height=59 * reso)
    all_bills_text.place(x=640 * reso, y=310 * reso, width=240 * reso, height=300 * reso)
    selected_bills_text.place(x=900 * reso, y=310 * reso, width=240 * reso, height=300 * reso)
    asl_text.place(x=640 * reso, y=260 * reso, width=480 * reso, height=48 * reso)
    print_page.place(x=0, y=0)
    only_sm = ''
    try:
        dr, num_lines = update_wallet()
        # update serial numbers in all_bills_text text field
        for bsm in runtime_json.wallet_token_lines(dr):
            if not bsm.startswith('-'):
                only_sm += bsm.split()[0] + '\n'
        all_bills_text.delete(1.0, END)
        all_bills_text.insert(1.0, only_sm[:-1])
    except:
        pass
    
def wallet_button():
    # this button function opens the 'wallet' tab in the right upper corner
    close()
    ensure_bill_images()
    refresh_bill_buttons()
    button.config(bg='black', fg='white'),button2.config(bg='black', fg='white'),button3.config(bg='black', fg='white')
    button4.config(bg='white', fg='black'), button_settings.config(bg='black', fg='white')
    plus_bills_button.place(x=435 * reso, y=725 * reso, width=275 * reso, height=30 * reso)
    receiver.place(x=853 * reso, y=(213 + WALLET_SEND_Y_OFFSET) * reso, width=343 * reso, height=36 * reso)
    send.place(x=1075 * reso, y=(340 + WALLET_SEND_Y_OFFSET) * reso, width=120 * reso, height=34 * reso)
    b.place(x=340 * reso, y=187 * reso, width=480 * reso, height=60 * reso)
    balance_top.place(x=660 * reso, y=30 * reso, width=450 * reso, height=40 * reso)
    frame_w.place(x=18 * reso, y=170 * reso, width=305 * reso, height=595 * reso)
    close_amount_button.place(x=1157 * reso, y=(299 + WALLET_SEND_Y_OFFSET) * reso, width=32 * reso,
                              height=30 * reso)
    receiver_button.place(x=747 * reso, y=190 * reso, width=52 * reso, height=52 * reso)
    a.place(x=853 * reso, y=(295 + WALLET_SEND_Y_OFFSET) * reso, width=343 * reso, height=36 * reso)
    next_button.place(x=720 * reso, y=730 * reso, width=80 * reso, height=22 * reso)
    receiver_history.place(x=343 * reso, y=310 * reso, width=480 * reso, height=450 * reso)
    wallet.place(x=0, y=0)
    try:
        ensure_wallet_qr()
        qr.place(x=898 * reso, y=468 * reso)
        tf_button.place(x=1155 * reso, y=570 * reso, width=44 * reso, height=42 * reso)
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

def settings_button():
    close()
    button.config(bg='black', fg='white'),button2.config(bg='black', fg='white'),button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white'), button_settings.config(bg='white', fg='black')
    load_security_settings_form()
    settings_peer_servers.place(x=72 * reso, y=292 * reso, width=436 * reso, height=105 * reso)
    settings_ping_button.place(x=72 * reso, y=418 * reso, width=92 * reso, height=34 * reso)
    settings_ping_status.place(x=178 * reso, y=414 * reso, width=330 * reso, height=52 * reso)
    settings_finality_entry.place(x=305 * reso, y=472 * reso, width=110 * reso, height=34 * reso)
    settings_timeout_entry.place(x=305 * reso, y=526 * reso, width=110 * reso, height=34 * reso)
    settings_require_log.place(x=305 * reso, y=578 * reso, width=110 * reso, height=38 * reso)
    settings_save_button.place(x=62 * reso, y=658 * reso, width=146 * reso, height=46 * reso)
    settings_reset_button.place(x=230 * reso, y=658 * reso, width=146 * reso, height=46 * reso)
    settings_status.place(x=398 * reso, y=650 * reso, width=164 * reso, height=66 * reso)
    settings_root_domains.place(x=630 * reso, y=220 * reso, width=500 * reso, height=62 * reso)
    settings_root_mirrors.place(x=630 * reso, y=356 * reso, width=500 * reso, height=72 * reso)
    settings_operator_url_entry.place(x=790 * reso, y=462 * reso, width=340 * reso, height=34 * reso)
    settings_operator_key.place(x=630 * reso, y=556 * reso, width=500 * reso, height=46 * reso)
    settings_root_lag_entry.place(x=755 * reso, y=630 * reso, width=82 * reso, height=34 * reso)
    settings_min_mirrors_entry.place(x=990 * reso, y=630 * reso, width=60 * reso, height=34 * reso)
    settings_page.place(x=0, y=0)

def generate_wallet_button():
    # this button function opens the 'Generate address' tab in the sign in window
    button_show.place_forget(),enter_key.place_forget(),log_in_button2.place_forget()
    enter_address.place_forget(),sign_in.place_forget(), button_checkmark.place_forget(), button_checkbox.place_forget()
    button_generate_wallet.config(bg='white', fg='black')
    button_log_in.config(bg='black', fg='white')
    place_sign_in_control(generate_address_text, 380, 318, 370, 40)
    place_sign_in_control(generate_address_button, 760, 318, 100, 41)
    place_sign_in_control(public_key, 380, 420, 480, 30)
    place_sign_in_control(private_key, 380, 500, 429, 30)
    place_sign_in_control(button_show2, 819, 500, 41, 31)
    place_sign_in_control(choose_password, 380, 600, 415, 40)
    place_sign_in_control(generate_wallet_button2, 505, 660, 213, 58)
    place_sign_in_control(button_show3, 805, 600, 54, 41)
    generate_wallet.place(x=0, y=0)

tf_text = Text(font=(APP_FONT_FAMILY, 28 * reso), bg='black', fg='white', bd=0)
def transfer_wallet():
    # this function generates a qr code, containing wallet address, public key, private key and wallet password
    try:
        if not ensure_wallet_qr():
            return
        wallet_lines, _ = update_wallet()
        data_wallet = ''.join(wallet_lines[:3])
        wallet_qr = qrcode.QRCode(version=1, box_size=4, border=1,
                                  error_correction=qrcode.constants.ERROR_CORRECT_L)
        wallet_qr.add_data(data_wallet)
        wqr_make_security = wallet_qr.make_image(fill_color='#F5F5F5', back_color='white')
        wqr_resize_security = wqr_make_security.resize((250 * reso, 250 * reso), Image.Resampling.LANCZOS)
        wqr_security_img = ImageTk.PhotoImage(wqr_resize_security)
        qr.wqr_security_img = wqr_security_img
        qr.config(image=wqr_security_img)
        qr.config(text='SECURITY RISK', font=(APP_FONT_FAMILY, 36 * reso, 'bold'), fg='red', compound='center')
        tf_text.delete(1.0, END)
        tf_text.insert(1.0, 'Transfer wallet')
        tf_text.place(x=935 * reso, y=420 * reso, width=190 * reso, height=45 * reso)
        tf_button.place_forget()
    except Exception:
        return

    def config_normal():
        r_button.place(x=850 * reso, y=570 * reso, width=44 * reso, height=42 * reso)
        wqr_make = wallet_qr.make_image(fill_color='black', back_color='#D3D3D3')
        wqr_resize = wqr_make.resize((250 * reso, 250 * reso), Image.Resampling.LANCZOS)
        wqr_img = ImageTk.PhotoImage(wqr_resize)
        qr.wqr_img = wqr_img
        qr.config(image=wqr_img, text=' ')
    root.after(5000, config_normal)

def receive_qr():
    r_button.place_forget()
    tf_button.place(x=1155 * reso, y=570 * reso, width=44 * reso, height=42 * reso)
    tf_text.place_forget()
    if ensure_wallet_qr():
        qr.config(image=qr_img)

tf_button = make_asset_button('different_buttons', 'tf_button', transfer_wallet, 'TX', font_size=16,
                              bg=IND_BLACK)
r_button = make_asset_button('different_buttons', 'r_button', receive_qr, 'QR', font_size=16, bg=IND_BLACK)

page_wallet = 1
place_next_button = 0
def page():
    # this function is flips the pages between transaction history
    global place_next_button
    try:
        conf = ''
        num_of_bills = 0
        try:
            dr_new, _ = update_wallet()
            for t in reversed(runtime_json.wallet_token_lines(dr_new)):
                conf += t.split()[0] + '\t\t        ' + str(datetime.fromtimestamp(int(t.split()[2])).strftime('%Y-%m-%d   %H:%M')) + '\n\n'
                num_of_bills += 1
        except Exception:
            pass
        if place_next_button != 0:
            next_button.place(x=720 * reso, y=730 * reso, width=80 * reso, height=22 * reso)
            place_next_button -= 1
        if page_wallet > 1:
            previous_button.place(x=345 * reso, y=730 * reso, width=80 * reso, height=22 * reso)
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


next_button = make_asset_button('different_buttons', 'next_button', next_, 'Next', font_size=16, bg=IND_BLACK)
previous_button = make_asset_button('different_buttons', 'previous_button', previous, 'Back', font_size=16,
                                    bg=IND_BLACK)
page()

BILL_VALUES = (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000)
BILL_IMAGES = {}
BILL_IMAGES_LOADED = False


def bill_var(value, prefix):
    return f'{prefix}_w{value}'


def wallet_bill_image_path(value, selected=False):
    selected_suffix = 'c' if selected else ''
    return BASE_DIR / 'img' / 'wallet_bills' / f'_{value}{selected_suffix}{res}.png'


def ensure_bill_images():
    global BILL_IMAGES_LOADED
    if BILL_IMAGES_LOADED:
        return
    for value in BILL_VALUES:
        for selected in (False, True):
            image_path = wallet_bill_image_path(value, selected=selected)
            if image_path.exists():
                BILL_IMAGES[(value, selected)] = PhotoImage(file=str(image_path))
    BILL_IMAGES_LOADED = True


def bill_button_text(value, remaining):
    return f'{value:,}$   {remaining}'


def make_bill_button(command):
    return Button(
        frame_w,
        command=command,
        state='disabled',
        highlightthickness=0,
        bd=1,
        relief=SOLID,
        overrelief=SOLID,
        font=app_font(19),
        fg=IND_WHITE,
        bg='#111111',
        activeforeground=IND_WHITE,
        activebackground=IND_GREEN,
        disabledforeground=IND_MUTED,
        cursor='',
    )


def configure_bill_button(button, value, remaining, enabled):
    remaining = max(remaining, 0)
    image = BILL_IMAGES.get((value, enabled))
    if image is None and BILL_IMAGES_LOADED:
        image = BILL_IMAGES.get((value, False))
    if image is not None:
        button.config(
            image=image,
            text='       ' + str(remaining) if remaining > 0 else '',
            compound='center',
            font=app_font(30),
            cursor='hand2' if enabled else '',
            state='normal' if enabled else 'disabled',
            bg=IND_BLACK,
            fg=IND_WHITE,
            disabledforeground=IND_WHITE,
        )
    else:
        button.config(
            image='',
            text=bill_button_text(value, remaining) if remaining > 0 else '',
            compound='none',
            font=app_font(19),
            cursor='hand2' if enabled else '',
            state='normal' if enabled else 'disabled',
            bg=IND_GREEN if enabled else '#111111',
            fg=IND_WHITE if enabled else IND_MUTED,
            disabledforeground=IND_MUTED,
        )

amount = 0
bills_w1, bills_w2, bills_w5, bills_w10, bills_w20, bills_w50, bills_w100, bills_w200, bills_w500 = 0, 0, 0, 0, 0, 0, 0, 0, 0
bills_w1000, bills_w2000, bills_w5000, bills_w10000, bills_w20000, bills_w50000, bills_w100000 = 0, 0, 0, 0, 0, 0, 0
selected_w1, selected_w2, selected_w5, selected_w10, selected_w20 = 0, 0, 0, 0, 0
selected_w50, selected_w100, selected_w200, selected_w500, selected_w1000 = 0, 0, 0, 0, 0
selected_w2000, selected_w5000, selected_w10000, selected_w20000 = 0, 0, 0, 0
selected_w50000, selected_w100000 = 0, 0
def update_balance():
    # this function updates all balance indicators for the user
    global first_iteration, amount, count_selected
    global bills_w1, bills_w2, bills_w5, bills_w10, bills_w20, bills_w50, bills_w100, bills_w200, bills_w500
    global bills_w1000, bills_w2000, bills_w5000, bills_w10000, bills_w20000, bills_w50000, bills_w100000
    try:
        dr_new2, _ = update_wallet()
    except:
        pass
    bills_w1 = bills_w2 = bills_w5 = bills_w10 = bills_w20 = bills_w50 = bills_w100 = bills_w200 = bills_w500 = 0
    bills_w1000 = bills_w2000 = bills_w5000 = bills_w10000 = bills_w20000 = bills_w50000 = bills_w100000 = 0
    # recount the existance of bills in the wallet
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

# these "add" functions are responsible for updating the amounts selected by the user
# changing the count text on the bills and the color if no more bills are available
####################################################################
def add_bill_value(value):
    global amount, count_selected
    selected_name = bill_var(value, 'selected')
    bills_name = bill_var(value, 'bills')
    selected = globals()[selected_name]
    available = globals()[bills_name]
    remaining = available - selected
    button_bill = globals()[f'w{value}']

    if remaining > 0:
        if count_selected:
            globals()[selected_name] = selected + 1
            amount += value
            remaining -= 1
        configure_bill_button(button_bill, value, remaining, remaining > 0)

    if remaining <= 0:
        configure_bill_button(button_bill, value, 0, False)
    amount_config()


def add_1():
    add_bill_value(1)


def add_2():
    add_bill_value(2)


def add_5():
    add_bill_value(5)


def add_10():
    add_bill_value(10)


def add_20():
    add_bill_value(20)


def add_50():
    add_bill_value(50)


def add_100():
    add_bill_value(100)


def add_200():
    add_bill_value(200)


def add_500():
    add_bill_value(500)


def add_1000():
    add_bill_value(1000)


def add_2000():
    add_bill_value(2000)


def add_5000():
    add_bill_value(5000)


def add_10000():
    add_bill_value(10000)


def add_20000():
    add_bill_value(20000)


def add_50000():
    add_bill_value(50000)


def add_100000():
    add_bill_value(100000)


w1 = make_bill_button(add_1)
w2 = make_bill_button(add_2)
w5 = make_bill_button(add_5)
w10 = make_bill_button(add_10)
w20 = make_bill_button(add_20)
w50 = make_bill_button(add_50)
w100 = make_bill_button(add_100)
w200 = make_bill_button(add_200)
w500 = make_bill_button(add_500)
w1000 = make_bill_button(add_1000)
w2000 = make_bill_button(add_2000)
w5000 = make_bill_button(add_5000)
w10000 = make_bill_button(add_10000)
w20000 = make_bill_button(add_20000)
w50000 = make_bill_button(add_50000)
w100000 = make_bill_button(add_100000)

def start_bills():
    global count_selected
    for value in BILL_VALUES:
        add_bill_value(value)
    count_selected = True


def refresh_bill_buttons():
    global count_selected
    was_counting = count_selected
    count_selected = False
    for value in BILL_VALUES:
        add_bill_value(value)
    count_selected = was_counting


start_bills()
update_balance()
####################################################################


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
    # this function invokes receive_bills() which will ask the node network for new bills
    root.config(cursor='watch')
    receiver_button.config(cursor='watch')
    def thrd():
        sender_node.update_ip_list()
    def thrd2():
        sender_node.receive_bills()
        time.sleep(12)

        def finish():
            update_balance()
            page()
            root.config(cursor='arrow')
            receiver_button.config(cursor='hand2')

        root.after(0, finish)
    threading.Thread(target=thrd, daemon=True).start()
    threading.Thread(target=thrd2, daemon=True).start()

receiver_button = make_asset_button('different_buttons', 'reload_button', receive_bills, 'Sync', font_size=16,
                                    bg=IND_GREEN)
# visual of password or important private key to display as : ******** or : password123
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
    # this function upon button press will change if the user doesnt log out upon closing
    if runtime_json.toggle_check_signed_in():
        button_checkbox.place_forget()
        place_sign_in_control(button_checkmark, 465, 602, 26, 27)
    else:
        button_checkmark.place_forget()
        place_sign_in_control(button_checkbox, 465, 602, 26, 26)

def log_in():
    # this function will sign the user into a encrypted wallet
    unlocked = wallet_decryption.wallet_decrypt(enter_key.get(), address_variable.get())
    # check if the right password was entered
    def check_decrypted():
        global decrypted
        for decrypted_wallet in runtime_json.iter_decrypted_wallet_files():
            if decrypted_wallet.name.startswith('wallet_decrypted'):
                enter_key.delete(0, END)
                wallet_button()
                break
    if unlocked:
        check_decrypted()
    else:
        messagebox.showerror('Wallet locked', 'That password did not unlock this wallet.')

address_variable = StringVar(root)
options_addr = ['                                                                        ']
# add to the dropdown menu of addresses in the sign in window
for s in runtime_json.iter_encrypted_wallet_files() + runtime_json.iter_decrypted_wallet_files():
    wallet_raw = runtime_json.wallet_address_from_name(s.name)
    if wallet_raw not in options_addr:
        options_addr.append(wallet_raw)
if len(options_addr) == 1:
    men = 0
else:
    men = 1
enter_address = OptionMenu(root, address_variable, *options_addr[men:])
enter_address.config(font=(APP_FONT_FAMILY, 21 * reso, 'bold'), cursor='hand2', bg='black', fg='white')
eadrr = root.nametowidget(enter_address.menuname)
eadrr.config(font=(APP_FONT_FAMILY, 20 * reso))

enter_key = Entry(root, font=(APP_FONT_FAMILY, 26 * reso), show='*', bg='light grey')
log_in_button2 = make_asset_button('different_buttons', 'log_in_button', log_in, 'Sign in', font_size=26,
                                   bg=IND_GREEN)
button_show = make_asset_button('different_buttons', 'show_button', show_key_s, 'Show', font_size=16,
                                bg=IND_BLACK)
button_show3 = make_asset_button('different_buttons', 'show3_button', show_password, 'Show', font_size=16,
                                 bg=IND_BLACK)
button_checkbox = make_asset_button('different_buttons', 'checkbox', stay_signed, '', font_size=14, bg=IND_BLACK)
button_checkmark = make_asset_button('different_buttons', 'checkmark', stay_signed, '', font_size=14, bg=IND_BLACK)

def gen_ad():
    # this function is responsible for invoking generate_address.py
    runtime_json.clear_wallet_generation()
    generate_address_text.config(state='normal'),public_key.config(state='normal'),private_key.config(state='normal')
    generate_address_text.delete(0, END),public_key.delete(0, END),private_key.delete(0, END)
    root.config(cursor='watch')
    generate_address_button.config(cursor='watch')

    def finish(generated_wallet):
        runtime_json.write_wallet_generation(generated_wallet[0], generated_wallet[1], generated_wallet[2])
        # get the info of the generated wallet
        ha = runtime_json.wallet_generation_lines()
        h_address = ha[0].strip()
        h_private_key = ha[1].strip()
        h_public_key = ha[2].strip()
        generate_address_text.insert(0, h_address),public_key.insert(0, h_public_key)
        private_key.insert(0, h_private_key)
        generate_address_text.config(state='readonly'),public_key.config(state='readonly')
        private_key.config(state='readonly'),generate_address_button.config(cursor='hand2')
        root.config(cursor='arrow')

    def fail(exc):
        generate_address_button.config(cursor='hand2')
        root.config(cursor='arrow')
        messagebox.showerror('Wallet generation failed', str(exc))

    def t():
        try:
            import generate_address as generate_address_module
            generated_wallet = []
            generate_address_module.hash_func(generated_wallet)
        except Exception as exc:
            root.after(0, lambda exc=exc: fail(exc))
            return
        root.after(0, lambda generated_wallet=generated_wallet: finish(generated_wallet))
    threading.Thread(target=t, daemon=True).start()
def generate_wallet_final():
    addr_hash = runtime_json.read_wallet_generation()["address"]
    # encrypt the new wallet
    try:
        wallet_encryption.wallet_encrypt(choose_password.get())
    except wallet_encryption.PasswordPolicyError as exc:
        messagebox.showerror('Weak wallet password', str(exc))
        return
    except Exception as exc:
        messagebox.showerror('Wallet generation failed', str(exc))
        return
    choose_password.delete(0, END)
    runtime_json.clear_wallet_generation()
    address_variable.set(addr_hash)
    sign_in_button()
    success.place(x=282 * reso, y=193 * reso)
    success.lift()
    root.after(3500, success.place_forget)

success = ModalCanvas(root, 'success', 653, 550, bg='#007a3b')
generate_address_text = Entry(root, font=(APP_FONT_FAMILY, 21 * reso), bd=0, bg='light grey')
generate_address_button = make_asset_button('different_buttons', 'generate_address_button', gen_ad, 'Generate',
                                            font_size=22, bg=IND_GREEN)
public_key = Entry(root, font=(APP_FONT_FAMILY, 18 * reso), bd=0, bg='light grey')
private_key = Entry(root, font=(APP_FONT_FAMILY, 18 * reso), bd=0, show='*', bg='light grey')
button_show2 = make_asset_button('different_buttons', 'show2_button', show_key_p, 'Show', font_size=16,
                                 bg=IND_BLACK)
choose_password = Entry(root, font=(APP_FONT_FAMILY, 22 * reso), bd=0, bg='light grey')
generate_wallet_button2 = make_asset_button('different_buttons', 'generate_wallet_button', generate_wallet_final,
                                            'Generate Wallet', font_size=24, bg=IND_GREEN)

button_log_in = Button(root, font=(APP_FONT_FAMILY, 30 * reso), text='Sign In', bd=0, highlightthickness=0, cursor='hand2',
                       bg='black', fg='white', command=sign_in_button)
button_generate_wallet = Button(root, font=(APP_FONT_FAMILY, 30 * reso), text='Generate Wallet', bd=0, highlightthickness=0,
                                cursor='hand2', bg='black', fg='white', command=generate_wallet_button)

def send_bills(serial_num_start):
    """Select wallet tokens by denomination and queue signed sends to the receiver."""

    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if wallet_path.name.startswith('wallet_decrypted'):
            of = runtime_json.read_decrypted_wallet_lines(wallet_path)
            updated = []
            for wb in of:
                if wb.split('x')[0] + 'x' in serial_num_start:
                    serial_num_start.remove(wb.split('x')[0] + 'x')
                    try:
                        state = write_transfer_announcement(of, wb, receiver.get())
                        if state:
                            updated.append('-' + wb.split()[0] + ' ' + str(state.sequence) + ' ' + str(int(time.time())) + '\n')
                        else:
                            updated.append(wb)
                    except:
                        updated.append(wb)
                else:
                    updated.append(wb)
            runtime_json.write_decrypted_wallet_lines(wallet_path, updated)

def confirm_transaction():
    """Convert the selected UI amount into denomination prefixes and send them."""

    global selected_w1,selected_w2,selected_w5,selected_w10,selected_w20
    global selected_w50,selected_w100,selected_w200,selected_w500,selected_w1000
    global selected_w2000,selected_w5000,selected_w10000,selected_w20000,selected_w50000
    global selected_w100000, function_call

    if runtime_json.has_pending_transactions():
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
        # get a few new nodes (30)
        for _ in range(3):
            sender_node.update_ip_list()
        recipient_address = ind_token.validate_address(receiver.get().strip(), "recipient address")
        if amount != 0 and recipient_address != dr[0].strip():
            confirm_transaction()
    except:
        pass
def close():
    # this function will make all labels, buttons and images disappear.
    claim_bills_amount.place_forget(), webcam_scanner.place_forget(), private_key_entry.place_forget()
    claim_bill.place_forget(),close_button.place_forget(), next_button.place_forget(), end_button.place_forget()
    serial_num.place_forget(), public_key_entry.place_forget(), check_validity_button.place_forget()
    send.place_forget(), receiver.place_forget(), a.place_forget(), frame_w.place_forget()
    b.place_forget(), close_amount_button.place_forget(),plus_bills_button.place_forget(), r_button.place_forget()
    previous_button.place_forget(), start_button.place_forget(), receiver_history.place_forget()
    panel.pack_forget(), print_page.place_forget(), wallet.place_forget(), receiver_button.place_forget()
    sign_in.place_forget(), log_in_button2.place_forget(), button_log_in.place_forget(), enter_address.place_forget()
    enter_key.place_forget(), button_generate_wallet.place_forget(), generate_wallet.place_forget()
    button_show.place_forget(), generate_address_text.place_forget(), generate_address_button.place_forget()
    public_key.place_forget(), private_key.place_forget(), button_show2.place_forget(), choose_password.place_forget()
    generate_wallet_button2.place_forget(), node_terminal.place_forget(), tf_button.place_forget()
    button_show3.place_forget(), button_checkmark.place_forget(), number_entry.place_forget()
    button_checkbox.place_forget(), info.place_forget(), tf_text.place_forget(), button_print.place_forget()
    add_bill_button.place_forget(), node_port_notice.place_forget(), charge_bills_button.place_forget()
    ron.place_forget(), bak.place_forget(), asl_text.place_forget(), all_bills_text.place_forget()
    selected_bills_text.place_forget(), button_only_qr.place_forget()
    settings_page.place_forget()
    success.place_forget()
    for settings_widget in settings_widgets:
        settings_widget.place_forget()
    try:
        qr.place_forget(), address_txt.place_forget()
    except Exception:
        pass
def close_amount():
    # this function will reset the amount selected
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
    # close the qr code scanner
    serial_num.place_forget(), public_key_entry.place_forget(), check_validity_button.place_forget()
    claim_bills_amount.place_forget(), webcam_scanner.place_forget(), close_button.place_forget()
    claim_bill.place_forget(), add_bill_button.place_forget(), private_key_entry.place_forget()
    number_entry.place_forget()

send = make_asset_button('different_buttons', 'send_button', send_button, 'Send', font_size=24, bg=IND_GREEN)
try:
    close_button_img = PhotoImage(file=str(BASE_DIR / 'img' / 'pop_up' / f'close{res}.png'))
    close_button = Button(root, image=close_button_img, bd=0, highlightthickness=0, cursor='hand2',
                          command=close_bill_claimer)
except Exception:
    close_button = make_icon_button('X', close_bill_claimer, font_size=18, bg=IND_BLACK, fg=IND_WHITE)
try:
    close_amount_button_img = PhotoImage(
        file=str(BASE_DIR / 'img' / 'different_buttons' / f'close_amount{res}.png')
    )
    close_amount_button = Button(root, image=close_amount_button_img, bd=0, highlightthickness=0, cursor='hand2',
                                 command=close_amount)
except Exception:
    close_amount_button = make_icon_button('X', close_amount, font_size=14, bg=IND_RED, fg=IND_WHITE)

def plus_bills():
    # this function opens up the claim bills window, invoked by the "Scan Qr code" button in wallet
    restore_webcam_scanner_prompt()
    claim_bill.place(x=335 * reso, y=154 * reso)
    claim_bills_amount.place()
    close_button.place(x=785 * reso, y=163 * reso, width=37 * reso, height=33 * reso)
    close_button.lift()
    check_validity_button.place(x=366 * reso, y=727 * reso, width=198 * reso, height=30 * reso)
    add_bill_button.place(x=605 * reso, y=727 * reso, width=198 * reso, height=30 * reso)
    serial_num.place(x=364 * reso, y=295 * reso, width=440 * reso, height=40 * reso)
    public_key_entry.place(x=364 * reso, y=390 * reso, width=440 * reso, height=40 * reso)
    private_key_entry.place(x=364 * reso, y=482 * reso, width=440 * reso, height=40 * reso)
    webcam_scanner.place(x=364 * reso, y=538 * reso, width=280 * reso, height=176 * reso)
    claim_bills_amount.place(x=655 * reso, y=640 * reso, width=140 * reso, height=100 * reso)
    claim_bills_amount.bind("<Key>", lambda e: "break")
    number_entry.place(x=655 * reso, y=539 * reso, width=150 * reso, height=42 * reso)
    number_entry.delete(0, END)
    number_entry.insert(0, 'Number:')
    number_entry.bind("<Key>", lambda e: number_entry.delete(0, END))
    webcam_scanner.lift()

plus_bills_button = make_asset_button('different_buttons', 'plus_bills_button', plus_bills, 'Scan Qr code',
                                      font_size=18, bg='black', fg='white')
claim_bill = ModalCanvas(root, 'claim', 493, 620, bg=IND_BLACK)
claim_bills_amount = Entry(root, font=(APP_FONT_FAMILY, 26 * reso, 'bold'), fg='white', bg='black', highlightthickness=0, bd=0)
claim_bills_amount.insert(0, '0$')

used_codes = []
num_of_times_clicked = 0
def claim_bills():
    """Claim scanned bills by issuing receipts or spending paper-wallet tokens."""

    for bill in used_codes:
        for wallet_path in runtime_json.iter_decrypted_wallet_files():
            if wallet_path.name.startswith('wallet_decrypted'):
                wallet_lines = runtime_json.read_decrypted_wallet_lines(wallet_path)
                try:
                    wallet_address = runtime_json.wallet_address_from_name(wallet_path.name)
                    wallet_services.claim_bill_payload(bill, wallet_lines, wallet_address)
                except Exception:
                    continue
    sender_node.send_bills()
    time.sleep(2)
    receive_bills()
    update_balance()

def add_bill():
    """Add a manually entered bill payload to the pending claim list."""

    global used_codes
    full_code = serial_num.get(0, END) + '\n' + private_key_entry.get(0, END) + '\n' + public_key_entry.get(0, END) + '\n' + number_entry.get(0, END)
    if full_code not in used_codes:
        used_codes.append(full_code)
        am = int(claim_bills_amount.get().strip('$'))
        claim_bills_amount.delete(0, END)
        claim_bills_amount.insert(0, str(am + int(serial_num.get().split('x')[0])) + '$')

check_validity_button = make_asset_button('different_buttons', 'check_validity_button', claim_bills, 'Claim bills',
                                          font_size=20, bg='white', fg='black')
add_bill_button = make_asset_button('different_buttons', 'add_bill_button', add_bill, 'Add bills', font_size=20,
                                    bg='white', fg='black')
valid = ModalCanvas(root, 'valid', 493, 620, bg=IND_GREEN)
not_valid = ModalCanvas(root, 'not_valid', 493, 620, bg=IND_RED)
serial_num = Entry(root, font=(APP_FONT_FAMILY, 22 * reso), bg='light grey')
public_key_entry = Entry(root, font=(APP_FONT_FAMILY, 22 * reso), bg='light grey')
private_key_entry = Entry(root, font=(APP_FONT_FAMILY, 22 * reso), bg='light grey')
number_entry = Entry(root, font=(APP_FONT_FAMILY, 22 * reso), bg='light grey')


def qr_decoder(qrimage):
    """Decode wallet addresses, bearer tokens, and paper-wallet claims from QR images."""

    global used_codes
    for code in decode(qrimage):
        decoded_qrcode = code.data.decode('utf-8')
        if decoded_qrcode not in used_codes:
            if decoded_qrcode.startswith('x'):
                receiver.delete(0, END)
                receiver.insert(0, decoded_qrcode)
            elif decoded_qrcode.startswith('{'):
                used_codes.append(decoded_qrcode)
                try:
                    message = json.loads(decoded_qrcode)
                    token_payload = message.get("token", message)
                    state = ind_token.verify_token(token_payload)
                    serial_num.delete(0, END)
                    serial_num.insert(0, state.display_id)
                    am = int(claim_bills_amount.get().strip('$'))
                    claim_bills_amount.delete(0, END)
                    claim_bills_amount.insert(0, str(state.value + am) + '$')
                except Exception:
                    pass
            else:
                used_codes.append(decoded_qrcode)
                serial_num.delete(0, END)
                serial_num.insert(0, decoded_qrcode.splitlines()[0])
                private_key_entry.delete(0, END)
                private_key_entry.insert(0, decoded_qrcode.splitlines()[1])
                public_key_entry.delete(0, END)
                public_key_entry.insert(0, decoded_qrcode.splitlines()[2])
                number_entry.delete(0, END)
                number_entry.insert(0, decoded_qrcode.splitlines()[3])
                am = int(claim_bills_amount.get().strip('$'))
                claim_bills_amount.delete(0, END)
                claim_bills_amount.insert(0, str(int(decoded_qrcode.split('x')[0]) + am) + '$')


webcam_scanner_img = None


def ensure_webcam_scanner_image():
    global webcam_scanner_img
    if webcam_scanner_img is None:
        try:
            webcam_scanner_img = PhotoImage(file=str(control_image_path('pop_up', 'qr_overlay')))
        except Exception:
            webcam_scanner_img = ''
    return webcam_scanner_img


def restore_webcam_scanner_prompt():
    image = ensure_webcam_scanner_image()
    if image:
        webcam_scanner.config(image=image, text='', cursor='hand2', bd=0, highlightthickness=0)
    else:
        webcam_scanner.config(image='', text=GUI_TEXT['qr_drop'], cursor='hand2', bd=1, highlightthickness=1)


def qr_scan():
    # this function will access the webcam, and scan for qr codes
    # you can also choose a picture from laptop hardrive, or drag and drop images
    global num_of_times_clicked, cap
    num_of_times_clicked += 1
    webcam_scanner.config(cursor='watch')
    if (num_of_times_clicked % 2) != 0:
        if platform.system() == 'Windows':
            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        elif platform.system() == 'Linux':
            cap = cv2.VideoCapture(0, cv2.CAP_V4L2)
        else:
            cap = cv2.VideoCapture(0)
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
        restore_webcam_scanner_prompt()
        cap.release()
        cv2.destroyAllWindows()

webcam_scanner = Button(
    root,
    text=GUI_TEXT['qr_drop'],
    cursor='hand2',
    highlightthickness=1,
    bd=1,
    command=qr_scan,
    font=app_font(18),
    fg=IND_WHITE,
    bg=IND_BLACK,
    activeforeground=IND_WHITE,
    activebackground=IND_BLACK,
)


def drop(event):
    # drag and drop qr code images
    qr_path = event.data.strip('{}')
    qr_path_tk = Image.open(qr_path)
    resized = qr_path_tk.resize((280 * reso, 177 * reso), Image.Resampling.LANCZOS)
    drag_and_drop_img = ImageTk.PhotoImage(resized)
    webcam_scanner.drag_and_drop_img = drag_and_drop_img
    webcam_scanner.config(image=drag_and_drop_img)
    qr_decoder(qr_path_tk)

webcam_scanner.drop_target_register(DND_FILES)
webcam_scanner.dnd_bind('<<Drop>>', drop)

#######################################
# main buttons for 4 major tabs 'Node Terminal', 'Information', 'Print', 'Wallet'
button = Button(root, command=node_terminal_button, text='Node Terminal', bg='black', fg='white',
                font=(APP_FONT_FAMILY, 24 * reso), cursor='hand2', bd=0, activebackground='white', highlightthickness=0,)
place_header_button(button, 577, 100, 169, 50)

button2 = Button(root, command=info_button, text='Information', bg='black', fg='white', font=(APP_FONT_FAMILY, 24 * reso),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
place_header_button(button2, 750, 100, 169, 50)

button3 = Button(root, command=print_page_button, text='Print', bg='black', fg='white', font=(APP_FONT_FAMILY, 24 * reso),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
place_header_button(button3, 923, 100, 169, 50)

button4 = Button(root, command=wallet_button, text='Wallet', bg='black', fg='white', font=(APP_FONT_FAMILY, 24 * reso),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
place_header_button(button4, 1096, 100, 114, 50)

button_settings = make_text_button('Settings', settings_button, font_size=22, bg=IND_BLACK, fg=IND_WHITE,
                                   bd=1, relief=SOLID)
place_header_button(button_settings, 1016, 18, 94, 64)

button6 = make_asset_button('different_buttons', 'sign_in_button', sign_in_button, 'Sign\nin', font_size=22,
                            bg='white', fg='black')
place_header_button(button6, 1120, 18, 77, 64)
international_dollar.lift()
logo.lift()
#######################################
def on_closing():
    # this function will be invoked upon closing the tkinter GUI
    try:
        _node_class, run_on_startup, run_in_background = runtime_json.read_node_config()
        # check if the user wants to run his node in the background
        if run_in_background == 'NO':
            runtime_json.set_kill_node(True)
        for wallet_path in runtime_json.iter_decrypted_wallet_files():
            if wallet_path.name.startswith('wallet_decrypted'):
                address = runtime_json.wallet_address_from_name(wallet_path.name)
                w = runtime_json.read_decrypted_wallet_payload(wallet_path)
                encrypted_record = {}
                for encrypted_path in runtime_json.iter_encrypted_wallet_files():
                    if runtime_json.wallet_address_from_name(encrypted_path.name) == address:
                        encrypted_record = runtime_json.read_encrypted_wallet_record(encrypted_path)
                        break
                try:
                    wallet_encryption.wallet_reencrypt_unlocked(address, w)
                except Exception:
                    if encrypted_record.get("format") != "INDW2":
                        legacy_lines = str(w).splitlines()
                        legacy_password = legacy_lines[3] if len(legacy_lines) > 3 else ""
                        runtime_json.write_wallet_generation_from_payload(w)
                        if legacy_password:
                            wallet_encryption.wallet_encrypt(legacy_password)
                wallet_decryption.secure_delete(wallet_path)
                runtime_json.clear_decrypted_wallet(address)
                runtime_json.clear_wallet_generation()
        # remove the bat path in case the user does no longer want to start the node on startup
        if run_on_startup == 'NO':
            os.remove(bat_path + '/ind_node.bat')
    except:
        pass
    root.destroy()


def restart_after_update():
    hide_root_window()
    on_closing()
    start_new_app_process()


root.protocol('WM_DELETE_WINDOW', on_closing)


def start_update_check_later():
    try:
        auto_update = importlib.import_module('ind.auto_update')
        auto_update.start_startup_update_check(root, BASE_DIR, restart_after_update)
    except Exception:
        pass


show_root_when_ready()
root.after(1000, start_update_check_later)
mainloop()
