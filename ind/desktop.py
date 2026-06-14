"""Tk desktop interface for wallet, node, print, claim, and settings workflows."""

import importlib
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import json
import queue
from pathlib import Path
from tkinter import (
    BOTH,
    DISABLED,
    END,
    FLAT,
    INSERT,
    NORMAL,
    SOLID,
    Button,
    Canvas,
    Entry,
    Frame,
    Label,
    Listbox,
    OptionMenu,
    Radiobutton,
    Scrollbar,
    StringVar,
    TclError,
    Text,
    Tk,
    Toplevel,
    mainloop,
)
from tkinter import filedialog, messagebox
from tkinter import font as tkfont

from tkinterdnd2 import DND_FILES, TkinterDnD
import getpass
from datetime import datetime

import platform
from . import runtime as runtime_json
from . import settings as ind_settings
from . import node_services

BASE_DIR = Path(__file__).resolve().parent.parent
os.chdir(BASE_DIR)
logger = logging.getLogger(__name__)
APP_FONT_FAMILY = 'Teko Light'
FONT_PATH = BASE_DIR / 'Teko-Light.ttf'
RUNTIME_DIRS = runtime_json.RUNTIME_DIRS
RUNTIME_FILES = {
    'files/security_settings.json': ind_settings.default_settings_json(),
}


def log_ignored_exception(context="suppressed desktop exception"):
    logger.debug(context, exc_info=True)


class LazyModule:
    """Delay heavyweight imports until the GUI path actually needs them."""

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
zxingcpp = LazyModule('zxingcpp')
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
    runtime_json.set_check_signed_in(False)
    runtime_json.clear_passphrase_request()
    for path, default in RUNTIME_FILES.items():
        if not os.path.exists(path):
            with open(path, 'w') as handle:
                handle.write(default)
    try:
        wallet_decryption.clear_plaintext_wallet_files(clear_memory=True)
    except Exception:
        log_ignored_exception()
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
        log_ignored_exception()
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
            log_ignored_exception()
    system = platform.system()
    if system == 'Windows':
        install_windows_font(font_path, font_family)
    elif system == 'Darwin':
        try:
            fonts_dir = Path.home() / 'Library' / 'Fonts'
            fonts_dir.mkdir(parents=True, exist_ok=True)
            copy_font_if_needed(font_path, fonts_dir / font_path.name)
        except Exception:
            log_ignored_exception()
    elif system == 'Linux':
        try:
            fonts_dir = Path.home() / '.local' / 'share' / 'fonts'
            fonts_dir.mkdir(parents=True, exist_ok=True)
            copy_font_if_needed(font_path, fonts_dir / font_path.name)
            subprocess.run(['fc-cache', '-f', str(fonts_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            log_ignored_exception()
def schedule_custom_font_load():
    try:
        if APP_FONT_FAMILY in tkfont.families(root):
            return
    except Exception:
        log_ignored_exception()
    root.after_idle(lambda: load_custom_font(FONT_PATH, APP_FONT_FAMILY))


def hide_root_window():
    try:
        root.withdraw()
        root.update_idletasks()
    except Exception:
        log_ignored_exception()
def show_root_when_ready():
    try:
        root.update_idletasks()
        root.deiconify()
        root.lift()
    except Exception:
        log_ignored_exception()
def start_new_app_process():
    subprocess.Popen([sys.executable, str(BASE_DIR / 'main.py')], cwd=str(BASE_DIR))


def relaunch_application():
    hide_root_window()
    start_new_app_process()
    root.destroy()


APP_BASE_WIDTH = 1214
APP_BASE_HEIGHT = 771
APP_SCALE_PRESETS = (2.0, 1.5, 1.25, 1.0)
APP_HIDPI_ASSET_SCALE = 1.75
APP_MIN_UPSCALE_WIDTH = 2000
APP_MIN_UPSCALE_HEIGHT = 1100
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
        log_ignored_exception()
def scaled_px(value, scale):
    return int(round(value * scale))


def windows_work_area_size():
    if platform.system() != 'Windows':
        return None

    try:
        import ctypes

        class RECT(ctypes.Structure):
            _fields_ = (
                ('left', ctypes.c_long),
                ('top', ctypes.c_long),
                ('right', ctypes.c_long),
                ('bottom', ctypes.c_long),
            )

        work_area = RECT()
        if ctypes.windll.user32.SystemParametersInfoW(48, 0, ctypes.byref(work_area), 0):
            return work_area.right - work_area.left, work_area.bottom - work_area.top
    except Exception:
        log_ignored_exception()
    return None


def monitor_work_area_size(tk_root):
    return windows_work_area_size() or (tk_root.winfo_screenwidth(), tk_root.winfo_screenheight())


def choose_app_scale(work_area_width, work_area_height):
    if work_area_width < APP_MIN_UPSCALE_WIDTH or work_area_height < APP_MIN_UPSCALE_HEIGHT:
        return 1.0

    for scale in APP_SCALE_PRESETS:
        if (
            scaled_px(APP_BASE_WIDTH, scale) <= work_area_width
            and scaled_px(APP_BASE_HEIGHT, scale) <= work_area_height
        ):
            return scale
    return APP_SCALE_PRESETS[-1]


enable_high_dpi_awareness()
root = TkinterDnD.Tk()
root.withdraw()
root.configure(background='black')
root.title('International Dollar')
root.tk.call('tk', 'scaling', 1.36)

work_area_width, work_area_height = monitor_work_area_size(root)
reso = choose_app_scale(work_area_width, work_area_height)
res = '4' if reso >= APP_HIDPI_ASSET_SCALE else ''
root.geometry(f'{scaled_px(APP_BASE_WIDTH, reso)}x{scaled_px(APP_BASE_HEIGHT, reso)}')
try:
    root.iconbitmap(str(BASE_DIR / 'img' / 'logo.ico'))
except Exception:
    log_ignored_exception()
schedule_custom_font_load()

IND_GREEN = '#009846'
IND_RED = '#ed1c24'
IND_ORANGE = '#f15a24'
IND_BLACK = '#000000'
IND_WHITE = '#ffffff'
IND_MUTED = '#bfbfbf'
IND_PENDING = '#777777'
NODE_PANEL_BG = '#050807'
NODE_CONSOLE_BG = '#020403'
NODE_HEADER_BG = '#0d1512'
NODE_CHIP_BG = '#0b0f0e'
NODE_CHIP_BORDER = '#33413d'
NODE_STATUS_X = 44
NODE_STATUS_Y = 206
NODE_STATUS_WIDTH = 1144
NODE_STATUS_HEIGHT = 64
NODE_ACTION_X = 995
NODE_ACTION_Y = 215
NODE_ACTION_WIDTH = 167
NODE_ACTION_HEIGHT = 46
NODE_PANEL_Y = 296
NODE_PANEL_HEIGHT = 462
NODE_SETUP_X = 44
NODE_SETUP_WIDTH = 350
NODE_CONSOLE_X = 416
NODE_CONSOLE_WIDTH = 774
NODE_CONSOLE_HEADER_HEIGHT = 56
NODE_LOG_X = NODE_CONSOLE_X + 18
NODE_LOG_Y = NODE_PANEL_Y + 74
NODE_LOG_WIDTH = NODE_CONSOLE_WIDTH - 36
NODE_LOG_HEIGHT = NODE_PANEL_HEIGHT - 92
WALLET_SEND_Y_OFFSET = 30
PRINT_LEFT_PANEL_X = 64
PRINT_RIGHT_PANEL_X = 614
PRINT_PANEL_Y = 190
PRINT_LEFT_PANEL_WIDTH = 520
PRINT_RIGHT_PANEL_WIDTH = 536
PRINT_PANEL_HEIGHT = 450
PRINT_PANEL_BOTTOM = PRINT_PANEL_Y + PRINT_PANEL_HEIGHT
PRINT_AVAILABLE_X = PRINT_LEFT_PANEL_X + 24
PRINT_QUEUE_X = PRINT_RIGHT_PANEL_X + 24
PRINT_AVAILABLE_LIST_Y = PRINT_PANEL_Y + 104
PRINT_QUEUE_LIST_Y = PRINT_PANEL_Y + 88
PRINT_AVAILABLE_LIST_WIDTH = PRINT_LEFT_PANEL_WIDTH - 48
PRINT_QUEUE_LIST_WIDTH = PRINT_RIGHT_PANEL_WIDTH - 48
PRINT_AVAILABLE_LIST_HEIGHT = 322
PRINT_QUEUE_LIST_HEIGHT = 150
PRINT_SELECT_ALL_X = PRINT_LEFT_PANEL_X + PRINT_LEFT_PANEL_WIDTH - 146
PRINT_SELECT_ALL_Y = PRINT_PANEL_Y + 27
PRINT_SELECT_ALL_WIDTH = 122
PRINT_SELECT_ALL_HEIGHT = 32
PRINT_OUTPUT_FULL_X = PRINT_RIGHT_PANEL_X + 24
PRINT_OUTPUT_QR_X = PRINT_RIGHT_PANEL_X + 24
PRINT_OUTPUT_LABEL_Y = PRINT_PANEL_Y + 252
PRINT_OUTPUT_FULL_Y = PRINT_PANEL_Y + 286
PRINT_OUTPUT_QR_Y = PRINT_PANEL_Y + 320
PRINT_OUTPUT_WIDTH = 168
PRINT_OUTPUT_HEIGHT = 30
PRINT_SUMMARY_X = PRINT_RIGHT_PANEL_X + PRINT_RIGHT_PANEL_WIDTH - 150
PRINT_SUMMARY_Y = PRINT_PANEL_Y + 20
PRINT_SUMMARY_WIDTH = 126
PRINT_SUMMARY_HEIGHT = 64
PRINT_PAGES_X = PRINT_RIGHT_PANEL_X + PRINT_RIGHT_PANEL_WIDTH - 156
PRINT_PAGES_Y = PRINT_PANEL_Y + 279
PRINT_PAGES_WIDTH = 110
PRINT_PAGES_HEIGHT = 58
PRINT_ACTION_STRIP_X = 64
PRINT_ACTION_STRIP_Y = 662
PRINT_ACTION_STRIP_WIDTH = 1086
PRINT_ACTION_STRIP_HEIGHT = 92
PRINT_STATUS_X = PRINT_ACTION_STRIP_X + 86
PRINT_STATUS_Y = PRINT_ACTION_STRIP_Y + 21
PRINT_STATUS_WIDTH = 560
PRINT_STATUS_HEIGHT = 54
PRINT_PRIMARY_BUTTON_X = PRINT_ACTION_STRIP_X + 698
PRINT_PRIMARY_BUTTON_WIDTH = 176
PRINT_CHARGE_BUTTON_X = PRINT_ACTION_STRIP_X + 894
PRINT_CHARGE_BUTTON_WIDTH = 168
PRINT_ACTION_Y = PRINT_ACTION_STRIP_Y + 21
PRINT_ACTION_BUTTON_HEIGHT = 50
GENERATE_WALLET_PANEL_LEFT = 282
GENERATE_WALLET_PANEL_RIGHT = 933
GENERATE_WALLET_PANEL_WIDTH = GENERATE_WALLET_PANEL_RIGHT - GENERATE_WALLET_PANEL_LEFT
GENERATE_WALLET_FIELD_X = 360
GENERATE_WALLET_FIELD_WIDTH = 400
GENERATE_WALLET_BUTTON_GAP = 12
GENERATE_WALLET_SIDE_BUTTON_WIDTH = 100
GENERATE_WALLET_SUBMIT_BUTTON_WIDTH = 267
GENERATE_WALLET_SIDE_BUTTON_X = GENERATE_WALLET_FIELD_X + GENERATE_WALLET_FIELD_WIDTH + GENERATE_WALLET_BUTTON_GAP
GENERATE_WALLET_SUBMIT_BUTTON_X = GENERATE_WALLET_PANEL_LEFT + (
    GENERATE_WALLET_PANEL_WIDTH - GENERATE_WALLET_SUBMIT_BUTTON_WIDTH
) // 2
GENERATE_WALLET_ADDRESS_Y = 312
GENERATE_WALLET_PUBLIC_KEY_Y = 405
GENERATE_WALLET_PRIVATE_KEY_Y = 498
GENERATE_WALLET_PASSWORD_Y = 591
GENERATE_WALLET_KEY_FIELD_HEIGHT = 38
GENERATE_WALLET_FIELD_HEIGHT = 42
CLAIM_COLUMN_GAP = 24
CLAIM_MODAL_X = 18
CLAIM_MODAL_Y = 154
CLAIM_MODAL_WIDTH = 493
CLAIM_MODAL_HEIGHT = 620
CLAIM_TITLE_X = 29
CLAIM_TITLE_Y = 20
CLAIM_LABEL_X = 29
CLAIM_LABEL_GAP_ABOVE_ENTRY = 36
CLAIM_ENTRY_X = CLAIM_MODAL_X + 29
CLAIM_ENTRY_WIDTH = 440
CLAIM_SERIAL_Y = CLAIM_MODAL_Y + 126
CLAIM_PUBLIC_Y = CLAIM_MODAL_Y + 216
CLAIM_PRIVATE_Y = CLAIM_MODAL_Y + 306
CLAIM_SCANNER_WIDTH = 340
CLAIM_SCANNER_HEIGHT = 214
CLAIM_SCANNER_X = CLAIM_ENTRY_X
CLAIM_SCANNER_Y = 520
CLAIM_SCANNER_STATUS_HEIGHT = 32
CLAIM_SCANNER_STATUS_Y = CLAIM_SCANNER_Y + CLAIM_SCANNER_HEIGHT + 2
CLAIM_RIGHT_SECTION_X = CLAIM_MODAL_X + CLAIM_MODAL_WIDTH + CLAIM_COLUMN_GAP
CLAIM_RIGHT_SECTION_Y = CLAIM_MODAL_Y
CLAIM_RIGHT_SECTION_WIDTH = APP_BASE_WIDTH - CLAIM_RIGHT_SECTION_X
CLAIM_RIGHT_PADDING = 20
CLAIM_RIGHT_CONTENT_WIDTH = CLAIM_RIGHT_SECTION_WIDTH - (CLAIM_RIGHT_PADDING * 2)
CLAIM_BACKGROUND_X = 0
CLAIM_BACKGROUND_Y = CLAIM_MODAL_Y
CLAIM_BACKGROUND_WIDTH = APP_BASE_WIDTH
CLAIM_BACKGROUND_HEIGHT = APP_BASE_HEIGHT - CLAIM_BACKGROUND_Y
CLAIM_BORDER_WIDTH = 2
CLAIM_HEADER_BORDER_Y = CLAIM_BACKGROUND_Y - 3
CLAIM_HEADER_BORDER_HEIGHT = 4
CLAIM_BOTTOM_BORDER_Y = APP_BASE_HEIGHT - CLAIM_BORDER_WIDTH
CLAIM_SEPARATOR_TOP = CLAIM_MODAL_Y + 34
CLAIM_SEPARATOR_HEIGHT = APP_BASE_HEIGHT - CLAIM_SEPARATOR_TOP - 34
CLAIM_LEFT_SEPARATOR_X = CLAIM_RIGHT_SECTION_X - (CLAIM_COLUMN_GAP // 2)
CLAIM_CLOSE_WIDTH = 37
CLAIM_CLOSE_HEIGHT = 33
CLAIM_CLOSE_X = CLAIM_RIGHT_SECTION_X + CLAIM_RIGHT_SECTION_WIDTH - CLAIM_RIGHT_PADDING - CLAIM_CLOSE_WIDTH
CLAIM_CLOSE_Y = CLAIM_RIGHT_SECTION_Y + 10
CLAIM_READY_TITLE_X = CLAIM_RIGHT_SECTION_X + CLAIM_RIGHT_PADDING
CLAIM_READY_TITLE_Y = CLAIM_RIGHT_SECTION_Y + 34
CLAIM_READY_TITLE_HEIGHT = 36
CLAIM_ACTION_WIDTH = 250
CLAIM_ACTION_X = CLAIM_READY_TITLE_X + CLAIM_RIGHT_CONTENT_WIDTH - CLAIM_ACTION_WIDTH
CLAIM_TOTAL_LABEL_HEIGHT = 42
CLAIM_BUTTON_HEIGHT = 58
CLAIM_ACTION_VERTICAL_GAP = 18
CLAIM_ACTION_BOTTOM_PADDING = 20
CLAIM_BUTTON_Y = APP_BASE_HEIGHT - CLAIM_ACTION_BOTTOM_PADDING - CLAIM_BUTTON_HEIGHT
CLAIM_TOTAL_LABEL_Y = CLAIM_BUTTON_Y - CLAIM_ACTION_VERTICAL_GAP - CLAIM_TOTAL_LABEL_HEIGHT
CLAIM_SUMMARY_GAP = 14
CLAIM_SUMMARY_ITEM_WIDTH = (CLAIM_RIGHT_CONTENT_WIDTH - CLAIM_SUMMARY_GAP) // 2
CLAIM_COUNT_LABEL_X = CLAIM_READY_TITLE_X + CLAIM_SUMMARY_ITEM_WIDTH + CLAIM_SUMMARY_GAP
SCANNED_SERIALS_OVERLAY_X = CLAIM_READY_TITLE_X
SCANNED_SERIALS_OVERLAY_Y = CLAIM_READY_TITLE_Y + CLAIM_READY_TITLE_HEIGHT + 18
SCANNED_SERIALS_OVERLAY_WIDTH = CLAIM_RIGHT_CONTENT_WIDTH
SCANNED_SERIALS_OVERLAY_HEIGHT = CLAIM_TOTAL_LABEL_Y - SCANNED_SERIALS_OVERLAY_Y - 22
SCANNED_SERIALS_OVERLAY_PADDING = 0
SCANNED_SERIALS_OVERLAY_TITLE_HEIGHT = 32
SCANNED_SERIALS_OVERLAY_SUBTITLE_HEIGHT = 32
SCANNED_SERIALS_LIST_Y = (
    SCANNED_SERIALS_OVERLAY_PADDING
    + SCANNED_SERIALS_OVERLAY_TITLE_HEIGHT
    + SCANNED_SERIALS_OVERLAY_SUBTITLE_HEIGHT
)
SCANNED_SERIALS_LIST_WIDTH = SCANNED_SERIALS_OVERLAY_WIDTH - (SCANNED_SERIALS_OVERLAY_PADDING * 2)
SCANNED_SERIALS_LIST_HEIGHT = (
    SCANNED_SERIALS_OVERLAY_HEIGHT
    - SCANNED_SERIALS_OVERLAY_TITLE_HEIGHT
    - SCANNED_SERIALS_OVERLAY_SUBTITLE_HEIGHT
    - (SCANNED_SERIALS_OVERLAY_PADDING * 2)
)
LOCAL_OPERATOR_URL = node_services.LOCAL_OPERATOR_URL
LOCAL_OPERATOR_ROOT_INTERVAL_SECONDS = node_services.LOCAL_OPERATOR_ROOT_INTERVAL_SECONDS
INFO_MAX_SUPPLY = f'{ind_token.MASTER_SUPPLY_NUMBER} Billion'

GUI_TEXT = {
    'app_title': 'International Dollar',
    'home_code_prefix': 'print',
    'home_code_open': '(',
    'home_code_body': '"Hello World!"',
    'home_code_suffix': ')',
    'node_labels': ('Node class:', 'Run on startup:', 'Run in background:', 'Transparency operator:'),
    'node_forwarding': (
        'If you are running a public node make sure to\n'
        f'forward TCP port {ind_settings.node_port()} to your local machine\n'
        'via your router terminal.'
    ),
    'node_description': (
        'A node keeps the IND gossip network alive: it accepts peer\n'
        'connections, relays transfers and receipts, stores local bill\n'
        'state, and forwards double-spend proofs.'
    ),
    'node_operator_description': (
        'Transparency operator mode runs the local public receipt log.\n'
        'It appends validated transfer hashes and publishes signed roots.'
    ),
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
        'IND is a fixed-supply bearer-bill network. There is no mining,\n'
        'staking, or blockchain consensus.\n\n'
        f'Supply is capped at {INFO_MAX_SUPPLY} IND. Genesis defines the full\n'
        'supply map with an issuer-signed manifest, while bills can remain lazy\n'
        'until they first move.\n\n'
        'Each bill has its own owner history. Transfers are signed with\n'
        'secp256k1 over canonical SHA3-256 data, and receivers verify every hop\n'
        'from genesis to the current owner.\n\n'
        'Desktop nodes gossip transfers, receipts, and double-spend proofs.\n'
        'Nodes do not vote on balances; locally conflicting incoming spends are\n'
        'rejected. Wait for the finality buffer before treating IND as settled.'
    ),
    'info_blockchain': 'Blockchain',
    'info_supply_amount': INFO_MAX_SUPPLY,
    'info_supply_label': 'max supply',
    'info_inflation': '0%\ninflation',
    'print_title': 'Print bills',
    'print_available_label': 'Available bills',
    'print_available_meta': 'Spendable and settled',
    'print_queue_label': 'Print batch',
    'print_queue_meta': 'Selected bills and output type',
    'wallet_send_title': 'Send IND',
    'wallet_receiver_label': 'Receiver address:',
    'wallet_amount_label': 'Amount (select bills):',
    'wallet_receive_title': 'Receive IND',
    'wallet_locked_message': 'No wallet unlocked.\nGo to Sign In to unlock one.',
    'signin_wallet_label': 'Enter wallet address',
    'signin_password_label': 'Enter wallet password',
    'generate_wallet_address': 'Wallet address',
    'generate_public_key': 'Public key',
    'generate_private_key': 'Private key',
    'generate_password': 'Choose password',
    'settings_title': 'Settings',
    'settings_subtitle': 'Network, bill safety, transparency, and updates.',
    'settings_peer_servers': 'Peer ping servers',
    'settings_dns_seeds': 'DNS seed hosts',
    'settings_network': 'Network',
    'settings_node_port': 'Node port',
    'settings_finality': 'Accept bills after (s)',
    'settings_timeout': 'Peer timeout (s)',
    'settings_require_log': 'Require Merkle log',
    'settings_security_profile': 'Security profile',
    'settings_untrusted_genesis': 'Allow untrusted genesis',
    'settings_genesis_keys': 'Trusted genesis issuer keys',
    'settings_genesis_hashes': 'Trusted genesis manifest hashes',
    'settings_root_domains': 'Trusted root domains',
    'settings_root_mirrors': 'Merkle root mirrors',
    'settings_operator_url': 'Operator URL',
    'settings_operator_key': 'Operator public key',
    'settings_root_lag': 'Max root lag (s)',
    'settings_current_root_age': 'Current root age (s)',
    'settings_future_skew': 'Future skew (s)',
    'settings_root_gossip': 'Root gossip',
    'settings_min_mirrors': 'Min mirrors',
    'settings_update_source': 'Update source',
    'settings_update_startup': 'Check on startup',
    'settings_update_status': 'Status',
    'claim_title': 'Claim bills',
    'claim_serial': 'Serial number',
    'claim_public': 'Public key',
    'claim_private': 'Private key',
    'claim_serials_title': 'Bills pending claim list',
    'claim_serials_subtitle': 'Review scanned or pasted bills before claiming',
    'claim_serials_empty': 'No bills pending yet',
    'claim_ready_title': 'Ready to claim',
    'claim_total_label': 'Total value: 0$',
    'claim_count_label': 'Bills: 0',
    'qr_drop': 'Drop QR image\nor use webcam',
    'success_title': 'Success!',
    'success_body': (
        'A new wallet has successfully been generated!\n'
        'Make sure to remember your password and\n'
        'keep your encrypted wallet folder safe.'
    ),
}


SETTINGS_TAB_NETWORK = 'network'
SETTINGS_TAB_BILL_SAFETY = 'bill_safety'
SETTINGS_TAB_TRANSPARENCY = 'transparency'
SETTINGS_TAB_UPDATES = 'updates'
SETTINGS_TABS = (
    (SETTINGS_TAB_NETWORK, 'Network'),
    (SETTINGS_TAB_BILL_SAFETY, 'Bill Safety'),
    (SETTINGS_TAB_TRANSPARENCY, 'Transparency'),
    (SETTINGS_TAB_UPDATES, 'Updates'),
)
settings_active_tab = SETTINGS_TAB_NETWORK
SETTINGS_TAB_X = 62
SETTINGS_TAB_Y = 190
SETTINGS_TAB_WIDTH = 206
SETTINGS_TAB_HEIGHT = 54
SETTINGS_TAB_GAP = 10
SETTINGS_PANEL_X = 62
SETTINGS_PANEL_Y = 258
SETTINGS_PANEL_RIGHT = 1152
SETTINGS_PANEL_BOTTOM = 708
SETTINGS_CONTENT_X = 88
SETTINGS_CONTENT_RIGHT = 1126
SETTINGS_TOP_LABEL_Y = 292
SETTINGS_TOP_FIELD_Y = 326
SETTINGS_DIVIDER_Y = 430
SETTINGS_BOTTOM_LABEL_Y = 466
SETTINGS_BOTTOM_FIELD_Y = 500
SETTINGS_BOTTOM_FIELD_BOTTOM = 690
SETTINGS_ROW_COLS = (88, 354, 620, 886)
SETTINGS_TWO_COL_LEFT = 88
SETTINGS_TWO_COL_RIGHT = 624
SETTINGS_TWO_COL_WIDTH = 508
SETTINGS_FOOTER_Y = 724


def px(value):
    return scaled_px(value, reso)


def error_detail(error):
    """Return a readable one-line error for wallet action popups."""

    if isinstance(error, Exception):
        message = str(error).strip()
        if message:
            return f"{error.__class__.__name__}: {message}"
        return error.__class__.__name__
    return str(error).strip() or "Unknown error"


def show_error_popup(title, error):
    """Show a simple error popup, safely scheduling it from worker threads."""

    detail = error_detail(error)

    def show():
        messagebox.showerror(title, detail)

    try:
        if threading.current_thread() is threading.main_thread():
            show()
        else:
            root.after(0, show)
    except Exception:
        log_ignored_exception()
def refresh_wallet_view():
    """Refresh visible wallet state and report refresh failures."""

    try:
        update_balance()
        page()
    except Exception as exc:
        show_error_popup('Wallet refresh failed', exc)


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


def raise_widget(widget):
    """Raise a Tk widget window, avoiding Canvas item-raise method collisions."""

    widget.tk.call('raise', widget._w)


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

class GuiScreen(Canvas):
    """Canvas-backed renderer for the fixed-size desktop screens.

    The application keeps most interactive widgets as normal Tk widgets placed
    over these canvases. These draw_* methods are therefore layout blueprints:
    they paint static chrome, separators, labels, and panels, while callbacks
    below handle widget placement and behavior.
    """

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
        """Draw the node control page around separately placed live widgets."""

        # Top strip: live node health values are overlaid as Labels/Canvas dots.
        self.rect(
            NODE_STATUS_X,
            NODE_STATUS_Y,
            NODE_STATUS_X + NODE_STATUS_WIDTH,
            NODE_STATUS_Y + NODE_STATUS_HEIGHT,
            fill=NODE_PANEL_BG,
            outline=IND_WHITE,
            width=1,
        )
        for x, width, label in (
            (300, 120, 'TCP'),
            (430, 100, 'Peers'),
            (540, 112, 'Events'),
            (662, 132, 'Operator'),
        ):
            self.rect(x, NODE_STATUS_Y + 14, x + width, NODE_STATUS_Y + 44, fill=NODE_CHIP_BG,
                      outline=NODE_CHIP_BORDER, width=1)

        # Left panel: persistent node settings and port-forwarding hints.
        self.rect(
            NODE_SETUP_X,
            NODE_PANEL_Y,
            NODE_SETUP_X + NODE_SETUP_WIDTH,
            NODE_PANEL_Y + NODE_PANEL_HEIGHT,
            fill=NODE_PANEL_BG,
            outline=IND_WHITE,
            width=1,
        )
        self.line(NODE_SETUP_X + 20, NODE_PANEL_Y + 54, NODE_SETUP_X + NODE_SETUP_WIDTH - 20,
                  NODE_PANEL_Y + 54, color='#313a36', width=1)
        for y, label, helper in (
            (NODE_PANEL_Y + 68, 'Node class', 'gossip network role'),
            (NODE_PANEL_Y + 138, 'PC startup', 'launch when this PC starts'),
            (NODE_PANEL_Y + 208, 'Background', 'keep running after close'),
            (NODE_PANEL_Y + 278, 'Transparency', 'operator receipt log'),
        ):
            canvas_text(self, NODE_SETUP_X + 22, y, label, 20)
            canvas_text(self, NODE_SETUP_X + 22, y + 26, helper, 13, fill=IND_MUTED, width=145)
        self.rect(NODE_SETUP_X + 178, NODE_PANEL_Y + 72, NODE_SETUP_X + NODE_SETUP_WIDTH - 22,
                  NODE_PANEL_Y + 108, fill=IND_BLACK, outline=IND_WHITE, width=1)
        for y in (NODE_PANEL_Y + 142, NODE_PANEL_Y + 212, NODE_PANEL_Y + 282):
            self.rect(NODE_SETUP_X + 178, y, NODE_SETUP_X + NODE_SETUP_WIDTH - 22, y + 36,
                      fill=IND_BLACK, outline=IND_WHITE, width=1)
        self.line(NODE_SETUP_X + 20, NODE_PANEL_Y + 334, NODE_SETUP_X + NODE_SETUP_WIDTH - 20,
                  NODE_PANEL_Y + 334, color='#313a36', width=1)
        canvas_text(self, NODE_SETUP_X + 22, NODE_PANEL_Y + 350, 'Port forwarding', 20)
        self.rect(300, NODE_PANEL_Y + 354, 374, NODE_PANEL_Y + 382, fill=IND_BLACK, outline=IND_WHITE, width=1)
        canvas_text(self, NODE_SETUP_X + 22, NODE_PANEL_Y + 388,
                    f'Open TCP port {ind_settings.node_port()} on your router/firewall', 16,
                    fill=IND_MUTED)
        canvas_text(self, NODE_SETUP_X + 22, NODE_PANEL_Y + 414,
                    'so external peers can reach this node.', 16, fill=IND_MUTED)

        # Right panel: console shell; Text widgets and filter buttons sit above it.
        self.rect(
            NODE_CONSOLE_X,
            NODE_PANEL_Y,
            NODE_CONSOLE_X + NODE_CONSOLE_WIDTH,
            NODE_PANEL_Y + NODE_PANEL_HEIGHT,
            fill=NODE_PANEL_BG,
            outline=IND_WHITE,
            width=1,
        )
        self.rect(
            NODE_CONSOLE_X + 1,
            NODE_PANEL_Y + 1,
            NODE_CONSOLE_X + NODE_CONSOLE_WIDTH - 1,
            NODE_PANEL_Y + NODE_CONSOLE_HEADER_HEIGHT,
            fill=NODE_HEADER_BG,
            outline=NODE_HEADER_BG,
            width=1,
        )
        canvas_text(self, NODE_CONSOLE_X + 22, NODE_PANEL_Y + 8, 'Console log', 29)
        self.line(NODE_CONSOLE_X, NODE_PANEL_Y + NODE_CONSOLE_HEADER_HEIGHT,
                  NODE_CONSOLE_X + NODE_CONSOLE_WIDTH, NODE_PANEL_Y + NODE_CONSOLE_HEADER_HEIGHT,
                  color='#313a36', width=1)
        self.rect(
            NODE_LOG_X,
            NODE_LOG_Y,
            NODE_LOG_X + NODE_LOG_WIDTH,
            NODE_LOG_Y + NODE_LOG_HEIGHT,
            fill=NODE_CONSOLE_BG,
            outline='#28332f',
            width=1,
        )

    def draw_info(self):
        self.line(362, 152, 362, APP_BASE_HEIGHT)
        self.line(981, 152, 981, APP_BASE_HEIGHT)
        y = 215
        for feature in GUI_TEXT['info_features']:
            self.checkmark(20, y)
            canvas_text(self, 85, y + 4, feature, 31)
            y += 90
        canvas_text(self, 682, 176, GUI_TEXT['info_title'], 38, anchor='n', justify='center')
        canvas_text(self, 382, 238, GUI_TEXT['info_body'], 17, fill=IND_WHITE, width=575)
        self.create_oval(px(1003), px(184), px(1183), px(364), outline=IND_RED, width=px(16))
        self.line(1030, 330, 1159, 210, color=IND_RED, width=14)
        canvas_text(self, 1093, 254, GUI_TEXT['info_blockchain'], 28, anchor='n', justify='center')
        self.create_oval(px(1003), px(402), px(1183), px(582), outline='#35c758', width=px(16))
        canvas_text(self, 1093, 449, GUI_TEXT['info_supply_amount'], 22, anchor='n', justify='center')
        canvas_text(self, 1093, 492, GUI_TEXT['info_supply_label'], 24, anchor='n', justify='center')
        canvas_text(self, 1093, 620, GUI_TEXT['info_inflation'], 43, anchor='n', justify='center')

    def draw_print_page(self):
        """Draw the paper-bill printing workflow shell."""

        # Left and right panels map to the available-bills list and print queue.
        self.rect(
            PRINT_LEFT_PANEL_X,
            PRINT_PANEL_Y,
            PRINT_LEFT_PANEL_X + PRINT_LEFT_PANEL_WIDTH,
            PRINT_PANEL_BOTTOM,
            fill='#101414',
            outline='#333c3b',
            width=1,
        )
        self.rect(
            PRINT_RIGHT_PANEL_X,
            PRINT_PANEL_Y,
            PRINT_RIGHT_PANEL_X + PRINT_RIGHT_PANEL_WIDTH,
            PRINT_PANEL_BOTTOM,
            fill='#101414',
            outline='#333c3b',
            width=1,
        )
        canvas_text(self, PRINT_AVAILABLE_X, PRINT_PANEL_Y + 30, GUI_TEXT['print_available_label'], 23, weight='bold')
        self.line(
            PRINT_AVAILABLE_X,
            PRINT_PANEL_Y + 86,
            PRINT_LEFT_PANEL_X + PRINT_LEFT_PANEL_WIDTH - 24,
            PRINT_PANEL_Y + 86,
            color='#333c3b',
            width=1,
        )
        canvas_text(self, PRINT_QUEUE_X, PRINT_PANEL_Y + 30, GUI_TEXT['print_queue_label'], 23, weight='bold')
        self.rect(
            PRINT_QUEUE_X,
            PRINT_QUEUE_LIST_Y,
            PRINT_QUEUE_X + PRINT_QUEUE_LIST_WIDTH,
            PRINT_QUEUE_LIST_Y + PRINT_QUEUE_LIST_HEIGHT,
            fill='#070909',
            outline='#48504f',
            width=1,
        )
        self.line(
            PRINT_QUEUE_X,
            PRINT_PANEL_Y + 238,
            PRINT_RIGHT_PANEL_X + PRINT_RIGHT_PANEL_WIDTH - 24,
            PRINT_PANEL_Y + 238,
            color='#333c3b',
            width=1,
        )
        canvas_text(self, PRINT_QUEUE_X, PRINT_OUTPUT_LABEL_Y, 'Output', 16, weight='bold')
        canvas_text(self, PRINT_QUEUE_X + 210, PRINT_OUTPUT_FULL_Y + 2, '6 per sheet', 14,
                    fill=IND_MUTED)
        canvas_text(self, PRINT_QUEUE_X + 210, PRINT_OUTPUT_QR_Y + 2, 'backup print', 14,
                    fill=IND_PENDING)
        self.rect(
            PRINT_PAGES_X,
            PRINT_PAGES_Y,
            PRINT_PAGES_X + PRINT_PAGES_WIDTH,
            PRINT_PAGES_Y + PRINT_PAGES_HEIGHT,
            fill='#090c0c',
            outline='#333c3b',
            width=1,
        )
        self.rect(
            PRINT_ACTION_STRIP_X,
            PRINT_ACTION_STRIP_Y,
            PRINT_ACTION_STRIP_X + PRINT_ACTION_STRIP_WIDTH,
            PRINT_ACTION_STRIP_Y + PRINT_ACTION_STRIP_HEIGHT,
            fill='#090c0c',
            outline='#333c3b',
            width=1,
        )
        # Bottom strip contains the PDF action, delayed charge action, and status.
        self.rect(
            PRINT_ACTION_STRIP_X + 24,
            PRINT_ACTION_STRIP_Y + 20,
            PRINT_ACTION_STRIP_X + 66,
            PRINT_ACTION_STRIP_Y + 72,
            fill=IND_WHITE,
            outline=IND_WHITE,
            width=1,
        )
        for row in range(2):
            for column in range(2):
                x = PRINT_ACTION_STRIP_X + 31 + column * 14
                y = PRINT_ACTION_STRIP_Y + 28 + row * 20
                self.rect(x, y, x + 10, y + 14, fill='#d7eadf', outline='#8db8a0', width=1)

    def draw_wallet(self):
        self.line(825, 151, 825, APP_BASE_HEIGHT)
        canvas_text(self, 1020, 138 + WALLET_SEND_Y_OFFSET, GUI_TEXT['wallet_send_title'], 30, anchor='n',
                    justify='center')
        canvas_text(self, 852, 176 + WALLET_SEND_Y_OFFSET, GUI_TEXT['wallet_receiver_label'], 22)
        canvas_text(self, 852, 257 + WALLET_SEND_Y_OFFSET, GUI_TEXT['wallet_amount_label'], 22)
        canvas_text(self, 1024, 420, GUI_TEXT['wallet_receive_title'], 30, anchor='n', justify='center')

    def draw_settings(self):
        self.rect(
            SETTINGS_PANEL_X,
            SETTINGS_PANEL_Y,
            SETTINGS_PANEL_RIGHT,
            SETTINGS_PANEL_BOTTOM,
            fill='#070707',
            outline=IND_WHITE,
            width=1,
        )

        def field_label(x, y, label, size=18):
            canvas_text(self, x, y, label, size, fill=IND_MUTED)

        def separator(y):
            self.line(SETTINGS_CONTENT_X, y, SETTINGS_CONTENT_RIGHT, y, color='#343c3a', width=1)

        if settings_active_tab == SETTINGS_TAB_NETWORK:
            field_label(SETTINGS_ROW_COLS[0], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_network'])
            field_label(SETTINGS_ROW_COLS[1], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_node_port'])
            field_label(SETTINGS_ROW_COLS[2], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_timeout'])
            separator(SETTINGS_DIVIDER_Y)
            field_label(SETTINGS_CONTENT_X, SETTINGS_BOTTOM_LABEL_Y, GUI_TEXT['settings_dns_seeds'])
            field_label(548, SETTINGS_BOTTOM_LABEL_Y, GUI_TEXT['settings_peer_servers'])
            field_label(928, SETTINGS_BOTTOM_LABEL_Y, 'Diagnostics')
        elif settings_active_tab == SETTINGS_TAB_BILL_SAFETY:
            field_label(SETTINGS_ROW_COLS[0], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_finality'])
            field_label(SETTINGS_ROW_COLS[1], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_require_log'])
            field_label(SETTINGS_ROW_COLS[2], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_security_profile'])
            field_label(SETTINGS_ROW_COLS[3], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_untrusted_genesis'])
            separator(SETTINGS_DIVIDER_Y)
            field_label(SETTINGS_TWO_COL_LEFT, SETTINGS_BOTTOM_LABEL_Y, 'Trusted issuer keys')
            field_label(SETTINGS_TWO_COL_RIGHT, SETTINGS_BOTTOM_LABEL_Y, 'Trusted manifest hashes')
        elif settings_active_tab == SETTINGS_TAB_TRANSPARENCY:
            field_label(SETTINGS_TWO_COL_LEFT, SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_operator_url'])
            field_label(SETTINGS_TWO_COL_RIGHT, SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_operator_key'])
            separator(SETTINGS_DIVIDER_Y)
            field_label(SETTINGS_CONTENT_X, SETTINGS_BOTTOM_LABEL_Y, 'Root domains', 18)
            field_label(354, SETTINGS_BOTTOM_LABEL_Y, 'Root mirrors', 18)
            field_label(620, SETTINGS_BOTTOM_LABEL_Y, 'Min', 18)
            field_label(706, SETTINGS_BOTTOM_LABEL_Y, 'Lag (s)', 18)
            field_label(804, SETTINGS_BOTTOM_LABEL_Y, 'Age (s)', 18)
            field_label(902, SETTINGS_BOTTOM_LABEL_Y, 'Gossip', 18)
            field_label(1010, SETTINGS_BOTTOM_LABEL_Y, 'Skew (s)', 18)
        elif settings_active_tab == SETTINGS_TAB_UPDATES:
            field_label(SETTINGS_CONTENT_X, SETTINGS_TOP_LABEL_Y, 'Domain')
            field_label(988, SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_update_startup'])
            separator(SETTINGS_DIVIDER_Y)
            field_label(SETTINGS_CONTENT_X, SETTINGS_BOTTOM_LABEL_Y, GUI_TEXT['settings_update_status'])

    def draw_sign_in_panel(self, generate=False):
        self.rect(282, 190, 933, 740, fill=IND_BLACK, outline=IND_WHITE, width=3)
        self.rect(282, 190, 933, 253, fill=IND_WHITE, outline=IND_WHITE, width=1)
        if generate:
            for label, y in (
                (GUI_TEXT['generate_wallet_address'], GENERATE_WALLET_ADDRESS_Y),
                (GUI_TEXT['generate_public_key'], GENERATE_WALLET_PUBLIC_KEY_Y),
                (GUI_TEXT['generate_private_key'], GENERATE_WALLET_PRIVATE_KEY_Y),
                (GUI_TEXT['generate_password'], GENERATE_WALLET_PASSWORD_Y),
            ):
                canvas_text(self, GENERATE_WALLET_FIELD_X, y - 36, label, 19, fill=IND_MUTED)
            for y in (
                GENERATE_WALLET_ADDRESS_Y + 58,
                GENERATE_WALLET_PUBLIC_KEY_Y + 58,
                GENERATE_WALLET_PRIVATE_KEY_Y + 58,
                GENERATE_WALLET_PASSWORD_Y + 58,
            ):
                self.line(348, y, 872, y, color='#242424', width=1)
        else:
            canvas_text(self, 607, 297, GUI_TEXT['signin_wallet_label'], 28, anchor='n', justify='center')
            canvas_text(self, 607, 442, GUI_TEXT['signin_password_label'], 28, anchor='n', justify='center')

    def draw_sign_in(self):
        self.draw_sign_in_panel(generate=False)

    def draw_generate_wallet(self):
        self.draw_sign_in_panel(generate=True)


class ModalCanvas(Canvas):
    """Renderer for small modal surfaces that still use the app canvas style."""

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
        if self.modal_name != 'claim':
            self.create_rectangle(px(1), px(1), px(self.width - 1), px(self.height - 1), outline=IND_WHITE,
                                  width=px(2), fill=self['bg'])
        if self.modal_name == 'claim':
            canvas_text(self, CLAIM_TITLE_X, CLAIM_TITLE_Y, GUI_TEXT['claim_title'], 36)
            canvas_text(
                self,
                CLAIM_LABEL_X,
                CLAIM_SERIAL_Y - CLAIM_MODAL_Y - CLAIM_LABEL_GAP_ABOVE_ENTRY,
                GUI_TEXT['claim_serial'],
                22,
                fill=IND_MUTED,
            )
            canvas_text(
                self,
                CLAIM_LABEL_X,
                CLAIM_PUBLIC_Y - CLAIM_MODAL_Y - CLAIM_LABEL_GAP_ABOVE_ENTRY,
                GUI_TEXT['claim_public'],
                22,
                fill=IND_MUTED,
            )
            canvas_text(
                self,
                CLAIM_LABEL_X,
                CLAIM_PRIVATE_Y - CLAIM_MODAL_Y - CLAIM_LABEL_GAP_ABOVE_ENTRY,
                GUI_TEXT['claim_private'],
                22,
                fill=IND_MUTED,
            )
            scanner_x = CLAIM_SCANNER_X - CLAIM_MODAL_X
            scanner_y = CLAIM_SCANNER_Y - CLAIM_MODAL_Y
            self.create_rectangle(
                px(scanner_x - 1),
                px(scanner_y - 1),
                px(scanner_x + CLAIM_SCANNER_WIDTH + 1),
                px(scanner_y + CLAIM_SCANNER_HEIGHT + 1),
                fill=IND_BLACK,
                outline=IND_WHITE,
            )
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
    font = app_font(font_size, font_weight)
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


def source_asset_image_path(folder, name):
    high_res_path = BASE_DIR / 'img' / folder / f'{name}4.png'
    if high_res_path.exists():
        return high_res_path
    return BASE_DIR / 'img' / folder / f'{name}.png'


class ScaledAssetButton(Button):
    """Image button that redraws bitmap assets at the active UI scale."""

    def __init__(self, master, image_path, command, bg=IND_BLACK):
        with Image.open(image_path) as source:
            self.source_image = source.convert('RGBA')
        self.current_image = None
        self.current_size = None
        super().__init__(
            master,
            command=command,
            bd=0,
            highlightthickness=0,
            cursor='hand2',
            bg=bg,
            activebackground=bg,
            relief=FLAT,
            overrelief=FLAT,
            padx=0,
            pady=0,
        )
        self.bind('<Configure>', self.resize_asset)

    def resize_asset(self, event=None):
        width = event.width if event else self.winfo_width()
        height = event.height if event else self.winfo_height()
        if width <= 1 or height <= 1 or self.current_size == (width, height):
            return
        self.current_size = (width, height)
        resized = self.source_image.resize((width, height), Image.Resampling.LANCZOS)
        self.current_image = ImageTk.PhotoImage(resized)
        self.config(image=self.current_image)


def make_asset_button(folder, name, command, fallback_text, font_size=18, bg=IND_BLACK, fg=IND_WHITE):
    try:
        return ScaledAssetButton(root, source_asset_image_path(folder, name), command, bg=bg)
    except Exception:
        return make_text_button(fallback_text, command, font_size=font_size, bg=bg, fg=fg, bd=1, relief=SOLID)


try:
    path = os.path.expanduser('~/wallet_folder_backup')
    try:
        os.mkdir(path)
    except Exception:
        log_ignored_exception()
    for wallet_path in runtime_json.iter_encrypted_wallet_files():
        shutil.copyfile(wallet_path, os.path.join(path, wallet_path.name))
except Exception:
    log_ignored_exception()
def update_wallet():
    """Return the active decrypted wallet lines, if a wallet is unlocked."""

    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        dr_w = runtime_json.read_decrypted_wallet_lines(wallet_path)
        num_lines_w = len(dr_w)
        return dr_w, num_lines_w


def wallet_is_unlocked():
    return any(
        wallet_path.name.startswith('wallet_decrypted')
        for wallet_path in runtime_json.iter_decrypted_wallet_files()
    )


def wallet_spendable_records():
    wallet_lines, _ = update_wallet()
    if not wallet_lines:
        return []
    wallet_address = wallet_lines[0].strip()
    store = ind_token.INDLocalStore()
    try:
        store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
    except Exception:
        log_ignored_exception()
    return wallet_services.spendable_wallet_records(wallet_address, store=store)


def wallet_pending_records():
    wallet_lines, _ = update_wallet()
    if not wallet_lines:
        return []
    wallet_address = wallet_lines[0].strip()
    store = ind_token.INDLocalStore()
    try:
        store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
    except Exception:
        log_ignored_exception()
    return wallet_services.pending_wallet_records(wallet_address, store=store)


def wallet_record_value(record):
    try:
        return int(record.get("value"))
    except Exception:
        try:
            return int(str(record.get("display_id", "")).split("x", 1)[0].lstrip("-"))
        except Exception:
            return 0


try:
    dr, num_lines = update_wallet()
except Exception:
    log_ignored_exception()

international_dollar = Text(root, font=app_font(45), bg='black', fg='white', bd=0, highlightthickness=0)
international_dollar.insert(1.0, GUI_TEXT['app_title'])
international_dollar.place(x=150 * reso, y=45 * reso, height=90 * reso, width=410 * reso)
international_dollar.config(state='disabled', cursor='arrow')


wa_sliced = None
qr_img = None
qr = None
address_txt = None
wallet_qr_mode = 'receive'
wallet_qr_warning_after_id = None
TRANSFER_WALLET_REVEAL_SECONDS = 5


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
        qr_resize = qr_make.resize((px(250), px(250)), Image.Resampling.LANCZOS)
        qr_img = ImageTk.PhotoImage(qr_resize)
        qr = Label(root, image=qr_img, bd=0, highlightthickness=0)
        address_txt = Text(root, font=app_font(19), bg='black', fg='white', bd=0,
                           highlightthickness=0)
        return True
    except Exception:
        return False


def cancel_wallet_qr_warning_timer():
    global wallet_qr_warning_after_id
    if wallet_qr_warning_after_id is None:
        return
    try:
        root.after_cancel(wallet_qr_warning_after_id)
    except Exception:
        log_ignored_exception()
    wallet_qr_warning_after_id = None


def reset_wallet_qr_mode():
    global wallet_qr_mode
    cancel_wallet_qr_warning_timer()
    wallet_qr_mode = 'receive'
    try:
        if qr is not None and qr_img is not None:
            qr.config(image=qr_img, text='', compound='none')
    except Exception:
        log_ignored_exception()
def transfer_wallet_warning_text(seconds_remaining):
    return f'SECURITY RISK\nQR in {seconds_remaining}s'

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
        log_ignored_exception()
root.after_idle(load_logo_image)
receiver = Entry(root, font=app_font(20), bg='light grey')
frame_w = Frame(root, bg='black')
root.resizable(False, False)


l2, l3, l4 = runtime_json.read_node_config()
l_operator = runtime_json.read_node_operator_enabled()

node_port_notice = Text(root, font=app_font(19), bg='black', fg='white', bd=0, highlightthickness=0)
node_port_notice.insert(1.0, f'Open TCP port {ind_settings.node_port()}\non your router/firewall')
node_port_notice.config(state='disabled', cursor='arrow')

ron_var = StringVar(root)
ron = OptionMenu(root, ron_var, 'YES', 'NO')
ron.config(font=app_font(16, 'bold'), cursor='hand2', bg=IND_BLACK, fg=IND_WHITE,
           activebackground=NODE_HEADER_BG, activeforeground=IND_WHITE, bd=0,
           highlightthickness=0, relief=FLAT)
rons = root.nametowidget(ron.menuname)
rons.config(font=app_font(16), bg=IND_BLACK, fg=IND_WHITE, activebackground=NODE_HEADER_BG,
            activeforeground=IND_WHITE)
ron_var.set(l3)

bak_var = StringVar(root)
bak = OptionMenu(root, bak_var, 'YES', 'NO')
bak.config(font=app_font(16, 'bold'), cursor='hand2', bg=IND_BLACK, fg=IND_WHITE,
           activebackground=NODE_HEADER_BG, activeforeground=IND_WHITE, bd=0,
           highlightthickness=0, relief=FLAT)
baks = root.nametowidget(bak.menuname)
baks.config(font=app_font(16), bg=IND_BLACK, fg=IND_WHITE, activebackground=NODE_HEADER_BG,
            activeforeground=IND_WHITE)
bak_var.set(l4)

transparency_operator_var = StringVar(root)
transparency_operator = OptionMenu(root, transparency_operator_var, 'NO', 'YES')
transparency_operator.config(font=app_font(16, 'bold'), cursor='hand2', bg=IND_BLACK, fg=IND_WHITE,
                             activebackground=NODE_HEADER_BG, activeforeground=IND_WHITE, bd=0,
                             highlightthickness=0, relief=FLAT)
transparency_operators = root.nametowidget(transparency_operator.menuname)
transparency_operators.config(font=app_font(16), bg=IND_BLACK, fg=IND_WHITE, activebackground=NODE_HEADER_BG,
                              activeforeground=IND_WHITE)
transparency_operator_var.set(l_operator)
transparency_operator_var.trace_add('write', lambda *_args: update_node_status_widgets())

try:
    USER_NAME = getpass.getuser()
    disk = os.path.realpath(__file__)[0]
    bat_path = disk + r':\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' % USER_NAME
except Exception:
    log_ignored_exception()
node_process = None
operator_process = None
node_console_entries = []
node_console_filter = 'all'
NODE_CONSOLE_MAX_ENTRIES = 500


def node_console_font(size=11):
    return ('Consolas', px(size))


def node_terminal_is_visible():
    try:
        return bool(node_terminal.winfo_ismapped() or node_terminal.place_info())
    except Exception:
        return False


def node_action_geometry():
    return {
        'x': NODE_ACTION_X * reso,
        'y': NODE_ACTION_Y * reso,
        'width': NODE_ACTION_WIDTH * reso,
        'height': NODE_ACTION_HEIGHT * reso,
    }


def count_known_node_peers():
    peers = set()
    try:
        peer_root = runtime_json.peer_root()
        for folder in ('1', '2'):
            path = Path(peer_root) / folder
            if path.exists():
                peers.update(item.name for item in path.iterdir() if item.is_file())
    except Exception:
        log_ignored_exception()
    try:
        peers.update(ind_settings.peer_ping_servers())
    except Exception:
        log_ignored_exception()
    return len(peers)


def node_operator_is_running():
    return operator_process is not None and operator_process.poll() is None


def update_node_status_widgets():
    if 'node_status_value' not in globals():
        return
    running = not runtime_json.get_kill_node()
    status_color = IND_GREEN if running else IND_RED
    node_status_value.config(text='RUNNING' if running else 'STOPPED', fg=status_color)
    if 'node_status_dot' in globals():
        node_status_dot.delete('all')
        node_status_dot.create_oval(px(2), px(2), px(12), px(12), fill=status_color, outline=status_color)
    node_port_value.config(text=str(ind_settings.node_port()))
    node_peer_value.config(text=str(count_known_node_peers()))
    node_event_value.config(text=str(len(node_console_entries)))
    if node_operator_is_running():
        operator_text = 'ON'
        operator_color = IND_GREEN
    elif transparency_operator_var.get() == 'YES':
        operator_text = 'READY'
        operator_color = IND_ORANGE
    else:
        operator_text = 'OFF'
        operator_color = IND_MUTED
    node_operator_value.config(text=operator_text, fg=operator_color)


def update_node_action_button():
    start_button.place_forget()
    end_button.place_forget()
    if not node_terminal_is_visible():
        return
    if runtime_json.get_kill_node():
        start_button.place(**node_action_geometry())
    else:
        end_button.place(**node_action_geometry())


def node_log_level_for_line(line):
    text = line.lower()
    if any(marker in text for marker in ('warning', 'warn ', 'rejected', 'invalid', 'rate_limited', 'failed', 'error')):
        return 'WARN'
    if any(marker in text for marker in ('listening', 'starting', 'started', 'spawned')):
        return 'INFO'
    return 'NODE'


def node_log_category_for_line(line):
    text = line.lower()
    if any(marker in text for marker in ('gossip', 'transfer', 'receipt', 'double-spend', 'equivocation')):
        return 'gossip'
    if any(marker in text for marker in ('peer', 'bootstrap', 'connection')):
        return 'peer'
    return 'node'


def format_node_console_entry(entry):
    return f"{entry['time']}  {entry['level']:<6}  {entry['message']}"


def filtered_node_console_entries():
    if node_console_filter == 'all':
        return list(node_console_entries)
    return [entry for entry in node_console_entries if entry['category'] == node_console_filter]


def refresh_node_filter_buttons():
    if 'node_console_filter_buttons' not in globals():
        return
    for filter_name, button_widget in node_console_filter_buttons.items():
        active = filter_name == node_console_filter
        button_widget.config(
            bg=IND_WHITE if active else NODE_HEADER_BG,
            fg=IND_BLACK if active else IND_WHITE,
            activebackground=IND_WHITE if active else NODE_HEADER_BG,
            activeforeground=IND_BLACK if active else IND_WHITE,
        )


def render_node_console():
    if 'node_console_log' not in globals():
        return
    node_console_log.config(state=NORMAL)
    node_console_log.delete(1.0, END)
    for entry in filtered_node_console_entries():
        node_console_log.insert(END, entry['time'] + '  ', ('muted',))
        node_console_log.insert(END, f"{entry['level']:<6}", (entry['tag'],))
        node_console_log.insert(END, '  ' + entry['message'] + '\n', ('body',))
    node_console_log.see(END)
    node_console_log.config(state=DISABLED)
    update_node_status_widgets()
    refresh_node_filter_buttons()


def append_node_console(level, message, category='node'):
    if message is None:
        return
    text = str(message).strip()
    if not text:
        return
    entry = {
        'time': datetime.now().strftime('%H:%M:%S'),
        'level': str(level).upper()[:6],
        'message': text,
        'category': category,
        'tag': category if category in {'peer', 'gossip'} else str(level).lower(),
    }
    node_console_entries.append(entry)
    if len(node_console_entries) > NODE_CONSOLE_MAX_ENTRIES:
        del node_console_entries[:len(node_console_entries) - NODE_CONSOLE_MAX_ENTRIES]
    try:
        if threading.current_thread() is threading.main_thread():
            render_node_console()
        else:
            root.after(0, render_node_console)
    except Exception:
        log_ignored_exception()
def set_node_console_filter(filter_name):
    global node_console_filter
    node_console_filter = filter_name
    render_node_console()


def clear_node_console():
    node_console_entries.clear()
    append_node_console('CLEAR', 'console cleared', 'node')


def copy_node_console():
    text = '\n'.join(format_node_console_entry(entry) for entry in filtered_node_console_entries())
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        append_node_console('COPY', 'console text copied to clipboard', 'node')
    except Exception as exc:
        append_node_console('WARN', 'copy failed: ' + error_detail(exc), 'node')


def copy_node_port():
    try:
        root.clipboard_clear()
        root.clipboard_append(str(ind_settings.node_port()))
        append_node_console('COPY', f'TCP port {ind_settings.node_port()} copied to clipboard', 'node')
    except Exception as exc:
        append_node_console('WARN', 'copy port failed: ' + error_detail(exc), 'node')


def read_node_process_output(process):
    pipe = process.stdout
    if pipe is None:
        return
    try:
        for line in iter(pipe.readline, ''):
            message = line.strip()
            if not message:
                continue
            append_node_console(
                node_log_level_for_line(message),
                message,
                node_log_category_for_line(message),
            )
    except Exception as exc:
        append_node_console('WARN', 'console reader stopped: ' + error_detail(exc), 'node')


def handle_node_process_exit(return_code):
    append_node_console('EXIT', f'node process exited with code {return_code}', 'node')
    if not runtime_json.get_kill_node():
        runtime_json.set_kill_node(True)
        append_node_console('WARN', 'node stopped unexpectedly', 'node')
    update_node_status_widgets()
    update_node_action_button()


def local_operator_settings():
    return node_services.local_operator_settings(BASE_DIR)


def apply_operator_environment():
    return node_services.apply_operator_environment(BASE_DIR)


def restore_operator_environment():
    node_services.restore_operator_environment()


def subprocess_kwargs(env=None):
    return node_services.subprocess_kwargs(BASE_DIR, env=env)


def start_transparency_operator_if_enabled():
    global operator_process
    if transparency_operator_var.get() != 'YES':
        restore_operator_environment()
        return os.environ.copy()
    env, mirror_dir = apply_operator_environment()
    Path(mirror_dir).mkdir(parents=True, exist_ok=True)
    if operator_process is None or operator_process.poll() is not None:
        try:
            append_node_console('OPER', 'starting local Merkle transparency log', 'node')
            operator_process = subprocess.Popen(
                node_services.local_operator_command(BASE_DIR, mirror_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **subprocess_kwargs(env),
            )
        except Exception:
            restore_operator_environment()
            raise
        time.sleep(1)
        append_node_console('OPER', f'local transparency log running on {LOCAL_OPERATOR_URL}', 'node')
    return env


def stop_transparency_operator():
    global operator_process
    if operator_process is None or operator_process.poll() is not None:
        operator_process = None
        restore_operator_environment()
        return
    operator_process.terminate()
    try:
        operator_process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        operator_process.kill()
    operator_process = None
    restore_operator_environment()
    append_node_console('OPER', 'local transparency log stopped', 'node')


def stop_node_process():
    global node_process
    if node_process is not None and node_process.poll() is None:
        try:
            append_node_console('STOP', 'terminate signal sent to node process', 'node')
            node_process.terminate()
        except Exception:
            log_ignored_exception()
    node_process = None


def startup_bat_contents(node_script):
    return node_services.startup_bat_contents(
        BASE_DIR,
        node_script,
        include_operator=transparency_operator_var.get() == 'YES',
    )


def start():
    """Start the local gossip node and optional transparency operator from the GUI."""

    runtime_json.write_node_config('NODE', ron_var.get(), bak_var.get(), transparency_operator_var.get())
    append_node_console(
        'SAVE',
        f'node config saved: startup={ron_var.get()} background={bak_var.get()} operator={transparency_operator_var.get()}',
        'node',
    )

    if ron_var.get() == 'YES':
        try:
            file_path = str(BASE_DIR / 'node_client.py')
            with open(bat_path + '\\' + 'ind_node.bat', 'w+') as bat_file:
                bat_file.write(startup_bat_contents(file_path))
            append_node_console('START', 'startup launcher updated', 'node')
        except Exception:
            log_ignored_exception()
            append_node_console('WARN', 'startup launcher could not be updated', 'node')

    runtime_json.set_kill_node(False)
    append_node_console('START', 'launch requested from GUI', 'node')
    update_node_status_widgets()
    update_node_action_button()

    # Run the gossip node as a child process so the GUI can keep updating.
    def subp():
        global node_process
        try:
            env = start_transparency_operator_if_enabled()
            env['PYTHONUNBUFFERED'] = '1'
            node_process = subprocess.Popen(
                [sys.executable, '-u', str(BASE_DIR / 'node_client.py')],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                **subprocess_kwargs(env),
            )
            append_node_console('NODE', f'spawned node_client.py pid {node_process.pid}', 'node')
            threading.Thread(target=read_node_process_output, args=(node_process,), daemon=True).start()
            return_code = node_process.wait()
            root.after(0, lambda code=return_code: handle_node_process_exit(code))
        except Exception as exc:
            runtime_json.set_kill_node(True)
            append_node_console('ERROR', 'node start failed: ' + error_detail(exc), 'node')
            root.after(0, update_node_status_widgets)
            root.after(0, update_node_action_button)
    threading.Thread(target=subp).start()
    time.sleep(0.5)

    def thrd2():
        # Peer discovery is delayed until the node has had a moment to bind its socket.
        time.sleep(5)
        try:
            for _ in range(3):
                sender_node.update_ip_list()
            append_node_console('PEER', 'bootstrap peer cache refresh requested', 'peer')
        except Exception as exc:
            append_node_console('WARN', 'peer refresh failed: ' + error_detail(exc), 'peer')

    threading.Thread(target=thrd2, daemon=True).start()

def end():
    runtime_json.set_kill_node(True)
    append_node_console('STOP', 'stop requested from GUI', 'node')
    stop_node_process()
    stop_transparency_operator()
    update_node_status_widgets()
    update_node_action_button()
    time.sleep(1)
b = Text(root, font=app_font(37), bg='black', fg='white', bd=0, highlightthickness=0)
balance_top = Text(root, font=app_font(26), bg='black', fg='white', bd=0, highlightthickness=0)

start_button = make_asset_button('different_buttons', 'start', start, 'Start', font_size=32, bg=IND_GREEN)
end_button = make_asset_button('different_buttons', 'end', end, 'End', font_size=32, bg=IND_RED)

node_status_dot = Canvas(root, width=px(14), height=px(14), bg=NODE_PANEL_BG, bd=0, highlightthickness=0)
node_status_title = Label(root, text='Node status', font=app_font(20, 'bold'), bg=NODE_PANEL_BG,
                          fg=IND_WHITE, bd=0, highlightthickness=0, anchor='w')
node_status_value = Label(root, font=app_font(18, 'bold'), bg=NODE_PANEL_BG, fg=IND_RED, bd=0,
                          highlightthickness=0, anchor='w')
node_port_label = Label(root, text='TCP', font=app_font(15), bg=NODE_CHIP_BG, fg=IND_MUTED, bd=0,
                        highlightthickness=0, anchor='w')
node_port_value = Label(root, font=app_font(16), bg=NODE_CHIP_BG, fg='#5dd7ff', bd=0,
                        highlightthickness=0, anchor='e')
node_peer_label = Label(root, text='Peers', font=app_font(15), bg=NODE_CHIP_BG, fg=IND_MUTED, bd=0,
                        highlightthickness=0, anchor='w')
node_peer_value = Label(root, font=app_font(16), bg=NODE_CHIP_BG, fg=IND_WHITE, bd=0,
                        highlightthickness=0, anchor='e')
node_event_label = Label(root, text='Events', font=app_font(15), bg=NODE_CHIP_BG, fg=IND_MUTED, bd=0,
                         highlightthickness=0, anchor='w')
node_event_value = Label(root, font=app_font(16), bg=NODE_CHIP_BG, fg=IND_ORANGE, bd=0,
                         highlightthickness=0, anchor='e')
node_operator_label = Label(root, text='Operator', font=app_font(15), bg=NODE_CHIP_BG, fg=IND_MUTED, bd=0,
                            highlightthickness=0, anchor='w')
node_operator_value = Label(root, font=app_font(16), bg=NODE_CHIP_BG, fg=IND_MUTED, bd=0,
                            highlightthickness=0, anchor='e')
node_class_value = Label(root, text='NODE', font=app_font(18), bg=IND_BLACK, fg='#5dd7ff', bd=0,
                         highlightthickness=0, anchor='e')
node_console_log = Text(
    root,
    font=node_console_font(11),
    bg=NODE_CONSOLE_BG,
    fg=IND_WHITE,
    insertbackground=IND_WHITE,
    bd=0,
    highlightthickness=0,
    wrap='word',
    padx=14 * reso,
    pady=10 * reso,
)
node_console_scrollbar = Scrollbar(root, command=node_console_log.yview, bd=0, highlightthickness=0)
node_console_log.config(yscrollcommand=node_console_scrollbar.set, state=DISABLED)
node_console_log.tag_config('muted', foreground='#7f8b86')
node_console_log.tag_config('body', foreground=IND_WHITE)
node_console_log.tag_config('ready', foreground=IND_GREEN)
node_console_log.tag_config('start', foreground=IND_GREEN)
node_console_log.tag_config('save', foreground=IND_GREEN)
node_console_log.tag_config('copy', foreground=IND_GREEN)
node_console_log.tag_config('clear', foreground=IND_MUTED)
node_console_log.tag_config('node', foreground='#5dd7ff')
node_console_log.tag_config('info', foreground=IND_WHITE)
node_console_log.tag_config('peer', foreground='#5dd7ff')
node_console_log.tag_config('gossip', foreground=IND_ORANGE)
node_console_log.tag_config('warn', foreground=IND_ORANGE)
node_console_log.tag_config('error', foreground=IND_RED)
node_console_log.tag_config('exit', foreground=IND_MUTED)
node_console_log.tag_config('stop', foreground=IND_RED)
node_console_log.tag_config('oper', foreground=IND_GREEN)

node_copy_port_button = make_text_button('Copy port', copy_node_port, font_size=16, bg=IND_BLACK,
                                         fg=IND_WHITE, bd=1, relief=SOLID)
node_console_copy_button = make_text_button('Copy', copy_node_console, font_size=16, bg=NODE_HEADER_BG,
                                            fg=IND_WHITE, bd=1, relief=SOLID)
node_console_clear_button = make_text_button('Clear', clear_node_console, font_size=16, bg=NODE_HEADER_BG,
                                             fg=IND_WHITE, bd=1, relief=SOLID)
node_console_filter_buttons = {
    'all': make_text_button('All', lambda: set_node_console_filter('all'), font_size=16,
                            bg=IND_WHITE, fg=IND_BLACK, bd=1, relief=SOLID),
    'node': make_text_button('Node', lambda: set_node_console_filter('node'), font_size=16,
                             bg=NODE_HEADER_BG, fg=IND_WHITE, bd=1, relief=SOLID),
    'gossip': make_text_button('Gossip', lambda: set_node_console_filter('gossip'), font_size=16,
                               bg=NODE_HEADER_BG, fg=IND_WHITE, bd=1, relief=SOLID),
    'peer': make_text_button('Peer', lambda: set_node_console_filter('peer'), font_size=16,
                             bg=NODE_HEADER_BG, fg=IND_WHITE, bd=1, relief=SOLID),
}
node_terminal_widgets = (
    node_status_dot,
    node_status_title,
    node_status_value,
    node_port_label,
    node_port_value,
    node_peer_label,
    node_peer_value,
    node_event_label,
    node_event_value,
    node_operator_label,
    node_operator_value,
    node_class_value,
    ron,
    bak,
    transparency_operator,
    node_copy_port_button,
    node_console_log,
    node_console_scrollbar,
    node_console_copy_button,
    node_console_clear_button,
    *node_console_filter_buttons.values(),
)


def hide_node_terminal_widgets():
    for widget in node_terminal_widgets:
        widget.place_forget()


def place_node_terminal_controls():
    node_terminal.place(x=0, y=0)
    update_node_status_widgets()
    node_status_title.place(x=66 * reso, y=220 * reso, width=112 * reso, height=36 * reso)
    node_status_dot.place(x=184 * reso, y=231 * reso, width=14 * reso, height=14 * reso)
    node_status_value.place(x=206 * reso, y=220 * reso, width=90 * reso, height=36 * reso)
    node_port_label.place(x=314 * reso, y=222 * reso, width=44 * reso, height=26 * reso)
    node_port_value.place(x=368 * reso, y=222 * reso, width=40 * reso, height=26 * reso)
    node_peer_label.place(x=444 * reso, y=222 * reso, width=44 * reso, height=26 * reso)
    node_peer_value.place(x=496 * reso, y=222 * reso, width=18 * reso, height=26 * reso)
    node_event_label.place(x=554 * reso, y=222 * reso, width=58 * reso, height=26 * reso)
    node_event_value.place(x=622 * reso, y=222 * reso, width=18 * reso, height=26 * reso)
    node_operator_label.place(x=676 * reso, y=222 * reso, width=68 * reso, height=26 * reso)
    node_operator_value.place(x=746 * reso, y=222 * reso, width=40 * reso, height=26 * reso)
    node_class_value.place(x=222 * reso, y=368 * reso, width=150 * reso, height=36 * reso)
    ron.place(x=222 * reso, y=438 * reso, width=150 * reso, height=32 * reso)
    bak.place(x=222 * reso, y=508 * reso, width=150 * reso, height=32 * reso)
    transparency_operator.place(x=222 * reso, y=578 * reso, width=150 * reso, height=32 * reso)
    node_copy_port_button.place(x=302 * reso, y=652 * reso, width=70 * reso, height=26 * reso)
    node_console_filter_buttons['all'].place(x=746 * reso, y=314 * reso, width=52 * reso, height=26 * reso)
    node_console_filter_buttons['node'].place(x=806 * reso, y=314 * reso, width=70 * reso, height=26 * reso)
    node_console_filter_buttons['gossip'].place(x=884 * reso, y=314 * reso, width=82 * reso, height=26 * reso)
    node_console_filter_buttons['peer'].place(x=974 * reso, y=314 * reso, width=64 * reso, height=26 * reso)
    node_console_copy_button.place(x=1046 * reso, y=314 * reso, width=58 * reso, height=26 * reso)
    node_console_clear_button.place(x=1112 * reso, y=314 * reso, width=58 * reso, height=26 * reso)
    node_console_log.place(x=434 * reso, y=370 * reso, width=724 * reso, height=370 * reso)
    node_console_scrollbar.place(x=1158 * reso, y=370 * reso, width=14 * reso, height=370 * reso)
    update_node_action_button()
    render_node_console()


append_node_console('READY', 'node terminal ready; waiting for start', 'node')


def make_settings_text(font_size=15):
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


def make_settings_entry(font_size=17):
    return Entry(
        root,
        font=app_font(font_size),
        bg='light grey',
        fg=IND_BLACK,
        insertbackground=IND_BLACK,
        bd=0,
        highlightthickness=0,
    )


def make_settings_option(variable, *values, font_size=17):
    option = OptionMenu(root, variable, *values)
    option.config(font=app_font(font_size, 'bold'), cursor='hand2', bg=IND_BLACK, fg=IND_WHITE,
                  activebackground=IND_WHITE, activeforeground=IND_BLACK, highlightthickness=0)
    menu = root.nametowidget(option.menuname)
    menu.config(font=app_font(15), bg=IND_BLACK, fg=IND_WHITE, activebackground=IND_WHITE,
                activeforeground=IND_BLACK)
    return option


def _text_lines(widget):
    return [line.strip() for line in widget.get('1.0', END).splitlines() if line.strip()]


def _set_text_lines(widget, lines):
    widget.config(state='normal')
    widget.delete('1.0', END)
    widget.insert('1.0', '\n'.join(lines))


def _set_entry_value(widget, value):
    widget.delete(0, END)
    widget.insert(0, str(value))


def _set_node_port_value(widget, settings):
    configured_port = int(settings.get('node_port') or 0)
    if configured_port == 0:
        _set_entry_value(widget, 'AUTO (%s)' % ind_settings.node_port(settings))
    else:
        _set_entry_value(widget, configured_port)


def _bool_label(value):
    return 'YES' if value else 'NO'


def _option_bool(variable):
    return variable.get().strip().upper() == 'YES'


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


def _set_update_status(message, color=IND_WHITE):
    settings_update_status.config(state='normal', fg=color)
    settings_update_status.delete('1.0', END)
    settings_update_status.insert('1.0', message)
    settings_update_status.config(state='disabled')


settings_peer_servers = make_settings_text(15)
settings_dns_seed_hosts = make_settings_text(15)
settings_root_domains = make_settings_text(15)
settings_root_mirrors = make_settings_text(15)
settings_genesis_issuer_keys = make_settings_text(14)
settings_genesis_manifest_hashes = make_settings_text(14)
settings_operator_key = make_settings_text(14)
settings_node_port_entry = make_settings_entry(17)
settings_finality_entry = make_settings_entry(17)
settings_timeout_entry = make_settings_entry(17)
settings_operator_url_entry = make_settings_entry(17)
settings_root_lag_entry = make_settings_entry(17)
settings_min_mirrors_entry = make_settings_entry(17)
settings_max_current_root_age_entry = make_settings_entry(17)
settings_current_root_future_skew_entry = make_settings_entry(17)
settings_update_source_entry = make_settings_entry(18)
settings_status = make_settings_text(15)
settings_status.config(state='disabled')
settings_ping_status = make_settings_text(14)
settings_ping_status.config(state='disabled')
settings_update_status = make_settings_text(16)
settings_update_status.config(state='disabled')
settings_network_var = StringVar(root)
settings_network = make_settings_option(settings_network_var, 'MAINNET', 'TESTNET')
settings_require_log_var = StringVar(root)
settings_require_log = make_settings_option(settings_require_log_var, 'YES', 'NO')
settings_security_profile_var = StringVar(root)
settings_security_profile = make_settings_option(settings_security_profile_var, 'DEVELOPMENT', 'PRODUCTION')
settings_allow_untrusted_genesis_var = StringVar(root)
settings_allow_untrusted_genesis = make_settings_option(settings_allow_untrusted_genesis_var, 'NO', 'YES')
settings_root_gossip_var = StringVar(root)
settings_root_gossip = make_settings_option(settings_root_gossip_var, 'YES', 'NO')
settings_update_check_var = StringVar(root)
settings_update_check = make_settings_option(settings_update_check_var, 'YES', 'NO')


def load_security_settings_form():
    settings = ind_settings.load_security_settings(validate_production=False)
    _set_text_lines(settings_peer_servers, settings['peer_ping_servers'])
    _set_text_lines(settings_dns_seed_hosts, settings['dns_seed_hosts'])
    _set_text_lines(settings_root_domains, settings['trusted_root_domains'])
    _set_text_lines(settings_root_mirrors, settings['trusted_root_mirrors'])
    _set_text_lines(settings_genesis_issuer_keys, settings['trusted_genesis_issuer_keys'])
    _set_text_lines(settings_genesis_manifest_hashes, settings['trusted_genesis_manifest_hashes'])
    _set_text_lines(settings_operator_key, [settings['transparency_operator_public_key']])
    _set_node_port_value(settings_node_port_entry, settings)
    _set_entry_value(settings_finality_entry, settings['finality_buffer_seconds'])
    _set_entry_value(settings_timeout_entry, settings['peer_request_timeout_seconds'])
    _set_entry_value(settings_operator_url_entry, settings['transparency_operator_url'])
    _set_entry_value(settings_root_lag_entry, settings['max_root_lag_seconds'])
    _set_entry_value(settings_min_mirrors_entry, settings['min_root_mirrors'])
    _set_entry_value(settings_max_current_root_age_entry, settings['max_current_root_age_seconds'])
    _set_entry_value(settings_current_root_future_skew_entry, settings['current_root_future_skew_seconds'])
    _set_entry_value(settings_update_source_entry, settings['update_source'])
    settings_network_var.set(settings['network'].upper())
    settings_require_log_var.set(_bool_label(settings['require_transparency_log']))
    settings_security_profile_var.set(settings['security_profile'].upper())
    settings_allow_untrusted_genesis_var.set(_bool_label(settings['allow_untrusted_genesis']))
    settings_root_gossip_var.set(_bool_label(settings['transparency_root_gossip']))
    settings_update_check_var.set(_bool_label(settings['update_check_on_startup']))
    _set_settings_status('No unsaved changes.', IND_MUTED)
    _set_ping_status('Ready', IND_MUTED)
    _set_update_status('Ready to check for updates.')


def collect_security_settings_form():
    try:
        settings = ind_settings.load_security_settings(validate_production=False)
    except Exception:
        settings = ind_settings.default_settings()
    node_port_value = settings_node_port_entry.get().strip()
    if node_port_value.upper().startswith('AUTO'):
        node_port_value = '0'
    settings.update({
        'network': settings_network_var.get().strip().lower(),
        'node_port': node_port_value,
        'peer_ping_servers': _text_lines(settings_peer_servers),
        'dns_seed_hosts': _text_lines(settings_dns_seed_hosts),
        'trusted_root_domains': _text_lines(settings_root_domains),
        'trusted_root_mirrors': _text_lines(settings_root_mirrors),
        'trusted_genesis_issuer_keys': _text_lines(settings_genesis_issuer_keys),
        'trusted_genesis_manifest_hashes': _text_lines(settings_genesis_manifest_hashes),
        'transparency_operator_url': settings_operator_url_entry.get().strip(),
        'transparency_operator_public_key': '\n'.join(_text_lines(settings_operator_key)).strip(),
        'require_transparency_log': _option_bool(settings_require_log_var),
        'security_profile': settings_security_profile_var.get().strip().lower(),
        'allow_untrusted_genesis': _option_bool(settings_allow_untrusted_genesis_var),
        'min_root_mirrors': settings_min_mirrors_entry.get().strip(),
        'max_root_lag_seconds': settings_root_lag_entry.get().strip(),
        'max_current_root_age_seconds': settings_max_current_root_age_entry.get().strip(),
        'current_root_future_skew_seconds': settings_current_root_future_skew_entry.get().strip(),
        'transparency_root_gossip': _option_bool(settings_root_gossip_var),
        'finality_buffer_seconds': settings_finality_entry.get().strip(),
        'peer_request_timeout_seconds': settings_timeout_entry.get().strip(),
        'update_source': settings_update_source_entry.get().strip(),
        'update_check_on_startup': _option_bool(settings_update_check_var),
    })
    return settings


def save_security_settings_form(show_message=True):
    try:
        settings = ind_settings.save_security_settings(collect_security_settings_form())
        load_security_settings_form()
        if show_message:
            _set_settings_status(
                'Saved. Bills settle after %s seconds; %s Merkle mirror(s) required.'
                % (settings['finality_buffer_seconds'], settings['min_root_mirrors']),
                IND_GREEN,
            )
        return settings
    except Exception as exc:
        _set_settings_status('Save failed: ' + str(exc), IND_RED)
        return None


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


def _short_update_rev(rev):
    return rev[:12] if rev else 'unknown'


def run_manual_update_check():
    """Check the configured update source and offer an install when safe."""

    settings = save_security_settings_form(show_message=False)
    if settings is None:
        _set_update_status('Save failed; update not checked.', IND_RED)
        return
    settings_update_button.config(cursor='watch')
    _set_update_status('Checking %s...' % settings['update_source'], IND_MUTED)

    def worker():
        try:
            updater = importlib.import_module('ind.auto_update')
            info = updater.check_for_updates(BASE_DIR, manual=True)
        except Exception as exc:
            root.after(0, lambda exc=exc: finish_check_error(exc))
            return
        root.after(0, lambda: finish_check(updater, info))

    def finish_check_error(exc):
        settings_update_button.config(cursor='hand2')
        _set_update_status('Update check failed: ' + error_detail(exc), IND_RED)

    def finish_check(updater, info):
        settings_update_button.config(cursor='hand2')
        if not info.available:
            if info.error:
                _set_update_status('Update check failed: ' + info.error, IND_ORANGE)
            else:
                _set_update_status('Already up to date.', IND_GREEN)
            return

        details = (
            'Source: %s\nBranch: %s\nCurrent: %s\nLatest: %s'
            % (info.source, info.upstream_ref, _short_update_rev(info.local_rev), _short_update_rev(info.remote_rev))
        )
        if info.dirty:
            # Auto-update should not overwrite a checkout with local edits.
            messagebox.showwarning(
                'International Dollar update available',
                details + '\n\nLocal files have changes, so the update will not be installed automatically.',
            )
            _set_update_status('Update available, but local files have changes.', IND_ORANGE)
            return
        if info.ahead:
            # A locally ahead branch may contain unreleased work; leave it untouched.
            messagebox.showwarning(
                'International Dollar update available',
                details + '\n\nThis checkout has local commits that are not on the update branch.',
            )
            _set_update_status('Update available, but local branch is ahead.', IND_ORANGE)
            return
        if not messagebox.askyesno('International Dollar update available', details + '\n\nInstall this update now?'):
            _set_update_status('Update available. Install skipped.', IND_ORANGE)
            return
        settings_update_button.config(cursor='watch')
        _set_update_status('Installing update...')

        def install_worker():
            result = updater.install_update(BASE_DIR, info)
            root.after(0, lambda: finish_install(result))

        threading.Thread(target=install_worker, name='INDManualUpdateInstall', daemon=True).start()

    def finish_install(result):
        settings_update_button.config(cursor='hand2')
        if not result.success:
            _set_update_status('Update failed: ' + (result.error or 'unknown error'), IND_RED)
            messagebox.showerror('Update failed', result.error or 'The update could not be installed.')
            return
        summary = 'Updated from %s to %s.' % (_short_update_rev(result.old_rev), _short_update_rev(result.new_rev))
        _set_update_status(summary, IND_GREEN)
        if messagebox.askyesno('Update installed', summary + '\n\nRestart now to use the new version?'):
            restart_after_update()

    threading.Thread(target=worker, name='INDManualUpdateCheck', daemon=True).start()


settings_save_button = make_text_button('Save', save_security_settings_form, font_size=24, bg=IND_GREEN)
settings_reset_button = make_text_button('Reset', reset_security_settings_form, font_size=24, bg=IND_ORANGE)
settings_ping_button = make_text_button('Ping', ping_security_servers, font_size=22, bg=IND_BLACK,
                                        fg=IND_WHITE, bd=1, relief=SOLID)
settings_update_button = make_text_button('Update', run_manual_update_check, font_size=24, bg=IND_GREEN)
settings_tab_buttons = {
    tab_key: make_text_button(label, lambda key=tab_key: set_settings_tab(key), font_size=22,
                              bg=IND_BLACK, fg=IND_WHITE, bd=1, relief=SOLID)
    for tab_key, label in SETTINGS_TABS
}
settings_widgets = (
    *settings_tab_buttons.values(),
    settings_network,
    settings_node_port_entry,
    settings_peer_servers,
    settings_dns_seed_hosts,
    settings_root_domains,
    settings_root_mirrors,
    settings_genesis_issuer_keys,
    settings_genesis_manifest_hashes,
    settings_operator_key,
    settings_finality_entry,
    settings_timeout_entry,
    settings_operator_url_entry,
    settings_root_lag_entry,
    settings_min_mirrors_entry,
    settings_max_current_root_age_entry,
    settings_current_root_future_skew_entry,
    settings_update_source_entry,
    settings_require_log,
    settings_security_profile,
    settings_allow_untrusted_genesis,
    settings_root_gossip,
    settings_update_check,
    settings_status,
    settings_ping_status,
    settings_update_status,
    settings_save_button,
    settings_reset_button,
    settings_ping_button,
    settings_update_button,
)


def redraw_settings_page():
    settings_page.delete('all')
    settings_page.draw()


def update_settings_tab_buttons():
    for tab_key, button_widget in settings_tab_buttons.items():
        active = tab_key == settings_active_tab
        button_widget.config(
            bg=IND_WHITE if active else IND_BLACK,
            fg=IND_BLACK if active else IND_WHITE,
            activebackground=IND_WHITE if active else IND_BLACK,
            activeforeground=IND_BLACK if active else IND_WHITE,
        )


def hide_settings_widgets():
    for widget in settings_widgets:
        widget.place_forget()


def place_settings_common_widgets():
    for index, (tab_key, _label) in enumerate(SETTINGS_TABS):
        place_scaled(
            settings_tab_buttons[tab_key],
            SETTINGS_TAB_X + index * (SETTINGS_TAB_WIDTH + SETTINGS_TAB_GAP),
            SETTINGS_TAB_Y,
            SETTINGS_TAB_WIDTH,
            SETTINGS_TAB_HEIGHT,
        )
    place_scaled(settings_status, SETTINGS_TAB_X, SETTINGS_FOOTER_Y, 742, 38)
    place_scaled(settings_reset_button, 834, SETTINGS_FOOTER_Y, 148, 38)
    place_scaled(settings_save_button, 1004, SETTINGS_FOOTER_Y, 148, 38)
    update_settings_tab_buttons()


def place_settings_tab_widgets():
    if settings_active_tab == SETTINGS_TAB_NETWORK:
        place_scaled(settings_network, SETTINGS_ROW_COLS[0], SETTINGS_TOP_FIELD_Y, 230, 38)
        place_scaled(settings_node_port_entry, SETTINGS_ROW_COLS[1], SETTINGS_TOP_FIELD_Y, 230, 38)
        place_scaled(settings_timeout_entry, SETTINGS_ROW_COLS[2], SETTINGS_TOP_FIELD_Y, 120, 38)
        place_scaled(settings_dns_seed_hosts, SETTINGS_CONTENT_X, SETTINGS_BOTTOM_FIELD_Y, 430, 190)
        place_scaled(settings_peer_servers, 548, SETTINGS_BOTTOM_FIELD_Y, 350, 190)
        place_scaled(settings_ping_button, 928, SETTINGS_BOTTOM_FIELD_Y, 104, 40)
        place_scaled(settings_ping_status, 1052, SETTINGS_BOTTOM_FIELD_Y, 82, 40)
    elif settings_active_tab == SETTINGS_TAB_BILL_SAFETY:
        place_scaled(settings_finality_entry, SETTINGS_ROW_COLS[0], SETTINGS_TOP_FIELD_Y, 130, 38)
        place_scaled(settings_require_log, SETTINGS_ROW_COLS[1], SETTINGS_TOP_FIELD_Y, 110, 38)
        place_scaled(settings_security_profile, SETTINGS_ROW_COLS[2], SETTINGS_TOP_FIELD_Y, 160, 38)
        place_scaled(settings_allow_untrusted_genesis, SETTINGS_ROW_COLS[3], SETTINGS_TOP_FIELD_Y, 110, 38)
        place_scaled(settings_genesis_issuer_keys, SETTINGS_TWO_COL_LEFT, SETTINGS_BOTTOM_FIELD_Y,
                     SETTINGS_TWO_COL_WIDTH, 190)
        place_scaled(settings_genesis_manifest_hashes, SETTINGS_TWO_COL_RIGHT, SETTINGS_BOTTOM_FIELD_Y,
                     SETTINGS_TWO_COL_WIDTH, 190)
    elif settings_active_tab == SETTINGS_TAB_TRANSPARENCY:
        place_scaled(settings_operator_url_entry, SETTINGS_TWO_COL_LEFT, SETTINGS_TOP_FIELD_Y,
                     SETTINGS_TWO_COL_WIDTH, 38)
        place_scaled(settings_operator_key, SETTINGS_TWO_COL_RIGHT, SETTINGS_TOP_FIELD_Y,
                     SETTINGS_TWO_COL_WIDTH, 38)
        place_scaled(settings_root_domains, SETTINGS_CONTENT_X, SETTINGS_BOTTOM_FIELD_Y, 240, 142)
        place_scaled(settings_root_mirrors, 354, SETTINGS_BOTTOM_FIELD_Y, 240, 142)
        place_scaled(settings_min_mirrors_entry, 620, SETTINGS_BOTTOM_FIELD_Y, 64, 38)
        place_scaled(settings_root_lag_entry, 706, SETTINGS_BOTTOM_FIELD_Y, 76, 38)
        place_scaled(settings_max_current_root_age_entry, 804, SETTINGS_BOTTOM_FIELD_Y, 76, 38)
        place_scaled(settings_root_gossip, 902, SETTINGS_BOTTOM_FIELD_Y, 86, 38)
        place_scaled(settings_current_root_future_skew_entry, 1010, SETTINGS_BOTTOM_FIELD_Y, 70, 38)
    elif settings_active_tab == SETTINGS_TAB_UPDATES:
        place_scaled(settings_update_source_entry, SETTINGS_CONTENT_X, SETTINGS_TOP_FIELD_Y, 628, 40)
        place_scaled(settings_update_button, 744, SETTINGS_TOP_FIELD_Y, 180, 40)
        place_scaled(settings_update_check, 988, SETTINGS_TOP_FIELD_Y, 110, 40)
        place_scaled(settings_update_status, SETTINGS_CONTENT_X, SETTINGS_BOTTOM_FIELD_Y, 998, 190)


def refresh_settings_widgets():
    redraw_settings_page()
    hide_settings_widgets()
    place_settings_common_widgets()
    place_settings_tab_widgets()


def set_settings_tab(tab_key):
    global settings_active_tab
    if tab_key not in dict(SETTINGS_TABS):
        return
    settings_active_tab = tab_key
    refresh_settings_widgets()


a = Entry(root, font=app_font(20), bg='light grey')
receiver_history = Text(root, font=app_font(18), bg='black', fg='light grey', bd=0, highlightthickness=0)
receiver_history.bind("<Key>", lambda e: "break")

def write_transfer_announcement(wallet_lines, wallet_bill_line, recipient_address):
    """Spend one locally stored bill and queue its transfer announcement."""

    return wallet_services.spend_wallet_bill(wallet_lines, wallet_bill_line, recipient_address)

address_to_charge = []


def print_selected_bill_ids():
    return list(filter(None, selected_bills_text.get(1.0, END).splitlines()))


def print_bill_value_from_id(display_id):
    try:
        return int(str(display_id).split('x', 1)[0])
    except (TypeError, ValueError):
        return 0


def print_selection_total():
    return sum(print_bill_value_from_id(display_id) for display_id in print_selected_bill_ids())


def print_estimated_page_count(count=None):
    count = len(print_selected_bill_ids()) if count is None else count
    if count <= 0:
        return 0
    if print_output_mode.get() == 'qr':
        return (count + 23) // 24
    return ((count + print_tools.BILLS_PER_PRINT_PAGE - 1) // print_tools.BILLS_PER_PRINT_PAGE) * 2


def set_print_status(message, color=IND_MUTED):
    try:
        print_status_label.config(text=message, fg=color)
    except Exception:
        log_ignored_exception()
def set_print_charge_ready(ready):
    try:
        charge_bills_button.config(
            state=NORMAL if ready else DISABLED,
            text='Charge bills' if ready else 'Charge after PDF',
            cursor='hand2' if ready else 'arrow',
        )
    except Exception:
        log_ignored_exception()
def refresh_print_summary(event=None):
    try:
        count = len(print_selected_bill_ids())
        total = print_selection_total()
        print_summary_label.config(text=f'{total}$\n{count} bill' + ('' if count == 1 else 's'))
        page_count = print_estimated_page_count(count)
        print_pages_label.config(text=f'{page_count} page' + ('' if page_count == 1 else 's') + '\nestimated')
        print_full_radio.config(fg=IND_WHITE if print_output_mode.get() == 'full' else IND_MUTED)
        print_qr_radio.config(fg=IND_WHITE if print_output_mode.get() == 'qr' else IND_MUTED)
    except Exception:
        log_ignored_exception()
    try:
        if event is not None and event.widget is selected_bills_text:
            selected_bills_text.edit_modified(False)
    except Exception:
        log_ignored_exception()
def reset_print_actions():
    button_print.config(state=NORMAL, cursor='hand2')
    set_print_charge_ready(False)
    set_print_status('PDF is generated first. Charge sends funds to the printed paper-wallet addresses after printing.')


def select_all_print_bills():
    lines = list(filter(None, all_bills_text.get(1.0, END).splitlines()))
    selected_bills_text.delete(1.0, END)
    selected_bills_text.insert(1.0, '\n'.join(lines))
    refresh_print_summary()


def text_line_at_event(widget, event):
    index = widget.index(f'@{event.x},{event.y}')
    return widget.get(f'{index} linestart', f'{index} lineend').strip()


def add_print_bill_from_available(event):
    display_id = text_line_at_event(all_bills_text, event)
    if display_id and display_id not in print_selected_bill_ids():
        if len(selected_bills_text.get(1.0, END).strip()):
            selected_bills_text.insert(END, '\n')
        selected_bills_text.insert(END, display_id)
        refresh_print_summary()
    return 'break'


def remove_print_bill_from_queue(event):
    index = selected_bills_text.index(f'@{event.x},{event.y}')
    if text_line_at_event(selected_bills_text, event):
        selected_bills_text.delete(f'{index} linestart', f'{index} lineend +1c')
        refresh_print_summary()
    return 'break'


def on_print_selection_modified(event):
    refresh_print_summary(event)


def print_selected_output():
    """Route the print action to the selected paper-bill output format."""

    if print_output_mode.get() == 'qr':
        print_only_qr()
    else:
        print_bills()


def charge_bills():
    """Send selected printed bills to the generated paper-wallet addresses."""

    root.config(cursor='watch')
    charge_bills_button.config(cursor='watch')
    sent_count = 0
    errors = []
    charge_succeeded = False
    try:
        list_sm = print_selected_bill_ids()
        if not list_sm:
            raise ValueError("No printed bills are selected.")
        if len(address_to_charge) < len(list_sm):
            raise ValueError("Printed bill addresses are missing. Print the bills again before charging them.")
        for wallet_path in runtime_json.iter_decrypted_wallet_files():
            if wallet_path.name.startswith('wallet_decrypted'):
                of = runtime_json.read_decrypted_wallet_lines(wallet_path)
                updated = []
                for wb in of:
                    parts = wb.split()
                    if parts and parts[0] in list_sm:
                        index_item = list_sm.index(parts[0])
                        try:
                            state = write_transfer_announcement(of, wb, address_to_charge[index_item])
                            if not state:
                                raise RuntimeError("bill is not spendable or is not settled")
                            updated.append('-' + parts[0] + ' ' + str(state.sequence) + ' ' + str(int(time.time())) + '\n')
                            sent_count += 1
                        except Exception as exc:
                            errors.append(f"{parts[0]}: {error_detail(exc)}")
                            updated.append(wb)
                    else:
                        updated.append(wb)
                runtime_json.write_decrypted_wallet_lines(wallet_path, updated)
        if sent_count:
            sender_node.send_bills()
        if errors:
            raise RuntimeError("\n".join(errors))
        charge_succeeded = True
        selected_bills_text.delete(1.0, END)
        address_to_charge.clear()
        set_print_status('Printed bills charged and queued for gossip.', IND_GREEN)
    except Exception as exc:
        show_error_popup('Charge bills failed', exc)
        set_print_status('Charge failed. Review the selected bills and try again.', IND_ORANGE)
    finally:
        root.config(cursor='arrow')
        refresh_wallet_view()
        charge_bills_button.config(cursor='hand2')
        if charge_succeeded:
            set_print_charge_ready(False)
        refresh_print_summary()

def selected_print_bill_sequences():
    if len(selected_bills_text.get(1.0, END)) <= 2:
        set_print_status('Select at least one bill before creating a PDF.', IND_ORANGE)
        return None
    list_bills = print_selected_bill_ids()
    records_by_display_id = {record["display_id"]: record for record in wallet_spendable_records()}
    list_bills_2 = [
        (display_id, str(int(records_by_display_id[display_id]["sequence"]) + 1))
        for display_id in list_bills
        if display_id in records_by_display_id
    ]
    if not list_bills_2:
        set_print_status('None of the selected bills are currently spendable.', IND_ORANGE)
        return None
    return list_bills_2


def start_print_pdf_job(
    print_method_name,
    creating_status,
    error_title,
    opened_status,
    ready_status,
    extra_busy_buttons=(),
):
    """Run PDF generation off the Tk thread and unlock charging after a delay."""

    list_bills_2 = selected_print_bill_sequences()
    if list_bills_2 is None:
        return
    address_to_charge.clear()
    set_print_charge_ready(False)
    set_print_status(creating_status, IND_MUTED)
    root.config(cursor='watch')
    button_print.config(state=DISABLED, cursor='watch')
    for button_widget in extra_busy_buttons:
        button_widget.config(cursor='watch')

    def t():
        # The print tools open OS/PDF UI, so Tk state is restored through after().
        try:
            return_addr = getattr(print_tools, print_method_name)(list_bills_2)
            error = None
        except Exception as exc:
            return_addr = []
            error = exc

        def finish():
            root.config(cursor='arrow')
            button_print.config(state=NORMAL, cursor='hand2')
            for button_widget in extra_busy_buttons:
                button_widget.config(cursor='hand2')
            if error is not None:
                set_print_status('PDF creation failed.', IND_ORANGE)
                show_error_popup(error_title, error)
                return
            address_to_charge.extend(return_addr)
            set_print_status(opened_status)

            def enable_charge():
                # Charging is delayed so users have time to complete the print dialog first.
                set_print_charge_ready(True)
                set_print_status(ready_status, IND_ORANGE)

            root.after(60000, enable_charge)

        root.after(0, finish)

    threading.Thread(target=t, daemon=True).start()


def print_bills():
    """Create full paper-bill PDF output for the selected spendable bills."""

    start_print_pdf_job(
        'full_bill',
        'Creating full bill PDF...',
        'Print bills failed',
        'PDF opened. Print it first; Charge unlocks after the print window has time to finish.',
        'PDF should be ready. Charge bills after you have printed the paper copies.',
    )


def print_only_qr():
    """Create a QR-only paper-bill PDF containing private keys for offline custody."""

    start_print_pdf_job(
        'only_qr',
        'Creating QR-only PDF...',
        'Print QR bills failed',
        'QR PDF opened. Print it first; Charge unlocks after the print window has time to finish.',
        'PDF should be ready. Charge bills after you have printed the QR copies.',
        extra_busy_buttons=(button_only_qr,),
    )


print_output_mode = StringVar(root, value='full')
button_print = make_text_button('Create PDF', print_selected_output, font_size=22, font_weight='bold', bg=IND_GREEN)
button_only_qr = make_text_button('QR only', print_only_qr, font_size=18, bg='#111616', fg=IND_WHITE, bd=1,
                                  relief=SOLID)
print_select_all_button = make_text_button('Select all', select_all_print_bills, font_size=15, font_weight='bold',
                                           bg='#0b1813', fg='#c9ffe3', bd=1, relief=SOLID)
all_bills_text = Text(
    root,
    font=app_font(16),
    bg='#101414',
    fg='#e6e6e6',
    insertbackground=IND_WHITE,
    bd=0,
    relief=FLAT,
    highlightthickness=0,
    highlightbackground='#101414',
    highlightcolor=IND_GREEN,
    padx=0,
    pady=0,
    wrap='none',
)
selected_bills_text = Text(
    root,
    font=app_font(16),
    bg='#070909',
    fg='#f2f2f2',
    insertbackground=IND_WHITE,
    bd=0,
    relief=FLAT,
    highlightthickness=0,
    highlightbackground='#070909',
    highlightcolor=IND_GREEN,
    padx=14 * reso,
    pady=10 * reso,
    wrap='none',
)
all_bills_text.bind('<Key>', lambda e: 'break')
all_bills_text.bind('<Double-Button-1>', add_print_bill_from_available)
selected_bills_text.bind('<Double-Button-1>', remove_print_bill_from_queue)
selected_bills_text.bind('<<Modified>>', on_print_selection_modified)
print_full_radio = Radiobutton(
    root,
    text='Full bills PDF',
    variable=print_output_mode,
    value='full',
    command=refresh_print_summary,
    font=app_font(16, 'bold'),
    bg='#101414',
    fg=IND_WHITE,
    activebackground='#101414',
    activeforeground=IND_WHITE,
    selectcolor=IND_BLACK,
    highlightthickness=0,
    bd=0,
    cursor='hand2',
)
print_qr_radio = Radiobutton(
    root,
    text='QR only sheet',
    variable=print_output_mode,
    value='qr',
    command=refresh_print_summary,
    font=app_font(16, 'bold'),
    bg='#101414',
    fg=IND_MUTED,
    activebackground='#101414',
    activeforeground=IND_WHITE,
    selectcolor=IND_BLACK,
    highlightthickness=0,
    bd=0,
    cursor='hand2',
)
print_summary_label = Label(
    root,
    text='0$\n0 bills',
    font=app_font(17, 'bold'),
    fg='#c9ffe3',
    bg='#101414',
    bd=0,
    highlightthickness=0,
    justify='right',
    anchor='e',
)
print_pages_label = Label(
    root,
    text='0 pages\nestimated',
    font=app_font(16, 'bold'),
    fg=IND_WHITE,
    bg='#090c0c',
    bd=0,
    highlightthickness=0,
    justify='center',
    anchor='center',
)
print_status_label = Label(
    root,
    text='PDF is generated first. Charge sends funds to the printed paper-wallet addresses after printing.',
    font=app_font(15),
    fg=IND_MUTED,
    bg='#090c0c',
    bd=0,
    highlightthickness=0,
    justify='left',
    anchor='w',
    wraplength=px(PRINT_STATUS_WIDTH),
)
asl_text = Label(
    root,
    text='Double-click to add or remove bills.',
    font=app_font(15),
    bg='#101414',
    fg=IND_MUTED,
    bd=0,
    highlightthickness=0,
    anchor='w',
)
charge_bills_button = make_text_button('Charge after PDF', charge_bills, font_size=15, font_weight='bold',
                                       bg='#35180f', fg='#ffd3c6', bd=1, relief=SOLID)
charge_bills_button.config(state=DISABLED, disabledforeground='#ffd3c6')


# Header navigation callbacks.
def node_terminal_button():
    close()
    button.config(bg='white', fg='black'),button2.config(bg='black', fg='white'), button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white'), button_log_in.config(bg='black', fg='black')
    button_settings.config(bg='black', fg='white')
    place_node_terminal_controls()

def sign_in_button():
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
    place_sign_in_control(button_show, 765, 500, 60, 50)
    sign_in.place(x=0, y=0)

def info_button():
    close()
    button.config(bg='black', fg='white'),button2.config(bg='white', fg='black'),button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white')
    button_settings.config(bg='black', fg='white')
    info.place(x=0, y=0)

def print_page_button():
    """Show the print workflow and load the currently spendable wallet bills."""

    close()
    button.config(bg='black', fg='white'),button4.config(bg='black', fg='white'),button2.config(bg='black', fg='white')
    button3.config(bg='white', fg='black')
    button_settings.config(bg='black', fg='white')
    print_page.place(x=0, y=0)
    print_select_all_button.place(
        x=PRINT_SELECT_ALL_X * reso,
        y=PRINT_SELECT_ALL_Y * reso,
        width=PRINT_SELECT_ALL_WIDTH * reso,
        height=PRINT_SELECT_ALL_HEIGHT * reso,
    )
    button_print.place(
        x=PRINT_PRIMARY_BUTTON_X * reso,
        y=PRINT_ACTION_Y * reso,
        width=PRINT_PRIMARY_BUTTON_WIDTH * reso,
        height=PRINT_ACTION_BUTTON_HEIGHT * reso,
    )
    charge_bills_button.place(
        x=PRINT_CHARGE_BUTTON_X * reso,
        y=PRINT_ACTION_Y * reso,
        width=PRINT_CHARGE_BUTTON_WIDTH * reso,
        height=PRINT_ACTION_BUTTON_HEIGHT * reso,
    )
    all_bills_text.place(
        x=PRINT_AVAILABLE_X * reso,
        y=PRINT_AVAILABLE_LIST_Y * reso,
        width=PRINT_AVAILABLE_LIST_WIDTH * reso,
        height=PRINT_AVAILABLE_LIST_HEIGHT * reso,
    )
    selected_bills_text.place(
        x=PRINT_QUEUE_X * reso,
        y=PRINT_QUEUE_LIST_Y * reso,
        width=PRINT_QUEUE_LIST_WIDTH * reso,
        height=PRINT_QUEUE_LIST_HEIGHT * reso,
    )
    print_full_radio.place(
        x=PRINT_OUTPUT_FULL_X * reso,
        y=PRINT_OUTPUT_FULL_Y * reso,
        width=PRINT_OUTPUT_WIDTH * reso,
        height=PRINT_OUTPUT_HEIGHT * reso,
    )
    print_qr_radio.place(
        x=PRINT_OUTPUT_QR_X * reso,
        y=PRINT_OUTPUT_QR_Y * reso,
        width=PRINT_OUTPUT_WIDTH * reso,
        height=PRINT_OUTPUT_HEIGHT * reso,
    )
    print_summary_label.place(
        x=PRINT_SUMMARY_X * reso,
        y=PRINT_SUMMARY_Y * reso,
        width=PRINT_SUMMARY_WIDTH * reso,
        height=PRINT_SUMMARY_HEIGHT * reso,
    )
    print_pages_label.place(
        x=PRINT_PAGES_X * reso,
        y=PRINT_PAGES_Y * reso,
        width=PRINT_PAGES_WIDTH * reso,
        height=PRINT_PAGES_HEIGHT * reso,
    )
    print_status_label.place(
        x=PRINT_STATUS_X * reso,
        y=PRINT_STATUS_Y * reso,
        width=PRINT_STATUS_WIDTH * reso,
        height=PRINT_STATUS_HEIGHT * reso,
    )
    only_sm = ''
    try:
        # The available list intentionally excludes unsettled or already spent bills.
        for record in wallet_spendable_records():
            only_sm += record["display_id"] + '\n'
        all_bills_text.delete(1.0, END)
        all_bills_text.insert(1.0, only_sm[:-1])
    except Exception:
        log_ignored_exception()
    reset_print_actions()
    refresh_print_summary()
    
def wallet_button():
    """Show the wallet page and refresh balance, bill buttons, and receive QR."""

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
    page()
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
        log_ignored_exception()
def settings_button():
    """Show settings, then load persisted values into the active tab widgets."""

    close()
    button.config(bg='black', fg='white'),button2.config(bg='black', fg='white'),button3.config(bg='black', fg='white')
    button4.config(bg='black', fg='white'), button_settings.config(bg='white', fg='black')
    load_security_settings_form()
    settings_page.place(x=0, y=0)
    refresh_settings_widgets()

def generate_wallet_button():
    """Switch the sign-in panel into the wallet-generation form."""

    button_show.place_forget(),enter_key.place_forget(),log_in_button2.place_forget()
    enter_address.place_forget(),sign_in.place_forget()
    button_generate_wallet.config(bg='white', fg='black')
    button_log_in.config(bg='black', fg='white')
    place_sign_in_control(
        generate_address_text,
        GENERATE_WALLET_FIELD_X,
        GENERATE_WALLET_ADDRESS_Y,
        GENERATE_WALLET_FIELD_WIDTH,
        GENERATE_WALLET_FIELD_HEIGHT,
    )
    place_sign_in_control(
        generate_address_button,
        GENERATE_WALLET_SIDE_BUTTON_X,
        GENERATE_WALLET_ADDRESS_Y,
        GENERATE_WALLET_SIDE_BUTTON_WIDTH,
        GENERATE_WALLET_FIELD_HEIGHT,
    )
    place_sign_in_control(
        public_key,
        GENERATE_WALLET_FIELD_X,
        GENERATE_WALLET_PUBLIC_KEY_Y,
        GENERATE_WALLET_FIELD_WIDTH + GENERATE_WALLET_BUTTON_GAP + GENERATE_WALLET_SIDE_BUTTON_WIDTH,
        GENERATE_WALLET_KEY_FIELD_HEIGHT,
    )
    place_sign_in_control(
        private_key,
        GENERATE_WALLET_FIELD_X,
        GENERATE_WALLET_PRIVATE_KEY_Y,
        GENERATE_WALLET_FIELD_WIDTH,
        GENERATE_WALLET_KEY_FIELD_HEIGHT,
    )
    place_sign_in_control(
        button_show2,
        GENERATE_WALLET_SIDE_BUTTON_X,
        GENERATE_WALLET_PRIVATE_KEY_Y,
        GENERATE_WALLET_SIDE_BUTTON_WIDTH,
        GENERATE_WALLET_KEY_FIELD_HEIGHT,
    )
    place_sign_in_control(
        choose_password,
        GENERATE_WALLET_FIELD_X,
        GENERATE_WALLET_PASSWORD_Y,
        GENERATE_WALLET_FIELD_WIDTH,
        GENERATE_WALLET_FIELD_HEIGHT,
    )
    place_sign_in_control(
        generate_wallet_button2,
        GENERATE_WALLET_SUBMIT_BUTTON_X,
        668,
        GENERATE_WALLET_SUBMIT_BUTTON_WIDTH,
        58,
    )
    place_sign_in_control(
        button_show3,
        GENERATE_WALLET_SIDE_BUTTON_X,
        GENERATE_WALLET_PASSWORD_Y,
        GENERATE_WALLET_SIDE_BUTTON_WIDTH,
        GENERATE_WALLET_FIELD_HEIGHT,
    )
    generate_wallet.place(x=0, y=0)

tf_text = Text(font=app_font(28), bg='black', fg='white', bd=0)
def transfer_wallet():
    """Reveal a full-wallet transfer QR after a delay because it contains private keys."""

    global wallet_qr_mode, wallet_qr_warning_after_id
    try:
        if not ensure_wallet_qr():
            return
        cancel_wallet_qr_warning_timer()
        wallet_lines, _ = update_wallet()
        data_wallet = ''.join(wallet_lines[:3])
        wallet_qr = qrcode.QRCode(version=1, box_size=4, border=1,
                                  error_correction=qrcode.constants.ERROR_CORRECT_L)
        wallet_qr.add_data(data_wallet)
        wqr_security_img = ImageTk.PhotoImage(Image.new('RGB', (px(250), px(250)), 'white'))
        qr.wqr_security_img = wqr_security_img
        qr.config(image=wqr_security_img)
        qr.config(
            text=transfer_wallet_warning_text(TRANSFER_WALLET_REVEAL_SECONDS),
            font=app_font(31, 'bold'),
            fg='red',
            compound='center',
        )
        tf_text.delete(1.0, END)
        tf_text.insert(1.0, 'Transfer wallet')
        tf_text.place(x=935 * reso, y=420 * reso, width=190 * reso, height=45 * reso)
        tf_button.place_forget()
        r_button.place(x=850 * reso, y=570 * reso, width=44 * reso, height=42 * reso)
        wallet_qr_mode = 'transfer_warning'
    except Exception:
        return

    def show_transfer_qr():
        global wallet_qr_mode, wallet_qr_warning_after_id
        if wallet_qr_mode != 'transfer_warning':
            wallet_qr_warning_after_id = None
            return
        wallet_qr_warning_after_id = None
        wallet_qr_mode = 'transfer'
        r_button.place(x=850 * reso, y=570 * reso, width=44 * reso, height=42 * reso)
        wqr_make = wallet_qr.make_image(fill_color='black', back_color='#D3D3D3')
        wqr_resize = wqr_make.resize((px(250), px(250)), Image.Resampling.LANCZOS)
        wqr_img = ImageTk.PhotoImage(wqr_resize)
        qr.wqr_img = wqr_img
        qr.config(image=wqr_img, text='', compound='none')

    def update_warning_countdown(seconds_remaining):
        global wallet_qr_warning_after_id
        if wallet_qr_mode != 'transfer_warning':
            wallet_qr_warning_after_id = None
            return
        if seconds_remaining <= 0:
            show_transfer_qr()
            return
        qr.config(text=transfer_wallet_warning_text(seconds_remaining))
        wallet_qr_warning_after_id = root.after(
            1000,
            lambda: update_warning_countdown(seconds_remaining - 1),
        )

    wallet_qr_warning_after_id = root.after(
        1000,
        lambda: update_warning_countdown(TRANSFER_WALLET_REVEAL_SECONDS - 1),
    )

def receive_qr():
    global wallet_qr_mode
    cancel_wallet_qr_warning_timer()
    wallet_qr_mode = 'receive'
    r_button.place_forget()
    tf_button.place(x=1155 * reso, y=570 * reso, width=44 * reso, height=42 * reso)
    tf_text.place_forget()
    if ensure_wallet_qr():
        qr.config(image=qr_img, text='', compound='none')

tf_button = make_asset_button('different_buttons', 'tf_button', transfer_wallet, 'TX', font_size=16,
                              bg=IND_BLACK)
r_button = make_asset_button('different_buttons', 'r_button', receive_qr, 'QR', font_size=16, bg=IND_BLACK)

page_wallet = 1
place_next_button = 0
WALLET_HISTORY_ROWS_PER_PAGE = 4


def wallet_history_entries():
    entries = []
    try:
        dr_new, _ = update_wallet()
        for line in runtime_json.wallet_bill_lines(dr_new):
            parts = line.split()
            if len(parts) < 3:
                continue
            timestamp = int(parts[2])
            entries.append({
                "timestamp": timestamp,
                "line": parts[0] + '\t\t        ' + str(datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d   %H:%M')),
                "tag": "sent" if parts[0].startswith('-') else "wallet",
            })
    except Exception:
        log_ignored_exception()
    try:
        for record in wallet_pending_records():
            timestamp = int(record.get("updated_at") or record.get("first_seen") or time.time())
            entries.append({
                "timestamp": timestamp,
                "line": record["display_id"] + '\t\t        wallet        pending',
                "tag": "pending",
            })
    except Exception:
        log_ignored_exception()
    return sorted(entries, key=lambda entry: entry["timestamp"], reverse=True)


def page():
    """Render the current wallet-history page."""

    global place_next_button, page_wallet
    try:
        receiver_history.delete(1.0, END)
        receiver_history.tag_config('red', foreground='red')
        receiver_history.tag_config('pending', foreground=IND_PENDING)
        receiver_history.tag_config('empty', foreground=IND_MUTED, justify='center')
        receiver_history.tag_config('empty_top', spacing1=px(170))
        if not wallet_is_unlocked():
            next_button.place_forget()
            previous_button.place_forget()
            place_next_button = 1
            first_line, second_line = GUI_TEXT['wallet_locked_message'].split('\n', 1)
            receiver_history.insert(INSERT, first_line, ('empty', 'empty_top'))
            receiver_history.insert(INSERT, '\n' + second_line, 'empty')
            return

        entries = wallet_history_entries()
        num_of_bills = len(entries)
        total_pages = max(1, (num_of_bills + WALLET_HISTORY_ROWS_PER_PAGE - 1) // WALLET_HISTORY_ROWS_PER_PAGE)
        if page_wallet > total_pages:
            page_wallet = total_pages
        if page_wallet < 1:
            page_wallet = 1
        if page_wallet < total_pages:
            next_button.place(x=720 * reso, y=730 * reso, width=80 * reso, height=22 * reso)
            place_next_button = 0
        else:
            next_button.place_forget()
            place_next_button = 1
        if page_wallet > 1:
            previous_button.place(x=345 * reso, y=730 * reso, width=80 * reso, height=22 * reso)
        else:
            previous_button.place_forget()

        start_index = (page_wallet - 1) * WALLET_HISTORY_ROWS_PER_PAGE
        visible_entries = entries[start_index:start_index + WALLET_HISTORY_ROWS_PER_PAGE]
        for entry in visible_entries:
            row_start = receiver_history.index(INSERT)
            receiver_history.insert(INSERT, entry["line"] + '\n\n')
            row_end = receiver_history.index(INSERT)
            if entry["tag"] == "sent":
                receiver_history.tag_add('red', row_start, row_end)
            elif entry["tag"] == "pending":
                receiver_history.tag_add('pending', row_start, row_end)
    except Exception:
        log_ignored_exception()
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


def wallet_bill_button_size(value):
    if value >= 2000:
        return 149, 64
    return 139, 59


def wallet_bill_image_path(value, selected=False):
    selected_suffix = 'c' if selected else ''
    high_res_path = BASE_DIR / 'img' / 'wallet_bills' / f'_{value}{selected_suffix}4.png'
    if high_res_path.exists():
        return high_res_path
    return BASE_DIR / 'img' / 'wallet_bills' / f'_{value}{selected_suffix}.png'


def ensure_bill_images():
    global BILL_IMAGES_LOADED
    if BILL_IMAGES_LOADED:
        return
    for value in BILL_VALUES:
        for selected in (False, True):
            image_path = wallet_bill_image_path(value, selected=selected)
            if image_path.exists():
                width, height = wallet_bill_button_size(value)
                with Image.open(image_path) as bill_image:
                    resized = bill_image.convert('RGBA').resize((px(width), px(height)), Image.Resampling.LANCZOS)
                BILL_IMAGES[(value, selected)] = ImageTk.PhotoImage(resized)
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


def bill_overlay_text(remaining, pending):
    if remaining > 0 and pending > 0:
        return '       ' + str(remaining) + '\n' + str(pending) + ' Pending'
    if remaining > 0:
        return '       ' + str(remaining)
    if pending > 0:
        return str(pending) + ' Pending'
    return ''


def configure_bill_button(button, value, remaining, enabled, pending=0):
    remaining = max(remaining, 0)
    pending = max(pending, 0)
    image = BILL_IMAGES.get((value, enabled))
    if image is None and BILL_IMAGES_LOADED:
        image = BILL_IMAGES.get((value, False))
    if image is not None:
        button.config(
            image=image,
            text=bill_overlay_text(remaining, pending),
            compound='center',
            font=app_font(20 if pending > 0 else 30),
            cursor='hand2' if enabled else '',
            state='normal' if enabled else 'disabled',
            bg=IND_BLACK,
            fg=IND_WHITE if enabled else IND_PENDING,
            disabledforeground=IND_PENDING if pending > 0 else IND_WHITE,
        )
    else:
        button.config(
            image='',
            text=bill_button_text(value, remaining) if remaining > 0 else (
                f'{value:,}$   {pending} Pending' if pending > 0 else ''
            ),
            compound='none',
            font=app_font(19),
            cursor='hand2' if enabled else '',
            state='normal' if enabled else 'disabled',
            bg=IND_GREEN if enabled else '#111111',
            fg=IND_WHITE if enabled else IND_PENDING,
            disabledforeground=IND_PENDING if pending > 0 else IND_MUTED,
        )

amount = 0
pending_bill_counts = {}
bill_counts = {value: 0 for value in BILL_VALUES}
selected_bill_counts = {value: 0 for value in BILL_VALUES}
bill_buttons = {}


def update_balance():
    """Refresh wallet counters from locally settled and pending bill records."""

    global first_iteration, amount, count_selected, pending_bill_counts, bill_counts
    try:
        spendable_records = wallet_spendable_records()
    except Exception:
        log_ignored_exception()
        spendable_records = []
    try:
        pending_records = wallet_pending_records()
    except Exception:
        log_ignored_exception()
        pending_records = []
    pending_bill_counts = {value: 0 for value in BILL_VALUES}
    for record in pending_records:
        value = wallet_record_value(record)
        if value in pending_bill_counts:
            pending_bill_counts[value] += 1
    bill_counts = {value: 0 for value in BILL_VALUES}
    try:
        for record in spendable_records:
            value = wallet_record_value(record)
            if value in bill_counts:
                bill_counts[value] += 1
    except Exception:
        log_ignored_exception()
    balance = sum(value * count for value, count in bill_counts.items())
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

def add_bill_value(value):
    global amount, count_selected
    selected = selected_bill_counts[value]
    available = bill_counts[value]
    remaining = available - selected
    pending = pending_bill_counts.get(value, 0)
    button_bill = bill_buttons[value]

    if remaining > 0:
        if count_selected:
            selected_bill_counts[value] = selected + 1
            amount += value
            remaining -= 1
        configure_bill_button(button_bill, value, remaining, remaining > 0, pending)

    if remaining <= 0:
        configure_bill_button(button_bill, value, 0, False, pending)
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


w1 = bill_buttons[1] = make_bill_button(add_1)
w2 = bill_buttons[2] = make_bill_button(add_2)
w5 = bill_buttons[5] = make_bill_button(add_5)
w10 = bill_buttons[10] = make_bill_button(add_10)
w20 = bill_buttons[20] = make_bill_button(add_20)
w50 = bill_buttons[50] = make_bill_button(add_50)
w100 = bill_buttons[100] = make_bill_button(add_100)
w200 = bill_buttons[200] = make_bill_button(add_200)
w500 = bill_buttons[500] = make_bill_button(add_500)
w1000 = bill_buttons[1000] = make_bill_button(add_1000)
w2000 = bill_buttons[2000] = make_bill_button(add_2000)
w5000 = bill_buttons[5000] = make_bill_button(add_5000)
w10000 = bill_buttons[10000] = make_bill_button(add_10000)
w20000 = bill_buttons[20000] = make_bill_button(add_20000)
w50000 = bill_buttons[50000] = make_bill_button(add_50000)
w100000 = bill_buttons[100000] = make_bill_button(add_100000)

def start_bills():
    """Reset denomination buttons to their neutral state before a send selection."""

    global count_selected
    for value in BILL_VALUES:
        add_bill_value(value)
    count_selected = True


def refresh_bill_buttons():
    """Redraw denomination buttons without changing the current selection state."""

    global count_selected
    was_counting = count_selected
    count_selected = False
    for value in BILL_VALUES:
        add_bill_value(value)
    count_selected = was_counting


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
    """Synchronize wallet-visible bills from local settlement and peer gossip."""

    root.config(cursor='watch')
    receiver_button.config(cursor='watch')

    def worker():
        errors = []
        try:
            sender_node.update_ip_list()
        except Exception as exc:
            errors.append(f"Peer refresh failed: {error_detail(exc)}")
        try:
            sender_node.receive_bills()
        except Exception as exc:
            errors.append(f"Wallet sync failed: {error_detail(exc)}")

        def finish():
            root.config(cursor='arrow')
            receiver_button.config(cursor='hand2')
            refresh_wallet_view()
            if errors:
                show_error_popup('Sync failed', RuntimeError("\n".join(errors)))

        root.after(0, finish)

    threading.Thread(target=worker, daemon=True).start()

receiver_button = make_asset_button('different_buttons', 'reload_button', receive_bills, 'Sync', font_size=16,
                                    bg=IND_BLACK)

# Visibility toggles for masked password/key fields.
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

def log_in():
    """Unlock an encrypted wallet into the short-lived desktop session."""

    password = enter_key.get()
    unlocked = wallet_decryption.wallet_decrypt(password, address_variable.get())
    enter_key.delete(0, END)
    def check_decrypted():
        global decrypted
        for decrypted_wallet in runtime_json.iter_decrypted_wallet_files():
            if decrypted_wallet.name.startswith('wallet_decrypted'):
                wallet_button()
                break
    if unlocked:
        check_decrypted()
    else:
        messagebox.showerror('Wallet locked', 'That password did not unlock this wallet.')

address_variable = StringVar(root)
options_addr = ['                                                                        ']
for s in runtime_json.iter_encrypted_wallet_files() + runtime_json.iter_decrypted_wallet_files():
    wallet_raw = runtime_json.wallet_address_from_name(s.name)
    if wallet_raw not in options_addr:
        options_addr.append(wallet_raw)
if len(options_addr) == 1:
    men = 0
else:
    men = 1
enter_address = OptionMenu(root, address_variable, *options_addr[men:])
enter_address.config(font=app_font(21, 'bold'), cursor='hand2', bg='black', fg='white')
eadrr = root.nametowidget(enter_address.menuname)
eadrr.config(font=app_font(20))

enter_key = Entry(root, font=app_font(26), show='*', bg='light grey')
log_in_button2 = make_asset_button('different_buttons', 'log_in_button', log_in, 'Sign in', font_size=26,
                                   bg=IND_GREEN)
button_show = make_asset_button('different_buttons', 'show_button', show_key_s, 'Show', font_size=16,
                                bg=IND_WHITE, fg=IND_BLACK)
button_show3 = make_asset_button('different_buttons', 'show3_button', show_password, 'Show', font_size=16,
                                 bg=IND_WHITE, fg=IND_BLACK)

def gen_ad():
    """Generate one wallet keypair in a background thread for the sign-up form."""

    runtime_json.clear_wallet_generation()
    generate_address_text.config(state='normal'),public_key.config(state='normal'),private_key.config(state='normal')
    generate_address_text.delete(0, END),public_key.delete(0, END),private_key.delete(0, END)
    root.config(cursor='watch')
    generate_address_button.config(cursor='watch')

    def finish(generated_wallet):
        runtime_json.write_wallet_generation(generated_wallet[0], generated_wallet[1], generated_wallet[2])
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
            generated_wallet = generate_address_module.generate_keypair()
        except Exception as exc:
            root.after(0, lambda exc=exc: fail(exc))
            return
        root.after(0, lambda generated_wallet=generated_wallet: finish(generated_wallet))
    threading.Thread(target=t, daemon=True).start()
SUCCESS_POPUP_DURATION_MS = 7000
success_popup_hide_after_id = None


def hide_success_popup():
    global success_popup_hide_after_id
    if success_popup_hide_after_id is not None:
        try:
            root.after_cancel(success_popup_hide_after_id)
        except TclError:
            pass
        success_popup_hide_after_id = None
    success_popup.withdraw()


def raise_success_popup():
    try:
        success_popup.lift(root)
        success_popup.attributes('-topmost', True)
        raise_widget(success)
        success_popup.after(250, release_success_topmost)
    except TclError:
        pass


def release_success_topmost():
    try:
        success_popup.attributes('-topmost', False)
    except TclError:
        pass


def show_success_popup():
    global success_popup_hide_after_id
    hide_success_popup()
    root.update_idletasks()
    x = root.winfo_rootx() + px(282)
    y = root.winfo_rooty() + px(193)
    success_popup.geometry(f'{px(653)}x{px(550)}+{x}+{y}')
    success_popup.deiconify()
    raise_success_popup()
    root.after_idle(raise_success_popup)
    success_popup_hide_after_id = root.after(SUCCESS_POPUP_DURATION_MS, hide_success_popup)


def generate_wallet_final():
    addr_hash = runtime_json.read_wallet_generation()["address"]
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
    show_success_popup()

success_popup = Toplevel(root)
success_popup.withdraw()
success_popup.overrideredirect(True)
success_popup.configure(bg='#007a3b')
success_popup.transient(root)
success_popup.resizable(False, False)
success = ModalCanvas(success_popup, 'success', 653, 550, bg='#007a3b')
success.pack(fill=BOTH, expand=True)
generate_address_text = Entry(
    root,
    font=app_font(21),
    bd=0,
    bg='#eeeeee',
    fg='#111111',
    insertbackground='#111111',
    readonlybackground='#eeeeee',
    highlightthickness=1,
    highlightbackground='#555555',
    highlightcolor=IND_GREEN,
)
generate_address_button = make_asset_button('different_buttons', 'generate_address_button', gen_ad, 'Generate',
                                            font_size=22, bg=IND_GREEN)
public_key = Entry(
    root,
    font=app_font(18),
    bd=0,
    bg='#eeeeee',
    fg='#111111',
    insertbackground='#111111',
    readonlybackground='#eeeeee',
    highlightthickness=1,
    highlightbackground='#555555',
    highlightcolor=IND_GREEN,
)
private_key = Entry(
    root,
    font=app_font(18),
    bd=0,
    show='*',
    bg='#eeeeee',
    fg='#111111',
    insertbackground='#111111',
    readonlybackground='#eeeeee',
    highlightthickness=1,
    highlightbackground='#555555',
    highlightcolor=IND_GREEN,
)
button_show2 = make_asset_button('different_buttons', 'show2_button', show_key_p, 'Show', font_size=16,
                                 bg='#4d4d4d')
choose_password = Entry(
    root,
    font=app_font(22),
    bd=0,
    bg='#eeeeee',
    fg='#111111',
    insertbackground='#111111',
    highlightthickness=1,
    highlightbackground='#555555',
    highlightcolor=IND_GREEN,
)
generate_wallet_button2 = make_asset_button('different_buttons', 'generate_wallet_button', generate_wallet_final,
                                            'Generate Wallet', font_size=24, bg=IND_GREEN)

button_log_in = Button(root, font=app_font(30), text='Sign In', bd=0, highlightthickness=0, cursor='hand2',
                       bg='black', fg='white', command=sign_in_button)
button_generate_wallet = Button(root, font=app_font(30), text='Generate Wallet', bd=0, highlightthickness=0,
                                cursor='hand2', bg='black', fg='white', command=generate_wallet_button)

def send_bills(serial_num_start):
    """Select wallet bills by denomination and queue signed sends to the receiver."""

    errors = []
    sent_count = 0
    requested = list(serial_num_start)
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if wallet_path.name.startswith('wallet_decrypted'):
            of = runtime_json.read_decrypted_wallet_lines(wallet_path)
            updated = []
            for wb in of:
                parts = wb.split()
                display_id = parts[0] if parts else ""
                bill_prefix = wb.split('x')[0] + 'x'
                if bill_prefix in requested:
                    requested.remove(bill_prefix)
                    try:
                        state = write_transfer_announcement(of, wb, receiver.get())
                        if not state:
                            raise RuntimeError("bill is not spendable or is not settled")
                        updated.append('-' + display_id + ' ' + str(state.sequence) + ' ' + str(int(time.time())) + '\n')
                        sent_count += 1
                    except Exception as exc:
                        errors.append(f"{display_id or bill_prefix}: {error_detail(exc)}")
                        updated.append(wb)
                else:
                    updated.append(wb)
            runtime_json.write_decrypted_wallet_lines(wallet_path, updated)
    if requested:
        errors.append("Not enough settled bills for: " + ", ".join(requested))
    return sent_count, errors


def selected_bill_prefixes():
    prefixes = []
    for value in BILL_VALUES:
        selected = selected_bill_counts[value]
        prefixes.extend([f'{value}x'] * int(selected))
    return prefixes


def confirm_transaction():
    """Convert the selected UI amount into denomination prefixes and send them."""

    if runtime_json.has_pending_transactions():
        sender_node.send_bills()

    starts_with = selected_bill_prefixes()
    if not starts_with:
        raise ValueError("Select at least one bill before sending.")
    sent_count, errors = send_bills(starts_with)
    if sent_count:
        threading.Thread(target=sender_node.send_bills, daemon=True).start()
    if errors:
        raise RuntimeError("\n".join(errors))
    receiver.delete(0, END)

def send_button():
    root.config(cursor='watch')
    send.config(cursor='watch')
    try:
        # Refresh peer hints before validating and queueing the transfer.
        for _ in range(3):
            sender_node.update_ip_list()
        recipient_address = ind_token.validate_address(receiver.get().strip(), "recipient address")
        wallet_lines, _ = update_wallet()
        if amount == 0:
            raise ValueError("Select an amount before sending.")
        if recipient_address == wallet_lines[0].strip():
            raise ValueError("The recipient address is this wallet.")
        confirm_transaction()
    except Exception as exc:
        show_error_popup('Send failed', exc)
    finally:
        close_amount()
        root.config(cursor='arrow')
        send.config(cursor='hand2')
        refresh_wallet_view()


def close():
    """Hide all page-level widgets before showing the next desktop view."""

    try:
        if globals().get('cap') is not None or globals().get('num_of_times_clicked'):
            stop_qr_scan()
    except Exception:
        log_ignored_exception()
    reset_wallet_qr_mode()
    # Widgets are manually placed per page, so navigation explicitly hides each one.
    claim_bills_amount.place_forget(), webcam_scanner.place_forget(), qr_scan_status.place_forget(), private_key_entry.place_forget()
    claim_left_separator.place_forget(), claim_right_separator.place_forget()
    claim_ready_title.place_forget()
    claim_total_label.place_forget()
    claim_count_label.place_forget()
    hide_scanned_serials_list()
    hide_claim_background_overlay()
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
    button_show3.place_forget(), number_entry.place_forget()
    info.place_forget(), tf_text.place_forget(), button_print.place_forget()
    add_bill_button.place_forget(), node_port_notice.place_forget(), charge_bills_button.place_forget()
    ron.place_forget(), bak.place_forget(), transparency_operator.place_forget(), asl_text.place_forget(), all_bills_text.place_forget()
    selected_bills_text.place_forget(), button_only_qr.place_forget(), print_select_all_button.place_forget()
    print_full_radio.place_forget(), print_qr_radio.place_forget(), print_summary_label.place_forget()
    print_pages_label.place_forget(), print_status_label.place_forget()
    settings_page.place_forget()
    hide_node_terminal_widgets()
    hide_success_popup()
    for settings_widget in settings_widgets:
        settings_widget.place_forget()
    try:
        qr.place_forget(), address_txt.place_forget()
    except Exception:
        log_ignored_exception()
def close_amount():
    """Clear selected denominations and restore wallet bill button state."""

    global amount, count_selected
    for value in BILL_VALUES:
        selected_bill_counts[value] = 0
    amount = 0
    count_selected = False
    start_bills()


def close_bill_claimer():
    stop_qr_scan()
    serial_num.place_forget(), public_key_entry.place_forget(), check_validity_button.place_forget()
    claim_bills_amount.place_forget(), webcam_scanner.place_forget(), qr_scan_status.place_forget(), close_button.place_forget()
    claim_left_separator.place_forget(), claim_right_separator.place_forget()
    claim_ready_title.place_forget()
    claim_total_label.place_forget()
    claim_count_label.place_forget()
    hide_scanned_serials_list()
    hide_claim_background_overlay()
    claim_bill.place_forget(), add_bill_button.place_forget(), private_key_entry.place_forget()
    number_entry.place_forget()

send = make_asset_button('different_buttons', 'send_button', send_button, 'Send', font_size=24, bg=IND_GREEN)
close_button = make_asset_button('pop_up', 'close', close_bill_claimer, 'X', font_size=18, bg=IND_BLACK,
                                 fg=IND_RED)
close_amount_button = make_asset_button('different_buttons', 'close_amount', close_amount, 'X', font_size=14,
                                        bg='#d2d2d2', fg=IND_RED)

def plus_bills():
    """Open the claim workflow for manual entry, dropped images, or webcam scans."""

    restore_webcam_scanner_prompt()
    update_claim_summary()
    show_claim_background_overlay()
    claim_left_separator.place(
        x=CLAIM_LEFT_SEPARATOR_X * reso,
        y=CLAIM_SEPARATOR_TOP * reso,
        width=1 * reso,
        height=CLAIM_SEPARATOR_HEIGHT * reso,
    )
    claim_bill.place(x=CLAIM_MODAL_X * reso, y=CLAIM_MODAL_Y * reso)
    close_button.place(
        x=CLAIM_CLOSE_X * reso,
        y=CLAIM_CLOSE_Y * reso,
        width=CLAIM_CLOSE_WIDTH * reso,
        height=CLAIM_CLOSE_HEIGHT * reso,
    )
    check_validity_button.place(
        x=CLAIM_ACTION_X * reso,
        y=CLAIM_BUTTON_Y * reso,
        width=CLAIM_ACTION_WIDTH * reso,
        height=CLAIM_BUTTON_HEIGHT * reso,
    )
    claim_ready_title.place(
        x=CLAIM_READY_TITLE_X * reso,
        y=CLAIM_READY_TITLE_Y * reso,
        width=CLAIM_RIGHT_CONTENT_WIDTH * reso,
        height=CLAIM_READY_TITLE_HEIGHT * reso,
    )
    claim_total_label.place(
        x=CLAIM_READY_TITLE_X * reso,
        y=CLAIM_TOTAL_LABEL_Y * reso,
        width=CLAIM_SUMMARY_ITEM_WIDTH * reso,
        height=CLAIM_TOTAL_LABEL_HEIGHT * reso,
    )
    claim_count_label.place(
        x=CLAIM_COUNT_LABEL_X * reso,
        y=CLAIM_TOTAL_LABEL_Y * reso,
        width=CLAIM_SUMMARY_ITEM_WIDTH * reso,
        height=CLAIM_TOTAL_LABEL_HEIGHT * reso,
    )
    serial_num.place(x=CLAIM_ENTRY_X * reso, y=CLAIM_SERIAL_Y * reso, width=CLAIM_ENTRY_WIDTH * reso, height=40 * reso)
    public_key_entry.place(x=CLAIM_ENTRY_X * reso, y=CLAIM_PUBLIC_Y * reso, width=CLAIM_ENTRY_WIDTH * reso, height=40 * reso)
    private_key_entry.place(x=CLAIM_ENTRY_X * reso, y=CLAIM_PRIVATE_Y * reso, width=CLAIM_ENTRY_WIDTH * reso, height=40 * reso)
    webcam_scanner.place(
        x=CLAIM_SCANNER_X * reso,
        y=CLAIM_SCANNER_Y * reso,
        width=CLAIM_SCANNER_WIDTH * reso,
        height=CLAIM_SCANNER_HEIGHT * reso,
    )
    show_scanned_serials_list()
    qr_scan_status.place(
        x=CLAIM_SCANNER_X * reso,
        y=CLAIM_SCANNER_STATUS_Y * reso,
        width=CLAIM_SCANNER_WIDTH * reso,
        height=CLAIM_SCANNER_STATUS_HEIGHT * reso,
    )
    claim_bills_amount.bind("<Key>", lambda e: "break")
    raise_claim_widgets()

plus_bills_button = make_asset_button('different_buttons', 'plus_bills_button', plus_bills, 'Scan Qr code',
                                      font_size=18, bg=IND_BLACK, fg=IND_WHITE)
claim_bill = ModalCanvas(root, 'claim', CLAIM_MODAL_WIDTH, CLAIM_MODAL_HEIGHT, bg=IND_BLACK)
claim_bills_amount = Entry(
    root,
    font=app_font(30, 'bold'),
    fg='white',
    bg='black',
    highlightthickness=0,
    bd=0,
    justify='center',
)
claim_bills_amount.insert(0, '0$')

used_codes = []
scanned_serial_numbers = []
manual_bill_auto_add_after_id = None
reported_invalid_qr_codes = set()
num_of_times_clicked = 0
cap = None
zxing_available = None
qr_hard_scan_inflight = False
qr_hard_scan_generation = 0
qr_hard_scan_last_at = 0.0
qr_detection_paused_until = 0.0
qr_hard_scan_results = queue.Queue()
QR_HARD_SCAN_INTERVAL_SECONDS = 3.0
QR_DETECTION_PAUSE_SECONDS = 0.5
QR_STATUS_RESULT_HOLD_MS = 800
qr_scan_status_hold_until = 0.0


def claim_bills():
    """Claim scanned bills by issuing receipts or spending paper-wallet bills."""

    errors = []
    claim_count = 0
    try:
        if not used_codes:
            raise ValueError("No scanned bills are ready to claim.")
        for bill in used_codes:
            claimed = False
            for wallet_path in runtime_json.iter_decrypted_wallet_files():
                if wallet_path.name.startswith('wallet_decrypted'):
                    wallet_lines = runtime_json.read_decrypted_wallet_lines(wallet_path)
                    wallet_address = runtime_json.wallet_address_from_name(wallet_path.name)
                    try:
                        if wallet_services.claim_bill_payload(bill, wallet_lines, wallet_address):
                            claimed = True
                            claim_count += 1
                    except Exception as exc:
                        errors.append(f"{wallet_address}: {error_detail(exc)}")
            if not claimed:
                preview = str(bill).splitlines()[0] if str(bill).splitlines() else "scanned bill"
                errors.append(f"{preview}: could not be claimed")
        if claim_count:
            sender_node.send_bills()
            time.sleep(2)
            receive_bills()
        if errors:
            raise RuntimeError("\n".join(errors))
    except Exception as exc:
        show_error_popup('Claim bills failed', exc)
    finally:
        refresh_wallet_view()

def add_bill():
    """Add a manually entered bill payload to the pending claim list."""

    try:
        if not add_manual_bill_from_fields(show_errors=True):
            raise ValueError("Manual bill fields are incomplete or already in the pending claim list.")
    except Exception as exc:
        show_error_popup('Add bill failed', exc)
        refresh_wallet_view()

check_validity_button = make_text_button(
    'Claim bills',
    claim_bills,
    font_size=26,
    font_weight='bold',
    bg='#009244',
    fg=IND_WHITE,
)
add_bill_button = make_asset_button('different_buttons', 'add_bill_button', add_bill, 'Add bills', font_size=20,
                                    bg=IND_WHITE, fg=IND_BLACK)
valid = ModalCanvas(root, 'valid', 493, 620, bg=IND_GREEN)
not_valid = ModalCanvas(root, 'not_valid', 493, 620, bg=IND_RED)
serial_num = Entry(root, font=app_font(19), bg='light grey')
public_key_entry = Entry(root, font=app_font(19), bg='light grey')
private_key_entry = Entry(root, font=app_font(19), bg='light grey')
number_entry = Entry(root, font=app_font(19), bg='light grey')


def claim_amount_value():
    raw_amount = claim_bills_amount.get().strip().rstrip('$')
    return int(raw_amount) if raw_amount else 0


def set_claim_amount_value(value):
    claim_bills_amount.delete(0, END)
    claim_bills_amount.insert(0, f'{value}$')
    update_claim_summary()


def update_claim_summary():
    try:
        count = len(scanned_serial_numbers) if 'scanned_serial_numbers' in globals() else 0
        claim_total_label.config(text=f'Total value: {claim_amount_value()}$')
        claim_count_label.config(text=f'Bills: {count}')
    except Exception:
        log_ignored_exception()
def add_manual_bill_from_fields(show_errors=False):
    serial = serial_num.get().strip()
    private_key = private_key_entry.get().strip()
    public_key = public_key_entry.get().strip()
    bill_number = number_entry.get().strip()
    if not serial or not private_key or not public_key:
        return False
    if serial in scanned_serial_numbers:
        return False
    value_prefix = serial.split('x', 1)[0]
    if not value_prefix.isdigit():
        if show_errors:
            raise ValueError("IND bill serial must start with a numeric value before 'x'.")
        return False
    full_code = '\n'.join([serial, private_key, public_key, bill_number])
    if full_code in used_codes:
        return False
    used_codes.append(full_code)
    record_scanned_serial(serial)
    set_claim_amount_value(claim_amount_value() + int(value_prefix))
    set_qr_scan_status('Bill added to pending claim list', IND_GREEN)
    return True


def run_manual_bill_auto_add():
    global manual_bill_auto_add_after_id
    manual_bill_auto_add_after_id = None
    try:
        add_manual_bill_from_fields(show_errors=False)
    except Exception:
        log_ignored_exception()
def schedule_manual_bill_auto_add(event=None):
    global manual_bill_auto_add_after_id
    if manual_bill_auto_add_after_id is not None:
        try:
            root.after_cancel(manual_bill_auto_add_after_id)
        except TclError:
            pass
    manual_bill_auto_add_after_id = root.after(150, run_manual_bill_auto_add)


for manual_bill_entry in (serial_num, public_key_entry, private_key_entry):
    manual_bill_entry.bind('<<Paste>>', schedule_manual_bill_auto_add)
    manual_bill_entry.bind('<FocusOut>', schedule_manual_bill_auto_add)


def refresh_scanned_serials_list():
    try:
        scanned_serials_list.delete(0, END)
        if scanned_serial_numbers:
            scanned_serials_list.config(fg=IND_WHITE)
            for serial in scanned_serial_numbers:
                scanned_serials_list.insert(END, serial)
            scanned_serials_empty.place_forget()
        else:
            scanned_serials_empty.place(
                x=SCANNED_SERIALS_OVERLAY_PADDING * reso,
                y=SCANNED_SERIALS_LIST_Y * reso,
                width=SCANNED_SERIALS_LIST_WIDTH * reso,
                height=SCANNED_SERIALS_LIST_HEIGHT * reso,
            )
            raise_widget(scanned_serials_empty)
    except Exception:
        log_ignored_exception()
def show_scanned_serials_list():
    try:
        refresh_scanned_serials_list()
        scanned_serials_overlay.place(
            x=SCANNED_SERIALS_OVERLAY_X * reso,
            y=SCANNED_SERIALS_OVERLAY_Y * reso,
            width=SCANNED_SERIALS_OVERLAY_WIDTH * reso,
            height=SCANNED_SERIALS_OVERLAY_HEIGHT * reso,
        )
        scanned_serials_title.place(
            x=SCANNED_SERIALS_OVERLAY_PADDING * reso,
            y=SCANNED_SERIALS_OVERLAY_PADDING * reso,
            width=(SCANNED_SERIALS_OVERLAY_WIDTH - (SCANNED_SERIALS_OVERLAY_PADDING * 2)) * reso,
            height=SCANNED_SERIALS_OVERLAY_TITLE_HEIGHT * reso,
        )
        scanned_serials_subtitle.place(
            x=SCANNED_SERIALS_OVERLAY_PADDING * reso,
            y=(SCANNED_SERIALS_OVERLAY_PADDING + SCANNED_SERIALS_OVERLAY_TITLE_HEIGHT) * reso,
            width=(SCANNED_SERIALS_OVERLAY_WIDTH - (SCANNED_SERIALS_OVERLAY_PADDING * 2)) * reso,
            height=SCANNED_SERIALS_OVERLAY_SUBTITLE_HEIGHT * reso,
        )
        scanned_serials_list.place(
            x=SCANNED_SERIALS_OVERLAY_PADDING * reso,
            y=SCANNED_SERIALS_LIST_Y * reso,
            width=SCANNED_SERIALS_LIST_WIDTH * reso,
            height=SCANNED_SERIALS_LIST_HEIGHT * reso,
        )
        raise_widget(scanned_serials_overlay)
        raise_widget(scanned_serials_title)
        raise_widget(scanned_serials_subtitle)
        raise_widget(scanned_serials_list)
        if not scanned_serial_numbers:
            raise_widget(scanned_serials_empty)
        raise_widget(qr_scan_status)
    except Exception:
        log_ignored_exception()
def show_claim_background_overlay():
    try:
        claim_background_overlay.place(
            x=CLAIM_BACKGROUND_X * reso,
            y=CLAIM_BACKGROUND_Y * reso,
            width=CLAIM_BACKGROUND_WIDTH * reso,
            height=CLAIM_BACKGROUND_HEIGHT * reso,
        )
        raise_widget(claim_background_overlay)
        for border, x, y, width, height in claim_border_widgets:
            border.place(
                x=x * reso,
                y=y * reso,
                width=width * reso,
                height=height * reso,
            )
            raise_widget(border)
    except Exception:
        log_ignored_exception()
def hide_claim_background_overlay():
    try:
        claim_background_overlay.place_forget()
        for border, *_ in claim_border_widgets:
            border.place_forget()
    except Exception:
        log_ignored_exception()
def raise_claim_widgets():
    for widget in (
        claim_background_overlay,
        claim_left_separator,
        claim_right_separator,
        scanned_serials_overlay,
        scanned_serials_title,
        scanned_serials_subtitle,
        scanned_serials_list,
        scanned_serials_empty,
        claim_bill,
        claim_ready_title,
        claim_total_label,
        claim_count_label,
        serial_num,
        public_key_entry,
        private_key_entry,
        webcam_scanner,
        qr_scan_status,
        claim_bills_amount,
        check_validity_button,
        close_button,
        claim_border_top,
        claim_border_left,
        claim_border_right,
        claim_border_bottom,
    ):
        try:
            raise_widget(widget)
        except TclError:
            pass


def hide_scanned_serials_list():
    try:
        scanned_serials_title.place_forget()
        scanned_serials_subtitle.place_forget()
        scanned_serials_list.place_forget()
        scanned_serials_empty.place_forget()
        scanned_serials_overlay.place_forget()
    except Exception:
        log_ignored_exception()
def record_scanned_serial(serial):
    serial = str(serial).strip()
    if serial and serial not in scanned_serial_numbers:
        scanned_serial_numbers.append(serial)
        refresh_scanned_serials_list()
        update_claim_summary()


def set_qr_scan_status(message, color=IND_MUTED, hold_ms=0):
    global qr_scan_status_hold_until
    try:
        now = time.monotonic()
        if message == 'Scanning...' and now < qr_scan_status_hold_until:
            return
        if qr_scan_status.cget('text') != message or qr_scan_status.cget('fg') != color:
            qr_scan_status.config(text=message, fg=color)
        if hold_ms:
            qr_scan_status_hold_until = now + (hold_ms / 1000)
        raise_widget(qr_scan_status)
    except Exception:
        log_ignored_exception()
def report_invalid_qr(decoded_qrcode, error, suppress_repeated=False, show_popup=True):
    marker = decoded_qrcode or error_detail(error)
    if suppress_repeated and marker in reported_invalid_qr_codes:
        return
    reported_invalid_qr_codes.add(marker)
    if not show_popup:
        return
    show_error_popup(
        'Invalid QR code',
        ValueError(
            'The scanner detected a QR code, but it is not a valid IND bill or address.\n\n'
            f'Details: {error_detail(error)}'
        )
    )


def decode_paper_bill(decoded_qrcode):
    lines = [line.strip() for line in decoded_qrcode.splitlines()]
    if len(lines) < 4:
        raise ValueError('IND bill QR codes must contain serial, private key, public key, and number lines.')
    serial, private_key, public_key, bill_number = lines[:4]
    if not serial or not private_key or not public_key or not bill_number:
        raise ValueError('IND bill QR code contains an empty required field.')
    value_prefix = serial.split('x', 1)[0]
    if not value_prefix.isdigit():
        raise ValueError("IND bill serial must start with a numeric value before 'x'.")
    return serial, private_key, public_key, bill_number, int(value_prefix)


def update_qr_decode_status(result, live=False):
    if result['accepted']:
        set_qr_scan_status('QR accepted', IND_GREEN, hold_ms=QR_STATUS_RESULT_HOLD_MS)
    elif result['invalid']:
        set_qr_scan_status('Invalid IND QR', IND_RED)
    elif result['duplicate']:
        set_qr_scan_status('QR already scanned', IND_MUTED, hold_ms=QR_STATUS_RESULT_HOLD_MS)
    elif live:
        set_qr_scan_status('Scanning...', IND_MUTED)
    else:
        set_qr_scan_status('No QR code found', IND_MUTED)


def add_unique_qr_payload(payloads, seen_payloads, raw_payload):
    if raw_payload is None:
        return
    try:
        text = raw_payload.decode('utf-8') if isinstance(raw_payload, bytes) else str(raw_payload)
    except UnicodeDecodeError:
        text = raw_payload.decode('utf-8', errors='replace')
    if text and text not in seen_payloads:
        seen_payloads.add(text)
        payloads.append(text)


def add_pyzbar_qr_payloads(candidate, payloads, seen_payloads):
    try:
        for code in decode(candidate):
            add_unique_qr_payload(payloads, seen_payloads, code.data)
    except Exception:
        log_ignored_exception()
    return bool(payloads)


def add_zxing_qr_payloads(candidate, payloads, seen_payloads):
    global zxing_available
    if zxing_available is False:
        return False
    try:
        barcodes = zxingcpp.read_barcodes(
            candidate,
            formats=zxingcpp.BarcodeFormat.QRCode,
            try_rotate=True,
            try_downscale=True,
            try_invert=True,
        )
        zxing_available = True
    except (ImportError, ModuleNotFoundError):
        zxing_available = False
        return False
    except Exception:
        return False
    for barcode in barcodes:
        add_unique_qr_payload(payloads, seen_payloads, getattr(barcode, 'text', ''))
    return bool(payloads)


def pyzbar_qr_candidates(qrimage, include_mirror=False):
    yield 'raw', qrimage
    try:
        if hasattr(qrimage, 'shape'):
            gray = cv2.cvtColor(qrimage, cv2.COLOR_BGR2GRAY) if len(qrimage.shape) == 3 else qrimage
            yield 'gray', gray
            if include_mirror:
                yield 'flipped', cv2.flip(qrimage, 1)
                yield 'flipped gray', cv2.flip(gray, 1)
        else:
            gray = qrimage.convert('L')
            yield 'gray', gray
            if include_mirror:
                yield 'flipped', qrimage.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
                yield 'flipped gray', gray.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
    except Exception:
        log_ignored_exception()
def decode_zxing_payloads(qrimage, include_mirror=False):
    payloads = []
    seen_payloads = set()
    for source, candidate in pyzbar_qr_candidates(qrimage, include_mirror=include_mirror):
        before = len(payloads)
        add_zxing_qr_payloads(candidate, payloads, seen_payloads)
        if len(payloads) > before:
            return payloads, f'zxing {source}'
    return payloads, ''


def decode_pyzbar_payloads(qrimage, include_mirror=False):
    payloads = []
    seen_payloads = set()
    for source, candidate in pyzbar_qr_candidates(qrimage, include_mirror=include_mirror):
        before = len(payloads)
        add_pyzbar_qr_payloads(candidate, payloads, seen_payloads)
        if len(payloads) > before:
            return payloads, source
    return payloads, ''


def decode_qr_payloads_for_live(qrimage, include_mirror=False):
    payloads, source = decode_zxing_payloads(qrimage, include_mirror=include_mirror)
    if payloads:
        return payloads, source
    payloads, source = decode_pyzbar_payloads(qrimage, include_mirror=include_mirror)
    if source:
        source = f'pyzbar {source}'
    return payloads, source


def process_qr_payloads(payloads, suppress_repeated_invalid=False, show_invalid_errors=True):
    """Apply decoded QR payloads to wallet fields and return a scan result summary."""

    global used_codes
    result = {'found': 0, 'accepted': 0, 'duplicate': 0, 'invalid': 0}
    for decoded_qrcode in payloads:
        result['found'] += 1
        try:
            decoded_qrcode = decoded_qrcode.strip()
            if not decoded_qrcode:
                raise ValueError('QR code payload is empty.')
            if decoded_qrcode in used_codes:
                result['duplicate'] += 1
                continue
            if decoded_qrcode.startswith('x'):
                address = ind_token.validate_address(decoded_qrcode, "QR address")
                receiver.delete(0, END)
                receiver.insert(0, address)
                result['accepted'] += 1
            elif decoded_qrcode.startswith('{'):
                message = json.loads(decoded_qrcode)
                bill_payload = message.get("token", message)
                state = ind_token.verify_token(bill_payload)
                used_codes.append(decoded_qrcode)
                serial_num.delete(0, END)
                serial_num.insert(0, state.display_id)
                record_scanned_serial(state.display_id)
                set_claim_amount_value(claim_amount_value() + state.value)
                result['accepted'] += 1
            else:
                serial, private_key, public_key, bill_number, bill_value = decode_paper_bill(decoded_qrcode)
                used_codes.append(decoded_qrcode)
                serial_num.delete(0, END)
                serial_num.insert(0, serial)
                record_scanned_serial(serial)
                private_key_entry.delete(0, END)
                private_key_entry.insert(0, private_key)
                public_key_entry.delete(0, END)
                public_key_entry.insert(0, public_key)
                number_entry.delete(0, END)
                number_entry.insert(0, bill_number)
                set_claim_amount_value(claim_amount_value() + bill_value)
                result['accepted'] += 1
        except Exception as exc:
            result['invalid'] += 1
            report_invalid_qr(
                decoded_qrcode,
                exc,
                suppress_repeated=suppress_repeated_invalid,
                show_popup=show_invalid_errors,
            )
    return result


def qr_decoder(qrimage, suppress_repeated_invalid=False, live=False, show_invalid_errors=True):
    """Decode QR payloads with zxing-cpp first, falling back to pyzbar."""

    payloads, source = decode_qr_payloads_for_live(qrimage, include_mirror=live)
    result = process_qr_payloads(
        payloads,
        suppress_repeated_invalid=suppress_repeated_invalid,
        show_invalid_errors=show_invalid_errors,
    )
    result['source'] = source
    return result


def add_opencv_qr_payloads(candidate, payloads, seen_payloads):
    try:
        detector = cv2.QRCodeDetector()
        ok, decoded_info, _, _ = detector.detectAndDecodeMulti(candidate)
        if ok:
            for decoded_qrcode in decoded_info:
                add_unique_qr_payload(payloads, seen_payloads, decoded_qrcode)
            if payloads:
                return True
    except Exception:
        log_ignored_exception()
    try:
        decoded_qrcode, _, _ = cv2.QRCodeDetector().detectAndDecode(candidate)
        add_unique_qr_payload(payloads, seen_payloads, decoded_qrcode)
        if payloads:
            return True
    except Exception:
        log_ignored_exception()
    try:
        curved_decode = getattr(cv2.QRCodeDetector(), 'detectAndDecodeCurved', None)
        if curved_decode is not None:
            decoded_qrcode, _, _ = curved_decode(candidate)
            add_unique_qr_payload(payloads, seen_payloads, decoded_qrcode)
    except Exception:
        log_ignored_exception()
    return bool(payloads)


def hard_scan_scaled_crop_candidates(gray_image):
    height, width = gray_image.shape[:2]
    crop_size = int(min(height, width) * 0.62)
    if crop_size < 140:
        return
    for y_fraction in (0.35, 0.5, 0.65):
        for x_fraction in (0.3, 0.5, 0.7):
            left = int(round(width * x_fraction - crop_size / 2))
            top = int(round(height * y_fraction - crop_size / 2))
            left = min(max(0, left), max(0, width - crop_size))
            top = min(max(0, top), max(0, height - crop_size))
            crop = gray_image[top:top + crop_size, left:left + crop_size]
            if crop.size == 0:
                continue
            target_width = max(crop.shape[1], 1200)
            target_height = max(1, int(round(crop.shape[0] * (target_width / crop.shape[1]))))
            if target_width > crop.shape[1]:
                yield 'hard crop zoom', cv2.resize(crop, (target_width, target_height), interpolation=cv2.INTER_CUBIC)
            yield 'hard crop', crop


def hard_scan_candidates(frame):
    yield 'hard raw', frame
    try:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if len(frame.shape) == 3 else frame
    except Exception:
        gray = frame
    yield 'hard gray', gray
    try:
        yield 'hard flipped', cv2.flip(frame, 1)
        yield 'hard flipped gray', cv2.flip(gray, 1)
    except Exception:
        log_ignored_exception()
    try:
        equalized = cv2.equalizeHist(gray)
        yield 'hard equalized', equalized
        _, thresholded = cv2.threshold(equalized, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        yield 'hard threshold', thresholded
    except Exception:
        log_ignored_exception()
    try:
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        yield 'hard clahe', clahe.apply(gray)
    except Exception:
        log_ignored_exception()
    try:
        blurred = cv2.GaussianBlur(gray, (0, 0), 1.0)
        yield 'hard sharpened', cv2.addWeighted(gray, 1.7, blurred, -0.7, 0)
    except Exception:
        log_ignored_exception()
    yield from hard_scan_scaled_crop_candidates(gray)


def hard_decode_qr_payloads(frame):
    payloads = []
    seen_payloads = set()
    for source, candidate in hard_scan_candidates(frame):
        before = len(payloads)
        add_opencv_qr_payloads(candidate, payloads, seen_payloads)
        if len(payloads) > before:
            return payloads, source
        add_zxing_qr_payloads(candidate, payloads, seen_payloads)
        if len(payloads) > before:
            return payloads, f'zxing {source}'
        add_pyzbar_qr_payloads(candidate, payloads, seen_payloads)
        if len(payloads) > before:
            return payloads, f'pyzbar {source}'
    return payloads, ''


def hard_scan_worker(frame, generation):
    started_at = time.perf_counter()
    try:
        payloads, source = hard_decode_qr_payloads(frame)
        elapsed_ms = int(round((time.perf_counter() - started_at) * 1000))
        qr_hard_scan_results.put((generation, payloads, source, None, elapsed_ms))
    except Exception as exc:
        elapsed_ms = int(round((time.perf_counter() - started_at) * 1000))
        qr_hard_scan_results.put((generation, [], '', exc, elapsed_ms))


def detection_is_paused():
    return time.monotonic() < qr_detection_paused_until


def pause_detection_after_accept(result):
    global qr_detection_paused_until, qr_hard_scan_generation, qr_hard_scan_inflight
    if result.get('accepted'):
        qr_detection_paused_until = time.monotonic() + QR_DETECTION_PAUSE_SECONDS
        qr_hard_scan_generation += 1
        qr_hard_scan_inflight = False


def apply_scanner_result(result, source_label=None):
    if result['accepted']:
        source = source_label or result.get('source', '')
        source_text = f" ({source})" if source and source != 'raw' else ''
        set_qr_scan_status(f'QR accepted{source_text}', IND_GREEN, hold_ms=QR_STATUS_RESULT_HOLD_MS)
    elif result['duplicate']:
        set_qr_scan_status('QR already scanned', IND_MUTED, hold_ms=QR_STATUS_RESULT_HOLD_MS)
    elif result['invalid']:
        source = source_label or result.get('source', '')
        source_text = f" via {source}" if source else ''
        set_qr_scan_status(f'QR seen, rejected{source_text}', IND_RED)
    else:
        set_qr_scan_status('Scanning...', IND_MUTED)
    pause_detection_after_accept(result)


def maybe_start_hard_scan(frame):
    global qr_hard_scan_inflight, qr_hard_scan_generation, qr_hard_scan_last_at
    now = time.monotonic()
    if qr_hard_scan_inflight or detection_is_paused() or now - qr_hard_scan_last_at < QR_HARD_SCAN_INTERVAL_SECONDS:
        return
    # Slow image transforms run in a worker; the live camera path stays responsive.
    qr_hard_scan_inflight = True
    qr_hard_scan_generation += 1
    qr_hard_scan_last_at = now
    threading.Thread(
        target=hard_scan_worker,
        args=(frame.copy(), qr_hard_scan_generation),
        daemon=True,
    ).start()


def drain_hard_scan_results():
    global qr_hard_scan_inflight
    while True:
        try:
            generation, payloads, source, error, elapsed_ms = qr_hard_scan_results.get_nowait()
        except queue.Empty:
            break
        if generation != qr_hard_scan_generation:
            # A newer scan/cancel happened; ignore stale worker results.
            continue
        qr_hard_scan_inflight = False
        if detection_is_paused():
            continue
        if error is not None:
            continue
        result = process_qr_payloads(
            payloads,
            suppress_repeated_invalid=True,
            show_invalid_errors=False,
        )
        if result['found']:
            apply_scanner_result(result, f'{source} {elapsed_ms}ms'.strip())


webcam_scanner_img = None


def ensure_webcam_scanner_image():
    global webcam_scanner_img
    if webcam_scanner_img is None:
        try:
            with Image.open(source_asset_image_path('pop_up', 'qr_overlay')) as overlay:
                resized = overlay.convert('RGBA').resize(
                    (px(CLAIM_SCANNER_WIDTH), px(CLAIM_SCANNER_HEIGHT)),
                    Image.Resampling.LANCZOS,
                )
            webcam_scanner_img = ImageTk.PhotoImage(resized)
        except Exception:
            webcam_scanner_img = ''
    return webcam_scanner_img


def restore_webcam_scanner_prompt():
    image = ensure_webcam_scanner_image()
    if image:
        webcam_scanner.config(image=image, text='', cursor='hand2', bd=0, highlightthickness=0)
    else:
        webcam_scanner.config(image='', text=GUI_TEXT['qr_drop'], cursor='hand2', bd=1, highlightthickness=1)
    set_qr_scan_status('Click to scan or drop QR image', IND_MUTED)


def stop_qr_scan():
    global num_of_times_clicked, cap, qr_hard_scan_generation, qr_hard_scan_inflight, qr_scan_status_hold_until
    num_of_times_clicked = 0
    qr_hard_scan_generation += 1
    qr_hard_scan_inflight = False
    qr_scan_status_hold_until = 0.0
    restore_webcam_scanner_prompt()
    show_scanned_serials_list()
    if cap is not None:
        cap.release()
        cap = None
        cv2.destroyAllWindows()


def select_qr_image():
    filename = filedialog.askopenfilename(title='Find QR image', initialdir='quickaccess',
                                          filetypes=(('png files', '*.png'), ('all files', '*.*')))
    if not filename:
        show_scanned_serials_list()
        return
    try:
        img_e = Image.open(filename)
        img_explorer_resize = img_e.resize(
            (px(CLAIM_SCANNER_WIDTH), px(CLAIM_SCANNER_HEIGHT)),
            Image.Resampling.LANCZOS,
        )
        img_explorer = ImageTk.PhotoImage(img_explorer_resize)
        webcam_scanner.config(image=img_explorer)
        webcam_scanner.img_explorer = img_explorer
        result = qr_decoder(img_e)
        update_qr_decode_status(result)
        if not result['found']:
            messagebox.showinfo('No QR code found', 'No QR code was found in the selected image.')
        show_scanned_serials_list()
    except Exception as exc:
        restore_webcam_scanner_prompt()
        show_scanned_serials_list()
        show_error_popup('QR image failed', exc)


def fallback_to_qr_image_picker(error):
    messagebox.showinfo(
        'Webcam unavailable',
        'The webcam could not be opened or stopped returning images.\n\n'
        'Choose a QR image file instead.\n\n'
        f'Details: {error_detail(error)}'
    )
    select_qr_image()


def qr_scan():
    """Toggle live webcam scanning; image-file and drag/drop paths share the decoder."""

    global num_of_times_clicked, cap, reported_invalid_qr_codes
    global qr_hard_scan_generation, qr_hard_scan_inflight, qr_hard_scan_last_at, qr_detection_paused_until
    global qr_scan_status_hold_until
    num_of_times_clicked += 1
    webcam_scanner.config(cursor='watch')
    if (num_of_times_clicked % 2) != 0:
        reported_invalid_qr_codes = set()
        qr_hard_scan_generation += 1
        qr_hard_scan_inflight = False
        qr_hard_scan_last_at = 0.0
        qr_detection_paused_until = 0.0
        qr_scan_status_hold_until = 0.0
        while not qr_hard_scan_results.empty():
            try:
                qr_hard_scan_results.get_nowait()
            except queue.Empty:
                break
        show_scanned_serials_list()
        raise_widget(webcam_scanner)
        raise_widget(qr_scan_status)
        set_qr_scan_status('Starting webcam...', IND_MUTED)
        # OpenCV backend selection avoids long startup delays on Windows/Linux.
        if platform.system() == 'Windows':
            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        elif platform.system() == 'Linux':
            cap = cv2.VideoCapture(0, cv2.CAP_V4L2)
        else:
            cap = cv2.VideoCapture(0)
        webcam_scanner.config(cursor='hand2')
        set_qr_scan_status('Scanning...', IND_MUTED)

    def loop():
        try:
            # Each frame does a cheap decode first; heavier retries are queued above.
            ok, frame = cap.read()
            if not ok or frame is None:
                raise RuntimeError("The webcam stopped returning images.")
            cropped = frame[0:px(CLAIM_SCANNER_HEIGHT), 0:px(CLAIM_SCANNER_WIDTH)]
            cv2image = cv2.cvtColor(cropped, cv2.COLOR_BGR2RGBA)
            qr_pic = Image.fromarray(cv2image)
            imgtk = ImageTk.PhotoImage(image=qr_pic)
            webcam_scanner.imgtk = imgtk
            webcam_scanner.config(image=imgtk)
            drain_hard_scan_results()
            if not detection_is_paused():
                result = qr_decoder(frame, suppress_repeated_invalid=True, live=True, show_invalid_errors=False)
                apply_scanner_result(result)
                maybe_start_hard_scan(frame)
            if (num_of_times_clicked % 2) != 0:
                webcam_scanner.after(10, loop)
        except Exception:
            stop_qr_scan()
            select_qr_image()

    if (num_of_times_clicked % 2) != 0:
        loop()
    else:
        stop_qr_scan()

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

qr_scan_status = Label(
    root,
    text='Click to scan or drop QR image',
    font=app_font(16),
    fg=IND_MUTED,
    bg=IND_BLACK,
    bd=0,
    highlightthickness=0,
)

claim_background_overlay = Frame(
    root,
    bg=IND_BLACK,
    bd=0,
    highlightthickness=0,
)

claim_border_top = Frame(root, bg=IND_WHITE, bd=0, highlightthickness=0)
claim_border_left = Frame(root, bg=IND_WHITE, bd=0, highlightthickness=0)
claim_border_right = Frame(root, bg=IND_WHITE, bd=0, highlightthickness=0)
claim_border_bottom = Frame(root, bg=IND_WHITE, bd=0, highlightthickness=0)
claim_border_widgets = (
    (claim_border_top, 0, CLAIM_HEADER_BORDER_Y, APP_BASE_WIDTH, CLAIM_HEADER_BORDER_HEIGHT),
    (claim_border_left, 0, CLAIM_BACKGROUND_Y, CLAIM_BORDER_WIDTH, CLAIM_BACKGROUND_HEIGHT),
    (
        claim_border_right,
        APP_BASE_WIDTH - CLAIM_BORDER_WIDTH,
        CLAIM_BACKGROUND_Y,
        CLAIM_BORDER_WIDTH,
        CLAIM_BACKGROUND_HEIGHT,
    ),
    (claim_border_bottom, 0, CLAIM_BOTTOM_BORDER_Y, APP_BASE_WIDTH, CLAIM_BORDER_WIDTH),
)

claim_left_separator = Frame(root, bg='#303030', bd=0, highlightthickness=0)
claim_right_separator = Frame(root, bg='#303030', bd=0, highlightthickness=0)

scanned_serials_overlay = Frame(
    root,
    bg=IND_BLACK,
    bd=0,
    highlightthickness=0,
)

scanned_serials_title = Label(
    scanned_serials_overlay,
    text=GUI_TEXT['claim_serials_title'],
    font=app_font(18),
    fg=IND_WHITE,
    bg=IND_BLACK,
    bd=0,
    highlightthickness=0,
    anchor='w',
)

scanned_serials_subtitle = Label(
    scanned_serials_overlay,
    text=GUI_TEXT['claim_serials_subtitle'],
    font=app_font(14),
    fg=IND_MUTED,
    bg=IND_BLACK,
    bd=0,
    highlightthickness=0,
    anchor='w',
)

scanned_serials_list = Listbox(
    scanned_serials_overlay,
    font=app_font(18),
    fg=IND_WHITE,
    bg='#050505',
    selectforeground=IND_WHITE,
    selectbackground='#1f1f1f',
    activestyle='none',
    bd=0,
    highlightthickness=1,
    highlightbackground='#303030',
    highlightcolor='#303030',
    cursor='',
    exportselection=False,
)

scanned_serials_empty = Label(
    scanned_serials_overlay,
    text=GUI_TEXT['claim_serials_empty'],
    font=app_font(18),
    fg=IND_PENDING,
    bg='#050505',
    bd=0,
    highlightthickness=1,
    highlightbackground='#303030',
    highlightcolor='#303030',
    anchor='center',
    justify='center',
)

claim_ready_title = Label(
    root,
    text=GUI_TEXT['claim_ready_title'],
    font=app_font(30),
    fg=IND_WHITE,
    bg=IND_BLACK,
    bd=0,
    highlightthickness=0,
    anchor='w',
)

claim_total_label = Label(
    root,
    text=GUI_TEXT['claim_total_label'],
    font=app_font(16),
    fg=IND_MUTED,
    bg='#050505',
    bd=0,
    highlightthickness=1,
    highlightbackground='#303030',
    highlightcolor='#303030',
    anchor='center',
)

claim_count_label = Label(
    root,
    text=GUI_TEXT['claim_count_label'],
    font=app_font(16),
    fg=IND_MUTED,
    bg='#050505',
    bd=0,
    highlightthickness=1,
    highlightbackground='#303030',
    highlightcolor='#303030',
    anchor='center',
)


def drop(event):
    try:
        qr_path = event.data.strip('{}')
        qr_path_tk = Image.open(qr_path)
        resized = qr_path_tk.resize(
            (px(CLAIM_SCANNER_WIDTH), px(CLAIM_SCANNER_HEIGHT)),
            Image.Resampling.LANCZOS,
        )
        drag_and_drop_img = ImageTk.PhotoImage(resized)
        webcam_scanner.drag_and_drop_img = drag_and_drop_img
        webcam_scanner.config(image=drag_and_drop_img)
        result = qr_decoder(qr_path_tk)
        update_qr_decode_status(result)
        if not result['found']:
            messagebox.showinfo('No QR code found', 'No QR code was found in the dropped image.')
        show_scanned_serials_list()
    except Exception as exc:
        restore_webcam_scanner_prompt()
        show_scanned_serials_list()
        show_error_popup('QR image failed', exc)

webcam_scanner.drop_target_register(DND_FILES)
webcam_scanner.dnd_bind('<<Drop>>', drop)
scanned_serials_list.bind('<Button-1>', lambda event: 'break')

button = Button(root, command=node_terminal_button, text='Node Terminal', bg='black', fg='white',
                font=app_font(24), cursor='hand2', bd=0, activebackground='white', highlightthickness=0,)
place_header_button(button, 577, 100, 169, 50)

button2 = Button(root, command=info_button, text='Information', bg='black', fg='white', font=app_font(24),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
place_header_button(button2, 750, 100, 169, 50)

button3 = Button(root, command=print_page_button, text='Print', bg='black', fg='white', font=app_font(24),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
place_header_button(button3, 923, 100, 169, 50)

button4 = Button(root, command=wallet_button, text='Wallet', bg='black', fg='white', font=app_font(24),
                 cursor='hand2', bd=0, activebackground='white', highlightthickness=0)
place_header_button(button4, 1096, 100, 114, 50)

button_settings = make_text_button('Settings', settings_button, font_size=22, bg=IND_BLACK, fg=IND_WHITE,
                                   bd=1, relief=SOLID)
place_header_button(button_settings, 1016, 18, 94, 64)

button6 = make_asset_button('different_buttons', 'sign_in_button', sign_in_button, 'Sign\nin', font_size=22,
                            bg=IND_WHITE, fg=IND_BLACK)
place_header_button(button6, 1120, 18, 77, 64)
international_dollar.lift()
logo.lift()


def on_closing():
    """Persist unlocked wallet state and stop child processes before closing."""

    errors = []
    run_on_startup = 'NO'
    run_in_background = 'NO'
    try:
        _node_class, run_on_startup, run_in_background = runtime_json.read_node_config()
        if run_in_background == 'NO':
            runtime_json.set_kill_node(True)
            stop_node_process()
            stop_transparency_operator()
    except Exception as exc:
        errors.append(f"Could not read node settings: {error_detail(exc)}")

    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        if wallet_path.name.startswith('wallet_decrypted'):
            address = runtime_json.wallet_address_from_name(wallet_path.name)
            try:
                w = runtime_json.read_decrypted_wallet_payload(wallet_path)
                runtime_json.write_decrypted_wallet(address, w)
                encrypted_record = {}
                for encrypted_path in runtime_json.iter_encrypted_wallet_files():
                    if runtime_json.wallet_address_from_name(encrypted_path.name) == address:
                        encrypted_record = runtime_json.read_encrypted_wallet_record(encrypted_path)
                        break
                try:
                    wallet_encryption.wallet_reencrypt_unlocked(address, w)
                except Exception as exc:
                    if encrypted_record.get("format") == "INDW2":
                        raise
                    legacy_lines = str(w).splitlines()
                    legacy_password = legacy_lines[3] if len(legacy_lines) > 3 else ""
                    if not legacy_password:
                        raise
                    runtime_json.write_wallet_generation_from_payload(w)
                    wallet_encryption.wallet_encrypt(legacy_password)
                runtime_json.clear_decrypted_wallet(address)
                runtime_json.clear_wallet_generation()
            except Exception as exc:
                errors.append(f"Could not save wallet {address}: {error_detail(exc)}")
            finally:
                wallet_decryption.secure_delete(wallet_path)

    try:
        wallet_decryption.clear_plaintext_wallet_files(clear_memory=not errors)
        runtime_json.clear_passphrase_request()
        runtime_json.set_check_signed_in(False)
    except Exception as exc:
        errors.append(f"Could not lock wallet session: {error_detail(exc)}")

    try:
        if run_on_startup == 'NO' and 'bat_path' in globals():
            os.remove(bat_path + '/ind_node.bat')
    except FileNotFoundError:
        pass
    except Exception as exc:
        errors.append(f"Could not update startup shortcut: {error_detail(exc)}")

    if errors:
        show_error_popup('Could not close safely', RuntimeError("\n".join(errors)))
        refresh_wallet_view()
        return
    root.destroy()


def restart_after_update():
    hide_root_window()
    on_closing()
    start_new_app_process()


root.protocol('WM_DELETE_WINDOW', on_closing)


def start_update_check_later():
    try:
        settings = ind_settings.load_security_settings(validate_production=False)
        if not ind_settings.update_check_on_startup(settings):
            return
        auto_update = importlib.import_module('ind.auto_update')
        auto_update.start_startup_update_check(root, BASE_DIR, restart_after_update)
    except Exception:
        log_ignored_exception()
def run():
    show_root_when_ready()
    root.after(1000, start_update_check_later)
    mainloop()


if __name__ == "__main__":
    run()
