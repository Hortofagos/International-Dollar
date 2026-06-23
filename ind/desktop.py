# Tk desktop interface for wallet, node, print, claim, and settings workflows.

import contextlib
import getpass
import importlib
import json
import logging
import os
import platform
import queue
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
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
    Toplevel,
    filedialog,
)
from tkinter import font as tkfont
from tkinter import (
    mainloop,
    messagebox,
)

from tkinterdnd2 import DND_FILES, TkinterDnD

from . import node_services
from . import runtime as runtime_json
from . import settings as ind_settings

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


# Delay heavyweight imports until the GUI path actually needs them.
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
zxingcpp = LazyModule('zxingcpp')
sender_node = LazyModule('ind.sender_node', lambda module: module.ensure_runtime_files())
ind_token = LazyModule('ind.token')
protocol_v3 = LazyModule('ind.protocol_v3')
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
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_SET_VALUE
        ) as font_key:
            winreg.SetValueEx(
                font_key, font_family + ' (TrueType)', 0, winreg.REG_SZ, str(installed_path)
            )
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
            subprocess.run(
                ['fc-cache', '-f', str(fonts_dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
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
SIGN_IN_WALLET_DROPDOWN_ROWS = 8
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
PRINT_STATUS_X = PRINT_ACTION_STRIP_X + 24
PRINT_STATUS_Y = PRINT_ACTION_STRIP_Y + 21
PRINT_STATUS_WIDTH = 622
PRINT_STATUS_HEIGHT = 38
PRINT_PROGRESS_X = PRINT_STATUS_X
PRINT_PROGRESS_Y = PRINT_ACTION_STRIP_Y + 70
PRINT_PROGRESS_WIDTH = PRINT_STATUS_WIDTH
PRINT_PROGRESS_HEIGHT = 7
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
GENERATE_WALLET_SIDE_BUTTON_X = (
    GENERATE_WALLET_FIELD_X + GENERATE_WALLET_FIELD_WIDTH + GENERATE_WALLET_BUTTON_GAP
)
GENERATE_WALLET_SUBMIT_BUTTON_X = (
    GENERATE_WALLET_PANEL_LEFT
    + (GENERATE_WALLET_PANEL_WIDTH - GENERATE_WALLET_SUBMIT_BUTTON_WIDTH) // 2
)
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
CLAIM_CLOSE_X = (
    CLAIM_RIGHT_SECTION_X + CLAIM_RIGHT_SECTION_WIDTH - CLAIM_RIGHT_PADDING - CLAIM_CLOSE_WIDTH
)
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
    'node_labels': (
        'Node class:',
        'Run on startup:',
        'Run in background:',
        'Transparency operator:',
    ),
    'node_forwarding': (
        'If you are running a public node make sure to\n'
        f'forward TCP port {ind_settings.node_port()} to your local machine\n'
        'via your router terminal.'
    ),
    'node_description': (
        'A node keeps the IND gossip network alive: it accepts peer\n'
        'connections, relays transfers, stores local bill\n'
        'state, and forwards double-spend proofs.'
    ),
    'node_operator_description': (
        'Transparency operator mode runs the local public transfer log.\n'
        'It appends validated transfer hashes and publishes signed roots.'
    ),
    'info_features': (
        'No miner voting',
        '33 Billion max supply',
        'Bearer bills',
        'Signed transfers',
        'Owner sync',
        'Double-spend proofs',
    ),
    'info_title': 'IND Basics',
    'info_body': (
        'IND is a fixed-supply bearer-bill network. There is no mining,\n'
        'staking, or blockchain consensus.\n\n'
        f'Supply is capped at {INFO_MAX_SUPPLY} IND. Genesis defines the full\n'
        'supply map with an issuer-signed native V3 manifest and auditable\n'
        'genesis references.\n\n'
        'Each bill has its own owner history. V3 transfers are Ed25519-signed\n'
        'over canonical binary preimages, with proof bundles for old history.\n\n'
        'Desktop nodes gossip transfers and double-spend proofs.\n'
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
    'success_title': 'Wallet generated',
    'success_body': 'Save this password before signing in.',
    'success_password_label': 'Wallet password',
    'success_password_helper': 'Copy it. Store it safely.',
    'success_warning_title': 'No password = no wallet',
    'success_warning': 'IND cannot recover it. If you lose it, this wallet stays locked.',
    'success_not_saved_warning': (
        'Copy it first, then save it somewhere secure.'
    ),
    'success_copy_button': 'Copy',
    'success_saved_button': 'Saved securely',
    'success_not_saved_button': 'Not saved yet',
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


# Return a readable one-line error for wallet action popups.
def error_detail(error):
    if isinstance(error, Exception):
        message = str(error).strip()
        if message:
            return f"{error.__class__.__name__}: {message}"
        return error.__class__.__name__
    return str(error).strip() or "Unknown error"


# Show a simple error popup, safely scheduling it from worker threads.
def show_error_popup(title, error):
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


WALLET_VIEW_REFRESH_DELAY_MS = 400
wallet_view_refresh_after_id = None


# Refresh visible wallet state and report refresh failures.
def refresh_wallet_view():
    if not receiver_history.winfo_ismapped():
        return
    try:
        clear_wallet_record_cache()
        update_balance()
        page()
    except Exception as exc:
        show_error_popup('Wallet refresh failed', exc)


def _run_scheduled_wallet_view_refresh():
    global wallet_view_refresh_after_id
    wallet_view_refresh_after_id = None
    refresh_wallet_view()


def schedule_wallet_view_refresh(delay_ms=WALLET_VIEW_REFRESH_DELAY_MS):
    global wallet_view_refresh_after_id
    if wallet_view_refresh_after_id is not None:
        return
    try:
        wallet_view_refresh_after_id = root.after(
            max(1, int(delay_ms)),
            _run_scheduled_wallet_view_refresh,
        )
    except Exception:
        log_ignored_exception()


def flush_wallet_view_refresh():
    global wallet_view_refresh_after_id
    after_id = wallet_view_refresh_after_id
    wallet_view_refresh_after_id = None
    if after_id is not None:
        try:
            root.after_cancel(after_id)
        except Exception:
            log_ignored_exception()
    refresh_wallet_view()


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


# Raise a Tk widget window, avoiding Canvas item-raise method collisions.
def raise_widget(widget):
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


def canvas_text(
    canvas, x, y, text, size, fill=IND_WHITE, anchor='nw', justify='left', weight=None, width=None
):
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
        self.create_rectangle(
            px(x1), px(y1), px(x2), px(y2), fill=fill, outline=outline, width=px(width)
        )

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

    # Draw the node control page around separately placed live widgets.
    def draw_node_terminal(self):
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
        for x, width, _label in (
            (300, 120, 'TCP'),
            (430, 100, 'Peers'),
            (540, 112, 'Events'),
            (662, 132, 'Operator'),
        ):
            self.rect(
                x,
                NODE_STATUS_Y + 14,
                x + width,
                NODE_STATUS_Y + 44,
                fill=NODE_CHIP_BG,
                outline=NODE_CHIP_BORDER,
                width=1,
            )

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
        self.line(
            NODE_SETUP_X + 20,
            NODE_PANEL_Y + 54,
            NODE_SETUP_X + NODE_SETUP_WIDTH - 20,
            NODE_PANEL_Y + 54,
            color='#313a36',
            width=1,
        )
        for y, label, helper in (
            (NODE_PANEL_Y + 68, 'Node class', 'gossip network role'),
            (NODE_PANEL_Y + 138, 'PC startup', 'launch when this PC starts'),
            (NODE_PANEL_Y + 208, 'Background', 'keep running after close'),
            (NODE_PANEL_Y + 278, 'Transparency', 'operator transfer log'),
        ):
            canvas_text(self, NODE_SETUP_X + 22, y, label, 20)
            canvas_text(self, NODE_SETUP_X + 22, y + 26, helper, 13, fill=IND_MUTED, width=145)
        self.rect(
            NODE_SETUP_X + 178,
            NODE_PANEL_Y + 72,
            NODE_SETUP_X + NODE_SETUP_WIDTH - 22,
            NODE_PANEL_Y + 108,
            fill=IND_BLACK,
            outline=IND_WHITE,
            width=1,
        )
        for y in (NODE_PANEL_Y + 142, NODE_PANEL_Y + 212, NODE_PANEL_Y + 282):
            self.rect(
                NODE_SETUP_X + 178,
                y,
                NODE_SETUP_X + NODE_SETUP_WIDTH - 22,
                y + 36,
                fill=IND_BLACK,
                outline=IND_WHITE,
                width=1,
            )
        self.line(
            NODE_SETUP_X + 20,
            NODE_PANEL_Y + 334,
            NODE_SETUP_X + NODE_SETUP_WIDTH - 20,
            NODE_PANEL_Y + 334,
            color='#313a36',
            width=1,
        )
        canvas_text(self, NODE_SETUP_X + 22, NODE_PANEL_Y + 350, 'Port forwarding', 20)
        self.rect(
            300,
            NODE_PANEL_Y + 354,
            374,
            NODE_PANEL_Y + 382,
            fill=IND_BLACK,
            outline=IND_WHITE,
            width=1,
        )
        canvas_text(
            self,
            NODE_SETUP_X + 22,
            NODE_PANEL_Y + 388,
            f'Open TCP port {ind_settings.node_port()} on your router/firewall',
            16,
            fill=IND_MUTED,
        )
        canvas_text(
            self,
            NODE_SETUP_X + 22,
            NODE_PANEL_Y + 414,
            'so external peers can reach this node.',
            16,
            fill=IND_MUTED,
        )

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
        self.line(
            NODE_CONSOLE_X,
            NODE_PANEL_Y + NODE_CONSOLE_HEADER_HEIGHT,
            NODE_CONSOLE_X + NODE_CONSOLE_WIDTH,
            NODE_PANEL_Y + NODE_CONSOLE_HEADER_HEIGHT,
            color='#313a36',
            width=1,
        )
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
        canvas_text(
            self, 1093, 449, GUI_TEXT['info_supply_amount'], 22, anchor='n', justify='center'
        )
        canvas_text(
            self, 1093, 492, GUI_TEXT['info_supply_label'], 24, anchor='n', justify='center'
        )
        canvas_text(self, 1093, 620, GUI_TEXT['info_inflation'], 43, anchor='n', justify='center')

    # Draw the paper-bill printing workflow shell.
    def draw_print_page(self):
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
        canvas_text(
            self,
            PRINT_AVAILABLE_X,
            PRINT_PANEL_Y + 30,
            GUI_TEXT['print_available_label'],
            23,
            weight='bold',
        )
        self.line(
            PRINT_AVAILABLE_X,
            PRINT_PANEL_Y + 86,
            PRINT_LEFT_PANEL_X + PRINT_LEFT_PANEL_WIDTH - 24,
            PRINT_PANEL_Y + 86,
            color='#333c3b',
            width=1,
        )
        canvas_text(
            self,
            PRINT_QUEUE_X,
            PRINT_PANEL_Y + 30,
            GUI_TEXT['print_queue_label'],
            23,
            weight='bold',
        )
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
        canvas_text(
            self, PRINT_QUEUE_X + 210, PRINT_OUTPUT_FULL_Y + 2, '6 per sheet', 14, fill=IND_MUTED
        )
        canvas_text(
            self, PRINT_QUEUE_X + 210, PRINT_OUTPUT_QR_Y + 2, 'backup print', 14, fill=IND_PENDING
        )
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

    def draw_wallet(self):
        self.line(825, 151, 825, APP_BASE_HEIGHT)
        canvas_text(
            self,
            1020,
            138 + WALLET_SEND_Y_OFFSET,
            GUI_TEXT['wallet_send_title'],
            30,
            anchor='n',
            justify='center',
        )
        canvas_text(self, 852, 176 + WALLET_SEND_Y_OFFSET, GUI_TEXT['wallet_receiver_label'], 22)
        canvas_text(self, 852, 257 + WALLET_SEND_Y_OFFSET, GUI_TEXT['wallet_amount_label'], 22)
        canvas_text(
            self, 1024, 420, GUI_TEXT['wallet_receive_title'], 30, anchor='n', justify='center'
        )

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
            field_label(
                SETTINGS_ROW_COLS[1], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_require_log']
            )
            field_label(
                SETTINGS_ROW_COLS[2], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_security_profile']
            )
            field_label(
                SETTINGS_ROW_COLS[3], SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_untrusted_genesis']
            )
            separator(SETTINGS_DIVIDER_Y)
            field_label(SETTINGS_TWO_COL_LEFT, SETTINGS_BOTTOM_LABEL_Y, 'Trusted issuer keys')
            field_label(SETTINGS_TWO_COL_RIGHT, SETTINGS_BOTTOM_LABEL_Y, 'Trusted manifest hashes')
        elif settings_active_tab == SETTINGS_TAB_TRANSPARENCY:
            field_label(
                SETTINGS_TWO_COL_LEFT, SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_operator_url']
            )
            field_label(
                SETTINGS_TWO_COL_RIGHT, SETTINGS_TOP_LABEL_Y, GUI_TEXT['settings_operator_key']
            )
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
            field_label(
                SETTINGS_CONTENT_X, SETTINGS_BOTTOM_LABEL_Y, GUI_TEXT['settings_update_status']
            )

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
            canvas_text(
                self, 607, 297, GUI_TEXT['signin_wallet_label'], 28, anchor='n', justify='center'
            )
            canvas_text(
                self, 607, 442, GUI_TEXT['signin_password_label'], 28, anchor='n', justify='center'
            )

    def draw_sign_in(self):
        self.draw_sign_in_panel(generate=False)

    def draw_generate_wallet(self):
        self.draw_sign_in_panel(generate=True)


# Renderer for small modal surfaces that still use the app canvas style.
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
        if self.modal_name != 'claim':
            self.create_rectangle(
                px(1),
                px(1),
                px(self.width - 1),
                px(self.height - 1),
                outline=IND_WHITE,
                width=px(2),
                fill=self['bg'],
            )
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
            self.create_rectangle(
                px(1),
                px(1),
                px(self.width - 1),
                px(self.height - 1),
                outline='#d9ffe5',
                width=px(2),
                fill=SUCCESS_POPUP_BG,
            )
            self.create_rectangle(
                px(32),
                px(18),
                px(self.width - 32),
                px(140),
                outline='#62d286',
                width=px(1),
                fill=SUCCESS_POPUP_DARK_BG,
            )
            self.create_rectangle(
                px(32),
                px(140),
                px(self.width - 32),
                px(141),
                outline='#13ad5b',
                fill='#13ad5b',
            )
            self.create_oval(
                px(52),
                px(49),
                px(106),
                px(103),
                fill='#f3fff7',
                outline='#b7f2c7',
                width=px(2),
            )
            self.create_line(
                px(66),
                px(76),
                px(78),
                px(91),
                px(94),
                px(64),
                fill=SUCCESS_POPUP_BG,
                width=px(5),
            )
            canvas_text(
                self,
                128,
                38,
                GUI_TEXT['success_title'],
                43,
            )
            canvas_text(
                self,
                130,
                91,
                GUI_TEXT['success_body'],
                21,
                fill='#dcffe7',
            )
            canvas_text(
                self,
                32,
                168,
                GUI_TEXT['success_password_label'],
                23,
                fill='#edfff2',
            )
            canvas_text(
                self,
                33,
                195,
                GUI_TEXT['success_password_helper'],
                17,
                fill='#c7f7d5',
            )
            self.create_rectangle(
                px(32),
                px(224),
                px(self.width - 32),
                px(286),
                outline='#c7f6d3',
                width=px(1),
                fill='#f4fff7',
            )
            self.create_rectangle(
                px(32),
                px(310),
                px(self.width - 32),
                px(402),
                outline='#62d286',
                width=px(1),
                fill=SUCCESS_POPUP_WARNING_BG,
            )
            self.create_rectangle(
                px(32),
                px(310),
                px(40),
                px(402),
                outline=SUCCESS_POPUP_RED,
                fill=SUCCESS_POPUP_RED,
            )
            canvas_text(
                self,
                56,
                316,
                GUI_TEXT['success_warning_title'],
                22,
            )
        elif self.modal_name == 'valid':
            canvas_text(
                self,
                self.width / 2,
                self.height / 2,
                'Valid',
                44,
                anchor='center',
                justify='center',
            )
        elif self.modal_name == 'not_valid':
            canvas_text(
                self,
                self.width / 2,
                self.height / 2,
                'Not valid',
                44,
                anchor='center',
                justify='center',
            )


def make_text_button(
    text,
    command,
    font_size=24,
    bg=IND_GREEN,
    fg='white',
    font_weight=None,
    bd=0,
    relief=FLAT,
    master=None,
):
    font = app_font(font_size, font_weight)
    button_master = master or root
    return Button(
        button_master,
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


# Image button that redraws bitmap assets at the active UI scale.
class ScaledAssetButton(Button):
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


def make_asset_button(
    folder, name, command, fallback_text, font_size=18, bg=IND_BLACK, fg=IND_WHITE, master=None
):
    button_master = master or root
    try:
        return ScaledAssetButton(button_master, source_asset_image_path(folder, name), command, bg=bg)
    except Exception:
        return make_text_button(
            fallback_text,
            command,
            font_size=font_size,
            bg=bg,
            fg=fg,
            bd=1,
            relief=SOLID,
            master=button_master,
        )


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


active_wallet_address = ""


def normalized_wallet_address(address):
    return str(address or "").strip()


def selected_wallet_address():
    selected = normalized_wallet_address(active_wallet_address)
    if selected:
        return selected
    address_var = globals().get('address_variable')
    if address_var is None:
        return ""
    try:
        return normalized_wallet_address(address_var.get())
    except Exception:
        log_ignored_exception()
        return ""


def reset_wallet_view_state():
    global page_wallet, wallet_history_cached_entries
    if 'clear_wallet_record_cache' in globals():
        clear_wallet_record_cache()
    if 'wallet_history_cached_entries' in globals():
        wallet_history_cached_entries = []
    if 'page_wallet' in globals():
        page_wallet = 1


def set_active_wallet_address(address):
    global active_wallet_address
    address = normalized_wallet_address(address)
    if address != active_wallet_address:
        active_wallet_address = address
        reset_wallet_view_state()
    else:
        active_wallet_address = address
        if 'clear_wallet_record_cache' in globals():
            clear_wallet_record_cache()


# Return the selected active decrypted wallet lines, if that wallet is unlocked.
def active_wallet_path():
    active_address = selected_wallet_address()
    if active_address:
        for wallet_path in runtime_json.iter_decrypted_wallet_files():
            if runtime_json.wallet_address_from_name(wallet_path.name) == active_address:
                return wallet_path
        return None
    for wallet_path in runtime_json.iter_decrypted_wallet_files():
        return wallet_path
    return None


def read_active_wallet_context(wallet_path=None):
    wallet_path = wallet_path or active_wallet_path()
    if wallet_path is None:
        return [], None
    return runtime_json.read_decrypted_wallet_lines(wallet_path), wallet_path


def update_wallet():
    dr_w, _wallet_path = read_active_wallet_context()
    return dr_w, len(dr_w)


def wallet_is_unlocked():
    return active_wallet_path() is not None


def wallet_store_paths():
    paths = []
    try:
        paths.append(ind_settings.default_store_path())
    except Exception:
        log_ignored_exception()
    for path in getattr(ind_settings, "DEFAULT_STORE_PATHS", {}).values():
        paths.append(path)
    unique = []
    seen = set()
    for path in paths:
        text = str(path).strip()
        if text and text not in seen:
            unique.append(text)
            seen.add(text)
    return unique


def wallet_store_for_address(wallet_address):
    fallback = None
    for store_path in wallet_store_paths():
        try:
            store = sender_node.wallet_sync_store(db_path=store_path)
            try:
                store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
            except Exception:
                log_ignored_exception()
            if fallback is None:
                fallback = store
            spendable = wallet_services.spendable_wallet_records(
                wallet_address, store=store, limit=1
            )
            pending = wallet_services.pending_wallet_records(wallet_address, store=store, limit=1)
            if spendable or pending:
                return store
        except Exception:
            log_ignored_exception()
    return fallback or sender_node.wallet_sync_store()


WALLET_RECORD_CACHE_TTL_SECONDS = 2.0
wallet_record_cache = None


def clear_wallet_record_cache():
    global wallet_record_cache
    wallet_record_cache = None


def wallet_file_cache_key(wallet_path):
    if wallet_path is None:
        return None
    try:
        stat = wallet_path.stat()
        return str(wallet_path), stat.st_mtime_ns, stat.st_size
    except Exception:
        log_ignored_exception()
        return str(wallet_path)


def wallet_records_snapshot(force_refresh=False):
    global wallet_record_cache
    wallet_path = active_wallet_path()
    wallet_address = runtime_json.wallet_address_from_name(wallet_path.name) if wallet_path else ""
    cache_key = (wallet_address, wallet_file_cache_key(wallet_path))
    now = time.monotonic()
    if not force_refresh and wallet_record_cache is not None:
        cached_key, cached_at, cached_snapshot = wallet_record_cache
        if cached_key == cache_key and now - cached_at <= WALLET_RECORD_CACHE_TTL_SECONDS:
            return cached_snapshot

    wallet_lines, wallet_path = read_active_wallet_context(wallet_path)
    wallet_address = wallet_lines[0].strip() if wallet_lines else wallet_address
    cache_key = (wallet_address, wallet_file_cache_key(wallet_path))
    snapshot = {
        "wallet_lines": wallet_lines,
        "wallet_path": wallet_path,
        "wallet_address": wallet_address,
        "store": None,
        "spendable_records": [],
        "pending_records": [],
    }
    if wallet_address:
        store = wallet_store_for_address(wallet_address)
        snapshot["store"] = store
        try:
            store.finalize_pending(buffer_seconds=ind_settings.finality_buffer_seconds())
        except Exception:
            log_ignored_exception()
        try:
            snapshot["spendable_records"] = wallet_services.spendable_wallet_records(
                wallet_address,
                store=store,
                limit=None,
            )
        except Exception:
            log_ignored_exception()
        try:
            snapshot["pending_records"] = wallet_services.pending_wallet_records(
                wallet_address,
                store=store,
                limit=None,
            )
        except Exception:
            log_ignored_exception()
    wallet_record_cache = (cache_key, now, snapshot)
    return snapshot


def wallet_spendable_records():
    snapshot = wallet_records_snapshot()
    return list(
        wallet_services.filter_locally_sent_records(
            snapshot["spendable_records"],
            snapshot["wallet_lines"],
        )
    )


def wallet_pending_records():
    return list(wallet_records_snapshot()["pending_records"])


def wallet_snapshot_store():
    if wallet_record_cache is not None:
        _cached_key, _cached_at, cached_snapshot = wallet_record_cache
        store = cached_snapshot.get("store")
        if store is not None:
            return store
        wallet_address = cached_snapshot.get("wallet_address", "")
    else:
        wallet_lines, _wallet_path = read_active_wallet_context()
        wallet_address = wallet_lines[0].strip() if wallet_lines else ""
    if not wallet_address:
        return None
    return wallet_store_for_address(wallet_address)


def wallet_record_value(record):
    try:
        return int(record.get("value"))
    except Exception:
        return wallet_services.wallet_display_value(record.get("display_id", ""))


def wallet_line_bill_counts():
    try:
        wallet_lines = wallet_records_snapshot()["wallet_lines"]
    except Exception:
        log_ignored_exception()
        return {value: 0 for value in BILL_VALUES}
    counts = {value: 0 for value in BILL_VALUES}
    for line in runtime_json.wallet_bill_lines(wallet_lines):
        value = wallet_services.wallet_owned_line_value(line)
        if value in counts:
            counts[value] += 1
    return counts


try:
    dr, num_lines = update_wallet()
except Exception:
    log_ignored_exception()

international_dollar = Text(
    root, font=app_font(45), bg='black', fg='white', bd=0, highlightthickness=0
)
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
        address_txt = Text(
            root, font=app_font(19), bg='black', fg='white', bd=0, highlightthickness=0
        )
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
ron.config(
    font=app_font(16, 'bold'),
    cursor='hand2',
    bg=IND_BLACK,
    fg=IND_WHITE,
    activebackground=NODE_HEADER_BG,
    activeforeground=IND_WHITE,
    bd=0,
    highlightthickness=0,
    relief=FLAT,
)
rons = root.nametowidget(ron.menuname)
rons.config(
    font=app_font(16),
    bg=IND_BLACK,
    fg=IND_WHITE,
    activebackground=NODE_HEADER_BG,
    activeforeground=IND_WHITE,
)
ron_var.set(l3)

bak_var = StringVar(root)
bak = OptionMenu(root, bak_var, 'YES', 'NO')
bak.config(
    font=app_font(16, 'bold'),
    cursor='hand2',
    bg=IND_BLACK,
    fg=IND_WHITE,
    activebackground=NODE_HEADER_BG,
    activeforeground=IND_WHITE,
    bd=0,
    highlightthickness=0,
    relief=FLAT,
)
baks = root.nametowidget(bak.menuname)
baks.config(
    font=app_font(16),
    bg=IND_BLACK,
    fg=IND_WHITE,
    activebackground=NODE_HEADER_BG,
    activeforeground=IND_WHITE,
)
bak_var.set(l4)

transparency_operator_var = StringVar(root)
transparency_operator = OptionMenu(root, transparency_operator_var, 'NO', 'YES')
transparency_operator.config(
    font=app_font(16, 'bold'),
    cursor='hand2',
    bg=IND_BLACK,
    fg=IND_WHITE,
    activebackground=NODE_HEADER_BG,
    activeforeground=IND_WHITE,
    bd=0,
    highlightthickness=0,
    relief=FLAT,
)
transparency_operators = root.nametowidget(transparency_operator.menuname)
transparency_operators.config(
    font=app_font(16),
    bg=IND_BLACK,
    fg=IND_WHITE,
    activebackground=NODE_HEADER_BG,
    activeforeground=IND_WHITE,
)
transparency_operator_var.set(l_operator)
transparency_operator_var.trace_add('write', lambda *_args: update_node_status_widgets())

try:
    USER_NAME = getpass.getuser()
    disk = os.path.realpath(__file__)[0]
    bat_path = f"{disk}:\\Users\\{USER_NAME}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
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
        node_status_dot.create_oval(
            px(2), px(2), px(12), px(12), fill=status_color, outline=status_color
        )
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
    if any(
        marker in text
        for marker in ('warning', 'warn ', 'rejected', 'invalid', 'rate_limited', 'failed', 'error')
    ):
        return 'WARN'
    if any(marker in text for marker in ('listening', 'starting', 'started', 'spawned')):
        return 'INFO'
    return 'NODE'


def node_log_category_for_line(line):
    text = line.lower()
    if any(
        marker in text
        for marker in ('gossip', 'transfer', 'double-spend', 'equivocation')
    ):
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
        del node_console_entries[: len(node_console_entries) - NODE_CONSOLE_MAX_ENTRIES]
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
        append_node_console(
            'COPY', f'TCP port {ind_settings.node_port()} copied to clipboard', 'node'
        )
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
        append_node_console(
            'OPER', f'local transparency log running on {LOCAL_OPERATOR_URL}', 'node'
        )
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


# Start the local gossip node and optional transparency operator from the GUI.
def start():
    runtime_json.write_node_config(
        'NODE', ron_var.get(), bak_var.get(), transparency_operator_var.get()
    )
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
            threading.Thread(
                target=read_node_process_output, args=(node_process,), daemon=True
            ).start()
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

start_button = make_asset_button(
    'different_buttons', 'start', start, 'Start', font_size=32, bg=IND_GREEN
)
end_button = make_asset_button('different_buttons', 'end', end, 'End', font_size=32, bg=IND_RED)

node_status_dot = Canvas(
    root, width=px(14), height=px(14), bg=NODE_PANEL_BG, bd=0, highlightthickness=0
)
node_status_title = Label(
    root,
    text='Node status',
    font=app_font(20, 'bold'),
    bg=NODE_PANEL_BG,
    fg=IND_WHITE,
    bd=0,
    highlightthickness=0,
    anchor='w',
)
node_status_value = Label(
    root,
    font=app_font(18, 'bold'),
    bg=NODE_PANEL_BG,
    fg=IND_RED,
    bd=0,
    highlightthickness=0,
    anchor='w',
)
node_port_label = Label(
    root,
    text='TCP',
    font=app_font(15),
    bg=NODE_CHIP_BG,
    fg=IND_MUTED,
    bd=0,
    highlightthickness=0,
    anchor='w',
)
node_port_value = Label(
    root, font=app_font(16), bg=NODE_CHIP_BG, fg='#5dd7ff', bd=0, highlightthickness=0, anchor='e'
)
node_peer_label = Label(
    root,
    text='Peers',
    font=app_font(15),
    bg=NODE_CHIP_BG,
    fg=IND_MUTED,
    bd=0,
    highlightthickness=0,
    anchor='w',
)
node_peer_value = Label(
    root, font=app_font(16), bg=NODE_CHIP_BG, fg=IND_WHITE, bd=0, highlightthickness=0, anchor='e'
)
node_event_label = Label(
    root,
    text='Events',
    font=app_font(15),
    bg=NODE_CHIP_BG,
    fg=IND_MUTED,
    bd=0,
    highlightthickness=0,
    anchor='w',
)
node_event_value = Label(
    root, font=app_font(16), bg=NODE_CHIP_BG, fg=IND_ORANGE, bd=0, highlightthickness=0, anchor='e'
)
node_operator_label = Label(
    root,
    text='Operator',
    font=app_font(15),
    bg=NODE_CHIP_BG,
    fg=IND_MUTED,
    bd=0,
    highlightthickness=0,
    anchor='w',
)
node_operator_value = Label(
    root, font=app_font(16), bg=NODE_CHIP_BG, fg=IND_MUTED, bd=0, highlightthickness=0, anchor='e'
)
node_class_value = Label(
    root,
    text='NODE',
    font=app_font(18),
    bg=IND_BLACK,
    fg='#5dd7ff',
    bd=0,
    highlightthickness=0,
    anchor='e',
)
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

node_copy_port_button = make_text_button(
    'Copy port', copy_node_port, font_size=16, bg=IND_BLACK, fg=IND_WHITE, bd=1, relief=SOLID
)
node_console_copy_button = make_text_button(
    'Copy', copy_node_console, font_size=16, bg=NODE_HEADER_BG, fg=IND_WHITE, bd=1, relief=SOLID
)
node_console_clear_button = make_text_button(
    'Clear', clear_node_console, font_size=16, bg=NODE_HEADER_BG, fg=IND_WHITE, bd=1, relief=SOLID
)
node_console_filter_buttons = {
    'all': make_text_button(
        'All',
        lambda: set_node_console_filter('all'),
        font_size=16,
        bg=IND_WHITE,
        fg=IND_BLACK,
        bd=1,
        relief=SOLID,
    ),
    'node': make_text_button(
        'Node',
        lambda: set_node_console_filter('node'),
        font_size=16,
        bg=NODE_HEADER_BG,
        fg=IND_WHITE,
        bd=1,
        relief=SOLID,
    ),
    'gossip': make_text_button(
        'Gossip',
        lambda: set_node_console_filter('gossip'),
        font_size=16,
        bg=NODE_HEADER_BG,
        fg=IND_WHITE,
        bd=1,
        relief=SOLID,
    ),
    'peer': make_text_button(
        'Peer',
        lambda: set_node_console_filter('peer'),
        font_size=16,
        bg=NODE_HEADER_BG,
        fg=IND_WHITE,
        bd=1,
        relief=SOLID,
    ),
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
    node_console_filter_buttons['all'].place(
        x=746 * reso, y=314 * reso, width=52 * reso, height=26 * reso
    )
    node_console_filter_buttons['node'].place(
        x=806 * reso, y=314 * reso, width=70 * reso, height=26 * reso
    )
    node_console_filter_buttons['gossip'].place(
        x=884 * reso, y=314 * reso, width=82 * reso, height=26 * reso
    )
    node_console_filter_buttons['peer'].place(
        x=974 * reso, y=314 * reso, width=64 * reso, height=26 * reso
    )
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
    option.config(
        font=app_font(font_size, 'bold'),
        cursor='hand2',
        bg=IND_BLACK,
        fg=IND_WHITE,
        activebackground=IND_WHITE,
        activeforeground=IND_BLACK,
        highlightthickness=0,
    )
    menu = root.nametowidget(option.menuname)
    menu.config(
        font=app_font(15),
        bg=IND_BLACK,
        fg=IND_WHITE,
        activebackground=IND_WHITE,
        activeforeground=IND_BLACK,
    )
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
        _set_entry_value(widget, f"AUTO ({ind_settings.node_port(settings)})")
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
settings_security_profile = make_settings_option(
    settings_security_profile_var, 'DEVELOPMENT', 'PRODUCTION'
)
settings_allow_untrusted_genesis_var = StringVar(root)
settings_allow_untrusted_genesis = make_settings_option(
    settings_allow_untrusted_genesis_var, 'NO', 'YES'
)
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
    _set_entry_value(
        settings_current_root_future_skew_entry, settings['current_root_future_skew_seconds']
    )
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
    settings.update(
        {
            'network': settings_network_var.get().strip().lower(),
            'node_port': node_port_value,
            'peer_ping_servers': _text_lines(settings_peer_servers),
            'dns_seed_hosts': _text_lines(settings_dns_seed_hosts),
            'trusted_root_domains': _text_lines(settings_root_domains),
            'trusted_root_mirrors': _text_lines(settings_root_mirrors),
            'trusted_genesis_issuer_keys': _text_lines(settings_genesis_issuer_keys),
            'trusted_genesis_manifest_hashes': _text_lines(settings_genesis_manifest_hashes),
            'transparency_operator_url': settings_operator_url_entry.get().strip(),
            'transparency_operator_public_key': '\n'.join(
                _text_lines(settings_operator_key)
            ).strip(),
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
        }
    )
    return settings


def save_security_settings_form(show_message=True):
    try:
        settings = ind_settings.save_security_settings(collect_security_settings_form())
        load_security_settings_form()
        if show_message:
            _set_settings_status(
                f"Saved. Bills settle after {settings['finality_buffer_seconds']} seconds; "
                f"{settings['min_root_mirrors']} Merkle mirror(s) required.",
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
            f"Reset to defaults. Bills settle after {settings['finality_buffer_seconds']} seconds.",
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
            _set_ping_status(
                '\n'.join(results), IND_GREEN if any('OK' in row for row in results) else IND_ORANGE
            )

        root.after(0, finish)

    threading.Thread(target=worker, daemon=True).start()


def _short_update_rev(rev):
    return rev[:12] if rev else 'unknown'


# Check the configured update source and offer an install when safe.
def run_manual_update_check():
    settings = save_security_settings_form(show_message=False)
    if settings is None:
        _set_update_status('Save failed; update not checked.', IND_RED)
        return
    settings_update_button.config(cursor='watch')
    _set_update_status(f"Checking {settings['update_source']}...", IND_MUTED)

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
            f"Source: {info.source}\n"
            f"Branch: {info.upstream_ref}\n"
            f"Current: {_short_update_rev(info.local_rev)}\n"
            f"Latest: {_short_update_rev(info.remote_rev)}"
        )
        if info.dirty:
            # Auto-update should not overwrite a checkout with local edits.
            messagebox.showwarning(
                'International Dollar update available',
                details
                + '\n\nLocal files have changes, so the update will not be installed automatically.',
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
        if not messagebox.askyesno(
            'International Dollar update available', details + '\n\nInstall this update now?'
        ):
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
            messagebox.showerror(
                'Update failed', result.error or 'The update could not be installed.'
            )
            return
        summary = (
            f"Updated from {_short_update_rev(result.old_rev)} "
            f"to {_short_update_rev(result.new_rev)}."
        )
        _set_update_status(summary, IND_GREEN)
        if messagebox.askyesno(
            'Update installed', summary + '\n\nRestart now to use the new version?'
        ):
            restart_after_update()

    threading.Thread(target=worker, name='INDManualUpdateCheck', daemon=True).start()


settings_save_button = make_text_button(
    'Save', save_security_settings_form, font_size=24, bg=IND_GREEN
)
settings_reset_button = make_text_button(
    'Reset', reset_security_settings_form, font_size=24, bg=IND_ORANGE
)
settings_ping_button = make_text_button(
    'Ping', ping_security_servers, font_size=22, bg=IND_BLACK, fg=IND_WHITE, bd=1, relief=SOLID
)
settings_update_button = make_text_button(
    'Update', run_manual_update_check, font_size=24, bg=IND_GREEN
)
settings_tab_buttons = {
    tab_key: make_text_button(
        label,
        lambda key=tab_key: set_settings_tab(key),
        font_size=22,
        bg=IND_BLACK,
        fg=IND_WHITE,
        bd=1,
        relief=SOLID,
    )
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
        place_scaled(
            settings_allow_untrusted_genesis, SETTINGS_ROW_COLS[3], SETTINGS_TOP_FIELD_Y, 110, 38
        )
        place_scaled(
            settings_genesis_issuer_keys,
            SETTINGS_TWO_COL_LEFT,
            SETTINGS_BOTTOM_FIELD_Y,
            SETTINGS_TWO_COL_WIDTH,
            190,
        )
        place_scaled(
            settings_genesis_manifest_hashes,
            SETTINGS_TWO_COL_RIGHT,
            SETTINGS_BOTTOM_FIELD_Y,
            SETTINGS_TWO_COL_WIDTH,
            190,
        )
    elif settings_active_tab == SETTINGS_TAB_TRANSPARENCY:
        place_scaled(
            settings_operator_url_entry,
            SETTINGS_TWO_COL_LEFT,
            SETTINGS_TOP_FIELD_Y,
            SETTINGS_TWO_COL_WIDTH,
            38,
        )
        place_scaled(
            settings_operator_key,
            SETTINGS_TWO_COL_RIGHT,
            SETTINGS_TOP_FIELD_Y,
            SETTINGS_TWO_COL_WIDTH,
            38,
        )
        place_scaled(settings_root_domains, SETTINGS_CONTENT_X, SETTINGS_BOTTOM_FIELD_Y, 240, 142)
        place_scaled(settings_root_mirrors, 354, SETTINGS_BOTTOM_FIELD_Y, 240, 142)
        place_scaled(settings_min_mirrors_entry, 620, SETTINGS_BOTTOM_FIELD_Y, 64, 38)
        place_scaled(settings_root_lag_entry, 706, SETTINGS_BOTTOM_FIELD_Y, 76, 38)
        place_scaled(settings_max_current_root_age_entry, 804, SETTINGS_BOTTOM_FIELD_Y, 76, 38)
        place_scaled(settings_root_gossip, 902, SETTINGS_BOTTOM_FIELD_Y, 86, 38)
        place_scaled(settings_current_root_future_skew_entry, 1010, SETTINGS_BOTTOM_FIELD_Y, 70, 38)
    elif settings_active_tab == SETTINGS_TAB_UPDATES:
        place_scaled(
            settings_update_source_entry, SETTINGS_CONTENT_X, SETTINGS_TOP_FIELD_Y, 628, 40
        )
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
receiver_history = Text(
    root, font=app_font(18), bg='black', fg='light grey', bd=0, highlightthickness=0
)


def readonly_text_key(event):
    control_pressed = bool(event.state & 0x0004)
    key = str(event.keysym).lower()
    if control_pressed and key in {"c", "insert"}:
        return None
    if control_pressed and key == "a":
        event.widget.tag_add("sel", "1.0", "end-1c")
        event.widget.mark_set("insert", "1.0")
        event.widget.see("insert")
        return "break"
    if key in {
        "left",
        "right",
        "up",
        "down",
        "home",
        "end",
        "prior",
        "next",
        "shift_l",
        "shift_r",
        "control_l",
        "control_r",
    }:
        return None
    return "break"


receiver_history.bind("<Key>", readonly_text_key)
wallet_sync_status_label = Label(
    root,
    font=app_font(15),
    bg=IND_BLACK,
    fg=IND_MUTED,
    bd=0,
    highlightthickness=0,
    anchor='e',
)


def set_wallet_sync_status(message="", color=IND_MUTED):
    try:
        wallet_sync_status_label.config(text=message, fg=color)
    except Exception:
        log_ignored_exception()


def wallet_sync_summary_text(summary, errors):
    if errors:
        return "Sync failed: " + errors[0], IND_ORANGE
    if not summary:
        return "Sync finished.", IND_MUTED
    backend_errors = summary.get("errors") or []
    if backend_errors:
        return f"Sync issues: {len(backend_errors)} message error(s)", IND_ORANGE
    parts = []
    fetched = int(summary.get("fetched_messages") or 0)
    fetched_records = int(summary.get("fetched_records") or 0)
    finalized = int(summary.get("finalized") or 0)
    added = int(summary.get("wallet_bills_added") or 0)
    pending = int(summary.get("pending") or 0)
    peer_timeouts = int(summary.get("peer_timeouts") or 0)
    if fetched:
        parts.append(f"fetched {fetched} messages")
    if fetched_records:
        parts.append(f"received {fetched_records} peer records")
    if finalized:
        parts.append(f"settled {finalized} bills")
    if added:
        parts.append(f"added {added} unique bills")
    if pending:
        parts.append(f"pending finality {pending} bills")
    if peer_timeouts:
        parts.append(f"timeouts {peer_timeouts}")
    if not parts:
        parts.append("no new bills")
    if pending or peer_timeouts:
        color = IND_ORANGE
    elif finalized or fetched_records or added:
        color = IND_GREEN
    else:
        color = IND_MUTED
    return "Sync: " + ", ".join(parts), color


def wallet_sync_progress_text(progress):
    summary = progress.get("summary") or {}
    event = progress.get("event", "")
    display_id = str(progress.get("display_id") or "").strip()
    display_label = wallet_services.wallet_display_label(display_id) if display_id else ""
    fetched = int(summary.get("fetched_messages") or 0)
    fetched_records = int(summary.get("fetched_records") or 0)
    unique_records = int(summary.get("fetched_unique_records") or 0)
    finalized = int(summary.get("finalized") or 0)
    added = int(summary.get("wallet_bills_added") or 0)
    peer_timeouts = int(summary.get("peer_timeouts") or 0)
    if event == "wallet_started":
        return "Sync: checking this wallet...", IND_MUTED
    if event == "local_messages":
        count = int(progress.get("message_count") or 0)
        return f"Sync: checking {count} local message(s)...", IND_MUTED
    if event == "peer_report":
        count = int(progress.get("message_count") or 0)
        status = str(progress.get("status") or "")
        if status == "ok" and count:
            if unique_records:
                return f"Sync: found {unique_records} bill(s), processing...", IND_MUTED
            return f"Sync: received {fetched + fetched_records} peer item(s), processing...", IND_MUTED
        if status == "timeout":
            return f"Sync: received {fetched + fetched_records} peer item(s), timeouts {peer_timeouts}", IND_ORANGE
        return f"Sync: checked peer, received {fetched + fetched_records} item(s)...", IND_MUTED
    if event == "record_accepted":
        return f"Sync: imported {display_label}", IND_GREEN
    if event == "finalized":
        return f"Sync: settled {finalized} bill(s), updating wallet...", IND_GREEN
    if event == "bills_added":
        count = int(progress.get("count") or 0)
        if count > 1:
            return f"Sync: added {count} bills ({added} total)", IND_GREEN
        return f"Sync: added {added} bill(s)", IND_GREEN
    if event == "bill_added":
        return f"Sync: added {display_label} ({added} total)", IND_GREEN
    if event == "message_accepted":
        processed = int(summary.get("processed_messages") or 0)
        accepted = int(summary.get("accepted_messages") or 0)
        return f"Sync: processed {processed} message(s), accepted {accepted}", IND_MUTED
    if event == "message_error":
        return "Sync: skipped one invalid message.", IND_ORANGE
    if event == "wallet_complete":
        return "Sync: wallet checked, finishing...", IND_MUTED
    return "Syncing wallet...", IND_MUTED


# Spend one locally stored bill and queue its transfer announcement.
def write_transfer_announcement(wallet_lines, wallet_bill_line, recipient_address, store=None):
    return wallet_services.spend_wallet_bill(
        wallet_lines,
        wallet_bill_line,
        recipient_address,
        store=store or sender_node.wallet_sync_store(),
    )


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


def set_print_progress(completed=0, total=1, message=None):
    try:
        total = max(1, int(total or 1))
        completed = max(0, min(int(completed or 0), total))
        ratio = completed / total
        print_progress_fill.place(
            x=0,
            y=0,
            width=px(PRINT_PROGRESS_WIDTH * ratio),
            height=px(PRINT_PROGRESS_HEIGHT),
        )
        if message:
            set_print_status(f'{message} ({completed}/{total})', IND_MUTED)
    except Exception:
        log_ignored_exception()


def update_print_progress(progress):
    set_print_progress(
        progress.get("completed", 0),
        progress.get("total", 1),
        progress.get("message"),
    )


def set_print_charge_ready(ready):
    try:
        charge_bills_button.config(
            state=NORMAL if ready else DISABLED,
            text='I printed it - Charge' if ready else 'Charge after PDF',
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
        print_pages_label.config(
            text=f'{page_count} page' + ('' if page_count == 1 else 's') + '\nestimated'
        )
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
    set_print_progress(0, 1)
    set_print_status(
        'PDF is generated first. Charge sends funds to the printed paper-wallet addresses after printing.'
    )


def select_all_print_bills():
    lines = list(filter(None, all_bills_text.get(1.0, END).splitlines()))
    selected_bills_text.delete(1.0, END)
    selected_bills_text.insert(1.0, '\n'.join(lines))
    refresh_print_summary()


def text_line_at_event(widget, event):
    index = widget.index(f'@{event.x},{event.y}')
    return widget.get(f'{index} linestart', f'{index} lineend').strip()


def copy_text_selection(event):
    try:
        text = event.widget.selection_get()
    except TclError:
        return 'break'
    root.clipboard_clear()
    root.clipboard_append(text)
    return 'break'


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


# Route the print action to the selected paper-bill output format.
def print_selected_output():
    if print_output_mode.get() == 'qr':
        print_only_qr()
    else:
        print_bills()


# Send selected printed bills to the generated paper-wallet addresses.
def charge_bills():
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
            raise ValueError(
                "Printed bill addresses are missing. Print the bills again before charging them."
            )
        wallet_path = active_wallet_path()
        if wallet_path is None:
            raise ValueError("Sign in to a wallet before charging printed bills.")
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
                    updated.append(
                        '-'
                        + parts[0]
                        + ' '
                        + str(state.sequence)
                        + ' '
                        + str(int(time.time()))
                        + '\n'
                    )
                    sent_count += 1
                except Exception as exc:
                    errors.append(f"{parts[0]}: {error_detail(exc)}")
                    updated.append(wb)
            else:
                updated.append(wb)
        runtime_json.write_decrypted_wallet_lines(wallet_path, updated)
        if sent_count:
            start_wallet_send_worker(expected_total=sent_count)
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
        if not wallet_send_running:
            root.config(cursor='arrow')
        refresh_wallet_view()
        charge_bills_button.config(cursor='watch' if wallet_send_running else 'hand2')
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


# Run PDF generation off the Tk thread and unlock charging after the PDF opens.
def start_print_pdf_job(
    print_method_name,
    creating_status,
    error_title,
    opened_status,
    ready_status,
    extra_busy_buttons=(),
):
    list_bills_2 = selected_print_bill_sequences()
    if list_bills_2 is None:
        return
    address_to_charge.clear()
    set_print_charge_ready(False)
    set_print_progress(0, print_estimated_page_count(len(list_bills_2)))
    set_print_status(creating_status, IND_MUTED)
    root.config(cursor='watch')
    button_print.config(state=DISABLED, cursor='watch')
    for button_widget in extra_busy_buttons:
        button_widget.config(cursor='watch')

    def progress(progress_event):
        root.after(0, lambda event=progress_event: update_print_progress(event))

    def t():
        # The print tools open OS/PDF UI, so Tk state is restored through after().
        try:
            return_addr = getattr(print_tools, print_method_name)(
                list_bills_2,
                progress_callback=progress,
            )
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
            set_print_progress(1, 1)
            set_print_status(opened_status)
            set_print_charge_ready(True)
            set_print_status(ready_status, IND_ORANGE)

        root.after(0, finish)

    threading.Thread(target=t, daemon=True).start()


# Create full paper-bill PDF output for the selected spendable bills.
def print_bills():
    start_print_pdf_job(
        'full_bill',
        'Creating full bill PDF...',
        'Print bills failed',
        'PDF opened. Print or save it, then click "I printed it - Charge".',
        'After printing, click "I printed it - Charge" to send funds to the paper wallets.',
    )


# Create a QR-only paper-bill PDF containing private keys for offline custody.
def print_only_qr():
    start_print_pdf_job(
        'only_qr',
        'Creating QR-only PDF...',
        'Print QR bills failed',
        'QR PDF opened. Print or save it, then click "I printed it - Charge".',
        'After printing, click "I printed it - Charge" to send funds to the QR wallets.',
        extra_busy_buttons=(button_only_qr,),
    )


print_output_mode = StringVar(root, value='full')
button_print = make_text_button(
    'Create PDF', print_selected_output, font_size=22, font_weight='bold', bg=IND_GREEN
)
button_only_qr = make_text_button(
    'QR only', print_only_qr, font_size=18, bg='#111616', fg=IND_WHITE, bd=1, relief=SOLID
)
print_select_all_button = make_text_button(
    'Select all',
    select_all_print_bills,
    font_size=15,
    font_weight='bold',
    bg='#0b1813',
    fg='#c9ffe3',
    bd=1,
    relief=SOLID,
)
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
all_bills_text.bind('<Control-c>', copy_text_selection)
all_bills_text.bind('<Control-C>', copy_text_selection)
all_bills_text.bind('<Control-Insert>', copy_text_selection)
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
print_progress_track = Frame(root, bg='#16201d', bd=0, highlightthickness=0)
print_progress_fill = Frame(print_progress_track, bg=IND_GREEN, bd=0, highlightthickness=0)
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
charge_bills_button = make_text_button(
    'Charge after PDF',
    charge_bills,
    font_size=15,
    font_weight='bold',
    bg='#35180f',
    fg='#ffd3c6',
    bd=1,
    relief=SOLID,
)
charge_bills_button.config(state=DISABLED, disabledforeground='#ffd3c6')


# Header navigation callbacks.
def node_terminal_button():
    close()
    button.config(bg='white', fg='black'), button2.config(bg='black', fg='white'), button3.config(
        bg='black', fg='white'
    )
    button4.config(bg='black', fg='white'), button_log_in.config(bg='black', fg='black')
    button_settings.config(bg='black', fg='white')
    place_node_terminal_controls()


def sign_in_button():
    close()
    refresh_sign_in_wallet_dropdown()
    button.config(bg='black', fg='white'), button2.config(bg='black', fg='white'), button3.config(
        bg='black', fg='white'
    )
    button4.config(bg='black', fg='white'), button_log_in.config(bg='white', fg='black')
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
    button.config(bg='black', fg='white'), button2.config(bg='white', fg='black'), button3.config(
        bg='black', fg='white'
    )
    button4.config(bg='black', fg='white')
    button_settings.config(bg='black', fg='white')
    info.place(x=0, y=0)


# Show the print workflow and load the currently spendable wallet bills.
def load_print_available_bills():
    if not all_bills_text.winfo_ismapped():
        return
    try:
        # The available list intentionally excludes unsettled or already spent bills.
        only_sm = '\n'.join(str(record["display_id"]) for record in wallet_spendable_records())
        all_bills_text.delete(1.0, END)
        all_bills_text.insert(1.0, only_sm)
    except Exception:
        log_ignored_exception()


def print_page_button():
    close()
    button.config(bg='black', fg='white'), button4.config(bg='black', fg='white'), button2.config(
        bg='black', fg='white'
    )
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
    print_progress_track.place(
        x=PRINT_PROGRESS_X * reso,
        y=PRINT_PROGRESS_Y * reso,
        width=PRINT_PROGRESS_WIDTH * reso,
        height=PRINT_PROGRESS_HEIGHT * reso,
    )
    set_print_progress(0, 1)
    all_bills_text.delete(1.0, END)
    root.after_idle(load_print_available_bills)
    reset_print_actions()
    refresh_print_summary()


# Show the wallet page and refresh balance, bill buttons, and receive QR.
def wallet_button():
    close()
    clear_wallet_record_cache()
    ensure_bill_images()
    button.config(bg='black', fg='white'), button2.config(bg='black', fg='white'), button3.config(
        bg='black', fg='white'
    )
    button4.config(bg='white', fg='black'), button_settings.config(bg='black', fg='white')
    plus_bills_button.place(x=435 * reso, y=725 * reso, width=275 * reso, height=30 * reso)
    receiver.place(
        x=853 * reso, y=(213 + WALLET_SEND_Y_OFFSET) * reso, width=343 * reso, height=36 * reso
    )
    send.place(
        x=1075 * reso, y=(340 + WALLET_SEND_Y_OFFSET) * reso, width=120 * reso, height=34 * reso
    )
    b.place(x=340 * reso, y=187 * reso, width=480 * reso, height=60 * reso)
    frame_w.place(x=18 * reso, y=170 * reso, width=305 * reso, height=595 * reso)
    close_amount_button.place(
        x=1157 * reso, y=(299 + WALLET_SEND_Y_OFFSET) * reso, width=32 * reso, height=30 * reso
    )
    receiver_button.place(x=747 * reso, y=190 * reso, width=52 * reso, height=52 * reso)
    a.place(x=853 * reso, y=(295 + WALLET_SEND_Y_OFFSET) * reso, width=343 * reso, height=36 * reso)
    wallet_sync_status_label.place(
        x=343 * reso, y=274 * reso, width=480 * reso, height=24 * reso
    )
    receiver_history.place(x=343 * reso, y=310 * reso, width=480 * reso, height=450 * reso)
    wallet.place(x=0, y=0)
    receiver_history.delete(1.0, END)
    b.delete(1.0, END)
    b.insert(1.0, 'Balance:  0$')
    root.after_idle(refresh_wallet_view)
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


# Show settings, then load persisted values into the active tab widgets.
def settings_button():
    close()
    button.config(bg='black', fg='white'), button2.config(bg='black', fg='white'), button3.config(
        bg='black', fg='white'
    )
    button4.config(bg='black', fg='white'), button_settings.config(bg='white', fg='black')
    load_security_settings_form()
    settings_page.place(x=0, y=0)
    refresh_settings_widgets()


# Switch the sign-in panel into the wallet-generation form.
def generate_wallet_button():
    button_show.place_forget(), enter_key.place_forget(), log_in_button2.place_forget()
    enter_address.place_forget(), sign_in.place_forget()
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
        GENERATE_WALLET_FIELD_WIDTH
        + GENERATE_WALLET_BUTTON_GAP
        + GENERATE_WALLET_SIDE_BUTTON_WIDTH,
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


# Reveal a full-wallet transfer QR after a delay because it contains private keys.
def transfer_wallet():
    global wallet_qr_mode, wallet_qr_warning_after_id
    try:
        if not ensure_wallet_qr():
            return
        cancel_wallet_qr_warning_timer()
        wallet_lines, _ = update_wallet()
        data_wallet = ''.join(wallet_lines[:3])
        wallet_qr = qrcode.QRCode(
            version=1, box_size=4, border=1, error_correction=qrcode.constants.ERROR_CORRECT_L
        )
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


tf_button = make_asset_button(
    'different_buttons', 'tf_button', transfer_wallet, 'TX', font_size=16, bg=IND_BLACK
)
r_button = make_asset_button(
    'different_buttons', 'r_button', receive_qr, 'QR', font_size=16, bg=IND_BLACK
)

page_wallet = 1
place_next_button = 0
WALLET_HISTORY_ROWS_PER_PAGE = 8
WALLET_HISTORY_PREVIOUS_X = 345
WALLET_HISTORY_NEXT_X = 720
WALLET_HISTORY_NAV_Y = 730
WALLET_HISTORY_NAV_WIDTH = 80
WALLET_HISTORY_NAV_HEIGHT = 22
WALLET_HISTORY_TIMESTAMP_TAB_X = 466
WALLET_HISTORY_HOVER_FG = '#9aa3a0'
wallet_history_cached_entries = []


def claim_workflow_is_visible():
    try:
        widget = globals().get('claim_bill')
        return bool(widget is not None and widget.winfo_ismapped())
    except Exception:
        log_ignored_exception()
        return False


def hide_wallet_history_nav():
    next_button.place_forget()
    previous_button.place_forget()


def show_wallet_history_nav(button, x):
    if claim_workflow_is_visible():
        hide_wallet_history_nav()
        return
    button.place(
        x=x * reso,
        y=WALLET_HISTORY_NAV_Y * reso,
        width=WALLET_HISTORY_NAV_WIDTH * reso,
        height=WALLET_HISTORY_NAV_HEIGHT * reso,
    )
    raise_widget(button)


def wallet_history_timestamp_text(timestamp, include_seconds=False):
    try:
        date_time = datetime.fromtimestamp(int(timestamp))
    except Exception:
        date_time = datetime.fromtimestamp(int(time.time()))
    return date_time.strftime('%Y-%m-%d   %H:%M:%S' if include_seconds else '%Y-%m-%d   %H:%M')


def wallet_history_decode_bill(record=None, bill=None):
    if isinstance(bill, dict):
        return bill
    blob = dict(record or {}).get("bill_blob")
    if blob is None:
        return None
    try:
        return protocol_v3.decode_bill(bytes(blob))
    except Exception:
        log_ignored_exception()
        return None


def wallet_history_transfer_context(record=None, bill=None):
    bill_obj = wallet_history_decode_bill(record=record, bill=bill)
    if not isinstance(bill_obj, dict):
        return {"transfer_note": "Sender wallet not available in this local history entry."}
    transfers = bill_obj.get("recent_transfers")
    if isinstance(transfers, list) and transfers:
        transfer = transfers[-1]
        context = {
            "from_wallet": str(transfer.get("sender_address") or "").strip(),
            "to_wallet": str(transfer.get("recipient_address") or "").strip(),
            "transfer_sequence": str(transfer.get("sequence") or "").strip(),
            "transfer_timestamp": transfer.get("timestamp"),
        }
        try:
            context["transfer_hash"] = protocol_v3.transfer_hash(transfer)
        except Exception:
            log_ignored_exception()
        return context
    checkpoint = bill_obj.get("checkpoint_core") if isinstance(bill_obj, dict) else {}
    owner = str(dict(checkpoint or {}).get("owner_address") or "").strip()
    context = {
        "to_wallet": owner,
        "transfer_note": "Sender wallet not stored in this compacted local bill record.",
    }
    sequence = dict(checkpoint or {}).get("sequence")
    if sequence is not None:
        context["transfer_sequence"] = str(sequence)
    return context


def wallet_history_entry(
    display_id,
    *,
    timestamp,
    direction,
    status,
    sequence="",
    source="Wallet history",
    record=None,
    bill=None,
    display_label=None,
):
    clean_display_id = str(display_id).strip().lstrip("-")
    display_label = display_label or wallet_services.wallet_display_label(display_id)
    value = wallet_services.wallet_display_value(clean_display_id)
    try:
        timestamp_value = int(timestamp)
    except Exception:
        timestamp_value = int(time.time())
    record_data = {}
    for key, record_value in dict(record or {}).items():
        if key in {"bill_blob", "payload", "genesis_json"}:
            continue
        record_data[key] = record_value
    transfer_context = wallet_history_transfer_context(bill=bill) if bill is not None else {}
    status_key = str(status).lower()
    if str(direction).lower() == "sent":
        tag = "sent"
    elif status_key == "pending":
        tag = "pending"
    else:
        tag = "wallet"
    return {
        "display_id": clean_display_id,
        "display_label": display_label,
        "timestamp": timestamp_value,
        "timestamp_text": wallet_history_timestamp_text(timestamp_value),
        "direction": str(direction),
        "status": str(status),
        "sequence": str(sequence).strip(),
        "source": str(source),
        "value": value,
        "record": record_data,
        **transfer_context,
        "tag": tag,
    }


def wallet_history_sequence_number(sequence):
    try:
        return int(str(sequence).strip())
    except Exception:
        return None


def wallet_history_seen_key(display_id, sequence):
    return (str(display_id).strip().lstrip("-"), str(sequence).strip())


def wallet_history_record_is_newer(record, current):
    if current is None:
        return True
    record_sequence = wallet_history_sequence_number(record.get("sequence"))
    current_sequence = wallet_history_sequence_number(current.get("sequence"))
    if record_sequence is not None and current_sequence is not None:
        if record_sequence != current_sequence:
            return record_sequence > current_sequence
    elif record_sequence is not None:
        return True
    elif current_sequence is not None:
        return False
    record_updated = int(record.get("updated_at") or record.get("first_seen") or 0)
    current_updated = int(current.get("updated_at") or current.get("first_seen") or 0)
    return record_updated > current_updated


def keep_latest_wallet_history_record(records_by_display_id, record):
    display_id = str(record["display_id"]).strip().lstrip("-")
    current = records_by_display_id.get(display_id)
    if wallet_history_record_is_newer(record, current):
        records_by_display_id[display_id] = record


def wallet_history_record_for_sequence(records_by_display_id, display_id, sequence):
    record = records_by_display_id.get(str(display_id).strip().lstrip("-"))
    if record is None:
        return None
    record_sequence = str(record.get("sequence", "")).strip()
    line_sequence = str(sequence).strip()
    if record_sequence and line_sequence and record_sequence != line_sequence:
        return None
    return record


def wallet_history_entries():
    entries = []
    seen_records = set()
    record_by_display_id = {}
    pending_by_display_id = {}
    try:
        snapshot = wallet_records_snapshot()
        dr_new = snapshot["wallet_lines"]
        spendable_records = snapshot["spendable_records"]
        pending_records = snapshot["pending_records"]
    except Exception:
        log_ignored_exception()
        dr_new = []
        spendable_records = []
        pending_records = []
    try:
        for record in spendable_records:
            keep_latest_wallet_history_record(record_by_display_id, record)
    except Exception:
        log_ignored_exception()
    try:
        for record in pending_records:
            keep_latest_wallet_history_record(pending_by_display_id, record)
    except Exception:
        log_ignored_exception()
    try:
        for line in runtime_json.wallet_bill_lines(dr_new):
            parts = line.split()
            if len(parts) < 3:
                continue
            timestamp = int(parts[2])
            display_id = parts[0].lstrip("-")
            sequence = parts[1] if len(parts) > 1 else ""
            seen_records.add(wallet_history_seen_key(display_id, sequence))
            direction = "Sent" if parts[0].startswith('-') else "Received"
            display_label = wallet_services.wallet_display_label(parts[0])
            record = (
                wallet_history_record_for_sequence(record_by_display_id, display_id, sequence)
                or wallet_history_record_for_sequence(pending_by_display_id, display_id, sequence)
            )
            entries.append(
                wallet_history_entry(
                    display_id,
                    timestamp=timestamp,
                    direction=direction,
                    status=direction,
                    sequence=sequence,
                    source="Wallet history",
                    record=record,
                    display_label=display_label,
                )
            )
    except Exception:
        log_ignored_exception()
    try:
        for record in record_by_display_id.values():
            display_id = str(record["display_id"])
            sequence = record.get("sequence", "")
            if wallet_history_seen_key(display_id, sequence) in seen_records:
                continue
            timestamp = int(record.get("updated_at") or record.get("first_seen") or time.time())
            entries.append(
                wallet_history_entry(
                    display_id,
                    timestamp=timestamp,
                    direction="Received",
                    status=str(record.get("status") or "settled"),
                    sequence=sequence,
                    source="Local store",
                    record=record,
                )
            )
            seen_records.add(wallet_history_seen_key(display_id, sequence))
    except Exception:
        log_ignored_exception()
    try:
        for record in pending_by_display_id.values():
            display_id = str(record["display_id"])
            sequence = record.get("sequence", "")
            if wallet_history_seen_key(display_id, sequence) in seen_records:
                continue
            timestamp = int(record.get("updated_at") or record.get("first_seen") or time.time())
            entries.append(
                wallet_history_entry(
                    display_id,
                    timestamp=timestamp,
                    direction="Incoming",
                    status=str(record.get("status") or "pending"),
                    sequence=sequence,
                    source="Local store",
                    record=record,
                )
            )
            seen_records.add(wallet_history_seen_key(display_id, sequence))
    except Exception:
        log_ignored_exception()
    return sorted(entries, key=lambda entry: entry["timestamp"], reverse=True)


def refresh_wallet_history_cache():
    global wallet_history_cached_entries
    wallet_history_cached_entries = wallet_history_entries() if wallet_is_unlocked() else []


def wallet_history_detail_transfer_context(entry):
    display_id = str(entry.get("display_id") or "").strip()
    if not display_id:
        return {}
    try:
        store = wallet_snapshot_store()
        if store is None:
            return {}
        bill = store.get_bill_v3_by_display_id(display_id)
        if not bill:
            return {}
        return wallet_history_transfer_context(bill=bill)
    except Exception:
        log_ignored_exception()
        return {}


def wallet_history_with_detail_context(entry):
    if any(
        entry.get(key)
        for key in (
            "from_wallet",
            "to_wallet",
            "transfer_note",
            "transfer_hash",
            "transfer_timestamp",
            "transfer_sequence",
        )
    ):
        return entry
    transfer_context = wallet_history_detail_transfer_context(entry)
    if not transfer_context:
        return entry
    enriched = dict(entry)
    enriched.update(transfer_context)
    return enriched


def wallet_history_detail_text(entry):
    entry = wallet_history_with_detail_context(entry)
    record = dict(entry.get("record") or {})
    details = [
        f"Serial: {entry.get('display_id', '')}",
        f"Direction: {entry.get('direction', '')}",
        f"Status: {entry.get('status', '')}",
        f"Value: {entry.get('value', 0):,} IND",
    ]
    from_wallet = str(entry.get("from_wallet") or "").strip()
    to_wallet = str(entry.get("to_wallet") or "").strip()
    transfer_note = str(entry.get("transfer_note") or "").strip()
    if from_wallet:
        details.append(f"From wallet: {from_wallet}")
    if to_wallet:
        details.append(f"To wallet: {to_wallet}")
    if transfer_note:
        details.append(f"From wallet: {transfer_note}")
    if entry.get("transfer_timestamp"):
        details.append(
            "Transfer time: "
            + wallet_history_timestamp_text(entry["transfer_timestamp"], include_seconds=True)
        )
    if entry.get("sequence"):
        details.append(f"Sequence: {entry['sequence']}")
    elif entry.get("transfer_sequence"):
        details.append(f"Sequence: {entry['transfer_sequence']}")
    details.append(
        "Timestamp: "
        + wallet_history_timestamp_text(entry.get("timestamp", time.time()), include_seconds=True)
    )
    details.append(f"Source: {entry.get('source', '')}")

    technical = []
    for label, key in (
        ("Display ID", "display_id"),
        ("Token ID", "token_id"),
        ("Bill hash", "bill_hash"),
        ("Current owner", "owner_address"),
        ("Store sequence", "sequence"),
        ("Store status", "status"),
        ("Checkpoint hash", "checkpoint_hash"),
        ("Proof bundle hash", "proof_bundle_hash"),
    ):
        value = str(record.get(key) or "").strip()
        if value:
            technical.append(f"{label}: {value}")
    transfer_hash = str(entry.get("transfer_hash") or "").strip()
    if transfer_hash:
        technical.append(f"Transfer hash: {transfer_hash}")
    for label, key in (("First seen", "first_seen"), ("Updated", "updated_at")):
        value = record.get(key)
        if value:
            technical.append(
                f"{label}: {wallet_history_timestamp_text(value, include_seconds=True)}"
            )
    shown_keys = {
        "display_id",
        "token_id",
        "bill_hash",
        "owner_address",
        "sequence",
        "status",
        "checkpoint_hash",
        "proof_bundle_hash",
        "first_seen",
        "updated_at",
    }
    extra_fields = []
    for key in sorted(record):
        if key in shown_keys:
            continue
        value = str(record.get(key) or "").strip()
        if value:
            extra_fields.append(f"{key}: {value}")
    if extra_fields:
        technical.extend(["Local store fields:", *extra_fields])
    if technical:
        details.extend(["", "Technical:", *technical])
    return "\n".join(details)


def copy_text_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(str(text))


def show_wallet_history_detail(entry):
    detail_text = wallet_history_detail_text(entry)
    popup = Toplevel(root)
    popup.title('Transaction details')
    popup.configure(bg=IND_BLACK)
    popup.resizable(True, True)
    popup.transient(root)

    title = Label(
        popup,
        text='Transaction details',
        font=app_font(24, 'bold'),
        bg=IND_BLACK,
        fg=IND_WHITE,
        anchor='w',
    )
    detail = Text(
        popup,
        font=app_font(16),
        bg='#101414',
        fg=IND_WHITE,
        insertbackground=IND_WHITE,
        selectbackground=IND_GREEN,
        selectforeground=IND_WHITE,
        bd=0,
        highlightthickness=0,
        wrap='word',
        padx=12,
        pady=10,
    )
    scrollbar = Scrollbar(popup, command=detail.yview, bd=0, highlightthickness=0)
    detail.config(yscrollcommand=scrollbar.set)
    detail.insert('1.0', detail_text)
    detail.bind("<Key>", readonly_text_key)

    def copy_all():
        copy_text_to_clipboard(detail_text)

    copy_button = Button(
        popup,
        text='Copy all',
        command=copy_all,
        font=app_font(15),
        bg=IND_GREEN,
        fg=IND_WHITE,
        activebackground=IND_GREEN,
        activeforeground=IND_WHITE,
        bd=0,
        highlightthickness=0,
        cursor='hand2',
    )
    close_button_popup = Button(
        popup,
        text='Close',
        command=popup.destroy,
        font=app_font(15),
        bg=IND_BLACK,
        fg=IND_WHITE,
        activebackground=IND_BLACK,
        activeforeground=IND_WHITE,
        bd=1,
        highlightthickness=0,
        cursor='hand2',
        relief=SOLID,
        overrelief=SOLID,
    )

    title.grid(row=0, column=0, columnspan=2, padx=16, pady=(14, 8), sticky='ew')
    detail.grid(row=1, column=0, padx=(16, 0), pady=0, sticky='nsew')
    scrollbar.grid(row=1, column=1, padx=(0, 16), pady=0, sticky='ns')
    copy_button.grid(row=2, column=0, padx=16, pady=14, sticky='w')
    close_button_popup.grid(row=2, column=0, columnspan=2, padx=16, pady=14, sticky='e')
    popup.grid_columnconfigure(0, weight=1, minsize=px(540))
    popup.grid_rowconfigure(1, weight=1, minsize=px(330))
    detail.focus_set()

    try:
        popup.geometry(f'+{root.winfo_rootx() + px(360)}+{root.winfo_rooty() + px(180)}')
    except Exception:
        log_ignored_exception()


def bind_wallet_history_row(row_tag, entry):
    def show_detail(_event, detail_entry=entry):
        show_wallet_history_detail(detail_entry)
        return "break"

    def set_hover(active):
        ranges = receiver_history.tag_ranges(row_tag)
        if active:
            receiver_history.tag_remove('history_hover', '1.0', END)
        for index in range(0, len(ranges), 2):
            start = ranges[index]
            end = ranges[index + 1]
            if active:
                receiver_history.tag_add('history_hover', start, end)
            else:
                receiver_history.tag_remove('history_hover', start, end)

    def enter_row(_event):
        receiver_history.config(cursor='hand2')
        set_hover(True)

    def leave_row(_event):
        receiver_history.config(cursor='')
        set_hover(False)

    receiver_history.tag_bind(row_tag, "<Enter>", enter_row)
    receiver_history.tag_bind(row_tag, "<Leave>", leave_row)
    receiver_history.tag_bind(row_tag, "<Button-1>", show_detail)


# Render the current wallet-history page.
def page(refresh_entries=True):
    global place_next_button, page_wallet
    try:
        if not receiver_history.winfo_ismapped():
            next_button.place_forget()
            previous_button.place_forget()
            return
        receiver_history.config(cursor='')
        receiver_history.delete(1.0, END)
        receiver_history.tag_config('red', foreground='red')
        receiver_history.tag_config('pending', foreground=IND_PENDING)
        receiver_history.tag_config(
            'history_row',
            tabs=(px(WALLET_HISTORY_TIMESTAMP_TAB_X), 'right'),
            spacing3=px(8),
        )
        receiver_history.tag_config('history_hover', foreground=WALLET_HISTORY_HOVER_FG)
        receiver_history.tag_raise('history_hover')
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

        if refresh_entries:
            refresh_wallet_history_cache()
        entries = wallet_history_cached_entries
        num_of_bills = len(entries)
        total_pages = max(
            1, (num_of_bills + WALLET_HISTORY_ROWS_PER_PAGE - 1) // WALLET_HISTORY_ROWS_PER_PAGE
        )
        if page_wallet > total_pages:
            page_wallet = total_pages
        if page_wallet < 1:
            page_wallet = 1
        if page_wallet < total_pages:
            show_wallet_history_nav(next_button, WALLET_HISTORY_NEXT_X)
            place_next_button = 0
        else:
            next_button.place_forget()
            place_next_button = 1
        if page_wallet > 1:
            show_wallet_history_nav(previous_button, WALLET_HISTORY_PREVIOUS_X)
        else:
            previous_button.place_forget()

        start_index = (page_wallet - 1) * WALLET_HISTORY_ROWS_PER_PAGE
        visible_entries = entries[start_index : start_index + WALLET_HISTORY_ROWS_PER_PAGE]
        for index, entry in enumerate(visible_entries):
            row_tag = f'history_row_{index}'
            row_start = receiver_history.index(INSERT)
            receiver_history.insert(
                INSERT,
                entry["display_label"] + '\t' + entry["timestamp_text"] + '\n',
                ('history_row', row_tag),
            )
            row_end = receiver_history.index(INSERT)
            if entry["tag"] == "sent":
                receiver_history.tag_add('red', row_start, row_end)
            elif entry["tag"] == "pending":
                receiver_history.tag_add('pending', row_start, row_end)
            bind_wallet_history_row(row_tag, entry)
    except Exception:
        log_ignored_exception()


def next_():
    global page_wallet
    page_wallet += 1
    page(refresh_entries=False)


def previous():
    global page_wallet
    page_wallet -= 1
    page(refresh_entries=False)


next_button = make_asset_button(
    'different_buttons', 'next_button', next_, 'Next', font_size=16, bg=IND_BLACK
)
previous_button = make_asset_button(
    'different_buttons', 'previous_button', previous, 'Back', font_size=16, bg=IND_BLACK
)
page()

BILL_VALUES = tuple(ind_token.ALLOWED_BILL_VALUES)
BILL_IMAGES = {}
BILL_IMAGES_LOADED = False
BILL_COUNT_FONT_SIZE = 21
BILL_PENDING_FONT_SIZE = 16
BILL_COUNT_TEXT_INDENT = '        ' + '\u2009\u200a'
BILL_HOLD_REPEAT_DELAY_MS = 350
BILL_HOLD_REPEAT_INTERVAL_MS = 20


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
                    resized = bill_image.convert('RGBA').resize(
                        (px(width), px(height)), Image.Resampling.LANCZOS
                    )
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


def bind_bill_hold_repeat(button, command):
    repeat_after_id = None
    hold_repeated = False

    def cancel_repeat():
        nonlocal repeat_after_id
        if repeat_after_id is None:
            return
        try:
            root.after_cancel(repeat_after_id)
        except Exception:
            log_ignored_exception()
        repeat_after_id = None

    def button_can_repeat():
        try:
            return str(button.cget('state')) != DISABLED
        except Exception:
            log_ignored_exception()
            return False

    def repeat_once():
        nonlocal repeat_after_id, hold_repeated
        repeat_after_id = None
        if not button_can_repeat():
            return
        hold_repeated = True
        try:
            command()
        except Exception:
            log_ignored_exception()
            return
        if button_can_repeat():
            repeat_after_id = root.after(BILL_HOLD_REPEAT_INTERVAL_MS, repeat_once)

    def start_repeat(_event):
        nonlocal repeat_after_id, hold_repeated
        cancel_repeat()
        hold_repeated = False
        if button_can_repeat():
            repeat_after_id = root.after(BILL_HOLD_REPEAT_DELAY_MS, repeat_once)

    def stop_repeat(_event):
        cancel_repeat()
        if hold_repeated:
            return "break"
        return None

    button.bind("<ButtonPress-1>", start_repeat, add="+")
    button.bind("<ButtonRelease-1>", stop_repeat, add="+")
    button.bind("<Leave>", lambda _event: cancel_repeat(), add="+")
    button.bind("<Destroy>", lambda _event: cancel_repeat(), add="+")


def bill_overlay_text(remaining, pending):
    if remaining > 0 and pending > 0:
        return BILL_COUNT_TEXT_INDENT + str(remaining) + '\n' + str(pending) + ' Pending'
    if remaining > 0:
        return BILL_COUNT_TEXT_INDENT + str(remaining)
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
            font=app_font(BILL_PENDING_FONT_SIZE if pending > 0 else BILL_COUNT_FONT_SIZE),
            cursor='hand2' if enabled else '',
            state='normal' if enabled else 'disabled',
            bg=IND_BLACK,
            fg=IND_WHITE if enabled else IND_PENDING,
            disabledforeground=IND_PENDING if pending > 0 else IND_WHITE,
        )
    else:
        button.config(
            image='',
            text=(
                bill_button_text(value, remaining)
                if remaining > 0
                else (f'{value:,}$   {pending} Pending' if pending > 0 else '')
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


# Refresh wallet counters from locally settled and pending bill records.
def update_balance():
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
    owned_line_counts = wallet_line_bill_counts()
    for value, count in owned_line_counts.items():
        bill_counts[value] = max(bill_counts.get(value, 0), count)
    balance = sum(value * count for value, count in bill_counts.items())
    balance_format = f'{balance:,}'
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

for value, add_command in (
    (1, add_1),
    (2, add_2),
    (5, add_5),
    (10, add_10),
    (20, add_20),
    (50, add_50),
    (100, add_100),
    (200, add_200),
    (500, add_500),
    (1000, add_1000),
    (2000, add_2000),
    (5000, add_5000),
    (10000, add_10000),
    (20000, add_20000),
    (50000, add_50000),
    (100000, add_100000),
):
    bind_bill_hold_repeat(bill_buttons[value], add_command)


# Reset denomination buttons to their neutral state before a send selection.
def start_bills():
    global count_selected
    for value in BILL_VALUES:
        add_bill_value(value)
    count_selected = True


# Redraw denomination buttons without changing the current selection state.
def refresh_bill_buttons():
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


wallet_sync_running = False
WALLET_SYNC_PROGRESS_DELAY_MS = 200
WALLET_SYNC_PROGRESS_IMMEDIATE_EVENTS = {
    "wallet_started",
    "local_messages",
    "peer_report",
    "message_error",
    "wallet_complete",
    "complete",
}
WALLET_SYNC_REFRESH_EVENTS = {
    "message_accepted",
    "record_accepted",
    "finalized",
    "bill_added",
    "bills_added",
    "wallet_complete",
}


def start_wallet_sync(show_busy=False, show_errors=False):
    global wallet_sync_running
    if wallet_sync_running:
        logger.debug("wallet sync already running")
        if show_busy:
            set_wallet_sync_status("Sync already running.", IND_MUTED)
        return
    wallet_sync_running = True
    set_wallet_sync_status("Syncing wallet...", IND_MUTED)
    if show_busy:
        root.config(cursor='watch')
        receiver_button.config(cursor='watch')
    progress_lock = threading.Lock()
    pending_progress_event = None
    pending_progress_requires_refresh = False
    progress_after_id = None
    last_progress_update = 0.0

    def apply_progress_update(progress_event, refresh_required=False):
        status_message, status_color = wallet_sync_progress_text(progress_event)
        set_wallet_sync_status(status_message, status_color)
        if refresh_required or progress_event.get("event") in WALLET_SYNC_REFRESH_EVENTS:
            schedule_wallet_view_refresh()

    def run_pending_progress_update():
        nonlocal pending_progress_event, pending_progress_requires_refresh
        nonlocal progress_after_id, last_progress_update
        with progress_lock:
            progress_event = pending_progress_event
            refresh_required = pending_progress_requires_refresh
            pending_progress_event = None
            pending_progress_requires_refresh = False
            progress_after_id = None
            last_progress_update = time.monotonic()
        if progress_event is not None:
            apply_progress_update(progress_event, refresh_required=refresh_required)

    def progress(progress_event):
        nonlocal pending_progress_event, pending_progress_requires_refresh, progress_after_id
        event = str(progress_event.get("event") or "")
        with progress_lock:
            pending_progress_event = progress_event
            if event in WALLET_SYNC_REFRESH_EVENTS:
                pending_progress_requires_refresh = True
            if progress_after_id is not None:
                return
            delay_ms = 0
            if event not in WALLET_SYNC_PROGRESS_IMMEDIATE_EVENTS:
                elapsed_ms = int((time.monotonic() - last_progress_update) * 1000)
                delay_ms = max(0, WALLET_SYNC_PROGRESS_DELAY_MS - elapsed_ms)
            try:
                progress_after_id = root.after(delay_ms, run_pending_progress_update)
            except Exception:
                progress_after_id = None
                log_ignored_exception()

    def cancel_pending_progress_update():
        nonlocal pending_progress_event, pending_progress_requires_refresh, progress_after_id
        with progress_lock:
            after_id = progress_after_id
            pending_progress_event = None
            pending_progress_requires_refresh = False
            progress_after_id = None
        if after_id is not None:
            try:
                root.after_cancel(after_id)
            except Exception:
                log_ignored_exception()

    def worker():
        errors = []
        sync_summary = None
        try:
            sender_node.maybe_refresh_dns_seed_peers(force=True)
        except Exception as exc:
            errors.append(f"Peer refresh failed: {error_detail(exc)}")
        try:
            sync_summary = sender_node.receive_bills(progress_callback=progress)
        except Exception as exc:
            errors.append(f"Wallet sync failed: {error_detail(exc)}")

        def finish():
            global wallet_sync_running
            wallet_sync_running = False
            cancel_pending_progress_update()
            if show_busy:
                root.config(cursor='arrow')
                receiver_button.config(cursor='hand2')
            flush_wallet_view_refresh()
            status_message, status_color = wallet_sync_summary_text(sync_summary, errors)
            set_wallet_sync_status(status_message, status_color)
            if errors:
                if show_errors:
                    show_error_popup('Sync failed', RuntimeError("\n".join(errors)))
                else:
                    logger.debug("background wallet sync failed: %s", "; ".join(errors))
            elif sync_summary and sync_summary.get("errors") and show_errors:
                show_error_popup(
                    'Sync issues',
                    RuntimeError("\n".join(sync_summary["errors"])),
                )

        root.after(0, finish)

    threading.Thread(target=worker, daemon=True).start()


# Synchronize wallet-visible bills from local settlement and peer gossip.
def receive_bills():
    start_wallet_sync(show_busy=True, show_errors=True)


def start_wallet_background_sync():
    start_wallet_sync(show_busy=False, show_errors=False)


wallet_send_running = False
wallet_send_popup = None
wallet_send_popup_widgets = {}
wallet_send_queue_monitor_after_id = None
wallet_send_queue_monitor_expected_total = 0
wallet_send_queue_monitor_sent_floor = 0
wallet_send_queue_monitor_ticks_remaining = 0
WALLET_SEND_QUEUE_MONITOR_INTERVAL_MS = 1000
WALLET_SEND_QUEUE_MONITOR_MAX_TICKS = 300
WALLET_SEND_POPUP_TRACK_BG = '#101a16'
WALLET_SEND_POPUP_PANEL_BG = '#040706'
WALLET_SEND_POPUP_STAT_BG = '#070c0a'
WALLET_SEND_POPUP_BADGE_BG = '#0d1713'
WALLET_SEND_POPUP_WIDTH = 470
WALLET_SEND_POPUP_BAR_WIDTH = 416
WALLET_SEND_POPUP_BAR_HEIGHT = 10


def format_eta(seconds):
    try:
        seconds = int(float(seconds))
    except (TypeError, ValueError):
        seconds = 0
    if seconds <= 0:
        return "estimating"
    if seconds < 60:
        return f"{seconds}s"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {remainder}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def wallet_send_bill_label(count):
    count = int(count or 0)
    return "bill" if count == 1 else "bills"


def wallet_send_phase_style(event, queued=0):
    event = str(event or "")
    queued = int(queued or 0)
    if event == "complete":
        return "Complete", IND_GREEN
    if event == "cancelled":
        return "Cancelled", IND_ORANGE
    if event == "cancelling":
        return "Cancelling", IND_ORANGE
    if event == "queued":
        return "Queued", IND_GREEN
    if event == "error":
        return "Needs review", IND_ORANGE
    if event == "rate_limited":
        return "Retrying", IND_ORANGE
    if event == "partial":
        return ("Retrying" if queued else "Complete"), IND_ORANGE if queued else IND_GREEN
    if event == "waiting":
        return "Waiting", IND_MUTED
    if event == "preparing":
        return "Preparing", IND_MUTED
    return "Broadcasting", IND_GREEN


def wallet_send_status_detail(progress, status_text):
    event = str(progress.get("event") or "")
    queued = int(progress.get("queued_remaining") or 0)
    eta = format_eta(progress.get("eta_seconds"))
    try:
        retry_after = int(float(progress.get("retry_after_seconds") or 0))
    except (TypeError, ValueError):
        retry_after = 0

    if event == "complete":
        return "All queued bills were handed to the background broadcaster."
    if event == "cancelled":
        return "Unsent queued bills were restored to the wallet."
    if event == "cancelling":
        return "Stopping before the next queued bill is dispatched."
    if event == "queued":
        return "Paced dispatch is running in the background."
    if event == "partial" and queued > 0:
        return "Retrying handoff automatically in the background."
    if event == "preparing":
        return "Checking queued transfer files before dispatch."
    if event == "rate_limited":
        if retry_after > 0:
            return f"Peers asked us to slow down. Next retry in about {retry_after}s."
        return "Peers asked us to slow down. Retrying automatically."
    if event == "waiting" and queued > 0:
        return "Waiting for peer handoff. Retrying automatically."
    if eta != "estimating":
        return f"Estimated time remaining: {eta}."
    return status_text


def wallet_send_progress_ratio(sent, total):
    try:
        total = int(total or 0)
        sent = int(sent or 0)
    except (TypeError, ValueError):
        return 0.0
    if total <= 0:
        return 0.0
    return max(0.0, min(1.0, float(sent) / float(total)))


def update_wallet_send_progress_bar(widgets, ratio, color):
    canvas = widgets.get("progress_canvas")
    fill = widgets.get("progress_fill")
    if canvas is None or fill is None:
        return
    width = px(WALLET_SEND_POPUP_BAR_WIDTH)
    height = px(WALLET_SEND_POPUP_BAR_HEIGHT)
    canvas.coords(fill, 0, 0, int(width * ratio), height)
    canvas.itemconfig(fill, fill=color)


def close_wallet_send_popup():
    global wallet_send_popup, wallet_send_popup_widgets
    try:
        if wallet_send_popup is not None and wallet_send_popup.winfo_exists():
            wallet_send_popup.destroy()
    except Exception:
        log_ignored_exception()
    wallet_send_popup = None
    wallet_send_popup_widgets = {}


def show_wallet_send_progress_popup(total):
    global wallet_send_popup, wallet_send_popup_widgets
    total = max(0, int(total or 0))
    try:
        if wallet_send_popup is not None and wallet_send_popup.winfo_exists():
            raise_widget(wallet_send_popup)
            return
    except Exception:
        wallet_send_popup = None
        wallet_send_popup_widgets = {}

    popup = Toplevel(root)
    popup.title("Sending bills")
    popup.configure(bg=IND_BLACK)
    popup.resizable(False, False)
    popup.protocol("WM_DELETE_WINDOW", close_wallet_send_popup)

    panel = Frame(
        popup,
        bg=WALLET_SEND_POPUP_PANEL_BG,
        bd=0,
        highlightthickness=1,
        highlightbackground=NODE_CHIP_BORDER,
        highlightcolor=NODE_CHIP_BORDER,
    )
    header = Frame(panel, bg=WALLET_SEND_POPUP_PANEL_BG, bd=0, highlightthickness=0)
    title = Label(
        header,
        text="Sending bills",
        font=app_font(28, 'bold'),
        bg=WALLET_SEND_POPUP_PANEL_BG,
        fg=IND_WHITE,
        anchor='w',
    )
    phase = Label(
        header,
        text="Preparing",
        font=app_font(15),
        bg=WALLET_SEND_POPUP_BADGE_BG,
        fg=IND_MUTED,
        anchor='center',
        width=12,
        padx=px(5),
        pady=px(1),
    )
    subtitle = Label(
        panel,
        text=f"Preparing {total} {wallet_send_bill_label(total)} for dispatch",
        font=app_font(17),
        bg=WALLET_SEND_POPUP_PANEL_BG,
        fg=IND_MUTED,
        anchor='w',
    )
    progress_canvas = Canvas(
        panel,
        width=px(WALLET_SEND_POPUP_BAR_WIDTH),
        height=px(WALLET_SEND_POPUP_BAR_HEIGHT),
        bg=WALLET_SEND_POPUP_TRACK_BG,
        bd=0,
        highlightthickness=0,
    )
    progress_fill = progress_canvas.create_rectangle(
        0,
        0,
        0,
        px(WALLET_SEND_POPUP_BAR_HEIGHT),
        fill=IND_GREEN,
        outline='',
    )
    progress = Label(
        panel,
        text=f"0 of {total}",
        font=app_font(17),
        bg=WALLET_SEND_POPUP_PANEL_BG,
        fg=IND_GREEN,
        anchor='w',
    )

    stats = Frame(panel, bg=WALLET_SEND_POPUP_PANEL_BG, bd=0, highlightthickness=0)

    def make_stat(parent, caption, value="0"):
        frame = Frame(
            parent,
            bg=WALLET_SEND_POPUP_STAT_BG,
            bd=0,
            highlightthickness=1,
            highlightbackground=NODE_CHIP_BORDER,
            highlightcolor=NODE_CHIP_BORDER,
            width=px(126),
            height=px(62),
        )
        frame.grid_propagate(False)
        value_label = Label(
            frame,
            text=value,
            font=app_font(25, 'bold'),
            bg=WALLET_SEND_POPUP_STAT_BG,
            fg=IND_WHITE,
            anchor='w',
        )
        caption_label = Label(
            frame,
            text=caption,
            font=app_font(13),
            bg=WALLET_SEND_POPUP_STAT_BG,
            fg=IND_MUTED,
            anchor='w',
        )
        value_label.grid(row=0, column=0, padx=px(10), pady=(px(5), 0), sticky='ew')
        caption_label.grid(row=1, column=0, padx=px(10), pady=(0, px(5)), sticky='ew')
        frame.grid_columnconfigure(0, weight=1)
        return frame, value_label, caption_label

    sent_card, sent_value, _sent_caption = make_stat(stats, "Sent")
    queued_card, queued_value, _queued_caption = make_stat(stats, "Queued")
    busy_card, busy_value, _busy_caption = make_stat(stats, "Busy peers")

    detail = Label(
        panel,
        text="Estimated time remaining: estimating.",
        font=app_font(16),
        bg=WALLET_SEND_POPUP_PANEL_BG,
        fg=IND_MUTED,
        anchor='w',
        justify='left',
        wraplength=px(420),
    )
    status = Label(
        panel,
        text="Preparing queued bills.",
        font=app_font(16),
        bg=WALLET_SEND_POPUP_PANEL_BG,
        fg=IND_MUTED,
        anchor='w',
        justify='left',
        wraplength=px(420),
    )
    footer = Frame(panel, bg=WALLET_SEND_POPUP_PANEL_BG, bd=0, highlightthickness=0)
    cancel = Button(
        footer,
        text="Cancel",
        font=app_font(14),
        command=cancel_wallet_send_button,
        bd=0,
        highlightthickness=0,
        bg=IND_ORANGE,
        fg=IND_BLACK,
        activebackground=IND_ORANGE,
        activeforeground=IND_BLACK,
        cursor='hand2',
        padx=px(12),
        pady=px(3),
    )
    hide = Button(
        footer,
        text="Hide",
        font=app_font(14),
        command=close_wallet_send_popup,
        bd=0,
        highlightthickness=0,
        bg=NODE_HEADER_BG,
        fg=IND_WHITE,
        activebackground=NODE_HEADER_BG,
        activeforeground=IND_WHITE,
        cursor='hand2',
        padx=px(12),
        pady=px(3),
    )

    panel.grid(row=0, column=0, padx=px(12), pady=px(12), sticky='nsew')
    header.grid(row=0, column=0, padx=px(18), pady=(px(16), 0), sticky='ew')
    title.grid(row=0, column=0, sticky='w')
    phase.grid(row=0, column=1, padx=(px(12), 0), sticky='e')
    subtitle.grid(row=1, column=0, padx=px(18), pady=(0, px(14)), sticky='ew')
    progress_canvas.grid(row=2, column=0, padx=px(18), pady=(0, px(8)), sticky='w')
    progress.grid(row=3, column=0, padx=px(18), pady=(0, px(10)), sticky='ew')
    stats.grid(row=4, column=0, padx=px(18), pady=(0, px(12)), sticky='ew')
    sent_card.grid(row=0, column=0, padx=(0, px(10)), sticky='ew')
    queued_card.grid(row=0, column=1, padx=(0, px(10)), sticky='ew')
    busy_card.grid(row=0, column=2, sticky='ew')
    detail.grid(row=5, column=0, padx=px(18), pady=(0, px(4)), sticky='ew')
    status.grid(row=6, column=0, padx=px(18), pady=(0, px(14)), sticky='ew')
    footer.grid(row=7, column=0, padx=px(18), pady=(0, px(16)), sticky='ew')
    cancel.grid(row=0, column=0, padx=(0, px(8)), sticky='e')
    hide.grid(row=0, column=1, sticky='e')
    popup.grid_columnconfigure(0, minsize=px(WALLET_SEND_POPUP_WIDTH))
    panel.grid_columnconfigure(0, weight=1)
    header.grid_columnconfigure(0, weight=1)
    footer.grid_columnconfigure(0, weight=1)

    wallet_send_popup = popup
    wallet_send_popup_widgets = {
        "title": title,
        "phase": phase,
        "subtitle": subtitle,
        "progress_canvas": progress_canvas,
        "progress_fill": progress_fill,
        "progress": progress,
        "sent_value": sent_value,
        "queued_value": queued_value,
        "busy_value": busy_value,
        "detail": detail,
        "status": status,
        "cancel": cancel,
    }
    update_wallet_send_progress(
        {
            "event": "preparing",
            "total": total,
            "sent": 0,
            "queued_remaining": total,
            "rate_limited_peers": 0,
            "eta_seconds": 0,
            "message": "Preparing queued bills.",
        }
    )
    try:
        root.update_idletasks()
        popup.lift()
    except Exception:
        log_ignored_exception()


def set_wallet_send_busy(busy):
    cursor = 'watch' if busy else 'arrow'
    send_cursor = 'watch' if busy else 'hand2'
    try:
        root.config(cursor=cursor)
    except Exception:
        log_ignored_exception()
    try:
        send.config(cursor=send_cursor)
    except Exception:
        log_ignored_exception()


def wallet_send_status_text(progress):
    event = str(progress.get("event") or "")
    total = int(progress.get("total") or 0)
    sent = int(progress.get("sent") or 0)
    queued = int(progress.get("queued_remaining") or 0)
    eta = format_eta(progress.get("eta_seconds"))
    message = str(progress.get("message") or "").strip()
    if event == "complete":
        return f"Send complete: {sent} {wallet_send_bill_label(sent)} dispatched.", IND_GREEN
    if event == "cancelled":
        return f"Send cancelled: {queued} unsent {wallet_send_bill_label(queued)} restored.", IND_ORANGE
    if event == "cancelling":
        return f"Send: cancelling, {queued} queued.", IND_ORANGE
    if event == "queued":
        return f"Send: {queued} {wallet_send_bill_label(queued)} queued for background dispatch.", IND_GREEN
    if event == "partial":
        return (
            f"Send: {sent}/{total} dispatched, {queued} queued for retry.",
            IND_ORANGE,
        )
    if event == "rate_limited":
        return f"Send: peers busy, {queued} queued, retrying.", IND_ORANGE
    if event == "waiting":
        return f"Send: handing off to peers, {sent}/{total} dispatched, ETA {eta}.", IND_MUTED
    if event == "preparing":
        return "Send: preparing queued bills.", IND_MUTED
    if event == "error":
        return message or "Send issue while processing queued bills.", IND_ORANGE
    return f"Send: dispatching {sent}/{total}, ETA {eta}.", IND_MUTED


def update_wallet_send_progress(progress):
    status_text, status_color = wallet_send_status_text(progress)
    set_wallet_sync_status(status_text, status_color)

    try:
        popup = wallet_send_popup
        if popup is None or not popup.winfo_exists():
            return
        widgets = wallet_send_popup_widgets
        total = int(progress.get("total") or 0)
        sent = int(progress.get("sent") or 0)
        queued = int(progress.get("queued_remaining") or 0)
        rate_limited_peers = int(progress.get("rate_limited_peers") or 0)
        event = str(progress.get("event") or "")
        phase_text, phase_color = wallet_send_phase_style(event, queued)
        ratio = wallet_send_progress_ratio(sent, total)
        progress_color = IND_GREEN if event == "complete" else phase_color
        message = str(progress.get("message") or status_text)

        widgets["title"].config(text="Sending bills")
        widgets["phase"].config(text=phase_text, fg=phase_color)
        widgets["subtitle"].config(
            text=f"{sent} of {total} {wallet_send_bill_label(total)} dispatched"
        )
        update_wallet_send_progress_bar(widgets, ratio, progress_color)
        widgets["progress"].config(
            text=f"{sent} of {total} dispatched",
            fg=progress_color,
        )
        widgets["sent_value"].config(text=str(sent), fg=IND_GREEN if sent else IND_WHITE)
        widgets["queued_value"].config(text=str(queued), fg=IND_ORANGE if queued else IND_WHITE)
        widgets["busy_value"].config(
            text=str(rate_limited_peers),
            fg=IND_ORANGE if rate_limited_peers else IND_WHITE,
        )
        widgets["detail"].config(
            text=wallet_send_status_detail(progress, status_text),
            fg=IND_MUTED if event != "rate_limited" else IND_ORANGE,
        )
        if event == "complete":
            widgets["subtitle"].config(text=f"Dispatched {sent} {wallet_send_bill_label(sent)}.")
            widgets["cancel"].config(state=DISABLED, cursor='arrow')
        elif event == "cancelled":
            widgets["subtitle"].config(text="Send cancelled.")
            widgets["progress"].config(text=f"{queued} restored", fg=progress_color)
            widgets["cancel"].config(state=DISABLED, cursor='arrow')
        elif event == "cancelling":
            widgets["subtitle"].config(text="Cancelling queued dispatch")
            widgets["progress"].config(text=f"{queued} queued", fg=progress_color)
            widgets["cancel"].config(state=DISABLED, cursor='arrow')
        elif event == "queued":
            widgets["subtitle"].config(
                text=f"{queued} {wallet_send_bill_label(queued)} queued locally for paced dispatch"
            )
            widgets["progress"].config(text=f"{queued} queued", fg=progress_color)
            widgets["cancel"].config(state=NORMAL, cursor='hand2')
        elif event == "partial":
            widgets["subtitle"].config(
                text=(
                    f"{sent} dispatched, {queued} queued for automatic retry"
                    if queued
                    else f"Dispatched {sent} {wallet_send_bill_label(sent)}."
                )
            )
        widgets["status"].config(text=message, fg=status_color)
    except Exception:
        log_ignored_exception()


def wallet_send_summary_text(summary, errors):
    if errors:
        return "Send failed: " + errors[0], IND_ORANGE
    if not summary:
        return "Send finished.", IND_MUTED
    if summary.get("status") == "cancelled":
        queued = int(summary.get("queued_remaining") or 0)
        return f"Send cancelled: {queued} unsent {wallet_send_bill_label(queued)} restored.", IND_ORANGE
    sent = int(summary.get("sent") or 0)
    queued = int(summary.get("queued_remaining") or 0)
    rate_limited = int(summary.get("rate_limited_peers") or 0)
    if queued:
        return f"Send: {queued} {wallet_send_bill_label(queued)} queued for retry.", IND_ORANGE
    if rate_limited:
        return f"Send complete: {sent} {wallet_send_bill_label(sent)} dispatched, slowed by busy peers.", IND_GREEN
    return f"Send complete: {sent} {wallet_send_bill_label(sent)} dispatched.", IND_GREEN


def show_wallet_send_locally_queued(expected_total=0):
    try:
        queued = len(runtime_json.transaction_files())
    except Exception:
        log_ignored_exception()
        queued = int(expected_total or 0)
    total = max(int(expected_total or 0), int(queued or 0))
    sent = max(0, total - int(queued or 0))
    update_wallet_send_progress(
        {
            "event": "queued",
            "total": total,
            "sent": sent,
            "queued_remaining": queued,
            "rate_limited_peers": 0,
            "eta_seconds": 0,
            "message": f"Queued {queued} {wallet_send_bill_label(queued)} for paced dispatch.",
        }
    )


def wallet_send_cancel_store():
    try:
        store = wallet_snapshot_store()
        if store is not None:
            return store
    except Exception:
        log_ignored_exception()
    try:
        return sender_node.wallet_sync_store()
    except Exception:
        log_ignored_exception()
    return ind_token.INDLocalStore(require_transparency=False)


def queued_wallet_transfer_detail(path, store):
    message = runtime_json.read_transaction_message(path)
    bill, proof_bundle, _archive_segments = protocol_v3.decode_transfer_announcement(message)
    trusted_operator_public_key = None
    trusted_key_getter = getattr(store, "_trusted_operator_key_from_proof_bundle_v3", None)
    if callable(trusted_key_getter) and proof_bundle is not None:
        trusted_operator_public_key = trusted_key_getter(proof_bundle)
    state = protocol_v3.verify_bill(
        bill,
        proof_bundle=proof_bundle,
        proof_bundle_resolver=getattr(store, "proof_bundle_resolver_v3", None),
        trusted_operator_public_key=trusted_operator_public_key,
        archive_segment_resolver=getattr(store, "archive_segment_resolver_v3", None),
    )
    return {
        "path": Path(path),
        "display_id": state.display_id,
        "owner_address": state.owner_address,
        "sequence": int(state.sequence),
        "bill_hash": protocol_v3.bill_hash(bill).hex(),
    }


def restore_cancelled_wallet_lines(details):
    details_by_display_id = {
        str(detail.get("display_id") or ""): detail
        for detail in details
        if detail.get("display_id")
    }
    if not details_by_display_id:
        return 0
    wallet_path = active_wallet_path()
    if wallet_path is None:
        return 0
    lines = runtime_json.read_decrypted_wallet_lines(wallet_path)
    updated = []
    restored = 0
    for line in lines:
        parts = str(line).split()
        display_id = parts[0].lstrip("-") if parts else ""
        detail = details_by_display_id.get(display_id)
        if parts and parts[0].startswith("-") and detail:
            parts[0] = display_id
            if len(parts) > 1:
                parts[1] = str(max(0, int(detail.get("sequence") or 1) - 1))
            updated.append(" ".join(parts) + "\n")
            restored += 1
        else:
            updated.append(line)
    if restored:
        runtime_json.write_decrypted_wallet_lines(wallet_path, updated)
        clear_wallet_record_cache()
    return restored


def cancel_queued_wallet_send_files():
    paths = list(runtime_json.transaction_files())
    if not paths:
        return {"removed": 0, "restored": 0, "discarded": 0, "details": []}
    store = wallet_send_cancel_store()
    details = []
    removed = 0
    discarded = 0
    for path in paths:
        detail = None
        try:
            detail = queued_wallet_transfer_detail(path, store)
            details.append(detail)
            discard = getattr(store, "discard_unsettled_bill_v3", None)
            if callable(discard) and discard(
                detail["bill_hash"],
                display_id=detail["display_id"],
                owner_address=detail["owner_address"],
                sequence=detail["sequence"],
            ):
                discarded += 1
        except Exception:
            log_ignored_exception("could not decode queued wallet send for cancellation")
        try:
            Path(path).unlink()
            removed += 1
        except FileNotFoundError:
            pass
        except Exception:
            log_ignored_exception("could not remove queued wallet send")
    restored = restore_cancelled_wallet_lines(details)
    try:
        refresh_wallet_history_cache()
    except Exception:
        log_ignored_exception()
    return {
        "removed": removed,
        "restored": restored,
        "discarded": discarded,
        "details": details,
    }


def emit_wallet_send_cancelled(summary):
    removed = int(summary.get("removed") or 0)
    restored = int(summary.get("restored") or 0)
    update_wallet_send_progress(
        {
            "event": "cancelled",
            "total": removed,
            "sent": 0,
            "queued_remaining": restored,
            "rate_limited_peers": 0,
            "eta_seconds": 0,
            "message": f"Cancelled send: restored {restored} unsent {wallet_send_bill_label(restored)}.",
        }
    )


def cancel_wallet_send_button():
    try:
        sender_node.request_cancel_queued_bills()
    except Exception:
        log_ignored_exception()
    queued = len(runtime_json.transaction_files())
    update_wallet_send_progress(
        {
            "event": "cancelling",
            "total": queued,
            "sent": 0,
            "queued_remaining": queued,
            "rate_limited_peers": 0,
            "eta_seconds": 0,
            "message": "Cancelling send before the next queued bill is dispatched.",
        }
    )
    if not wallet_send_running:
        emit_wallet_send_cancelled(cancel_queued_wallet_send_files())
        refresh_wallet_view()


def cancel_wallet_send_queue_for_shutdown():
    try:
        sender_node.request_cancel_queued_bills()
    except Exception:
        log_ignored_exception()
    try:
        return cancel_queued_wallet_send_files()
    except Exception:
        log_ignored_exception()
        return {"removed": 0, "restored": 0, "discarded": 0, "details": []}


def cancel_wallet_send_queue_monitor():
    global wallet_send_queue_monitor_after_id
    after_id = wallet_send_queue_monitor_after_id
    wallet_send_queue_monitor_after_id = None
    if after_id is not None:
        try:
            root.after_cancel(after_id)
        except Exception:
            log_ignored_exception()


def start_wallet_send_queue_monitor(expected_total=0, sent_floor=0):
    global wallet_send_queue_monitor_expected_total
    global wallet_send_queue_monitor_sent_floor
    global wallet_send_queue_monitor_ticks_remaining
    cancel_wallet_send_queue_monitor()
    wallet_send_queue_monitor_expected_total = max(0, int(expected_total or 0))
    wallet_send_queue_monitor_sent_floor = max(0, int(sent_floor or 0))
    wallet_send_queue_monitor_ticks_remaining = WALLET_SEND_QUEUE_MONITOR_MAX_TICKS
    schedule_wallet_send_queue_monitor_tick()


def schedule_wallet_send_queue_monitor_tick():
    global wallet_send_queue_monitor_after_id
    wallet_send_queue_monitor_after_id = root.after(
        WALLET_SEND_QUEUE_MONITOR_INTERVAL_MS,
        wallet_send_queue_monitor_tick,
    )


def wallet_send_queue_monitor_tick():
    global wallet_send_queue_monitor_after_id
    global wallet_send_queue_monitor_ticks_remaining
    wallet_send_queue_monitor_after_id = None
    try:
        queued = len(runtime_json.transaction_files())
    except Exception:
        log_ignored_exception()
        if wallet_send_queue_monitor_ticks_remaining > 0:
            wallet_send_queue_monitor_ticks_remaining -= 1
            schedule_wallet_send_queue_monitor_tick()
        return
    total = max(
        wallet_send_queue_monitor_expected_total,
        wallet_send_queue_monitor_sent_floor + queued,
    )
    sent = max(wallet_send_queue_monitor_sent_floor, total - queued)
    if queued <= 0:
        update_wallet_send_progress(
            {
                "event": "complete",
                "total": total,
                "sent": sent,
                "queued_remaining": 0,
                "eta_seconds": 0,
                "message": f"Send complete: {sent} bill(s) dispatched.",
            }
        )
        refresh_wallet_view()
        return

    wallet_send_queue_monitor_ticks_remaining -= 1
    update_wallet_send_progress(
        {
            "event": "waiting",
            "total": total,
            "sent": sent,
            "queued_remaining": queued,
            "eta_seconds": 0,
            "message": f"Retrying automatically: {queued} queued.",
        }
    )
    if wallet_send_queue_monitor_ticks_remaining > 0:
        schedule_wallet_send_queue_monitor_tick()


def start_wallet_send_worker(expected_total=0, show_popup=True, keep_ui_busy=True):
    global wallet_send_running
    expected_total = max(int(expected_total or 0), len(runtime_json.transaction_files()))
    cancel_wallet_send_queue_monitor()
    if show_popup:
        show_wallet_send_progress_popup(expected_total)
    if wallet_send_running:
        set_wallet_sync_status(
            f"Send: {expected_total} bill(s) queued; sender already running.",
            IND_MUTED,
        )
        if not keep_ui_busy:
            show_wallet_send_locally_queued(expected_total)
            set_wallet_send_busy(False)
        return

    wallet_send_running = True
    if keep_ui_busy:
        set_wallet_send_busy(True)
    else:
        show_wallet_send_locally_queued(expected_total)
        set_wallet_send_busy(False)

    def progress(progress_event):
        root.after(0, lambda event=progress_event: update_wallet_send_progress(event))

    def worker():
        errors = []
        summary = None
        try:
            sender_node.maybe_refresh_dns_seed_peers(force=True)
        except Exception as exc:
            logger.debug("peer refresh before wallet send failed: %s", error_detail(exc))
        try:
            summary = sender_node.send_queued_bills_paced(progress_callback=progress)
        except Exception as exc:
            errors.append(f"Send worker failed: {error_detail(exc)}")

        def finish():
            global wallet_send_running
            try:
                live_queued = len(runtime_json.transaction_files())
            except Exception:
                log_ignored_exception()
                live_queued = 0
            summary_queued = int(summary.get("queued_remaining") or 0) if summary else 0
            wallet_send_running = False
            set_wallet_send_busy(False)
            if not errors and summary and summary.get("status") == "cancelled":
                cancel_summary = cancel_queued_wallet_send_files()
                emit_wallet_send_cancelled(cancel_summary)
                refresh_wallet_view()
                return
            if not errors and live_queued > 0 and summary_queued <= 0:
                start_wallet_send_worker(
                    expected_total=max(expected_total, live_queued),
                    show_popup=False,
                    keep_ui_busy=False,
                )
                return
            refresh_wallet_view()
            status_message, status_color = wallet_send_summary_text(summary, errors)
            set_wallet_sync_status(status_message, status_color)
            if not errors and summary and int(summary.get("queued_remaining") or 0) > 0:
                start_wallet_send_queue_monitor(
                    expected_total=max(expected_total, int(summary.get("total") or 0)),
                    sent_floor=int(summary.get("sent") or 0),
                )
            if errors:
                show_error_popup('Send failed', RuntimeError("\n".join(errors)))

        root.after(0, finish)

    threading.Thread(target=worker, daemon=True).start()


receiver_button = make_asset_button(
    'different_buttons', 'reload_button', receive_bills, 'Sync', font_size=16, bg=IND_BLACK
)

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


# Unlock an encrypted wallet into the short-lived desktop session.
def log_in():
    address = normalized_wallet_address(address_variable.get())
    password = enter_key.get()
    unlocked = wallet_decryption.wallet_decrypt(password, address)
    enter_key.delete(0, END)

    def check_decrypted():
        set_active_wallet_address(address)
        if active_wallet_path() is None:
            messagebox.showerror('Wallet locked', 'That wallet did not unlock correctly.')
            return
        wallet_button()
        start_wallet_background_sync()

    if unlocked:
        check_decrypted()
    else:
        messagebox.showerror('Wallet locked', 'That password did not unlock this wallet.')


class SignInWalletDropdown(Frame):
    def __init__(self, master, variable, values):
        super().__init__(
            master,
            bg=IND_BLACK,
            bd=0,
            highlightthickness=1,
            highlightbackground=IND_WHITE,
            highlightcolor=IND_WHITE,
            cursor='hand2',
        )
        self.variable = variable
        self.values = []
        self.visible_rows = 1
        self.popup = None
        self.listbox = None

        self.selected_label = Label(
            self,
            textvariable=self.variable,
            font=app_font(21, 'bold'),
            bg=IND_BLACK,
            fg=IND_WHITE,
            bd=0,
            highlightthickness=0,
            anchor='w',
            padx=10,
            cursor='hand2',
        )
        self.selected_label.pack(side='left', fill=BOTH, expand=True)
        self.arrow_button = Button(
            self,
            text='v',
            font=app_font(16, 'bold'),
            bg=IND_BLACK,
            fg=IND_WHITE,
            activebackground=IND_BLACK,
            activeforeground=IND_WHITE,
            bd=0,
            highlightthickness=0,
            relief=FLAT,
            cursor='hand2',
            command=self.toggle_popup,
        )
        self.arrow_button.pack(side='right', fill=BOTH, padx=(0, 2), pady=2, ipadx=8)

        for widget in (self, self.selected_label):
            widget.bind('<Button-1>', self._toggle_from_event)
        self.bind('<FocusOut>', self._hide_from_focus)
        master.bind('<Button-1>', self._hide_from_outside_click, add='+')
        self.set_values(values)

    def _toggle_from_event(self, _event=None):
        self.toggle_popup()
        return 'break'

    def _has_multiple_wallets(self):
        return len([value for value in self.values if normalized_wallet_address(value)]) > 1

    def _refresh_click_state(self):
        cursor = 'hand2' if self._has_multiple_wallets() else 'arrow'
        self.config(cursor=cursor)
        self.selected_label.config(cursor=cursor)
        if self._has_multiple_wallets():
            self.arrow_button.config(cursor='hand2')
            if not self.arrow_button.winfo_manager():
                self.arrow_button.pack(side='right', fill=BOTH, padx=(0, 2), pady=2, ipadx=8)
        elif self.arrow_button.winfo_manager():
            self.arrow_button.pack_forget()

    def _clean_values(self, values):
        cleaned = []
        for value in values:
            value = normalized_wallet_address(value)
            if value and value not in cleaned:
                cleaned.append(value)
        return cleaned or ['']

    def set_values(self, values, preferred=None):
        selected = normalized_wallet_address(preferred or self.variable.get())
        self.values = self._clean_values(values)
        self.visible_rows = max(1, min(SIGN_IN_WALLET_DROPDOWN_ROWS, len(self.values)))
        if selected and selected in self.values:
            self.variable.set(selected)
        else:
            self.variable.set(self.values[0] if normalized_wallet_address(self.values[0]) else '')
        self.destroy_popup()
        self._refresh_click_state()

    def _contains_widget(self, widget):
        while widget is not None:
            if widget is self or widget is self.popup:
                return True
            widget = getattr(widget, 'master', None)
        return False

    def _hide_from_outside_click(self, event):
        if self.popup is None or not self.popup.winfo_ismapped():
            return
        widget = event.widget.winfo_containing(event.x_root, event.y_root)
        if not self._contains_widget(widget):
            self.hide_popup()

    def _hide_from_focus(self, _event=None):
        self.after(100, self._hide_if_focus_left)

    def _hide_if_focus_left(self):
        if self.popup is None or not self.popup.winfo_ismapped():
            return
        if not self._contains_widget(self.focus_get()):
            self.hide_popup()

    def _build_popup(self):
        popup = Frame(
            self.master,
            bg=IND_WHITE,
            bd=0,
            highlightthickness=1,
            highlightbackground=IND_WHITE,
        )
        listbox = Listbox(
            popup,
            font=app_font(20),
            bg=IND_BLACK,
            fg=IND_WHITE,
            selectbackground=IND_WHITE,
            selectforeground=IND_BLACK,
            activestyle='none',
            bd=0,
            highlightthickness=0,
            height=self.visible_rows,
            exportselection=False,
        )
        for value in self.values:
            listbox.insert(END, value)
        listbox.pack(side='left', fill=BOTH, expand=True, padx=(1, 0), pady=1)
        if len(self.values) > self.visible_rows:
            scrollbar = Scrollbar(
                popup,
                command=listbox.yview,
                bd=0,
                highlightthickness=0,
                bg=IND_BLACK,
                troughcolor='#171717',
                activebackground=IND_WHITE,
            )
            listbox.config(yscrollcommand=scrollbar.set)
            scrollbar.pack(side='right', fill='y', padx=(0, 1), pady=1)
        listbox.bind('<ButtonRelease-1>', self._select_current)
        listbox.bind('<Return>', self._select_current)
        listbox.bind('<Escape>', lambda _event: self.hide_popup())
        listbox.bind('<MouseWheel>', self._scroll_listbox)
        self.popup = popup
        self.listbox = listbox

    def _popup_height(self):
        self.popup.update_idletasks()
        requested_height = self.popup.winfo_reqheight()
        if requested_height > 1:
            return requested_height
        line_height = tkfont.Font(root=self.master, font=app_font(20)).metrics('linespace')
        return (line_height + px(8)) * self.visible_rows + px(2)

    def _scroll_listbox(self, event):
        if event.delta:
            self.listbox.yview_scroll(-1 * int(event.delta / 120), 'units')
            return 'break'
        return None

    def _select_current(self, _event=None):
        selection = self.listbox.curselection()
        if selection:
            self.variable.set(self.listbox.get(selection[0]))
        self.hide_popup()
        return 'break'

    def toggle_popup(self):
        if self.popup is not None and self.popup.winfo_ismapped():
            self.hide_popup()
        else:
            self.show_popup()

    def show_popup(self):
        if not self._has_multiple_wallets():
            self.hide_popup()
            return
        if self.popup is None:
            self._build_popup()
        self.update_idletasks()
        popup_y = self.winfo_y() + self.winfo_height() - 1
        self.popup.place(
            x=self.winfo_x(),
            y=popup_y,
            width=self.winfo_width(),
            height=self._popup_height(),
        )
        try:
            current = self.values.index(self.variable.get())
            self.listbox.selection_clear(0, END)
            self.listbox.selection_set(current)
            self.listbox.see(current)
        except ValueError:
            self.listbox.selection_clear(0, END)
        raise_widget(self.popup)
        self.listbox.focus_set()

    def hide_popup(self):
        if self.popup is not None:
            self.popup.place_forget()

    def destroy_popup(self):
        if self.popup is not None:
            self.popup.destroy()
            self.popup = None
            self.listbox = None

    def place_forget(self):
        self.hide_popup()
        super().place_forget()


def make_sign_in_wallet_dropdown(variable, values):
    return SignInWalletDropdown(root, variable, values)


def sign_in_wallet_addresses():
    addresses = []
    for wallet_path in runtime_json.iter_encrypted_wallet_files() + runtime_json.iter_decrypted_wallet_files():
        address = normalized_wallet_address(runtime_json.wallet_address_from_name(wallet_path.name))
        if address and address not in addresses:
            addresses.append(address)
    return addresses or ['']


address_variable = StringVar(root)
enter_address = make_sign_in_wallet_dropdown(address_variable, sign_in_wallet_addresses())


def refresh_sign_in_wallet_dropdown(preferred=None):
    enter_address.set_values(sign_in_wallet_addresses(), preferred=preferred)

enter_key = Entry(root, font=app_font(26), show='*', bg='light grey')
log_in_button2 = make_asset_button(
    'different_buttons', 'log_in_button', log_in, 'Sign in', font_size=26, bg=IND_GREEN
)
button_show = make_asset_button(
    'different_buttons', 'show_button', show_key_s, 'Show', font_size=16, bg=IND_WHITE, fg=IND_BLACK
)
button_show3 = make_asset_button(
    'different_buttons',
    'show3_button',
    show_password,
    'Show',
    font_size=16,
    bg=IND_WHITE,
    fg=IND_BLACK,
)


# Generate one wallet keypair in a background thread for the sign-up form.
def gen_ad():
    runtime_json.clear_wallet_generation()
    generate_address_text.config(state='normal'), public_key.config(
        state='normal'
    ), private_key.config(state='normal')
    generate_address_text.delete(0, END), public_key.delete(0, END), private_key.delete(0, END)
    root.config(cursor='watch')
    generate_address_button.config(cursor='watch')

    def finish(generated_wallet):
        runtime_json.write_wallet_generation(
            generated_wallet[0], generated_wallet[1], generated_wallet[2]
        )
        ha = runtime_json.wallet_generation_lines()
        h_address = ha[0].strip()
        h_private_key = ha[1].strip()
        h_public_key = ha[2].strip()
        generate_address_text.insert(0, h_address), public_key.insert(0, h_public_key)
        private_key.insert(0, h_private_key)
        generate_address_text.config(state='readonly'), public_key.config(state='readonly')
        private_key.config(state='readonly'), generate_address_button.config(cursor='hand2')
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


SUCCESS_POPUP_WIDTH = 653
SUCCESS_POPUP_HEIGHT = 550
SUCCESS_POPUP_BG = '#00833f'
SUCCESS_POPUP_DARK_BG = '#006331'
SUCCESS_POPUP_WARNING_BG = '#053f27'
SUCCESS_POPUP_RED = '#b83a45'
SUCCESS_POPUP_RED_ACTIVE = '#cc4653'
success_password_visible = False


def _set_success_password_entry(password):
    global success_password_visible
    success_password_visible = False
    success_password_entry.config(state=NORMAL, show='*')
    success_password_entry.delete(0, END)
    success_password_entry.insert(0, password)
    success_password_entry.config(state='readonly')


def _clear_success_password_entry():
    global success_password_visible
    success_password_visible = False
    if 'success_password_entry' not in globals():
        return
    success_password_entry.config(state=NORMAL, show='*')
    success_password_entry.delete(0, END)
    success_password_entry.config(state='readonly')
    success_status_label.config(text=GUI_TEXT['success_warning'], fg='#e6ffe9')


def _select_success_password(event=None):
    success_password_entry.focus_set()
    success_password_entry.selection_range(0, END)
    success_password_entry.icursor(END)
    return 'break' if event and getattr(event, 'keysym', '') == 'a' else None


def toggle_success_password_visibility():
    global success_password_visible
    success_password_visible = not success_password_visible
    success_password_entry.config(show='' if success_password_visible else '*')
    _select_success_password()


def copy_success_password():
    root.clipboard_clear()
    root.clipboard_append(success_password_entry.get())
    success_password_copy_button.config(text='Copied')
    root.after(1200, lambda: success_password_copy_button.config(text=GUI_TEXT['success_copy_button']))


def confirm_success_password_saved():
    hide_success_popup()


def mark_success_password_not_saved():
    success_status_label.config(text=GUI_TEXT['success_not_saved_warning'], fg='#ffe9e9')
    _select_success_password()
    raise_success_popup()


def hide_success_popup():
    _clear_success_password_entry()
    success_popup.place_forget()


def raise_success_popup():
    try:
        raise_widget(success_popup)
        raise_widget(success)
        for widget_name in (
            'success_password_entry',
            'success_password_show_button',
            'success_password_copy_button',
            'success_status_label',
            'success_saved_button',
            'success_not_saved_button',
        ):
            widget = globals().get(widget_name)
            if widget is not None:
                raise_widget(widget)
    except TclError:
        pass


def show_success_popup(password):
    hide_success_popup()
    root.update_idletasks()
    _set_success_password_entry(password)
    success_popup.place(
        x=px(GENERATE_WALLET_PANEL_LEFT),
        y=px(190),
        width=px(SUCCESS_POPUP_WIDTH),
        height=px(SUCCESS_POPUP_HEIGHT),
    )
    raise_success_popup()
    root.after_idle(raise_success_popup)
    root.after_idle(_select_success_password)


def generate_wallet_final():
    addr_hash = runtime_json.read_wallet_generation()["address"]
    wallet_password = choose_password.get()
    try:
        wallet_encryption.wallet_encrypt(wallet_password)
    except wallet_encryption.PasswordPolicyError as exc:
        messagebox.showerror('Weak wallet password', str(exc))
        return
    except Exception as exc:
        messagebox.showerror('Wallet generation failed', str(exc))
        return
    choose_password.delete(0, END)
    runtime_json.clear_wallet_generation()
    address_variable.set(addr_hash)
    refresh_sign_in_wallet_dropdown(preferred=addr_hash)
    sign_in_button()
    show_success_popup(wallet_password)


success_popup = Frame(root, bg=SUCCESS_POPUP_BG, bd=0, highlightthickness=0)
success = ModalCanvas(
    success_popup, 'success', SUCCESS_POPUP_WIDTH, SUCCESS_POPUP_HEIGHT, bg=SUCCESS_POPUP_BG
)
success.pack(fill=BOTH, expand=True)
success_password_entry = Entry(
    success_popup,
    font=app_font(23),
    bd=0,
    show='*',
    bg='#005f31',
    fg=IND_WHITE,
    insertbackground=IND_WHITE,
    readonlybackground='#005f31',
    selectbackground='#005a2c',
    selectforeground=IND_WHITE,
    highlightthickness=1,
    highlightbackground='#74db98',
    highlightcolor='#74db98',
)
success_password_entry.config(state='readonly')
success_password_entry.place(x=48 * reso, y=237 * reso, width=424 * reso, height=36 * reso)
success_password_entry.bind('<FocusIn>', _select_success_password)
success_password_entry.bind('<ButtonRelease-1>', _select_success_password)
success_password_entry.bind('<Control-a>', _select_success_password)
success_password_show_button = make_asset_button(
    'different_buttons',
    'show_button',
    toggle_success_password_visibility,
    'Show',
    font_size=16,
    bg='#eaffef',
    fg=IND_BLACK,
    master=success_popup,
)
success_password_show_button.place(x=482 * reso, y=237 * reso, width=50 * reso, height=36 * reso)
success_password_copy_button = make_text_button(
    GUI_TEXT['success_copy_button'],
    copy_success_password,
    font_size=15,
    bg=IND_WHITE,
    fg='#063f24',
    bd=1,
    relief=SOLID,
    master=success_popup,
)
success_password_copy_button.place(x=542 * reso, y=237 * reso, width=63 * reso, height=36 * reso)
success_status_label = Label(
    success_popup,
    text=GUI_TEXT['success_warning'],
    font=app_font(15),
    bg=SUCCESS_POPUP_WARNING_BG,
    fg='#e6ffe9',
    bd=0,
    justify='left',
    anchor='w',
    wraplength=px(535),
)
success_status_label.place(x=56 * reso, y=350 * reso, width=535 * reso, height=42 * reso)
success_saved_button = make_text_button(
    GUI_TEXT['success_saved_button'],
    confirm_success_password_saved,
    font_size=18,
    bg='#00a650',
    fg=IND_WHITE,
    font_weight='bold',
    master=success_popup,
)
success_saved_button.config(justify='center', activebackground='#10aa55')
success_saved_button.place(x=392 * reso, y=470 * reso, width=229 * reso, height=42 * reso)
success_not_saved_button = make_text_button(
    GUI_TEXT['success_not_saved_button'],
    mark_success_password_not_saved,
    font_size=18,
    bg=SUCCESS_POPUP_RED,
    fg=IND_WHITE,
    font_weight='bold',
    master=success_popup,
)
success_not_saved_button.config(justify='center', activebackground=SUCCESS_POPUP_RED_ACTIVE)
success_not_saved_button.place(x=186 * reso, y=470 * reso, width=190 * reso, height=42 * reso)
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
generate_address_button = make_asset_button(
    'different_buttons', 'generate_address_button', gen_ad, 'Generate', font_size=22, bg=IND_GREEN
)
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
button_show2 = make_asset_button(
    'different_buttons', 'show2_button', show_key_p, 'Show', font_size=16, bg='#4d4d4d'
)
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
generate_wallet_button2 = make_asset_button(
    'different_buttons',
    'generate_wallet_button',
    generate_wallet_final,
    'Generate Wallet',
    font_size=24,
    bg=IND_GREEN,
)

button_log_in = Button(
    root,
    font=app_font(30),
    text='Sign In',
    bd=0,
    highlightthickness=0,
    cursor='hand2',
    bg='black',
    fg='white',
    command=sign_in_button,
)
button_generate_wallet = Button(
    root,
    font=app_font(30),
    text='Generate Wallet',
    bd=0,
    highlightthickness=0,
    cursor='hand2',
    bg='black',
    fg='white',
    command=generate_wallet_button,
)


# Select wallet bills by denomination and queue signed sends to the receiver.
def send_bills(serial_num_start, recipient_address=None):
    errors = []
    sent_count = 0
    requested = list(serial_num_start)
    recipient_address = recipient_address or receiver.get()
    wallet_path = active_wallet_path()
    if wallet_path is None:
        return 0, ["Sign in to a wallet before sending bills."]
    of = runtime_json.read_decrypted_wallet_lines(wallet_path)
    wallet_address = of[0].strip() if of else ""
    store = wallet_store_for_address(wallet_address)
    updated = []
    for wb in of:
        parts = wb.split()
        display_id = parts[0] if parts else ""
        bill_prefix = wb.split('x')[0] + 'x'
        if bill_prefix in requested:
            requested.remove(bill_prefix)
            try:
                state = write_transfer_announcement(of, wb, recipient_address, store=store)
                if not state:
                    raise RuntimeError("bill is not spendable or is not settled")
                updated.append(
                    '-'
                    + display_id
                    + ' '
                    + str(state.sequence)
                    + ' '
                    + str(int(time.time()))
                    + '\n'
                )
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


# Convert the selected UI amount into denomination prefixes and send them.
def confirm_transaction(recipient_address):
    pending_before = len(runtime_json.transaction_files())
    starts_with = selected_bill_prefixes()
    if not starts_with:
        raise ValueError("Select at least one bill before sending.")
    show_wallet_send_progress_popup(pending_before + len(starts_with))
    set_wallet_send_busy(True)
    sent_count, errors = send_bills(starts_with, recipient_address)
    if sent_count or pending_before:
        start_wallet_send_worker(
            expected_total=pending_before + sent_count,
            keep_ui_busy=False,
        )
    if errors:
        if not sent_count and not pending_before:
            update_wallet_send_progress(
                {
                    "event": "error",
                    "total": pending_before + len(starts_with),
                    "sent": 0,
                    "queued_remaining": len(runtime_json.transaction_files()),
                    "eta_seconds": 0,
                    "message": "No bills were queued for send.",
                }
            )
        raise RuntimeError("\n".join(errors))
    receiver.delete(0, END)


def send_button():
    root.config(cursor='watch')
    send.config(cursor='watch')
    try:
        recipient_address = wallet_services.validate_recipient_address(receiver.get())
        wallet_lines, _ = update_wallet()
        if amount == 0:
            raise ValueError("Select an amount before sending.")
        if recipient_address == wallet_lines[0].strip():
            raise ValueError("The recipient address is this wallet.")
        confirm_transaction(recipient_address)
    except Exception as exc:
        show_error_popup('Send failed', exc)
    finally:
        close_amount()
        if not wallet_send_running:
            root.config(cursor='arrow')
            send.config(cursor='hand2')
        refresh_wallet_view()


# Hide all page-level widgets before showing the next desktop view.
def close():
    try:
        if globals().get('cap') is not None or globals().get('num_of_times_clicked'):
            stop_qr_scan()
    except Exception:
        log_ignored_exception()
    reset_wallet_qr_mode()
    cancel_manual_bill_auto_add()
    # Widgets are manually placed per page, so navigation explicitly hides each one.
    claim_bills_amount.place_forget(), webcam_scanner.place_forget(), qr_scan_status.place_forget(), private_key_entry.place_forget()
    claim_left_separator.place_forget(), claim_right_separator.place_forget()
    claim_ready_title.place_forget()
    claim_total_label.place_forget()
    claim_count_label.place_forget()
    hide_scanned_serials_list()
    hide_claim_background_overlay()
    claim_bill.place_forget(), close_button.place_forget(), next_button.place_forget(), end_button.place_forget()
    serial_num.place_forget(), public_key_entry.place_forget(), check_validity_button.place_forget()
    send.place_forget(), receiver.place_forget(), a.place_forget(), frame_w.place_forget()
    b.place_forget(), close_amount_button.place_forget(), plus_bills_button.place_forget(), r_button.place_forget()
    previous_button.place_forget(), start_button.place_forget(), receiver_history.place_forget()
    wallet_sync_status_label.place_forget()
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
    print_progress_track.place_forget()
    print_progress_fill.place_forget()
    settings_page.place_forget()
    hide_node_terminal_widgets()
    hide_success_popup()
    for settings_widget in settings_widgets:
        settings_widget.place_forget()
    try:
        qr.place_forget(), address_txt.place_forget()
    except Exception:
        log_ignored_exception()


# Clear selected denominations and restore wallet bill button state.
def close_amount():
    global amount, count_selected
    for value in BILL_VALUES:
        selected_bill_counts[value] = 0
    amount = 0
    count_selected = False
    start_bills()


def close_bill_claimer():
    stop_qr_scan()
    cancel_manual_bill_auto_add()
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
    if receiver_history.winfo_ismapped():
        page(refresh_entries=False)


send = make_asset_button(
    'different_buttons', 'send_button', send_button, 'Send', font_size=24, bg=IND_GREEN
)
close_button = make_asset_button(
    'pop_up', 'close', close_bill_claimer, 'X', font_size=18, bg=IND_BLACK, fg=IND_RED
)
close_amount_button = make_asset_button(
    'different_buttons', 'close_amount', close_amount, 'X', font_size=14, bg='#d2d2d2', fg=IND_RED
)


# Open the claim workflow for manual entry, dropped images, or webcam scans.
def plus_bills():
    hide_wallet_history_nav()
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
    serial_num.place(
        x=CLAIM_ENTRY_X * reso,
        y=CLAIM_SERIAL_Y * reso,
        width=CLAIM_ENTRY_WIDTH * reso,
        height=40 * reso,
    )
    public_key_entry.place(
        x=CLAIM_ENTRY_X * reso,
        y=CLAIM_PUBLIC_Y * reso,
        width=CLAIM_ENTRY_WIDTH * reso,
        height=40 * reso,
    )
    private_key_entry.place(
        x=CLAIM_ENTRY_X * reso,
        y=CLAIM_PRIVATE_Y * reso,
        width=CLAIM_ENTRY_WIDTH * reso,
        height=40 * reso,
    )
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


plus_bills_button = make_asset_button(
    'different_buttons',
    'plus_bills_button',
    plus_bills,
    'Scan Qr code',
    font_size=18,
    bg=IND_BLACK,
    fg=IND_WHITE,
)
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


def cancel_manual_bill_auto_add():
    global manual_bill_auto_add_after_id
    if manual_bill_auto_add_after_id is not None:
        with contextlib.suppress(TclError):
            root.after_cancel(manual_bill_auto_add_after_id)
        manual_bill_auto_add_after_id = None


# Claim scanned bills by importing transfer announcements or spending paper-wallet bills.
def claim_bills():
    errors = []
    claim_count = 0
    try:
        if not used_codes:
            raise ValueError("No scanned bills are ready to claim.")
        wallet_path = active_wallet_path()
        if wallet_path is None:
            raise ValueError("Sign in to a wallet before claiming bills.")
        wallet_lines = runtime_json.read_decrypted_wallet_lines(wallet_path)
        wallet_address = runtime_json.wallet_address_from_name(wallet_path.name)
        for bill in used_codes:
            claimed = False
            preview = str(bill).splitlines()[0] if str(bill).splitlines() else "scanned bill"
            try:
                if wallet_services.claim_bill_payload(bill, wallet_lines, wallet_address):
                    claimed = True
                    claim_count += 1
            except Exception as exc:
                errors.append(f"{preview}: {error_detail(exc)}")
                continue
            if not claimed:
                errors.append(f"{preview}: could not be claimed")
        if claim_count:
            start_wallet_send_worker(expected_total=claim_count)
            root.after(2000, receive_bills)
        if errors:
            raise RuntimeError("\n".join(errors))
    except Exception as exc:
        show_error_popup('Claim bills failed', exc)
    finally:
        refresh_wallet_view()


# Add a manually entered bill payload to the pending claim list.
def add_bill():
    try:
        if not add_manual_bill_from_fields(show_errors=True):
            raise ValueError(
                "Manual bill fields are incomplete or already in the pending claim list."
            )
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
add_bill_button = make_asset_button(
    'different_buttons',
    'add_bill_button',
    add_bill,
    'Add bills',
    font_size=20,
    bg=IND_WHITE,
    fg=IND_BLACK,
)
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


def parse_client_bill_serial(serial):
    try:
        return protocol_v3.parse_display_id(str(serial).strip(), "IND bill serial")
    except Exception as exc:
        raise ValueError(
            "IND bill serial must be formatted like 10x28 with a numeric value and numeric serial."
        ) from exc


def add_manual_bill_from_fields(show_errors=False):
    serial = serial_num.get().strip()
    private_key = private_key_entry.get().strip()
    public_key = public_key_entry.get().strip()
    bill_number = number_entry.get().strip()
    if not serial or not private_key or not public_key:
        return False
    if serial in scanned_serial_numbers:
        return False
    try:
        parsed_serial = parse_client_bill_serial(serial)
    except ValueError:
        if show_errors:
            raise
        return False
    full_code = '\n'.join([serial, private_key, public_key, bill_number])
    if full_code in used_codes:
        return False
    used_codes.append(full_code)
    record_scanned_serial(serial)
    set_claim_amount_value(claim_amount_value() + int(parsed_serial["value"]))
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
        with contextlib.suppress(TclError):
            root.after_cancel(manual_bill_auto_add_after_id)
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
        if not claim_workflow_is_visible():
            hide_scanned_serials_list()
            return
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
        with contextlib.suppress(TclError):
            raise_widget(widget)


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
        ),
    )


def decode_paper_bill(decoded_qrcode):
    lines = [line.strip() for line in decoded_qrcode.splitlines()]
    if len(lines) < 4:
        raise ValueError(
            'IND bill QR codes must contain serial, private key, public key, and number lines.'
        )
    serial, private_key, public_key, bill_number = lines[:4]
    if not serial or not private_key or not public_key or not bill_number:
        raise ValueError('IND bill QR code contains an empty required field.')
    parsed_serial = parse_client_bill_serial(serial)
    return serial, private_key, public_key, bill_number, int(parsed_serial["value"])


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


# Apply decoded QR payloads to wallet fields and return a scan result summary.
def process_qr_payloads(payloads, suppress_repeated_invalid=False, show_invalid_errors=True):
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
                address = wallet_services.validate_wallet_address(decoded_qrcode, "QR address")
                receiver.delete(0, END)
                receiver.insert(0, address)
                result['accepted'] += 1
            elif decoded_qrcode.startswith('{'):
                message = json.loads(decoded_qrcode)
                if message.get("type") != protocol_v3.TRANSFER_ANNOUNCEMENT_TYPE:
                    raise ValueError('QR JSON is not a V3 transfer announcement.')
                bill_payload, _proof_bundle, _archive_segments = (
                    protocol_v3.decode_transfer_announcement(message)
                )
                protocol_v3.validate_bill_display_id(bill_payload)
                used_codes.append(decoded_qrcode)
                serial_num.delete(0, END)
                display_id = bill_payload['checkpoint_core']['display_id']
                serial_num.insert(0, display_id)
                record_scanned_serial(display_id)
                set_claim_amount_value(claim_amount_value() + int(bill_payload['value']))
                result['accepted'] += 1
            else:
                serial, private_key, public_key, bill_number, bill_value = decode_paper_bill(
                    decoded_qrcode
                )
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


# Decode QR payloads with zxing-cpp first, falling back to pyzbar.
def qr_decoder(qrimage, suppress_repeated_invalid=False, live=False, show_invalid_errors=True):
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
            crop = gray_image[top : top + crop_size, left : left + crop_size]
            if crop.size == 0:
                continue
            target_width = max(crop.shape[1], 1200)
            target_height = max(1, int(round(crop.shape[0] * (target_width / crop.shape[1]))))
            if target_width > crop.shape[1]:
                yield 'hard crop zoom', cv2.resize(
                    crop, (target_width, target_height), interpolation=cv2.INTER_CUBIC
                )
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
    if (
        qr_hard_scan_inflight
        or detection_is_paused()
        or now - qr_hard_scan_last_at < QR_HARD_SCAN_INTERVAL_SECONDS
    ):
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
        webcam_scanner.config(
            image='', text=GUI_TEXT['qr_drop'], cursor='hand2', bd=1, highlightthickness=1
        )
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
    filename = filedialog.askopenfilename(
        title='Find QR image',
        initialdir='quickaccess',
        filetypes=(('png files', '*.png'), ('all files', '*.*')),
    )
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
        f'Details: {error_detail(error)}',
    )
    select_qr_image()


# Toggle live webcam scanning; image-file and drag/drop paths share the decoder.
def qr_scan():
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
            cropped = frame[0 : px(CLAIM_SCANNER_HEIGHT), 0 : px(CLAIM_SCANNER_WIDTH)]
            cv2image = cv2.cvtColor(cropped, cv2.COLOR_BGR2RGBA)
            qr_pic = Image.fromarray(cv2image)
            imgtk = ImageTk.PhotoImage(image=qr_pic)
            webcam_scanner.imgtk = imgtk
            webcam_scanner.config(image=imgtk)
            drain_hard_scan_results()
            if not detection_is_paused():
                result = qr_decoder(
                    frame, suppress_repeated_invalid=True, live=True, show_invalid_errors=False
                )
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

button = Button(
    root,
    command=node_terminal_button,
    text='Node Terminal',
    bg='black',
    fg='white',
    font=app_font(24),
    cursor='hand2',
    bd=0,
    activebackground='white',
    highlightthickness=0,
)
place_header_button(button, 577, 100, 169, 50)

button2 = Button(
    root,
    command=info_button,
    text='Information',
    bg='black',
    fg='white',
    font=app_font(24),
    cursor='hand2',
    bd=0,
    activebackground='white',
    highlightthickness=0,
)
place_header_button(button2, 750, 100, 169, 50)

button3 = Button(
    root,
    command=print_page_button,
    text='Print',
    bg='black',
    fg='white',
    font=app_font(24),
    cursor='hand2',
    bd=0,
    activebackground='white',
    highlightthickness=0,
)
place_header_button(button3, 923, 100, 169, 50)

button4 = Button(
    root,
    command=wallet_button,
    text='Wallet',
    bg='black',
    fg='white',
    font=app_font(24),
    cursor='hand2',
    bd=0,
    activebackground='white',
    highlightthickness=0,
)
place_header_button(button4, 1096, 100, 114, 50)

button_settings = make_text_button(
    'Settings', settings_button, font_size=22, bg=IND_BLACK, fg=IND_WHITE, bd=1, relief=SOLID
)
place_header_button(button_settings, 1016, 18, 94, 64)

button6 = make_asset_button(
    'different_buttons',
    'sign_in_button',
    sign_in_button,
    'Sign\nin',
    font_size=22,
    bg=IND_WHITE,
    fg=IND_BLACK,
)
place_header_button(button6, 1120, 18, 77, 64)
international_dollar.lift()
logo.lift()


# Persist unlocked wallet state and stop child processes before closing.
def on_closing():
    errors = []
    run_on_startup = 'NO'
    run_in_background = 'NO'
    try:
        cancel_wallet_send_queue_for_shutdown()
    except Exception as exc:
        errors.append(f"Could not cancel queued sends: {error_detail(exc)}")
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
                except Exception:
                    if encrypted_record.get("format") == "INDW3":
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
    cancel_wallet_send_queue_for_shutdown()
    show_root_when_ready()
    root.after(1000, start_update_check_later)
    mainloop()


if __name__ == "__main__":
    run()
