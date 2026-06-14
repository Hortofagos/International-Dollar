import os
from PIL import Image, ImageDraw, ImageFont, ImageOps
import re
import qrcode
import subprocess
import threading
import time
from pyautogui import hotkey
from PyPDF2 import PdfMerger
import platform
import sys
from pathlib import Path
from functools import lru_cache
from dataclasses import dataclass

from . import address_generation as generate_address
from . import runtime as runtime_json


BASE_DIR = Path(__file__).resolve().parent.parent
FONT_PATH = BASE_DIR / 'Teko-Light.ttf'
PRINT_ARTWORK_DIR = Path('img/bills_to_print')
PRINT_PAGE_CROP_RIGHT = 70
PRINT_PAGE_CROP_BOTTOM = 20
BILL_GRID_COLUMNS = 3
BILL_GRID_ROWS = 2
BILLS_PER_PRINT_PAGE = BILL_GRID_COLUMNS * BILL_GRID_ROWS
BILL_GRID_X_STEP = 351
BILL_GRID_Y_STEP = 805


@dataclass
class FullBillPrintState:
    back_slot: int = 0
    back_index: int = 0


@dataclass
class QrPrintState:
    x: int = 50
    y: int = 50
    slot: int = 0
    index: int = 0


def bill_font(size):
    return ImageFont.truetype(str(FONT_PATH), size)


def print_pdf():
    merger = PdfMerger()
    for pdf_file in sorted(Path('print_folder').glob('*.pdf')):
        if pdf_file.name == 'result.pdf':
            continue
        merger.append(str(pdf_file))
    with open('print_folder/result.pdf', 'wb') as fout:
        merger.write(fout)
    if platform.system() == 'Windows':
        os.startfile(os.path.normpath('print_folder/result.pdf'))
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, 'print_folder/result.pdf'])
    time.sleep(10)
    hotkey('ctrl', 'p')
    time.sleep(10)
    for f in os.listdir('print_folder'):
        os.remove('print_folder/' + f)


def _generate_address_lines():
    address, private_key, public_key = generate_address.generate_keypair()
    return [address + '\n', private_key + '\n', public_key + '\n']


@lru_cache(maxsize=1)
def _bill_slot_size():
    sizes = []
    for bill_artwork in PRINT_ARTWORK_DIR.glob('*.png'):
        if bill_artwork.name == 'a4.png':
            continue
        with Image.open(bill_artwork) as img:
            sizes.append(img.size)
    if not sizes:
        raise FileNotFoundError("No bill artwork found in img/bills_to_print.")
    return max(width for width, _height in sizes), max(height for _width, height in sizes)


def _bill_grid_origin(page, slot_size=None):
    slot_width, slot_height = slot_size or _bill_slot_size()
    print_width = page.width - PRINT_PAGE_CROP_RIGHT
    print_height = page.height - PRINT_PAGE_CROP_BOTTOM
    grid_width = BILL_GRID_X_STEP * (BILL_GRID_COLUMNS - 1) + slot_width
    grid_height = BILL_GRID_Y_STEP * (BILL_GRID_ROWS - 1) + slot_height
    return (print_width - grid_width) // 2, (print_height - grid_height) // 2


def _bill_position(slot_index, page, bill_size):
    slot_width, slot_height = _bill_slot_size()
    origin_x, origin_y = _bill_grid_origin(page, (slot_width, slot_height))
    column = slot_index % BILL_GRID_COLUMNS
    row = slot_index // BILL_GRID_COLUMNS
    bill_width, bill_height = bill_size
    return (
        origin_x + column * BILL_GRID_X_STEP + (slot_width - bill_width) // 2,
        origin_y + row * BILL_GRID_Y_STEP + (slot_height - bill_height) // 2,
    )


def _render_print_page(page):
    width, height = page.size
    crop_box = (0, 0, width - PRINT_PAGE_CROP_RIGHT, height - PRINT_PAGE_CROP_BOTTOM)
    return page.crop(crop_box).resize((width, height), Image.Resampling.LANCZOS)


def _save_print_page(page, output_path):
    _render_print_page(page).save(output_path)


def _clear_print_page(page):
    page.paste(Image.new(page.mode, page.size, color='white'))


def full_bill(list_bills):
    a4_png = Image.open('img/bills_to_print/a4.png')
    state = FullBillPrintState()

    def bill_gen_front():
        for index, bill in enumerate(list_bills):
            slot = index % BILLS_PER_PRINT_PAGE
            img = Image.open('img/bills_to_print/' + bill[0].split('x')[0] + '.png')
            a4_png.paste(img, _bill_position(slot, a4_png, img.size))
            if slot == BILLS_PER_PRINT_PAGE - 1 or index == len(list_bills) - 1:
                len_list = float(index / 5) * 2
                _save_print_page(a4_png, 'print_folder/' + str(len_list) + '.pdf')
                _clear_print_page(a4_png)

    def bill_gen_back(bill):
        sm = bill.splitlines()[0]
        img = Image.open('img/bills_to_print/' + sm.split('x')[0] + '_back.png')
        address_qr = qrcode.QRCode(version=1, box_size=6, border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
        address_qr.add_data(bill)
        qr_make = address_qr.make_image(fill_color='black', back_color='white')
        qr_resize = qr_make.resize((240, 240), Image.Resampling.LANCZOS)

        f = bill_font(27)
        f2 = bill_font(48)
        txt = Image.new('L', (770,310))
        d = ImageDraw.Draw(txt)

        def format_key(s):
            return re.sub("(.{20})", "\\1\n", s, 0, re.DOTALL)

        d.text((5, 120), "Private Key :\n" + format_key(bill.splitlines()[1]),  font=f, fill=255)
        d.text((510, 70), "Public Key :\n" + format_key(bill.splitlines()[2]),  font=f, fill=255)
        d.text((330, 278), "Number : " + bill.splitlines()[3], font=f, fill=255)
        d.text((5, 252), sm, font=f2, fill=255)
        d.text((760 - len(sm) * 20, 2), sm, font=f2, fill=255)
        rot = txt.rotate(90,  expand=1)

        img.paste(ImageOps.colorize(rot, (255,255,255), (255,255,255)), (20,10),  rot)
        img.paste(qr_resize.rotate(90, expand=1), (55, 290))
        img.paste(qr_resize.rotate(90, expand=1), (55, 290))
        a4_png.paste(img, _bill_position(state.back_slot, a4_png, img.size))
        if state.back_slot == BILLS_PER_PRINT_PAGE - 1 or state.back_index == len(list_bills) - 1:
            _save_print_page(a4_png, 'print_folder/' + str(float(state.back_index / 5) * 2 + 0.5) + '.pdf')
            _clear_print_page(a4_png)
            state.back_slot = -1
        state.back_slot += 1
        state.back_index += 1

    bill_gen_front()
    used_addr = []
    for i in list_bills:
        new_address = _generate_address_lines()
        used_addr.append(new_address[0].strip())
        bill_gen_back(i[0] + '\n' + ''.join(new_address[1:]) + i[1])
        runtime_json.clear_wallet_generation()
    threading.Thread(target=print_pdf).start()
    return used_addr

def only_qr(list_bills):
    a4_png = Image.open('img/bills_to_print/a4.png')
    state = QrPrintState()

    def bill_gen_qr(bill):
        sm = bill.splitlines()[0]
        address_qr = qrcode.QRCode(version=1, box_size=6, border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
        address_qr.add_data(bill)
        qr_make = address_qr.make_image(fill_color='black', back_color='white')
        qr_resize = qr_make.resize((240, 240), Image.Resampling.LANCZOS)
        f = bill_font(36)
        d = ImageDraw.Draw(a4_png)
        d.text((state.x + 120 - len(sm) * 7, state.y - 37), sm, font=f, fill=0)
        a4_png.paste(qr_resize, (state.x, state.y))
        if state.slot == 23 or state.index == len(list_bills) - 1:
            a4_png.save('print_folder/' + str(len(os.listdir('print_folder'))) + '.pdf')
            a4_png.paste(Image.new('L', (1190, 1680), color='white'))
            state.x = 50
            state.y = 50
            state.slot = -1
        elif state.slot in {3, 7, 11, 15, 19}:
            state.y += 275
            state.x -= 750
        else:
            state.x += 250
        state.slot += 1
        state.index += 1

    used_addr = []
    for i in list_bills:
        new_address = _generate_address_lines()
        used_addr.append(new_address[0].strip())
        bill_gen_qr(i[0] + '\n' + ''.join(new_address[1:]) + i[1])
        runtime_json.clear_wallet_generation()
    threading.Thread(target=print_pdf).start()
    return used_addr
