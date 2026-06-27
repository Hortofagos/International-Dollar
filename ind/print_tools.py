import contextlib
import csv
import os
import platform
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw, ImageFont, ImageOps
from pyautogui import hotkey
from PyPDF2 import PdfMerger

from . import address_generation as generate_address
from . import runtime as runtime_json

BASE_DIR = Path(__file__).resolve().parent.parent
FONT_PATH = BASE_DIR / 'Teko-Light.ttf'
PRINT_ARTWORK_DIR = Path('img/bills_to_print')
PRINT_OUTPUT_DIR = Path('print_folder')
PRINT_CHARGE_BACKUP_CSV = 'paper_wallet_charge_addresses.csv'
PRINT_CHARGE_BACKUP_COLUMNS = (
    'serial',
    'charge_address',
    'next_sequence',
    'selection_index',
    'pdf_order_index',
    'print_mode',
    'created_at_utc',
)
PRINT_ASSET_SCALE = 2
PRINT_PDF_DPI = 144 * PRINT_ASSET_SCALE
PRINT_PDF_JPEG_QUALITY = 95
PRINT_PAGE_CROP_RIGHT = 70 * PRINT_ASSET_SCALE
PRINT_PAGE_CROP_BOTTOM = 20 * PRINT_ASSET_SCALE
BILL_GRID_COLUMNS = 3
BILL_GRID_ROWS = 2
BILLS_PER_PRINT_PAGE = BILL_GRID_COLUMNS * BILL_GRID_ROWS
BILL_GRID_X_STEP = 348 * PRINT_ASSET_SCALE
BILL_GRID_Y_STEP = 805 * PRINT_ASSET_SCALE
QR_IMAGE_SIZE = 240 * PRINT_ASSET_SCALE
UPPER_SERIAL_TOP_MARGIN = 28 * PRINT_ASSET_SCALE
BACK_TEXT_LAYER_X = 20 * PRINT_ASSET_SCALE
BACK_TEXT_LAYER_Y = 10 * PRINT_ASSET_SCALE
BACK_TEXT_LAYER_WIDTH = 770 * PRINT_ASSET_SCALE
BACK_TEXT_LAYER_HEIGHT = 310 * PRINT_ASSET_SCALE
BACK_QR_X = 55 * PRINT_ASSET_SCALE
BACK_QR_Y = 290 * PRINT_ASSET_SCALE
BACK_NUMBER_MAX_WIDTH = 700 * PRINT_ASSET_SCALE
BACK_NUMBER_Y = 278 * PRINT_ASSET_SCALE
BACK_NUMBER_TEXT_CENTER_X = BACK_TEXT_LAYER_WIDTH + BACK_TEXT_LAYER_Y - (
    BACK_QR_Y + QR_IMAGE_SIZE / 2
)


@dataclass
class QrPrintState:
    x: int = 50 * PRINT_ASSET_SCALE
    y: int = 50 * PRINT_ASSET_SCALE
    slot: int = 0
    index: int = 0
    page_index: int = 0


def bill_font(size):
    return ImageFont.truetype(str(FONT_PATH), size)


def print_pdf():
    merger = PdfMerger()
    for pdf_file in sorted(PRINT_OUTPUT_DIR.glob('*.pdf')):
        if pdf_file.name == 'result.pdf':
            continue
        merger.append(str(pdf_file))
    result_path = PRINT_OUTPUT_DIR / 'result.pdf'
    with result_path.open('wb') as fout:
        merger.write(fout)
    if platform.system() == 'Windows':
        os.startfile(os.path.normpath(result_path))
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, str(result_path)])
    time.sleep(10)
    hotkey('ctrl', 'p')
    time.sleep(10)
    for pdf_file in PRINT_OUTPUT_DIR.glob('*.pdf'):
        pdf_file.unlink()


def _generate_address_lines():
    address, private_key, public_key = generate_address.generate_keypair()
    return [address + '\n', private_key + '\n', public_key + '\n']


def _clear_print_output_dir():
    PRINT_OUTPUT_DIR.mkdir(exist_ok=True)
    for pdf_file in PRINT_OUTPUT_DIR.glob('*.pdf'):
        pdf_file.unlink()
    charge_backup = charge_backup_csv_path()
    if charge_backup.exists():
        charge_backup.unlink()


def _print_page_path(page_index):
    return PRINT_OUTPUT_DIR / f'{page_index:04d}.pdf'


def _display_id_sort_key(display_id):
    text = str(display_id).strip().lstrip("-")
    value, separator, issue_index = text.partition("x")
    if separator:
        try:
            return int(value), int(issue_index), text
        except ValueError:
            pass
    return sys.maxsize, sys.maxsize, text


def _sort_print_bills(list_bills):
    indexed_bills = list(enumerate(list_bills))
    return [
        bill
        for _index, bill in sorted(
            indexed_bills,
            key=lambda item: (*_display_id_sort_key(item[1][0]), item[0]),
        )
    ]


def _print_bill_chunks(list_bills, chunk_size=BILLS_PER_PRINT_PAGE):
    sorted_bills = _sort_print_bills(list_bills)
    return [
        sorted_bills[index : index + chunk_size]
        for index in range(0, len(sorted_bills), chunk_size)
    ]


def _addresses_in_original_order(list_bills, address_by_display_id):
    return [address_by_display_id[bill[0]] for bill in list_bills]


def charge_backup_csv_path(output_dir=None):
    return Path(output_dir or PRINT_OUTPUT_DIR) / PRINT_CHARGE_BACKUP_CSV


def _print_backup_timestamp(created_at=None):
    if created_at is not None:
        return str(created_at)
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def write_charge_backup_csv(
    list_bills,
    address_by_display_id,
    *,
    print_mode='',
    output_dir=None,
    created_at=None,
):
    output_path = charge_backup_csv_path(output_dir)
    output_path.parent.mkdir(exist_ok=True)
    pdf_order = {
        bill[0]: index
        for index, bill in enumerate(_sort_print_bills(list_bills), start=1)
    }
    timestamp = _print_backup_timestamp(created_at)
    rows = []
    for selection_index, bill in enumerate(list_bills, start=1):
        display_id = str(bill[0]).strip()
        charge_address = str(address_by_display_id.get(display_id) or '').strip()
        if not display_id or not charge_address:
            raise ValueError(f"missing paper-wallet charge address for {display_id or 'bill'}")
        rows.append(
            {
                'serial': display_id,
                'charge_address': charge_address,
                'next_sequence': str(bill[1]).strip(),
                'selection_index': selection_index,
                'pdf_order_index': pdf_order.get(display_id, selection_index),
                'print_mode': str(print_mode or ''),
                'created_at_utc': timestamp,
            }
        )

    temp_path = output_path.with_name(output_path.name + '.tmp')
    with temp_path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=PRINT_CHARGE_BACKUP_COLUMNS,
            lineterminator='\n',
        )
        writer.writeheader()
        writer.writerows(rows)
    temp_path.replace(output_path)
    return output_path


def read_charge_backup_csv(path=None):
    csv_path = Path(path) if path is not None else charge_backup_csv_path()
    mapping = {}
    with csv_path.open(newline='', encoding='utf-8') as handle:
        for row in csv.DictReader(handle):
            display_id = str(row.get('serial') or row.get('display_id') or '').strip()
            charge_address = str(row.get('charge_address') or row.get('address') or '').strip()
            if display_id and charge_address:
                mapping[display_id] = charge_address
    if not mapping:
        raise ValueError(f'{csv_path} does not contain any printed bill charge addresses')
    return mapping


def _emit_progress(progress_callback, completed, total, message):
    if progress_callback is None:
        return
    with contextlib.suppress(Exception):
        progress_callback(
            {
                "completed": int(completed),
                "total": max(1, int(total)),
                "message": str(message),
            }
        )


def _right_aligned_text_x(draw, text, font, layer_width, right_margin):
    left, _top, right, _bottom = draw.textbbox((0, 0), text, font=font)
    return layer_width - (right - left) - right_margin - left


def _centered_text_x(draw, text, font, center_x):
    left, _top, right, _bottom = draw.textbbox((0, 0), text, font=font)
    return center_x - (right - left) / 2 - left


def _font_fitting_width(draw, text, starting_size, max_width, min_size):
    size = int(starting_size)
    while size > min_size:
        font = bill_font(size)
        left, _top, right, _bottom = draw.textbbox((0, 0), text, font=font)
        if right - left <= max_width:
            return font
        size -= PRINT_ASSET_SCALE
    return bill_font(min_size)


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


def _long_edge_duplex_back_slot(slot_index):
    column = slot_index % BILL_GRID_COLUMNS
    row = slot_index // BILL_GRID_COLUMNS
    mirrored_column = BILL_GRID_COLUMNS - 1 - column
    return row * BILL_GRID_COLUMNS + mirrored_column


def _render_print_page(page):
    width, height = page.size
    crop_box = (0, 0, width - PRINT_PAGE_CROP_RIGHT, height - PRINT_PAGE_CROP_BOTTOM)
    return page.crop(crop_box).resize((width, height), Image.Resampling.LANCZOS)


def _save_pdf_page(page, output_path):
    Image.init()
    page.convert('RGB').save(
        output_path,
        format='PDF',
        resolution=PRINT_PDF_DPI,
        quality=PRINT_PDF_JPEG_QUALITY,
        subsampling=0,
    )


def _save_print_page(page, output_path):
    _save_pdf_page(_render_print_page(page), output_path)


def _clear_print_page(page):
    page.paste(Image.new(page.mode, page.size, color='white'))


def _new_print_page():
    return Image.open('img/bills_to_print/a4.png').convert('RGB')


def _render_bill_back(bill):
    sm = bill.splitlines()[0]
    with Image.open('img/bills_to_print/' + sm.split('x')[0] + '_back.png') as source:
        img = source.convert('RGB')
    address_qr = qrcode.QRCode(
        version=1, box_size=6, border=2, error_correction=qrcode.constants.ERROR_CORRECT_L
    )
    address_qr.add_data(bill)
    qr_make = address_qr.make_image(fill_color='black', back_color='white')
    qr_resize = qr_make.resize((QR_IMAGE_SIZE, QR_IMAGE_SIZE), Image.Resampling.NEAREST)

    f = bill_font(27 * PRINT_ASSET_SCALE)
    f2 = bill_font(48 * PRINT_ASSET_SCALE)
    txt = Image.new('L', (BACK_TEXT_LAYER_WIDTH, BACK_TEXT_LAYER_HEIGHT))
    d = ImageDraw.Draw(txt)

    def format_key(s):
        return re.sub("(.{20})", "\\1\n", s, count=0, flags=re.DOTALL)

    d.text(
        (5 * PRINT_ASSET_SCALE, 120 * PRINT_ASSET_SCALE),
        "Private Key :\n" + format_key(bill.splitlines()[1]),
        font=f,
        fill=255,
    )
    d.text(
        (510 * PRINT_ASSET_SCALE, 70 * PRINT_ASSET_SCALE),
        "Public Key :\n" + format_key(bill.splitlines()[2]),
        font=f,
        fill=255,
    )
    bill_lines = bill.splitlines()
    number_caption = f"Number: {bill_lines[3]}" if len(bill_lines) > 3 else "Number:"
    number_font = _font_fitting_width(
        d,
        number_caption,
        27 * PRINT_ASSET_SCALE,
        BACK_NUMBER_MAX_WIDTH,
        18 * PRINT_ASSET_SCALE,
    )
    d.text(
        (
            _centered_text_x(d, number_caption, number_font, BACK_NUMBER_TEXT_CENTER_X),
            BACK_NUMBER_Y,
        ),
        number_caption,
        font=number_font,
        fill=255,
    )
    d.text((5 * PRINT_ASSET_SCALE, 252 * PRINT_ASSET_SCALE), sm, font=f2, fill=255)
    d.text(
        (
            _right_aligned_text_x(d, sm, f2, txt.width, UPPER_SERIAL_TOP_MARGIN),
            2 * PRINT_ASSET_SCALE,
        ),
        sm,
        font=f2,
        fill=255,
    )
    rot = txt.rotate(90, expand=1)

    img.paste(
        ImageOps.colorize(rot, (255, 255, 255), (255, 255, 255)),
        (BACK_TEXT_LAYER_X, BACK_TEXT_LAYER_Y),
        rot,
    )
    img.paste(
        qr_resize.rotate(90, expand=1),
        (BACK_QR_X, BACK_QR_Y),
    )
    img.paste(
        qr_resize.rotate(90, expand=1),
        (BACK_QR_X, BACK_QR_Y),
    )
    return img


def _orient_back_bill_for_long_edge_duplex(bill_back):
    return bill_back.transpose(Image.Transpose.ROTATE_180)


def _draw_front_page(page, page_bills):
    for slot, bill in enumerate(page_bills):
        with Image.open('img/bills_to_print/' + bill[0].split('x')[0] + '.png') as img:
            page.paste(img, _bill_position(slot, page, img.size))


def _draw_back_page(page, page_bills, address_by_display_id):
    for slot, bill in enumerate(page_bills):
        new_address = _generate_address_lines()
        charge_address = new_address[0].strip()
        address_by_display_id[bill[0]] = charge_address
        bill_back = _render_bill_back(
            bill[0] + '\n' + ''.join(new_address[1:]) + bill[1],
        )
        bill_back = _orient_back_bill_for_long_edge_duplex(bill_back)
        duplex_slot = _long_edge_duplex_back_slot(slot)
        page.paste(bill_back, _bill_position(duplex_slot, page, bill_back.size))
        runtime_json.clear_wallet_generation()


def full_bill(list_bills, progress_callback=None):
    _clear_print_output_dir()
    address_by_display_id = {}
    page_chunks = _print_bill_chunks(list_bills)
    total_pages = len(page_chunks) * 2
    _emit_progress(progress_callback, 0, total_pages, "Preparing full bill PDF...")
    for page_index, page_bills in enumerate(page_chunks):
        front_page = _new_print_page()
        _draw_front_page(front_page, page_bills)
        _save_print_page(front_page, _print_page_path(page_index * 2))
        _emit_progress(
            progress_callback,
            page_index * 2 + 1,
            total_pages,
            f"Saved front page {page_index + 1} of {len(page_chunks)}",
        )

        back_page = _new_print_page()
        _draw_back_page(back_page, page_bills, address_by_display_id)
        _save_print_page(back_page, _print_page_path(page_index * 2 + 1))
        _emit_progress(
            progress_callback,
            page_index * 2 + 2,
            total_pages,
            f"Saved matching back page {page_index + 1} of {len(page_chunks)}",
        )

    write_charge_backup_csv(list_bills, address_by_display_id, print_mode='full')
    threading.Thread(target=print_pdf).start()
    return _addresses_in_original_order(list_bills, address_by_display_id)


def only_qr(list_bills, progress_callback=None):
    _clear_print_output_dir()
    a4_png = Image.open('img/bills_to_print/a4.png')
    state = QrPrintState()
    sorted_bills = _sort_print_bills(list_bills)
    address_by_display_id = {}
    total_pages = max(1, (len(sorted_bills) + 23) // 24)
    _emit_progress(progress_callback, 0, total_pages, "Preparing QR PDF...")

    def bill_gen_qr(bill):
        sm = bill.splitlines()[0]
        address_qr = qrcode.QRCode(
            version=1, box_size=6, border=2, error_correction=qrcode.constants.ERROR_CORRECT_L
        )
        address_qr.add_data(bill)
        qr_make = address_qr.make_image(fill_color='black', back_color='white')
        qr_resize = qr_make.resize((QR_IMAGE_SIZE, QR_IMAGE_SIZE), Image.Resampling.NEAREST)
        f = bill_font(36 * PRINT_ASSET_SCALE)
        d = ImageDraw.Draw(a4_png)
        d.text(
            (
                _centered_text_x(d, sm, f, state.x + QR_IMAGE_SIZE / 2),
                state.y - 37 * PRINT_ASSET_SCALE,
            ),
            sm,
            font=f,
            fill=0,
        )
        a4_png.paste(qr_resize, (state.x, state.y))
        if state.slot == 23 or state.index == len(sorted_bills) - 1:
            _save_pdf_page(a4_png, _print_page_path(state.page_index))
            _emit_progress(
                progress_callback,
                state.page_index + 1,
                total_pages,
                f"Saved QR page {state.page_index + 1} of {total_pages}",
            )
            _clear_print_page(a4_png)
            state.x = 50 * PRINT_ASSET_SCALE
            state.y = 50 * PRINT_ASSET_SCALE
            state.slot = -1
            state.page_index += 1
        elif state.slot in {3, 7, 11, 15, 19}:
            state.y += 275 * PRINT_ASSET_SCALE
            state.x -= 750 * PRINT_ASSET_SCALE
        else:
            state.x += 250 * PRINT_ASSET_SCALE
        state.slot += 1
        state.index += 1

    for i in sorted_bills:
        new_address = _generate_address_lines()
        address_by_display_id[i[0]] = new_address[0].strip()
        bill_gen_qr(i[0] + '\n' + ''.join(new_address[1:]) + i[1])
        runtime_json.clear_wallet_generation()
    write_charge_backup_csv(list_bills, address_by_display_id, print_mode='qr')
    threading.Thread(target=print_pdf).start()
    return _addresses_in_original_order(list_bills, address_by_display_id)
