import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from PIL import Image, ImageChops, ImageDraw
from PyPDF2 import PdfReader

from ind import print_tools

ARTWORK_DIR = Path("img/bills_to_print")
A4_PDF_WIDTH_POINTS = 596
A4_PDF_HEIGHT_POINTS = 842


def _render_six_bills(denomination):
    with Image.open(ARTWORK_DIR / "a4.png") as page_image:
        page = page_image.copy()
    with Image.open(ARTWORK_DIR / f"{denomination}.png") as bill_image:
        bill = bill_image.copy()
    for slot_index in range(print_tools.BILLS_PER_PRINT_PAGE):
        page.paste(bill, print_tools._bill_position(slot_index, page, bill.size))
    return print_tools._render_print_page(page)


def _non_white_margins(image):
    bbox = ImageChops.difference(
        image.convert("RGB"),
        Image.new("RGB", image.size, "white"),
    ).getbbox()
    if bbox is None:
        raise AssertionError("Rendered print page is blank.")
    left, top, right, bottom = bbox
    return left, top, image.width - right, image.height - bottom


def _slot_box(slot_index, page, bill_size):
    x, y = print_tools._bill_position(slot_index, page, bill_size)
    return x, y, x + bill_size[0], y + bill_size[1]


class PrintToolsLayoutTests(unittest.TestCase):
    def test_bill_grid_origin_is_centered_in_print_area(self):
        with Image.open(ARTWORK_DIR / "a4.png") as page_image:
            page = page_image.copy()
        slot_width, slot_height = print_tools._bill_slot_size()
        origin_x, origin_y = print_tools._bill_grid_origin(page)
        print_width = page.width - print_tools.PRINT_PAGE_CROP_RIGHT
        print_height = page.height - print_tools.PRINT_PAGE_CROP_BOTTOM
        grid_width = print_tools.BILL_GRID_X_STEP * (print_tools.BILL_GRID_COLUMNS - 1) + slot_width
        grid_height = print_tools.BILL_GRID_Y_STEP * (print_tools.BILL_GRID_ROWS - 1) + slot_height

        self.assertLessEqual(abs(origin_x - (print_width - grid_width) / 2), 0.5)
        self.assertLessEqual(abs(origin_y - (print_height - grid_height) / 2), 0.5)

    def test_small_bill_grid_is_vertically_centered_after_rendering(self):
        image = _render_six_bills("1")
        _left, top, _right, bottom = _non_white_margins(image)

        self.assertLessEqual(abs(top - bottom), 1)

    def test_rendered_print_page_saves_as_pdf(self):
        with Image.open(ARTWORK_DIR / "a4.png") as page_image:
            page = page_image.copy()

        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "page.pdf"
            print_tools._save_print_page(page, output_path)

            self.assertGreater(output_path.stat().st_size, 0)
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF"))
            pdf_page = PdfReader(str(output_path)).pages[0]
            self.assertAlmostEqual(float(pdf_page.mediabox.width), A4_PDF_WIDTH_POINTS, delta=1)
            self.assertAlmostEqual(float(pdf_page.mediabox.height), A4_PDF_HEIGHT_POINTS, delta=1)

    def test_print_output_uses_sortable_page_names_and_pdf_cleanup(self):
        self.assertEqual(
            [print_tools._print_page_path(index).name for index in range(4)],
            ["0000.pdf", "0001.pdf", "0002.pdf", "0003.pdf"],
        )

        old_output_dir = print_tools.PRINT_OUTPUT_DIR
        with TemporaryDirectory() as tmpdir:
            try:
                print_tools.PRINT_OUTPUT_DIR = Path(tmpdir)
                (print_tools.PRINT_OUTPUT_DIR / "stale.pdf").write_bytes(b"%PDF")
                (print_tools.PRINT_OUTPUT_DIR / ".gitkeep").write_text("keep")

                print_tools._clear_print_output_dir()

                self.assertFalse((print_tools.PRINT_OUTPUT_DIR / "stale.pdf").exists())
                self.assertTrue((print_tools.PRINT_OUTPUT_DIR / ".gitkeep").exists())
            finally:
                print_tools.PRINT_OUTPUT_DIR = old_output_dir

    def test_print_bills_are_sorted_into_denomination_groups(self):
        bills = [
            ("100x5", "6"),
            ("20x9", "10"),
            ("1x3", "4"),
            ("20x1", "2"),
            ("100x2", "3"),
            ("20x4", "5"),
            ("1x1", "2"),
        ]

        self.assertEqual(
            [bill[0] for bill in print_tools._sort_print_bills(bills)],
            ["1x1", "1x3", "20x1", "20x4", "20x9", "100x2", "100x5"],
        )
        self.assertEqual(
            [[bill[0] for bill in chunk] for chunk in print_tools._print_bill_chunks(bills, 3)],
            [["1x1", "1x3", "20x1"], ["20x4", "20x9", "100x2"], ["100x5"]],
        )

    def test_addresses_return_in_original_selection_order_after_pdf_sorting(self):
        bills = [("100x5", "6"), ("20x1", "2"), ("1x1", "2")]
        address_by_display_id = {
            "1x1": "addr-for-1",
            "20x1": "addr-for-20",
            "100x5": "addr-for-100",
        }

        self.assertEqual(
            print_tools._addresses_in_original_order(bills, address_by_display_id),
            ["addr-for-100", "addr-for-20", "addr-for-1"],
        )

    def test_upper_serial_uses_measured_width_for_short_and_long_ids(self):
        layer_width = 770 * print_tools.PRINT_ASSET_SCALE
        layer = Image.new('L', (layer_width, 310 * print_tools.PRINT_ASSET_SCALE))
        draw = ImageDraw.Draw(layer)
        font = print_tools.bill_font(48 * print_tools.PRINT_ASSET_SCALE)

        for display_id in ("1x12", "20x780748972838"):
            with self.subTest(display_id=display_id):
                left, _top, right, _bottom = draw.textbbox((0, 0), display_id, font=font)
                x = print_tools._right_aligned_text_x(
                    draw,
                    display_id,
                    font,
                    layer_width,
                    print_tools.UPPER_SERIAL_TOP_MARGIN,
                )

                self.assertGreaterEqual(x + left, 0)
                self.assertEqual(x + right, layer_width - print_tools.UPPER_SERIAL_TOP_MARGIN)

    def test_qr_only_serial_label_is_centered_over_qr_code(self):
        image = Image.new('RGB', (1000, 400), 'white')
        draw = ImageDraw.Draw(image)
        font = print_tools.bill_font(36 * print_tools.PRINT_ASSET_SCALE)
        qr_x = 100
        center_x = qr_x + print_tools.QR_IMAGE_SIZE / 2

        for display_id in ("1x12", "20x780748972838"):
            with self.subTest(display_id=display_id):
                left, _top, right, _bottom = draw.textbbox((0, 0), display_id, font=font)
                x = print_tools._centered_text_x(draw, display_id, font, center_x)

                self.assertAlmostEqual(x + left + (right - left) / 2, center_x, delta=0.5)

    def test_back_slots_align_with_front_slots_for_long_edge_duplex(self):
        with Image.open(ARTWORK_DIR / "a4.png") as page_image:
            page = page_image.copy()
        slot_size = print_tools._bill_slot_size()
        print_width = page.width - print_tools.PRINT_PAGE_CROP_RIGHT

        self.assertEqual(
            [print_tools._long_edge_duplex_back_slot(slot) for slot in range(6)],
            [2, 1, 0, 5, 4, 3],
        )
        for front_slot in range(print_tools.BILLS_PER_PRINT_PAGE):
            back_slot = print_tools._long_edge_duplex_back_slot(front_slot)
            front_box = _slot_box(front_slot, page, slot_size)
            back_left, back_top, back_right, back_bottom = _slot_box(back_slot, page, slot_size)
            physical_back_box = (
                print_width - back_right,
                back_top,
                print_width - back_left,
                back_bottom,
            )

            self.assertEqual(front_box, physical_back_box)

    def test_front_and_back_artwork_share_slot_position(self):
        with Image.open(ARTWORK_DIR / "a4.png") as page_image:
            page = page_image.copy()
        for front_path in sorted(ARTWORK_DIR.glob("*.png")):
            if front_path.name == "a4.png" or front_path.stem.endswith("_back"):
                continue
            back_path = front_path.with_name(f"{front_path.stem}_back.png")
            with self.subTest(denomination=front_path.stem):
                with Image.open(front_path) as front_image:
                    front_size = front_image.size
                with Image.open(back_path) as back_image:
                    back_size = back_image.size

                self.assertEqual(
                    print_tools._bill_position(0, page, front_size),
                    print_tools._bill_position(0, page, back_size),
                )


if __name__ == "__main__":
    unittest.main()
