from pathlib import Path
import unittest

from PIL import Image, ImageChops

from ind import print_tools


ARTWORK_DIR = Path("img/bills_to_print")


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
