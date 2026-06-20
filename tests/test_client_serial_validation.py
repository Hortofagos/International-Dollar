import pytest

from ind import runtime as runtime_json
from ind import wallet_services


@pytest.mark.parametrize(
    "line",
    [
        "10x28",
        "-10x28 2 1781546900",
        "1x6000000000",
        "100000x100000000",
    ],
)
def test_client_wallet_bill_lines_accept_numeric_serials(line):
    assert runtime_json.is_wallet_bill_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "1xcofixp16",
        "-1xcofixp16 2 1781546900",
        "1x0341108e1",
        "10x",
        "10xx28",
        "1x0",
        "1x6000000001",
        "10x4500000001",
        "100000x100000001",
    ],
)
def test_client_wallet_bill_lines_reject_non_numeric_serials(line):
    assert not runtime_json.is_wallet_bill_line(line)


def test_client_wallet_services_ignore_non_numeric_serial_line():
    assert wallet_services._display_id_from_wallet_line("1xcofixp16 2 1781546900") is None
