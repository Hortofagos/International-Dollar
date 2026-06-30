from ind import transparency_client as log_client
from ind import wallet_display


def test_transparency_consistency_unavailable_is_soft_offline_display_error():
    error = log_client.ConsistencyUnavailableError("strict transparency check unavailable")

    assert wallet_display.is_transparency_temporarily_unavailable(error)
    assert wallet_display.offline_wallet_status_message(error) == "Offline: showing local wallet data"


def test_wrapped_consistency_unavailable_is_soft_offline_display_error():
    try:
        try:
            raise log_client.ConsistencyUnavailableError("mirrors unreachable")
        except log_client.ConsistencyUnavailableError as exc:
            raise RuntimeError("wallet refresh failed") from exc
    except RuntimeError as error:
        assert wallet_display.is_transparency_temporarily_unavailable(error)


def test_consistency_failure_is_not_soft_offline_display_error():
    error = log_client.ConsistencyProofError("operator history forked")

    assert not wallet_display.is_transparency_temporarily_unavailable(error)


def test_plain_runtime_error_is_not_soft_offline_display_error():
    assert not wallet_display.is_transparency_temporarily_unavailable(RuntimeError("boom"))


def test_bill_button_uses_neutral_art_when_pending_count_is_visible():
    assert wallet_display.bill_button_uses_active_art(enabled=True, pending=0)
    assert not wallet_display.bill_button_uses_active_art(enabled=True, pending=1)
    assert not wallet_display.bill_button_uses_active_art(enabled=False, pending=1)


def test_paginate_visual_rows_keeps_pending_rows_inside_line_limit():
    rows = [
        {"id": "a", "tag": "wallet"},
        {"id": "b", "tag": "wallet"},
        {"id": "c", "tag": "wallet"},
        {"id": "d", "tag": "wallet"},
        {"id": "e", "tag": "wallet"},
        {"id": "f", "tag": "wallet"},
        {"id": "g", "tag": "wallet"},
        {"id": "pending", "tag": "pending"},
        {"id": "after", "tag": "wallet"},
    ]

    first, total_pages = wallet_display.paginate_visual_rows(rows, 1, line_limit=8)
    second, _total_pages = wallet_display.paginate_visual_rows(rows, 2, line_limit=8)

    assert [row["id"] for row in first] == ["a", "b", "c", "d", "e", "f", "g"]
    assert [row["id"] for row in second] == ["pending", "after"]
    assert total_pages == 2


def test_pending_sync_retry_decision_schedules_and_exhausts():
    summary = {"status": "complete", "pending": 6}

    decision = wallet_display.pending_sync_retry_decision(summary, attempts=0, max_attempts=8)
    exhausted = wallet_display.pending_sync_retry_decision(summary, attempts=8, max_attempts=8)
    settled = wallet_display.pending_sync_retry_decision(
        {"status": "complete", "pending": 0},
        attempts=3,
        max_attempts=8,
    )

    assert decision == {
        "schedule": True,
        "exhausted": False,
        "pending": 6,
        "next_attempt": 1,
    }
    assert exhausted == {
        "schedule": False,
        "exhausted": True,
        "pending": 6,
        "next_attempt": 8,
    }
    assert settled == {
        "schedule": False,
        "exhausted": False,
        "pending": 0,
        "next_attempt": 0,
    }


def test_pending_sync_retry_decision_does_not_retry_errors_or_cancelled_sync():
    assert not wallet_display.pending_sync_retry_decision(
        {"status": "complete", "pending": 1},
        errors=["boom"],
    )["schedule"]
    assert not wallet_display.pending_sync_retry_decision(
        {"status": "cancelled", "pending": 1}
    )["schedule"]
