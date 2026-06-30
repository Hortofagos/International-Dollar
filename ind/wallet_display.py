# Helpers for wallet display behavior that should stay independent of Tk.


def exception_chain(error):
    seen = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = getattr(current, "__cause__", None) or getattr(current, "__context__", None)


def is_transparency_temporarily_unavailable(error):
    try:
        from . import transparency_client as log_client
    except Exception:
        log_client = None
    for exc in exception_chain(error):
        if log_client is not None and isinstance(exc, log_client.ConsistencyUnavailableError):
            return True
    return False


def offline_wallet_status_message(_error=None):
    return "Offline: showing local wallet data"


def bill_button_uses_active_art(enabled, pending=0):
    return bool(enabled) and int(pending or 0) <= 0


def wallet_history_visual_lines(entry):
    return 2 if str((entry or {}).get("tag") or "").lower() == "pending" else 1


def paginate_visual_rows(rows, page_number, line_limit=8, row_line_count=None):
    try:
        page_number = max(1, int(page_number))
    except Exception:
        page_number = 1
    try:
        line_limit = max(1, int(line_limit))
    except Exception:
        line_limit = 8
    row_line_count = row_line_count or wallet_history_visual_lines
    pages = [[]]
    used_lines = 0
    for row in list(rows or []):
        try:
            row_lines = max(1, int(row_line_count(row)))
        except Exception:
            row_lines = 1
        if pages[-1] and used_lines + row_lines > line_limit:
            pages.append([])
            used_lines = 0
        pages[-1].append(row)
        used_lines += min(row_lines, line_limit)
    total_pages = max(1, len(pages))
    if page_number > total_pages:
        page_number = total_pages
    return list(pages[page_number - 1]), total_pages


def pending_sync_retry_decision(summary, errors=None, attempts=0, max_attempts=8):
    errors = list(errors or [])
    if errors:
        return {"schedule": False, "exhausted": False, "pending": 0, "next_attempt": attempts}
    if not summary or str(summary.get("status") or "").lower() != "complete":
        return {"schedule": False, "exhausted": False, "pending": 0, "next_attempt": attempts}
    try:
        pending = max(0, int(summary.get("pending") or 0))
    except Exception:
        pending = 0
    try:
        attempts = max(0, int(attempts or 0))
    except Exception:
        attempts = 0
    try:
        max_attempts = max(0, int(max_attempts or 0))
    except Exception:
        max_attempts = 0
    if pending <= 0:
        return {"schedule": False, "exhausted": False, "pending": 0, "next_attempt": 0}
    if attempts >= max_attempts:
        return {
            "schedule": False,
            "exhausted": True,
            "pending": pending,
            "next_attempt": attempts,
        }
    return {
        "schedule": True,
        "exhausted": False,
        "pending": pending,
        "next_attempt": attempts + 1,
    }
