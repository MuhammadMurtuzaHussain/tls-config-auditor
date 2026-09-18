"""Console table and JSON rendering for a batch of result rows (plain
dicts, as produced by cli._to_row)."""

from __future__ import annotations

import json
from datetime import datetime

from tabulate import tabulate

from . import grading

_COLORS = {
    grading.PASS: "\033[32m",
    grading.WARN: "\033[33m",
    grading.FAIL: "\033[31m",
    grading.UNKNOWN: "\033[90m",
}
_RESET = "\033[0m"


def _colorize(text: str, status: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS.get(status, '')}{text}{_RESET}"


def render_table(rows: list[dict], use_color: bool = True) -> str:
    table_rows = []
    for row in rows:
        status = row["overall_status"]
        days = row.get("cert_days_remaining")
        table_rows.append(
            [
                row["domain"],
                _colorize(status, status, use_color),
                row.get("negotiated_protocol") or "-",
                row.get("negotiated_cipher") or "-",
                days if days is not None else "-",
                "; ".join(row.get("issues", [])[:2]) or "-",
            ]
        )
    headers = [
        "Domain",
        "Status",
        "Protocol",
        "Cipher",
        "Cert days left",
        "Top issue(s)",
    ]
    return tabulate(table_rows, headers=headers, tablefmt="simple")


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def render_json(rows: list[dict]) -> str:
    return json.dumps(rows, indent=2, default=_json_default)
