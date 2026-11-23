"""
history.py - 报文历史导入 / 导出

CSV 与 JSON 双向转换，字段与 server.py 的 record() 一致。
导出文件可直接用 Excel 打开；导入后可在界面中回放。
"""
from __future__ import annotations

import csv
import io
import json

FIELDS = ["ts", "protocol", "function", "params", "mode", "ok",
          "requestHex", "responseHex", "values", "error", "elapsedMs", "transport"]


def _cell(v) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return "" if v is None else str(v)


def to_csv(entries: list[dict]) -> str:
    """历史记录 -> CSV 文本（UTF-8 BOM，Excel 直接打开不乱码）。"""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    w.writeheader()
    for e in entries:
        w.writerow({k: _cell(e.get(k)) for k in FIELDS})
    return "\ufeff" + buf.getvalue()


def _parse_val(v: str, default):
    if v is None or v == "":
        return default
    try:
        return json.loads(v)
    except Exception:
        return v


def from_csv(text: str) -> list[dict]:
    """CSV 文本 -> 历史记录列表。"""
    text = text.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(text))
    out = []
    for row in reader:
        entry = {}
        for k in FIELDS:
            raw = row.get(k, "")
            if k == "params":
                entry[k] = _parse_val(raw, {})
            elif k == "values":
                entry[k] = _parse_val(raw, [])
            elif k == "ok":
                entry[k] = str(raw).lower() in ("true", "1", "yes", "ok")
            elif k == "elapsedMs":
                try:
                    entry[k] = float(raw)
                except Exception:
                    entry[k] = 0.0
            else:
                entry[k] = raw
        if entry.get("protocol") or entry.get("requestHex"):
            out.append(entry)
    return out


def to_json(entries: list[dict]) -> str:
    return json.dumps(entries, ensure_ascii=False, indent=2)


def from_json(text: str) -> list[dict]:
    try:
        data = json.loads(text.lstrip("\ufeff"))
    except Exception:
        return []
    return [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []
