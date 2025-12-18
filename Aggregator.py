#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class IOC:
    indicator: str
    type: str
    source: str
    pulse_id: str
    pulse_name: str
    pulse_created: str
    reference: str
    first_seen_utc: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_mock_pulses(input_path: Path, limit: int) -> List[Dict[str, Any]]:
    try:
        with input_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Mock input file not found: {input_path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Mock input file is not valid JSON: {input_path} ({e})")

    results = data.get("results", [])
    if not isinstance(results, list):
        return []
    return results[: max(0, int(limit))]


def normalize_indicator(value: Any, ioc_type: str) -> Optional[str]:
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None

    t = (ioc_type or "").lower().strip()

    if t in {"domain", "hostname"}:
        return v.lower()

    if t in {"ipv4", "ip"}:
        try:
            ip = ipaddress.ip_address(v)
            if ip.version != 4:
                return None
            return str(ip)
        except ValueError:
            return None

    if t == "url":
        return v

    if t in {"filehash-md5", "filehash-sha1", "filehash-sha256", "md5", "sha1", "sha256"}:
        return v.lower()

    return v


def map_indicator_type(raw_type: Any) -> str:
    t = str(raw_type or "").lower().strip()
    if t in {"ipv4", "ip"}:
        return "ipv4"
    if t in {"domain", "hostname"}:
        return t
    if t == "url":
        return "url"
    if t.startswith("filehash-"):
        return t
    if t in {"md5", "sha1", "sha256"}:
        return t
    return t or "unknown"


def extract_iocs_from_pulse(pulse: Dict[str, Any], source_name: str) -> Iterable[IOC]:
    pulse_id = str(pulse.get("id", "")).strip()
    name = str(pulse.get("name", "")).strip()
    created = str(pulse.get("created", "")).strip()
    reference = str(pulse.get("reference", "")).strip() or str(pulse.get("author_name", "")).strip()

    indicators = pulse.get("indicators", [])
    if not isinstance(indicators, list):
        return []

    now = utc_now_iso()
    out: List[IOC] = []

    for ind in indicators:
        if not isinstance(ind, dict):
            continue

        raw_value = ind.get("indicator")
        raw_type = ind.get("type", "")

        ioc_type = map_indicator_type(raw_type)
        norm = normalize_indicator(raw_value, ioc_type)

        if not norm or ioc_type == "unknown":
            continue

        out.append(
            IOC(
                indicator=norm,
                type=ioc_type,
                source=source_name,
                pulse_id=pulse_id,
                pulse_name=name,
                pulse_created=created,
                reference=reference,
                first_seen_utc=now,
            )
        )

    return out


def dedupe_iocs(iocs: Iterable[IOC]) -> List[IOC]:
    seen: Set[Tuple[str, str]] = set()
    out: List[IOC] = []
    for i in iocs:
        key = (i.indicator, i.type)
        if key in seen:
            continue
        seen.add(key)
        out.append(i)
    return out


def ensure_parent_dir(out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)


def write_json(iocs: List[IOC], out_path: Path) -> None:
    ensure_parent_dir(out_path)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump([asdict(i) for i in iocs], f, indent=2)
    print(f"Wrote JSON: {out_path} ({len(iocs)} IOCs)")


def write_csv(iocs: List[IOC], out_path: Path) -> None:
    ensure_parent_dir(out_path)
    fieldnames = list(asdict(iocs[0]).keys()) if iocs else [
        "indicator",
        "type",
        "source",
        "pulse_id",
        "pulse_name",
        "pulse_created",
        "reference",
        "first_seen_utc",
    ]
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for i in iocs:
            w.writerow(asdict(i))
    print(f"Wrote CSV: {out_path} ({len(iocs)} IOCs)")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Threat Intelligence Feed Aggregator (Mock Mode)")
    p.add_argument("--input", default="mock_pulses.json", help="Path to mock pulses JSON (default: mock_pulses.json)")
    p.add_argument("--limit", type=int, default=50, help="How many pulses to process (default: 50)")
    p.add_argument("--format", choices=["json", "csv"], default="json", help="Output format (json or csv)")
    p.add_argument("--out", default="output/iocs.json", help="Output file path (default: output/iocs.json)")
    p.add_argument("--no-dedupe", action="store_true", help="Disable deduplication")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    input_path = Path(args.input)
    out_path = Path(args.out)

    pulses = load_mock_pulses(input_path=input_path, limit=args.limit)

    all_iocs: List[IOC] = []
    for pulse in pulses:
        try:
            all_iocs.extend(list(extract_iocs_from_pulse(pulse, source_name=f"Mock Feed ({input_path.name})")))
        except Exception as e:
            print(f"Warning: failed to parse pulse: {e}", file=sys.stderr)

    if not args.no_dedupe:
        all_iocs = dedupe_iocs(all_iocs)

    if args.format == "json":
        write_json(all_iocs, out_path)
    else:
        write_csv(all_iocs, out_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
