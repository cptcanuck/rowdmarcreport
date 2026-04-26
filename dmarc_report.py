#!/usr/bin/env python3
"""
Fetches DMARC aggregate reports from a Gmail/Google Workspace inbox,
parses the XML, and prints a human-readable summary.

Setup: see README.md
"""

import argparse
import email
import gzip
import imaplib
import io
import ipaddress
import os
import socket
import sys
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993

# Emails containing DMARC reports have attachments with these extensions
DMARC_EXTENSIONS = (".xml", ".xml.gz", ".xml.zip", ".zip", ".gz")

# Common senders — used only for display, not filtering
KNOWN_REPORTERS = {
    "noreply-dmarc-support@google.com": "Google",
    "dmarc-reports@yahoo.com": "Yahoo",
    "dmarcreport@microsoft.com": "Microsoft",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AuthResult:
    spf: str = "none"      # pass / fail / softfail / neutral / none / permerror / temperror
    dkim: str = "none"


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str        # none / quarantine / reject
    dkim_aligned: str       # pass / fail
    spf_aligned: str        # pass / fail
    header_from: str
    envelope_from: str
    auth: AuthResult = field(default_factory=AuthResult)

    @property
    def passed(self) -> bool:
        return self.dkim_aligned == "pass" or self.spf_aligned == "pass"


@dataclass
class DmarcReport:
    org_name: str
    report_id: str
    date_begin: datetime
    date_end: datetime
    domain: str
    policy_p: str           # none / quarantine / reject
    policy_pct: int
    records: list[Record] = field(default_factory=list)

    @property
    def total_messages(self) -> int:
        return sum(r.count for r in self.records)

    @property
    def passed_messages(self) -> int:
        return sum(r.count for r in self.records if r.passed)

    @property
    def failed_messages(self) -> int:
        return self.total_messages - self.passed_messages


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def _text(element: Optional[ET.Element], default: str = "") -> str:
    if element is None:
        return default
    return (element.text or "").strip()


def parse_dmarc_xml(xml_bytes: bytes) -> DmarcReport:
    root = ET.fromstring(xml_bytes)

    meta = root.find("report_metadata")
    policy = root.find("policy_published")

    begin_ts = int(_text(meta.find("date_range/begin"), "0"))
    end_ts = int(_text(meta.find("date_range/end"), "0"))

    report = DmarcReport(
        org_name=_text(meta.find("org_name")),
        report_id=_text(meta.find("report_id")),
        date_begin=datetime.fromtimestamp(begin_ts, tz=timezone.utc),
        date_end=datetime.fromtimestamp(end_ts, tz=timezone.utc),
        domain=_text(policy.find("domain")),
        policy_p=_text(policy.find("p"), "none"),
        policy_pct=int(_text(policy.find("pct"), "100")),
    )

    for rec_el in root.findall("record"):
        row = rec_el.find("row")
        ids = rec_el.find("identifiers")
        auth = rec_el.find("auth_results")

        spf_result = _text(auth.find("spf/result")) if auth is not None else "none"
        dkim_result = _text(auth.find("dkim/result")) if auth is not None else "none"

        record = Record(
            source_ip=_text(row.find("source_ip")),
            count=int(_text(row.find("count"), "1")),
            disposition=_text(row.find("policy_evaluated/disposition"), "none"),
            dkim_aligned=_text(row.find("policy_evaluated/dkim"), "fail"),
            spf_aligned=_text(row.find("policy_evaluated/spf"), "fail"),
            header_from=_text(ids.find("header_from")) if ids is not None else "",
            envelope_from=_text(ids.find("envelope_from")) if ids is not None else "",
            auth=AuthResult(spf=spf_result, dkim=dkim_result),
        )
        report.records.append(record)

    return report


# ---------------------------------------------------------------------------
# Attachment extraction
# ---------------------------------------------------------------------------

def extract_xml_from_attachment(filename: str, data: bytes) -> Optional[bytes]:
    name = filename.lower()

    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            if xml_names:
                return zf.read(xml_names[0])

    elif name.endswith(".gz"):
        return gzip.decompress(data)

    elif name.endswith(".xml"):
        return data

    return None


# ---------------------------------------------------------------------------
# Gmail IMAP fetching
# ---------------------------------------------------------------------------

def fetch_reports_from_gmail(
    username: str,
    app_password: str,
    mailbox: str = "INBOX",
    max_emails: int = 50,
    mark_seen: bool = False,
) -> list[tuple[str, bytes]]:
    """
    Returns list of (filename, xml_bytes) tuples from unread DMARC report emails.
    """
    results = []

    print(f"Connecting to {IMAP_HOST} as {username} …")
    with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT) as imap:
        imap.login(username, app_password)
        imap.select(mailbox)

        _, msg_ids_data = imap.search(None, '(SUBJECT "Report Domain: rowswimming.ca")')
        msg_ids = msg_ids_data[0].split()

        if not msg_ids:
            print("No DMARC report emails found (subject: 'Report Domain: rowswimming.ca').")
            return results

        # Process most recent first, up to max_emails
        for msg_id in reversed(msg_ids[-max_emails:]):
            _, msg_data = imap.fetch(msg_id, "(RFC822)")
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)

            found_attachment = False
            for part in msg.walk():
                content_disp = part.get("Content-Disposition", "")
                filename = part.get_filename() or ""
                if not filename:
                    continue

                if any(filename.lower().endswith(ext) for ext in DMARC_EXTENSIONS):
                    payload = part.get_payload(decode=True)
                    xml_bytes = extract_xml_from_attachment(filename, payload)
                    if xml_bytes:
                        results.append((filename, xml_bytes))
                        found_attachment = True

            if found_attachment and mark_seen:
                imap.store(msg_id, "+FLAGS", "\\Seen")

    print(f"Found {len(results)} DMARC report(s).")
    return results


# ---------------------------------------------------------------------------
# DNS reverse lookup (best-effort)
# ---------------------------------------------------------------------------

def rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Reporting / display
# ---------------------------------------------------------------------------

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
WARN = "\033[33mWARN\033[0m"


def _pf(value: str) -> str:
    """Colour-code pass/fail strings for terminal output."""
    v = value.lower()
    if v == "pass":
        return PASS
    if v in ("fail", "reject", "quarantine"):
        return FAIL
    return f"\033[33m{value}\033[0m"


def print_report(report: DmarcReport, resolve_rdns: bool = False) -> None:
    hr = "─" * 72

    print(f"\n{hr}")
    print(f"  DMARC Report from: {report.org_name}")
    print(f"  Report ID:         {report.report_id}")
    print(f"  Domain:            {report.domain}")
    print(f"  Period:            {report.date_begin:%Y-%m-%d %H:%M UTC}  →  {report.date_end:%Y-%m-%d %H:%M UTC}")
    print(f"  Policy:            p={report.policy_p}  pct={report.policy_pct}%")
    print(f"  Messages:          {report.total_messages} total  |  "
          f"{report.passed_messages} passed  |  {report.failed_messages} failed")
    print(hr)

    if not report.records:
        print("  (no records)")
        return

    # Table header
    col_ip = 18
    col_host = 28
    col_cnt = 6
    col_res = 7
    col_dkim = 7
    col_spf = 7

    header = (
        f"  {'Source IP':<{col_ip}} {'Hostname':<{col_host}} "
        f"{'Count':>{col_cnt}} {'Result':>{col_res}} "
        f"{'DKIM':>{col_dkim}} {'SPF':>{col_spf}}"
    )
    print(header)
    print(f"  {'-'*(col_ip)} {'-'*(col_host)} {'-'*col_cnt} {'-'*col_res} {'-'*col_dkim} {'-'*col_spf}")

    for rec in sorted(report.records, key=lambda r: (-r.count, r.source_ip)):
        hostname = rdns(rec.source_ip) if resolve_rdns else ""
        overall = "pass" if rec.passed else "FAIL"
        print(
            f"  {rec.source_ip:<{col_ip}} {hostname:<{col_host}} "
            f"{rec.count:>{col_cnt}} {_pf(overall):>{col_res+9}} "   # +9 for ANSI escape codes
            f"{_pf(rec.dkim_aligned):>{col_dkim+9}} {_pf(rec.spf_aligned):>{col_spf+9}}"
        )
        if not rec.passed:
            print(f"    → header_from={rec.header_from}  envelope_from={rec.envelope_from}")
            print(f"      disposition={rec.disposition}  auth_dkim={rec.auth.dkim}  auth_spf={rec.auth.spf}")

    print()


def save_xml(filename: str, xml_bytes: bytes, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / filename
    # Strip .gz/.zip so we always save raw XML
    if dest.suffix in (".gz", ".zip"):
        dest = dest.with_suffix("")
    if not dest.suffix == ".xml":
        dest = dest.with_suffix(".xml")
    dest.write_bytes(xml_bytes)
    print(f"  Saved: {dest}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Fetch and summarise DMARC aggregate reports from Gmail.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Read credentials from environment variables (recommended)
  export DMARC_USER=postmaster@rowswimming.ca
  export DMARC_PASS=your-app-password
  python3 dmarc_report.py

  # Pass credentials inline
  python3 dmarc_report.py --user postmaster@rowswimming.ca --password YOUR_APP_PW

  # Enable reverse DNS lookups and save raw XML files
  python3 dmarc_report.py --rdns --save-xml

  # Parse a local XML file instead of fetching from Gmail
  python3 dmarc_report.py --file report.xml
""",
    )
    p.add_argument("--user", help="Gmail address (or set DMARC_USER env var)")
    p.add_argument("--password", help="Gmail App Password (or set DMARC_PASS env var)")
    p.add_argument("--mailbox", default="INBOX", help="IMAP mailbox to search (default: INBOX)")
    p.add_argument("--max", type=int, default=50, metavar="N", help="Max emails to scan (default: 50)")
    p.add_argument("--rdns", action="store_true", help="Resolve source IPs to hostnames (slower)")
    p.add_argument("--save-xml", action="store_true", help="Save extracted XML files to ./xml/")
    p.add_argument(
        "--file", metavar="PATH",
        help="Parse a local XML (or .gz/.zip) file instead of fetching from Gmail",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    reports: list[tuple[str, bytes]] = []

    if args.file:
        path = Path(args.file)
        data = path.read_bytes()
        xml_bytes = extract_xml_from_attachment(path.name, data)
        if xml_bytes is None:
            sys.exit(f"Could not extract XML from {args.file}")
        reports.append((path.name, xml_bytes))
    else:
        user = args.user or os.environ.get("DMARC_USER")
        password = args.password or os.environ.get("DMARC_PASS")

        if not user or not password:
            parser.error(
                "Provide --user / --password or set DMARC_USER / DMARC_PASS environment variables.\n"
                "See README.md for how to create a Gmail App Password."
            )

        reports = fetch_reports_from_gmail(
            username=user,
            app_password=password,
            mailbox=args.mailbox,
            max_emails=args.max,
        )

    if not reports:
        print("Nothing to display.")
        return

    for filename, xml_bytes in reports:
        if args.save_xml:
            save_xml(filename, xml_bytes, Path("xml"))

        try:
            report = parse_dmarc_xml(xml_bytes)
        except ET.ParseError as exc:
            print(f"Failed to parse {filename}: {exc}")
            continue

        print_report(report, resolve_rdns=args.rdns)


if __name__ == "__main__":
    main()
