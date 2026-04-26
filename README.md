# ROW Swim Club — DMARC Report Reader

Fetches DMARC aggregate reports from the `postmaster@rowswimming.ca` Gmail inbox,
parses the XML attachments, and prints a colour-coded summary in your terminal.

No third-party dependencies — uses only Python 3 standard library.

---

## What is a DMARC aggregate report?

When you publish a DMARC record, mail receivers (Google, Yahoo, Microsoft, etc.)
send you daily XML reports showing:

- Every IP address that sent email claiming to be from your domain
- How many messages came from each IP
- Whether SPF and DKIM passed or failed (aligned to your domain)
- What the receiver did with each message (none / quarantine / reject)

A **pass** means at least one of DKIM or SPF aligned to `rowswimming.ca`.
A **fail** means neither aligned — the message was likely spoofed or sent through
an unauthorised server.

---

## Setup (one-time)

### 1. Create a Gmail App Password

Google Workspace requires an **App Password** instead of your regular password
for IMAP access.

1. Sign in to the **postmaster@rowswimming.ca** account at
   `myaccount.google.com`.
2. Go to **Security → How you sign in to Google → 2-Step Verification**
   (enable it if not already on).
3. At the bottom of the 2-Step Verification page, choose **App passwords**.
4. Name it something like `DMARC Script` and click **Create**.
5. Copy the 16-character password that appears (format: `xxxx xxxx xxxx xxxx`).

### 2. Enable IMAP in Gmail

1. In Gmail, go to **Settings → See all settings → Forwarding and POP/IMAP**.
2. Under **IMAP Access**, select **Enable IMAP** and save.

### 3. Configure credentials

```bash
cp .env.example .env
# Edit .env and fill in your app password
```

Load the variables before running the script:

```bash
export $(cat .env | xargs)
```

Or pass them directly on the command line (see Usage below).

---

## Usage

```bash
# Fetch from Gmail (credentials from environment)
export DMARC_USER=postmaster@rowswimming.ca
export DMARC_PASS=your-app-password
python3 dmarc_report.py

# Pass credentials directly
python3 dmarc_report.py --user postmaster@rowswimming.ca --password YOUR_APP_PW

# Also resolve IP addresses to hostnames (slower, requires internet)
python3 dmarc_report.py --rdns

# Save the raw XML files into ./xml/ for archiving
python3 dmarc_report.py --save-xml

# Parse a local XML file (good for testing, or manually downloaded reports)
python3 dmarc_report.py --file sample_report.xml

# All options
python3 dmarc_report.py --help
```

---

## Reading the output

```
────────────────────────────────────────────────────────────────────────
  DMARC Report from: Google Inc.
  Domain:            rowswimming.ca
  Period:            2025-04-24 00:00 UTC  →  2025-04-25 00:00 UTC
  Policy:            p=quarantine  pct=100%
  Messages:          52 total  |  50 passed  |  2 failed
────────────────────────────────────────────────────────────────────────
  Source IP          Hostname                      Count  Result    DKIM     SPF
  209.85.220.41      mail-qk1-f41.google.com          47    PASS    PASS    PASS
  66.102.8.24        (forwarder)                       3    PASS    PASS    FAIL
  198.51.100.77      (unknown)                         2    FAIL    FAIL    FAIL
    → header_from=rowswimming.ca  envelope_from=spammer.invalid
      disposition=quarantine  auth_dkim=fail  auth_spf=fail
```

| Column | Meaning |
|---|---|
| Source IP | The server that sent the email |
| Hostname | Reverse DNS name of that server (with `--rdns`) |
| Count | Number of messages from that IP in the report period |
| Result | Overall DMARC result: PASS if either DKIM or SPF aligned |
| DKIM | Whether DKIM signature was aligned to your domain |
| SPF | Whether the sending server is in your SPF record |

**Common patterns:**

- `PASS / PASS / PASS` — Your own Google Workspace servers. Expected.
- `PASS / PASS / FAIL` — A forwarder or mailing list. DKIM held, so DMARC passes. Normal.
- `FAIL / FAIL / FAIL` — Spoofing attempt or unauthorised sender. Check the IP.

---

## What to do with failures

1. **Identify the IP** — use `--rdns` or look it up at `ipinfo.io/<ip>`.
2. **Legitimate sender you forgot?** Add it to your SPF record or make sure it
   signs with DKIM. Common examples: Mailchimp, your website's contact form,
   a third-party CRM.
3. **Spoofing/spam?** These are being handled by your DMARC policy
   (`quarantine` or `reject`). No action needed — that's DMARC working.

---

## How reports arrive in Gmail

DMARC reports land as email attachments (`.zip` or `.gz` files containing XML).
Senders include Google, Yahoo, Microsoft, and others. The script searches for
emails with "Report Domain" in the subject line, which is the standard format.

If reports land in a folder other than `INBOX` (e.g. a filter moves them to a
`DMARC` label), use `--mailbox "DMARC"`.

---

## Tightening your DMARC policy over time

Start with `p=none` to monitor, then progress once you're confident:

1. `p=none` — Reports only. No enforcement. Good for the first few weeks.
2. `p=quarantine` — Failures go to spam. ← You are here.
3. `p=reject` — Failures are dropped. Maximum protection.

Watch the reports for a week or two at each stage before moving to the next.
