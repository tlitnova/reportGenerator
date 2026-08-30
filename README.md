# reportGenerator

Monthly client report automation — replaces hand-assembled screenshots from
Autotask, NinjaOne, Sophos, Datto, Addigy, and other vendor consoles with a
pipeline that pulls the data via API and produces a finished report per
client, per month.

Originally scoped around four sources (Autotask, NinjaOne, Sophos Endpoint,
Sophos Email/Phish Threat) and grew to cover nine as client needs surfaced:
Datto SaaS Protection, Datto BCDR, Addigy, NinjaOne SaaS Backup, and
SentinelOne.

## Setup

1. **Install dependencies:**
   ```
   pip3 install requests pyyaml python-dotenv pypdf
   ```
2. **Copy `dotenv.example` to `.env`** and fill in real credentials.
   `.env` is git-ignored — never commit it, never paste its contents
   anywhere outside your own editor.
3. **Fill in `clients.yaml`** with each client's vendor IDs. The comment
   block at the top of the file explains where to find each one. A
   client's `sources:` block controls which collectors actually run for
   them — set a flag `false` (not blank) for anything that doesn't apply.

## Files

| File | Purpose | Status |
|---|---|---|
| `clients.yaml` | Per-client vendor ID mapping and per-source enable/disable flags | Populated for 8 clients |
| `.env` / `dotenv.example` | Credentials and settings; `.env` is your real local copy, `dotenv.example` is the checked-in template | `.env` fully populated locally |
| `Research Findings.md` | API feasibility notes across all 9 vendor sources — what's reachable via API vs. requires manual/mailbox workarounds | Reference doc, not run |
| `collect_autotask.py` | Tickets resolved, SLA %, hours worked by category | ✅ Done, verified against real data |
| `collect_ninja.py` | Device inventory, OS mix, 30-day staleness, patch compliance (with a per-client detail flag for CMMC-type needs) | ✅ Done, verified against real data |
| `collect_sophos.py` | Endpoint health, alerts (best-effort — see caveat below), account health-check score | ✅ Done, verified against real data |
| `collect_datto_saas.py` | M365/Google Workspace backup status (seats, backup %) | ✅ Done, verified against real data |
| `collect_datto_bcdr.py` | Appliance + per-agent backup status (local/offsite, screenshot verification) | ✅ Done, verified against real data |
| `collect_addigy.py` | macOS/iOS device compliance, encryption, staleness | ✅ Done, verified against real data |
| `collect_mailbox.py` | Scans a shared mailbox for Sophos Email + Phish Threat report PDFs, matches to clients, parses them | ✅ Parsers verified against real PDFs; **blocked** on the actual scheduled email arriving (see below) |
| `collect_ninjaone_saas_backup.py` | Dropsuite email/SaaS backup status | ❌ Not started |
| `collect_sentinelone.py` | Endpoint protection for clients not on Sophos Endpoint | ❌ Not started |
| `render_report.py` | Turns each client's collected JSON into the final PDF | ❌ Not started |
| `run_monthly.py` | Orchestrates all collectors + render for every client | ❌ Not started |

## Running a collector

Every collector supports:
```
python3 collect_X.py --client <slug> --dry-run --verbose
```
- `--dry-run` prints the result instead of writing to `output/<slug>/client_month.json`
- `--verbose` prints diagnostic info about API calls/responses — use this whenever something looks wrong
- Most collectors also take `--month YYYY-MM` (defaults to the previous calendar month). NinjaOne and Sophos device-health data is a live snapshot and doesn't take `--month`; NinjaOne's *patch* data does.

`collect_mailbox.py` is the one exception to "one client per run" — it
scans the whole shared mailbox at once and matches each report to whichever
client it belongs to. Use `--client <slug>` on it only to filter output
while debugging, not as its normal mode.

## Known open items

- **Sophos Phish Threat has no scheduled-report feature at all** — someone
  has to manually export the CSV/PDF from the Campaigns page each month.
  There's no way to automate this away; `collect_mailbox.py` can only parse
  what lands in the mailbox, not cause it to be sent.
- **Sophos Email's scheduled report is currently being sent as a PDF**
  (not CSV) to a placeholder address while the real setup is pending —
  `collect_mailbox.py`'s PDF parser was built and verified against a real
  sample, but the actual automated monthly delivery hasn't been confirmed
  end-to-end yet.
- **Sophos alerts (`collect_sophos.py`) are best-effort.** Confirmed against
  real data that `/common/v1/alerts` does not surface everything visible in
  Sophos's own "Recent threat graphs" console widget. Treat a low/zero
  alert count as "nothing the API surfaced," not "confirmed zero activity."
- **NinjaOne patch compliance won't exactly match NinjaOne's own dashboard
  number** — its internal methodology (likely catalog-scoping/dedup) isn't
  fully reproducible from the public API. Good operational summary, not a
  byte-exact replica.
- Three clients (`Just Neighbors`, `Middleburg Properties`, and others as
  they come up) may have additional per-client contradictions between a
  `sources:` flag and a filled-in ID — check inline `# NOTE` comments in
  `clients.yaml` if any exist before trusting a given source blindly.

## Gotchas discovered building this (worth knowing before debugging again)

- **Autotask**: the `zoneInformation` lookup returns both a `webUrl` (browser
  login host, e.g. `ww14.autotask.net`) and a `url` (the actual REST API
  host, e.g. `webservices14.autotask.net`) — using the wrong one produces a
  confusing Akamai-level "Access Denied," not an Autotask auth error.
  Autotask's API also sits behind Akamai, which blocks the default
  `python-requests` User-Agent as bot traffic — send a normal browser-like
  one.
- **NinjaOne**: the org-scoped device list endpoint doesn't include OS info
  at all; a separate per-device detail call is needed. Patch data is split
  across four separate endpoints (OS/software × installs/pending) with no
  single endpoint covering all four states — and install-history endpoints
  return a device's *entire* multi-year history with no server-side date
  filter, so month-scoping has to happen client-side using each item's
  timestamp.
- **Sophos**: Partner API credentials must be created at the Partner level,
  not inside a single customer tenant, or cross-tenant calls silently don't
  work as expected.
- **Datto**: SaaS Protection and BCDR are governed by the same Partner
  Portal API-keys page, but a key created with any "Vendor" selected
  (confirmed: even an unrelated-sounding one) is broken for both products —
  it must be created with Vendor left genuinely blank.
- **Addigy**: v2 auth uses an `x-api-key` header specifically, not
  `Authorization`. Facts live nested under `facts.{name}.value`, and the
  device-search endpoint only returns a small default fact set unless you
  request more via `desired_fact_identifiers`. The policy filter must be
  nested under `query.filters` — a flatter, differently-documented shape
  silently returns every device instead of erroring.

## Ground rules

- Never paste real API keys/secrets anywhere outside `.env`.
- Test one client in `--dry-run` before trusting a collector's numbers, and
  compare against the vendor's own console when a number looks surprising.
- `.env` is never committed. If you're setting this up on a new machine,
  re-create it from `dotenv.example` and re-enter credentials there.

## Getting started on a new machine

Name the project folder `reportGenerator` for consistency:
```bash
mkdir reportGenerator && cd reportGenerator
# copy in clients.yaml, dotenv.example, Research Findings.md, .gitignore,
# and every collect_*.py file
cp dotenv.example .env   # then fill in real credentials — never commit this
git init
git add .
git commit -m "Initial commit"
```
