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
| `collect_mailbox.py` | Scans a shared mailbox for Sophos Email + Phish Threat report PDFs, matches to clients, parses them | ✅ Done, verified against 5 real client reports |
| `collect_ninjaone_saas_backup.py` | Dropsuite email/SaaS backup status: seats, storage, mailbox coverage, added-this-month | ✅ Done, verified against real data |
| `collect_sentinelone.py` | Endpoint protection (agent staleness, infected devices, monthly threat detections) for clients not on Sophos Endpoint | ✅ Done, verified against real data |
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
  what lands in the mailbox, not cause it to be sent. Confirmed none of the
  5 real reports received so far are Phish Threat exports — Email only.
- **Sophos Email's scheduled report delivery has a real quirk**: Sophos
  can't send these directly to the destination M365 mailbox reliably, so
  the working setup routes through an intermediate Gmail address that then
  forwards to `craig@teamlogicnova.com` / "Monthly Reports". Confirmed
  working end-to-end for 5 clients (Activate Research, HCN, Just
  Neighbors, Main Event Caterers, Middleburg) as of the first real batch.
- **Activate Research's Sophos Email report only covers 1 day**
  (`date_range` showed Aug 31 → Sep 1), while the other 4 clients' reports
  correctly covered a full month (Aug 2 → Sep 1). Likely that client's
  report schedule in Sophos Central is set to a daily window instead of
  monthly — worth checking/fixing there, not a collector bug.
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
- **SentinelOne**: auth is `Authorization: ApiToken <token>` (not Bearer),
  base URL is your own tenant subdomain (not a shared host), and pagination
  is cursor-based (`pagination.nextCursor`), not page numbers. Like
  NinjaOne's `offline` flag, `isActive` is a live instant-in-time snapshot
  — a real device showed `isActive: false` with a `lastActiveDate` of the
  same day, confirming it's not a reliable staleness signal on its own;
  `lastActiveDate` age is the one that matters.
- **NinjaOne SaaS Backup (Dropsuite)**: the real REST API spec is a PDF
  ("REST API for Sub-reseller ver 1.0.0") not indexed publicly — worth
  asking the client/vendor for directly rather than guessing. Three
  confirmed non-obvious things: (1) auth headers are exactly
  `X-Reseller-Token` and `X-Access-Token`, not the more common
  `Authorization`/`Bearer` pattern; (2) `GET /users/{id}` (subscription
  summary) works with the reseller-wide **admin** token, but
  `/tenants` and `/accounts` need a **different, per-organization**
  token — solved without any manual portal hunting by calling
  `GET /users` (works with the admin token) and reading the target
  org's own `authentication_token` straight out of that response; (3)
  `tenant_id` belongs in the URL **path** (`/tenants/{tenant_id}/accounts`),
  not as a query parameter — the parameter table's wording was
  ambiguous, but the spec's own example `next_url`/`prev_url` values
  showed the real, correct structure once looked at closely.
- **`collect_mailbox.py` (Sophos Email PDFs)**: classification is
  content-based (checking the PDF's own text for markers like "inbound
  summary"), not filename/subject-based — real filenames like
  `ARMEmail.pdf` carry no useful signal. Client matching works off the
  PDF's `Company Name` field when present; when it isn't (Phish Threat
  reports), falls back to matching a single word from the client's name
  against the campaign name. PDF text extraction can wrap a long email
  address mid-word across a line break (confirmed real example:
  `leshaundra.cordier@hcnglobal.co` + newline + `m`) — the at-risk-users
  parser handles this with a token-stream approach rather than per-line
  regex, joining any non-numeric token before the three trailing number
  columns into one email.

## Ground rules

- Never paste real API keys/secrets anywhere outside `.env`.
- Test one client in `--dry-run` before trusting a collector's numbers, and
  compare against the vendor's own console when a number looks surprising.
- `.env` is never committed. If you're setting this up on a new machine,
  re-create it from `dotenv.example` and re-enter credentials there.

## Getting started on a new machine

The repo is live at `https://github.com/tlitnova/reportGenerator` (private).
Clone it rather than starting from scratch:
```bash
git clone https://github.com/tlitnova/reportGenerator.git
cd reportGenerator
cp dotenv.example .env   # then fill in real credentials — never commit this,
                          # and .env won't come down with the clone since
                          # it's git-ignored — copy your real one over
                          # from wherever it's already sitting, or fill
                          # in from scratch
```
