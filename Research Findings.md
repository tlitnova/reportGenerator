# Research Findings — Monthly Client Report Automation

Purpose: for each data source currently screenshotted into the manual report, establish whether it can be pulled via API, only via a scheduled/emailed report, or not at all — with the actual entity/endpoint names to build against. Sourced from official Autotask, NinjaOne, and Sophos developer documentation, current as of Aug 2026.

---

## 1. Autotask PSA (REST API v1.0)

**Auth:** API user (username + secret + integration/tracking code), zone URL from the `zoneInformation` endpoint. Already scaffolded in `dotenv.example`.

| Data needed | Entity / endpoint | Fields | Confidence |
|---|---|---|---|
| Tickets created (volume, by contact) | `Tickets` (`/query`) | `contactID`, `createDate`, `companyID` | High |
| First Response / Resolution SLA % | `Tickets` | `serviceLevelAgreementHasBeenMet` (bool), `firstResponseDateTime`, `firstResponseDueDateTime`, `resolvedDateTime`, `resolvedDueDateTime`, `resolutionPlanDateTime` — all native, queryable fields | **High** — this is a direct API field, not something you have to derive |
| Hours worked / month, hours per ticket | `TimeEntries` | `hoursWorked`, `dateWorked`, `ticketID` | High |
| Open tickets / tickets by issue | `Tickets` | `status`, `issueType`, `subIssueType`, `queueID` | High |
| Tickets by configuration item | `Tickets` | `configurationItemID` → join to `ConfigurationItems` | High |
| Open projects by status | `Projects` (`/query`) | `status` | High (not yet detailed — same query pattern as Tickets) |
| Contract expiration | `Contracts` | `endDate`, `status`, `isActive` (standard Autotask contract fields) | Medium-High — field names not independently re-verified this pass, but this is a long-standing part of the entity |

**Notes:** All timestamps are UTC. There's a per-hour query threshold per database — fine for a once-a-month per-client pull, just don't hammer it in a tight retry loop. Autotask enforces View/Add/Edit permissions per the API user's security level, so the API user needs read access to Tickets, TimeEntries, Projects, and Contracts specifically.

---

## 2. NinjaOne (Public API v2)

**Auth:** OAuth 2.0 client credentials ("API Services" app), scopes `monitoring management`. Already scaffolded.

| Data needed | Endpoint | Fields | Confidence |
|---|---|---|---|
| Device inventory, OS breakdown | `GET /v2/devices-detailed` (or `/v2/organization/{id}/devices`) | `nodeClass`, `offline`, `systemName`, per-device OS in `references` | High |
| Offline / stale devices | same | `lastContact` (epoch), `offline` (bool) — filter/sort client-side by staleness threshold | High |
| Patch status | `GET /device/{id}/os-patch-installs` | pending / installed / failed patches per device | High, but per-device — for a whole org's compliance %, you'll loop devices or use the patch management endpoints in bulk |
| Organizations / multi-client mapping | `GET /v2/organizations`, `/v2/organization/{id}/locations` | id, name | High — this is how you'll resolve `clients.yaml`'s NinjaOne org IDs |

**Notes:** Region matters — the base URL depends on which NinjaOne cloud instance (`app.ninjarmm.com` vs `eu`/`ca`/`oc`), already exposed as `NINJA_INSTANCE` in the env template. No client-facing "device health score" endpoint exists as a single number — that's a metric you'd compute (e.g., % patched, count offline >30 days) from the raw device list rather than pull ready-made.

---

## 3. Sophos Central — Endpoint Protection

**Auth:** OAuth2 client credentials (Partner or tenant credential), `X-Tenant-ID` header per tenant once resolved via the Partner API's tenant list + `whoami`.

| Data needed | Endpoint | Fields | Confidence |
|---|---|---|---|
| Device health summary (active/inactive/unprotected) | `GET /endpoint/v1/endpoints` | `healthStatus`, `lastSeenAt` (filterable via `lastSeenBefore`/`lastSeenAfter`), `tamperProtectionEnabled`, `os` | High |
| Recent threat/alert graphs | Common API `GET /common/v1/alerts` | `severity`, `category`, `raisedAt`, `description`, `product` | High |
| Overall account security posture | `GET /account-health-check/v1/health-check` | scored checks (protection, policy, exclusions, tamperProtection), 0–100 | High, and arguably a *better* client-facing number than the current raw threat table |

**Notes:** This is the strongest-documented of the three Sophos products. Partner credential + per-tenant `X-Tenant-ID` covers all 7 clients from one credential set, matching what `dotenv.example` already assumes.

---

## 4. Sophos Central — Email Security

**This is the one place the feasibility picture is more constrained than a first guess.**

- A **Message History API** exists (via the Sophos Central XDR Data Lake / Live Discover), which can return per-message data (category, verdict, sender/recipient) that the current dashboard's Inbound/Outbound Statistics are aggregated from.
- **However, it requires an XDR or MDR license** on top of Email Security — it is not available on a plain Email Security subscription.
- There is **no separate, simpler "email stats" API** for accounts without XDR/MDR — Sophos's own support forum confirms customers have asked for this and it doesn't exist as of the most recent public discussion.

| Scenario | Method | Confidence |
|---|---|---|
| Client has Sophos XDR or MDR add-on | Message History API (Data Lake query, 30-day windows, must stitch 3 queries for a full month + license required) | Medium — workable but adds real complexity (pagination across time windows, JSON→aggregate) |
| Client is Email Security only (likely most of your 7) | Scheduled CSV report → mailbox → `collect_mailbox.py`, exactly as `dotenv.example` already assumes | High — this is your only real path for those clients |

**Action for you:** check which of the 7 clients (if any) actually carry XDR/MDR — that determines whether `collect_sophos_email.py` needs an API path at all, or whether every client goes through the mailbox collector.

---

## 5. Sophos Central — Phish Threat

- **No dedicated results/reporting API exists.** Sophos's own community forum (API feedback board) confirms there is no endpoint for campaign results as of the most recent discussion — the dashboard/CSV export is the only interface.
- This matches `dotenv.example`'s assumption exactly: scheduled CSV report → mailbox → `collect_mailbox.py`.

| Data needed | Method | Confidence |
|---|---|---|
| Campaign summary, caught/report ratios | Scheduled CSV report from Phish Threat → mailbox collector | High confidence this is the *only* path, low effort to change later since there's nothing to swap to |

---

## 6. Datto SaaS Protection (M365 / Google Workspace backup)

**Auth:** API key pair (public/private) generated in the Datto Partner Portal (Admin > Integrations > API Keys). Swagger-documented REST API.

| Data needed | Endpoint | Fields | Confidence |
|---|---|---|---|
| Protected seat count, per-app | `GET /v1/saas/domains` and organization endpoints | seat counts per application (Exchange, OneDrive, SharePoint, Google apps) | High |
| Backup success rate | Organization/status endpoints | success rate over last 24h, per Datto's own "Backups Report" fields | High — this is literally one of Datto's built-in downloadable reports, also available live via API |
| Seat status (active/paused/archived) | `GET`/`PUT` seat endpoints | `status` per seat | High |

**Notes:** This is a real, well-documented REST API, not a scheduled-report workaround. One credential set covers all client orgs under your partner account, same shape as Sophos Partner.

---

## 7. Datto BCDR (on-prem/cloud backup appliances — SIRIS/ALTO/NAS)

**Auth:** Public/private key pair from the Datto Partner Portal (separate from SaaS Protection's keys). Basic auth scheme, Swagger-documented.

| Data needed | Endpoint | Fields | Confidence |
|---|---|---|---|
| Device list across all clients | Device list endpoint | one call returns all appliances under the partner account, each tagged to its client | High |
| Last local backup / last offsite sync | Single-device endpoint | timestamps for both, matching the thresholds MSPs already configure (defaults: local 1 day, offsite 2 days) | High |
| Screenshot (boot) verification | Single-device endpoint | pass/fail + timestamp of the last AI-verified boot test | High |
| Last 10 backup attempts | Single-device endpoint | pass/fail array | High |

**Notes:** Important setup gotcha carried over from how partners configure this API: when creating the API key, leave the "Organization" field blank — scoping it to one org breaks discovery of the rest. One credential set → all clients' appliances.

---

## 8. Addigy (macOS/iOS device management)

**Auth:** Bearer API token, generated per-partner in Account > Integrations > API & Webhooks. Full Swagger docs at `api.addigy.com/api/v2/documentation`.

| Data needed | Endpoint | Fields | Confidence |
|---|---|---|---|
| Device online/offline, last check-in | Universal Device Search (`POST /devices`) | `online` (bool), `last_online` (date) | High |
| Compliance status | Same | `is_compliant` (bool) — a ready-made pass/fail per Addigy's own compliance benchmarks (CIS/NIST/etc. if configured) | High |
| OS version / update posture | Same | `os_version`, `mac_os_x_version`, `mdm_update_eligibility` | High |
| Disk encryption | Same | `filevault_enabled`, `filevault_key_escrowed` | High |
| Filter by client | Same | filter on `policy_id` (one policy tree per client is the typical MSP setup) | High |

**Notes:** This is the richest, best-documented API of the whole set — a single paginated "device facts" search with dozens of fields, filterable per-client via policy ID. Rate limit is generous (1,000 req/10 sec).

---

## 9. NinjaOne SaaS Backup (formerly Dropsuite — email/M365/Google Workspace backup)

**Auth:** Reseller token + auth token from the Partner Portal's API Settings page.

| Data needed | Method | Confidence |
|---|---|---|
| Per-client backup coverage/health | GET API calls (Partner Portal exposes organizations + users) | Medium-High — a real API exists, but the documentation is a downloadable PDF rather than a public interactive spec, so exact field names need confirming once you have a token |
| Monthly backup summary | Built-in "Backup Summary Report," also emailable on the 5th of each month | High as a fallback — if the raw API fields turn out thin, this scheduled report is a ready-made per-client monthly summary already shaped like what you need |

**Notes:** Dropsuite is now a NinjaOne product (same parent company as your RMM), so it's plausible this eventually shares auth/tooling with your existing NinjaOne API credential — worth checking once you're in the portal, but treat as a separate credential for now.

---

## 10. SentinelOne (endpoint protection, for clients using it instead of/alongside Sophos)

**Auth:** Bearer token via `Authorization: ApiToken <token>`, generated from a **Service User** (Settings > Users > Service Users in the console). The base URL is tenant-specific — your own console hostname (e.g. `https://<yourmsp>.sentinelone.net/web/api/v2.1`), not a shared global endpoint like Sophos or NinjaOne.

**Multi-tenant structure:** SentinelOne organizes as **Account > Sites > Groups**. MSPs typically run one Site per client, with Groups inside a site for further segmentation (e.g., servers vs. workstations). This maps directly onto your per-client model — `sentinelone.site_id` is the field you need in `clients.yaml`, not a separate "customer" concept like Sophos.

| Data needed | Endpoint | Fields | Confidence |
|---|---|---|---|
| Site list (resolve client → site ID) | `GET /web/api/v2.1/sites` | `id`, `name`, `accountId` | High |
| Agent/device inventory, health | `GET /web/api/v2.1/agents` (filterable by `siteIds`) | online status, last active, OS, policy | High |
| Threats/detections | `GET /web/api/v2.1/threats` (filterable by `siteIds`) | `threatName`, `confidenceLevel`, `mitigationStatus` | High |

**Notes:** A Service User's token inherits whatever scope it was created with (Global / Account / Site) — for pulling data across all your SentinelOne clients from one credential, create it at **Account** scope with the Viewer role, not scoped to a single site, or you'll need a separate token per client. This is the same one-credential-many-clients pattern as Sophos Partner and Autotask, just with a tenant-specific hostname instead of a shared one.

---

## Summary table (Step 1.3 format)

| Metric | Source | Method | Confidence | Notes |
|---|---|---|---|---|
| SLA (first response / resolution %) | Autotask | API | High | Native ticket fields |
| Hours worked (monthly trend) | Autotask | API | High | TimeEntries |
| Ticket volume / by category | Autotask | API | High | Tickets |
| Contract expirations | Autotask | API | Med-High | Contracts.endDate |
| Device inventory / OS mix | NinjaOne | API | High | devices-detailed |
| Stale/offline devices | NinjaOne | API | High | lastContact filter |
| Patch compliance | NinjaOne | API | High | per-device, needs aggregation |
| Endpoint health (active/inactive/unprotected) | Sophos Endpoint | API | High | endpoint/v1/endpoints |
| Security posture score | Sophos Endpoint | API | High | account-health-check |
| Email threats blocked | Sophos Email | **API only with XDR/MDR**, else emailed report | Split — depends on client license | Verify per-client |
| At-risk users (email) | Sophos Email | Same as above | Split | Same caveat |
| Phish test results | Sophos Phish Threat | Emailed report only | High confidence in the *constraint* | No API exists to swap to |
| SaaS backup (M365/Google) coverage & success rate | Datto SaaS Protection | API | High | Real REST API, per-seat detail |
| BCDR appliance backup status | Datto BCDR | API | High | One credential, all clients |
| macOS device compliance/health | Addigy | API | High | Richest API of the set |
| Email/SaaS backup (Dropsuite) status | NinjaOne SaaS Backup | API (fields TBD) or emailed monthly report | Medium-High | Confirm field names once you have a token; scheduled report is a solid fallback |
| Endpoint protection (SentinelOne clients) | SentinelOne | API | High | One credential covers all clients if the Service User is Account-scoped, not Site-scoped |

---

*Compiled from Autotask, NinjaOne, and Sophos developer documentation, Aug 2026. Endpoint names should be spot-checked against your live tenants during collector build — vendor docs occasionally lag or vary slightly by account tier.*
