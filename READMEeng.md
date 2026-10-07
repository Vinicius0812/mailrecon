# MailRecon

[Portuguese version](README.md)

A Python CLI for ethical OSINT, technical email validation, and authorized defensive investigations. It organizes inputs, hypotheses, and public evidence for human review. It does not confirm a person's identity or the existence of an individual mailbox.

## Scope

A portfolio project for security students, defensive analysts, and authorized investigators. It uses format validation, public DNS, and optionally the documented Have I Been Pwned (HIBP) API. It can check suggested public pages without logging in.

It does not automate login, account recovery, credential testing, abusive enumeration, or private data collection. SMTP is isolated to labs, without MX discovery and outside the normal workflow. Use only your own data, fictional data, or an explicitly authorized scope.

## Features

- `analyze`: format, DNS (A, AAAA, MX, NS, TXT), SPF, DMARC, provider family, and optional HIBP.
- `investigate`: names, emails, usernames, domains, organizations, context, and explicit candidates; provenance, decision reasons, and limitations.
- `interactive`: guided prompts and export selection.
- `rerun-last`: reuses the saved investigation and manual exclusions.
- `lab-admin`: simulates profile states without contacting platforms.
- `lab-smtp-validate`: SMTP simulation or limited checks in a configured lab.
- JSON and Markdown; Brazilian Portuguese by default, optional English; masking in human-readable analysis/investigation output.

## Installation

Requirements: Python 3.11+, Git, and network access to install dependencies. HIBP is optional and requires an API-enabled key.

### Windows / PowerShell

```powershell
git clone https://github.com/Vinicius0812/mailrecon.git
cd mailrecon
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
.\.venv\Scripts\mailrecon.exe --language en --help
.\.venv\Scripts\mailrecon.exe --language en analyze person@example.com --no-hibp
```

Activation is unnecessary. To enable HIBP for the current session:

```powershell
$env:HIBP_API_KEY = "YOUR_KEY"
.\.venv\Scripts\mailrecon.exe --language en analyze person@example.com
```

### Linux / shell

```bash
git clone https://github.com/Vinicius0812/mailrecon.git
cd mailrecon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
mailrecon --language en --help
mailrecon --language en analyze person@example.com --no-hibp
export HIBP_API_KEY='YOUR_KEY'
```

Addresses at `example.com` are fictional; its real DNS does not represent a mailbox lab.

## Languages and Commands

`--language pt-br|en` is global: place it **before the subcommand**. Command names, flags, JSON keys, and technical values such as `low`, `medium`, and execution states remain English. Human-readable labels and confidence levels are translated.

The following examples assume an activated environment. In PowerShell without activation, use the executable path shown above.

```bash
mailrecon --language en analyze person@example.com --no-hibp
mailrecon --language en investigate --email person@example.com --username person --domain example.com --no-hibp
mailrecon --language en investigate --name "Example Person" --email person@example.com --candidate-email person@example.com --domain example.com --no-hibp --json-out reports/investigation.json --md-out reports/investigation.md
mailrecon --language en analyze person@example.com --no-hibp --md-out reports/analysis-pt.md --markdown-language pt-br
mailrecon --language en interactive --no-hibp
mailrecon --language en rerun-last
```

Markdown inherits the terminal language. `--markdown-language pt-br|en` overrides only the report and is available on all commands with Markdown export. Portuguese prompts accept `s`/`sim` and `n`/`não`/`nao`; English prompts accept `y`/`yes` and `n`/`no`. Enter uses the displayed default.

`rerun-last` reuses saved options, including HIBP; `rerun-last --no-hibp` can disable HIBP but never enable it if it was already disabled. `--check-public-profiles` optionally checks only the two official APIs below. Blocks, login redirects, rate limits, and errors do not establish account absence.

### Profile catalog and network

The typed, validated catalog belongs to MailRecon. GitHub uses `GET https://api.github.com/users/{handle}` ([official documentation](https://docs.github.com/en/rest/users/users#get-a-user)); GitLab uses `GET https://gitlab.com/api/v4/users?username={handle}` ([official documentation](https://docs.gitlab.com/api/users/)). Only an exact provided/derived username is queried: no email search, general listing, or pagination. LinkedIn, Instagram, Facebook, X, Spotify, Telegram, and Gravatar remain manual pivots without automatic HTTP. Search URLs are manual suggestions, never queried by the checker.

Requests have no authentication, persistent cookies, environment proxies, rotating User-Agent, retries, or automatic redirects. The User-Agent is `MailRecon/0.1`. Pivot origin, handle, and canonical URL are validated before network; endpoints come exclusively from the catalog. Streaming bounds bytes; unexpected compressed responses are inconclusive. Budgets bound requests per investigation/source; 401/403/429 disable that source until the next execution. Exhausted budgets and manual sources remain `not_checked`.

HTTP 200 requires expected JSON, a positive integer ID, an exactly matching handle under GitHub/GitLab case-insensitive semantics, and matching official canonical URL. Only the handle is compared with `casefold`; the URL must exactly match the catalog URL built from the validated returned handle, without relaxing host, path, encoding, query, or fragment. HTML, soft-404/login pages, generic/malformed or divergent bodies are `ambiguous`, never positive evidence. An empty GitLab array is `not_found`; multiple records are ambiguous. GitHub 404 means no public profile was returned, not proof of account absence; GitLab 404 is inconclusive. `rule_id`, `rule_version`, `check_method`, and `cache_hit` make rules traceable.

The cache is bounded, in memory only, per service instance, and not persistent. It stores only sanitized positive/negative classifications without raw bodies and expires by monotonic TTL. Reuse consumes no request budget and does not renew TTL; `checked_at` and `collected_at` keep the original observation time. Each investigation resets budgets/blocks but can reuse the same instance's live cache; new processes share no cache. Zero TTL/capacity disables caching.

## Confidence and Provenance

Deduplication retains the primary origin in `source`, in this order:

1. `seed_email`: directly supplied email.
2. `provided_candidate`: explicitly supplied candidate.
3. `username_domain_inference`: username/domain hypothesis.
4. `name_domain_inference`: name/domain hypothesis.

`sources` preserves all origins. An inference never replaces a direct input.

`confidence_scope` identifies the evaluated claim. Direct or explicit inputs receive `medium` confidence in the supplied information; inferences receive `low` confidence in the hypothesis. Invalid format, NXDOMAIN, and Null MX receive low confidence. DNS never increases identity confidence.

A public profile confirmed by an API rule receives medium confidence only in `public_profile_existence`, not ownership or a match to the email. Generic HTTP success never receives medium confidence. Unchecked, ambiguous, blocked, absent, or erroneous results remain low. Simulations have a synthetic scope, observe no real platform, and do not count toward the real breakdown. Identity correlation stays zero.

HIBP receives medium confidence in an exposure record only for `breaches_found`. Disabled queries, missing keys, negative responses, and failures receive low confidence. No known breaches does not prove safety, inactivity, or nonexistence.

`review_priority_score` is a **triage heuristic**, not a probability or accuracy percentage. Zero stays zero; legacy scores never replace it. Conservative caps remain: direct 70, explicit 60, username inference 45, name inference 30, role account 35, disposable domain 25, and reachable profile 45 (without automatically raising the initial score). Penalties reduce priority for noisy investigations.

The breakdown uses independent rules for validated syntax, DNS observations, and profile checks actually performed. Identity correlation remains zero without independent evidence. Supplied personal data, DNS, and URL patterns do not confirm identity. Scores are not statistically calibrated.

## Refinement and Privacy

State is stored in `.mailrecon-temp/last-investigation-refinement.json`. Add manually disproved URLs to `excluded_profile_urls`, then run `mailrecon rerun-last`. Older state remains readable; the next run uses its selected language.

Exclusions apply only when the fingerprint matches the query and are filtered before profile checks, including cache lookups. State never supplies HTTP destinations: suggested/arbitrary URLs in that file cannot create pivots; targets come only from the catalog. Name/username-inferred candidates are not sent to HIBP by default; direct seeds and explicitly provided candidates keep the current policy. The service offers `allow_inferred_hibp=True` only for an explicitly authorized scope, without mutating the global provider. `ReconService.analyze_email(..., use_hibp=False)` omits the provider for one call.

**JSON and refinement state contain complete data**, including emails, names, context, and URLs. Masking does not anonymize these files. Never publish real reports, keys, or local state. Restrict access and retention to the authorized scope. `--reveal-emails` reveals addresses in analysis/investigation output; SMTP human-readable output is also masked, but its JSON retains the supplied address.

Authored messages retain keys and parameters in optional JSON `localization` metadata. The same result can be rendered in another language without new queries. Inputs, URLs, external responses, and technical identifiers are preserved.

## Labs

Synthetic profile checks without contacting platforms:

```bash
mailrecon --language en lab-admin --handle fictional_user --scenario found --md-out reports/lab.md
mailrecon --language en lab-admin --handle fictional_user --scenario blocked
```

Do not supply a domain or email if you also want to avoid DNS collection. Scenarios: `found`, `not-found`, `ambiguous`, `blocked`, `rate-limited`.

SMTP without network access:

```bash
mailrecon --language en lab-smtp-validate person@lab.local --lab-domain lab.local --transport mock --no-network --check vrfy --md-out reports/smtp.md
```

Networked SMTP requires `MAILRECON_ENABLE_LAB_SMTP=1`, `--confirm-lab-only`, explicit compatible host/domain, and `localhost` or `private-lab` transport. Default: `mock`, up to three probes (`vrfy`, `rcpt`, `expn`). Do not use public services or unauthorized targets. Responses do not prove the existence or control of real mailboxes.

Security compatibility change: allowlisted hostnames are no longer accepted. Literal `localhost` is accepted only with `localhost` transport and connects directly to `127.0.0.1`; that transport only accepts loopback IPs. `private-lab` requires a literal RFC1918, IPv6 ULA, or loopback IP explicitly listed in `MAILRECON_LAB_SMTP_ALLOW_HOSTS`. The allowlist never permits public, link-local, multicast, unspecified, or other special/documentation ranges. No target DNS resolution is performed; connections use the classified IP. Ports 25/465/587 remain blocked outside loopback, and `expn` remains exclusive to `localhost`. Transport/host/domain are normalized before evaluation and execution; whitespace/case variants of `mock` and `--no-network` never open a connection.

SMTP terminal controls are escaped in human-readable terminal/Markdown output; JSON retains the decoded raw reply. Parser errors mask emails in both languages without hiding flags.

## Configuration

See [.env.example](.env.example).

| Variable | Default | Purpose |
| --- | --- | --- |
| `HIBP_API_KEY` | empty | Optional HIBP |
| `MAILRECON_HTTP_TIMEOUT` | `10.0` | HTTP timeout in seconds |
| `MAILRECON_DNS_TIMEOUT` | `5.0` | DNS timeout in seconds |
| `MAILRECON_ENABLE_LAB_SMTP` | `0` | Enable networked SMTP |
| `MAILRECON_LAB_SMTP_ALLOW_HOSTS` | empty | Allowed lab hosts |
| `MAILRECON_LAB_SMTP_TIMEOUT` | `3.0` | SMTP timeout in seconds |
| `MAILRECON_PROFILE_TOTAL_BUDGET` | `20` | API requests per investigation, 0 to 100 |
| `MAILRECON_PROFILE_SOURCE_BUDGET` | `10` | Requests per source/execution, 0 to 50 |
| `MAILRECON_PROFILE_MAX_RESPONSE_BYTES` | `65536` | Bytes per response, 1024 to 1048576 |
| `MAILRECON_PROFILE_CACHE_TTL` | `60` | TTL seconds, 0 to 300 |
| `MAILRECON_PROFILE_CACHE_ENTRIES` | `128` | In-memory entries, 0 to 512 |

Limits must be integers within these ranges; invalid values use the default. Zero request budget disables new API requests. Profile HTTP timeout is bounded to 60 seconds, with a 10-second fallback for invalid values.

In addition to the per-operation HTTP timeout, the same value sets a monotonic whole-response deadline, including connection/headers, checked on every unaggregated raw chunk and before classifying the body. Expiry stops collection, closes the response, and creates no cache. With synchronous I/O, an already blocked read can return only through the operation timeout; the deadline does not interrupt a blocked operating-system call.

## Architecture and Tests

```text
src/mailrecon/
  cli/          commands, prompts, language selection
  core/         models, catalogs, validation, configuration, safety
  services/     investigation, DNS, HIBP, profiles, refinement, SMTP labs
  reporting/    terminal output and JSON/Markdown export
tests/          isolated tests, mocked responses, regressions
```

PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
git diff --check
```

Linux:

```bash
python -m pytest -q
git diff --check
```

Tests use simulations rather than querying people or real services. They cover provenance, DNS/HTTP, confidence, scores, languages, masking, export, refinement, and SMTP controls. They do not replace authorized integration testing or establish statistical accuracy.

## Next Steps

For v0.2.0: green regressions, verified Windows/Linux installation, reviewed synthetic examples, privacy boundaries, and JSON compatibility. Future work should prioritize independently authorized evidence, traceability, and less ambiguity without expanding intrusive collection.
