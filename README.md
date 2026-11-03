# cryptnet-dump

![cryptnet-dump: certificate cache, investigation leads — with more cowbell](docs/assets/hero.jpg)

**Turn Windows' certificate cache into leads for an investigation.**

Recover cached certificate-validation URLs and candidate hostnames to help triage
malware callbacks and investigate past activity. One standalone Rust executable:
**no Python, no installation, read-only, offline by default.**

## See it in action

Extract OCSP records from the current user's cache and look up certificate names:

```powershell
.\cryptnet-dump.exe --ocsp-only --resolve
```

The default is a compact, colored table (illustrative data):

```text
┌─────────────────────┬────────────────────┬─────────────────┬─────────────────┐
│ Downloaded (UTC)    ┆ Endpoint           ┆ Serial          ┆ Names*          │
╞═════════════════════╪════════════════════╪═════════════════╪═════════════════╡
│ 2026-11-03 12:34:56 ┆ ocsp.example.test  ┆ 624D0AB3115587…  ┆ *.example.com   │
│                     ┆                    ┆                 ┆ example.com     │
└─────────────────────┴────────────────────┴─────────────────┴─────────────────┘
```

Long values are shortened with `…`; up to two names are shown, with a count of
additional names. `--json` keeps **all fields and full values** as JSON Lines,
including source paths, issuer hashes, content sizes, ETags, and warnings.
Use these leads to pivot on certificates and domains;
**they are not proof of a connection to every listed name or attribution to a process.**

## Usage

```powershell
# Dump the current user's cache without any network requests
.\cryptnet-dump.exe

# Save full evidence for scripts and further analysis
.\cryptnet-dump.exe --ocsp-only --resolve --json --output leads.jsonl

# Include other user and service profiles (run elevated for protected caches)
.\cryptnet-dump.exe --all-users --ocsp-only --resolve

# Examine a collected cache instead of the live machine
.\cryptnet-dump.exe --path D:\Evidence\CryptnetUrlCache --json --output evidence.jsonl
```

- Table rows and JSON records stream immediately, not after all lookups finish.
  `--output` saves the selected format and never overwrites an existing file.
  Colors are disabled in files/pipes; set `NO_COLOR=1` for a plain terminal table.
- Resolution shows an animated progress bar on stderr. Use `--no-progress` to
  hide it; redirecting stderr hides it automatically.
- `--resolve` sends serials to **ctlogs.dev first**, with **crt.sh as fallback**.
  No API key is required; ctlogs.dev's anonymous limit is 100 requests/hour.
- Run `--help` for all options. Records that succeed are kept if another fails;
  check stderr and the exit code for incomplete collection.

## Get the executable

Target: **64-bit Windows 10/11 and Server 2016+**; live-tested on Windows 11 x64.
No Python, OpenSSL DLLs, or VC++ runtime installation is needed on the target.

**[Download the latest release](https://github.com/truekonrads/ocspcryptneturlcache/releases/latest)**
and extract the ZIP for **x64** (most PCs) or **ARM64** (Windows on ARM).
Each ZIP includes the executable, documentation, and a SHA-256 checksum;
the release also includes checksums for the ZIPs themselves.

Build with stable Rust (MSVC) and Visual Studio C++ Build Tools:

```powershell
cargo build --release --locked
```

Copy `target\release\cryptnet-dump.exe` to the machine being examined. The
[Windows build workflow](https://github.com/truekonrads/ocspcryptneturlcache/blob/main/.github/workflows/build.yml) packages x64 and ARM64 builds
and publishes them on `v*` tags; ARM64 execution remains untested locally.

## How it works

Windows caches certificate-revocation checks in `CryptnetUrlCache`. The tool reads
that cache directly, extracts certificate serials and issuer hashes from OCSP
URLs and response bodies, and optionally searches Certificate Transparency data
for certificate names. Cache timestamps describe validation activity, not
connection times; lookup names are candidates, not issuer-verified matches.
Read [how it works](docs/how-it-works.md) for the technical details, limitations,
and investigation workflow. The original Python proof of concept is archived in
[`old/`](https://github.com/truekonrads/ocspcryptneturlcache/tree/main/old).
