# From Windows certificate cache to investigation leads

[Back to the quick start](../README.md)

## Why this is useful

A Windows certificate-validation cache can outlive the program or network
activity that caused it. When a browser history or a packet capture is missing,
cached OCSP checks can still give an investigator certificate serial numbers,
responder addresses, and timestamps to pivot on. Public Certificate Transparency
(CT) data may turn those serials into candidate hostnames. This can help triage
suspected malware callbacks or reconstruct leads from an acquired user profile.

The Rust tool makes that workflow a single command rather than a notebook and
several Python dependencies. It reads live or collected caches without modifying
them, works offline unless enrichment is requested, and streams a readable table
or full JSON Lines for other analysis tools. It is a source of leads, **not a
complete connection history or proof that every certificate name was contacted**.

## The approach

Windows caches certificate-validation downloads in `CryptnetUrlCache`, including
OCSP responses, CRLs, and certificate-related files. Each `MetaData` file carries
a URL, download and last-modified timestamps, declared content size, and ETag.
The matching file in `Content` holds the downloaded bytes.

The executable reads those files directly; it does not invoke certutil or Python.
It parses the fixed metadata header and UTF-16LE strings, then looks for OCSP
certificate IDs in two places:

- **GET requests:** a URL path can contain a percent-encoded, base64 DER OCSP
  request. The parser extracts serials, hash algorithm OIDs, and issuer hashes.
- **Cached responses:** DER OCSP response bodies can retain the same certificate
  IDs even when the request used POST and the URL alone contains no serial.

Multiple IDs in requests/responses are retained. Response IDs already extracted
from the URL are not added again. Non-OCSP URL evidence is kept unless
`--ocsp-only` is supplied. CRLs and other content types are not decoded further.

With `--resolve`, each serial is searched in **ctlogs.dev first**. The resolver
follows search pages and fetches certificate details to collect common names
and DNS Subject Alternative Names. Errors or no names trigger a **crt.sh** JSON
lookup instead. Names are sorted and deduplicated; successful results, including
empty fallback results, are cached per serial for the run. Errors are not cached.

## An investigation workflow

1. Start offline with `cryptnet-dump --path D:\Evidence\CryptnetUrlCache` to
   assess the collected cache. Preserve the original evidence separately.
2. Add `--ocsp-only` to focus on certificate IDs. Note the UTC cache-download
   times and responder addresses; these are not necessarily the application
   destinations or original connection times.
3. If disclosure of serials to public services is acceptable, add `--resolve`
   to obtain candidate names. Correlate them with other evidence such as DNS,
   proxy, EDR, process, or filesystem records before drawing conclusions.
4. Save unabridged evidence with `--json --output evidence.jsonl`. Source paths
   and issuer hashes provide pivots that the compact table intentionally omits.

## Cache locations and scope

The default is the current profile's
`%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache`.

`--all-users` also checks sibling user profiles, System32 and SysWOW64 system
profiles, and the LocalService and NetworkService profiles under `%SystemRoot%`.
Protected directories require elevation. Profiles outside the discovered
locations can be supplied with `--path`, which accepts a cache root or its
`MetaData` directory and can be repeated for multiple collected caches.

## Output and collection behavior

The default is a terminal-width table: UTC download time (to the second), cached
endpoint, first certificate serial, and up to two candidate names. OCSP request
paths are omitted, long values are shortened with `…`, additional serials/names
are counted, and per-entry warning counts are shown. Names remain unverified
candidates. Colors are enabled only for terminal stdout; `NO_COLOR=1` disables
them. Files and pipes receive an uncolored table.

Use `--json` for full-fidelity evidence: each record is one JSON object in a JSON
Lines stream, without table truncation. Combine with `--output evidence.jsonl`
to save it. Fields include:

| Field | Meaning |
| --- | --- |
| `metadata_path` | Source file for the record. |
| `url` | Cached validation URL, not necessarily the application destination. |
| `last_download_time` | Download FILETIME converted to UTC, retaining 100-nanosecond precision. |
| `last_modified_header` | Raw last-modified-header FILETIME converted to UTC. |
| `content_size`, `etag` | Declared content size and cached ETag. |
| `ocsp` | Certificate serials, hash algorithm OIDs, issuer name hashes, and issuer key hashes. |
| `candidate_names` | CN/SAN candidates, present only with `--resolve`. |
| `warnings` | Per-record issues, when present. |

Missing content is a per-record warning: metadata can still be useful on its own.
If resolution needs the fallback and it fails, the lookup fails; a successful
empty fallback result is not an error. A warning count in the table points to
details available in JSON output.

Every completed table row or JSON record is flushed immediately, even while
later lookups are pending. Progress and collection errors go to stderr. With
`--resolve`, an animated bar shows per-cache entry counts, elapsed time, ETA,
and the current serial lookup. Counts include non-OCSP and filtered entries,
not just HTTP requests. `--no-progress` or redirected stderr hides the bar.

`--output` refuses to overwrite existing files. Exit code 0 means the requested
scan completed (an absent default cache is reported on stderr); 1 means an I/O,
parsing, or lookup failure; 2 means invalid arguments. Valid records are retained
when another record fails.

## Privacy and limitations

`--resolve` sends certificate serial numbers to ctlogs.dev, and to crt.sh when
fallback is needed. Certificate IDs are also sent to ctlogs.dev for full details.
It does not send complete cache files or URLs. Serials are unique only within
an issuer: **lookup names are not issuer-verified**. Issuer hashes are retained
for further investigation; OCSP signatures are not verified.

A cached certificate check does not establish a connection to every SAN or
identify the responsible process. Windows components and certificate-chain
validation can populate caches too. Timestamps describe cache activity, not
connection times, and caches can expire or be cleared. CT coverage is incomplete,
particularly for private PKI and code-signing certificates. Finding no names or
no OCSP entries is not evidence that no network activity occurred.

Inputs are bounded to 1 MiB per metadata file, 32 MiB per content file, and 8 MiB
per CT response. Unsupported/corrupt metadata is reported rather than silently
discarded. Online requests have a 15-second timeout each; enrichment is sequential
and may take time on large caches. ctlogs.dev works without a key, but limits
anonymous use to 100 requests/hour and ten pages per query. Each serial search
page and certificate detail costs a request; rate limits or incomplete pagination
trigger crt.sh fallback. No API key is required or configured by this tool.

## Compatibility, builds, and tests

Deployment baseline: **64-bit Windows 10/11 and Windows Server 2016 or newer**.
The x86-64 MSVC build uses a statically linked C runtime and baseline CPU target;
there is no 32-bit build or Windows 7/8 support claim. ARM64 uses the same static
runtime in its own `aarch64-pc-windows-msvc` build. Compatibility is a target,
not a substitute for testing on those systems. Local live validation is Windows
11 x64; the CI matrix tests native x64 and ARM64 runners.

Building requires current stable Rust MSVC and Visual Studio C++ Build Tools;
these are build-machine requirements only. No Python, OpenSSL DLLs, or VC++
redistributable installation is needed on the target.

```powershell
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

Tests use synthetic metadata based on the live Windows layout, public OCSP
examples, and local HTTP servers for provider fallback. No developer browsing
history is included. The [Windows workflow](https://github.com/truekonrads/ocspcryptneturlcache/blob/main/.github/workflows/build.yml)
tests and packages both targets. Pushing a `v*` tag publishes the ZIPs and
SHA-256 checksums to GitHub Releases only after both builds pass.

## Background research

The [original Python write-up and notebook](https://github.com/truekonrads/ocspcryptneturlcache/tree/main/old) are archived in
`old/`. They explain the initial proof of concept and historical example output;
the executable, behavior, and cautions described above are the current approach.
