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

With `--resolve`, each serial is checked in the persistent cache first, then
searched in **ctlogs.dev** on a miss. The resolver
follows search pages and fetches certificate details to collect common names
and DNS Subject Alternative Names. Errors or no names trigger a **crt.sh** JSON
lookup instead. Names are sorted and deduplicated; successful results, including
empty fallback results, are cached per serial for the run. Non-empty matches
also persist across runs without expiry. Errors are not cached.

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

### Separate collection from online resolution

On the target, run `cryptnet-dump --json --output evidence.jsonl` without
`--resolve` to collect offline. Transfer that file to a forensic machine, then
run `cryptnet-dump --input evidence.jsonl --resolve --json --output resolved.jsonl`.
The forensic machine needs Internet access for CT lookups, but does not need the
original cache or access to the source paths recorded in the JSON. Alternatively,
transfer both `MetaData` and `Content` directories and use `--path` there.

`--input` accepts the tool's JSON Lines output, not a JSON array or the compact
table, and is mutually exclusive with `--path` and `--all-users`. Malformed
records are reported by line number; other valid records are retained and the
exit status indicates failure. Each input record is limited to 8 MiB. Input and
output files must be different; existing files are never overwritten. Source
fields and collection warnings are retained. `--resolve` replaces any previous
candidate names with cached or newly queried results, retaining historical warnings.

### Persistent resolver cache

The resolver saves non-empty name matches by normalized serial, **without a TTL**.
Certificate expiry does not invalidate historical results. Empty results remain
in memory only for the current run, allowing later runs to discover new CT data;
lookup failures are never cached. The cache stores unverified serial-only
candidates, not issuer-verified certificate identities.

The default directory is `%LOCALAPPDATA%\ocspcryptneturlcache\resolver.cache`
on Windows, falling back to `%USERPROFILE%\AppData\Local` as the base directory.
On non-Windows builds it is `$XDG_CACHE_HOME/ocspcryptneturlcache/resolver.cache`,
or `~/.cache/ocspcryptneturlcache/resolver.cache` if `XDG_CACHE_HOME` is unset or
relative. The selected path is printed on stderr. If no per-user location can
be determined, resolution continues with a warning and in-memory caching only.

Use `--resolver-cache <directory>` with `--resolve` to select a different
location. Each `<NORMALIZED_SERIAL>.json` holds a JSON array of names; atomic
per-file replacement prevents partial records and lost updates for unrelated
serials during concurrent runs. Newly created directories/files use private
permissions on Unix; Windows uses inherited directory permissions. Reads are
bounded to 8 MiB per file. Corrupt/unreadable records trigger a warning and an
online lookup; write failures warn but retain successful results in output.

`--no-resolver-cache` with `--resolve` bypasses persistent reads and writes, but
retains in-memory deduplication. Delete the relevant serial file (or the cache
directory) to force a lookup that repopulates it. Without `--resolve`, the disk
cache is not accessed or created. Source Windows cache/evidence files are never
modified. The resolver cache contains investigation leads; protect or remove it
as appropriate for your case. API keys, source URLs, and evidence paths are not
stored there. Keep enriched JSON as the case record: the resolver cache is not
a substitute for evidence provenance. Open `cryptnet-dump --input resolved.jsonl`
without `--resolve` to display saved enrichment without network requests.

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
`--resolve` while scanning cache directories, an animated bar shows per-cache
entry counts, elapsed time, ETA,
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
trigger crt.sh fallback. For better throughput, optionally configure the
`CTLOG_API_KEY` environment variable on the resolver machine (or the Amp secret
of that name when running in Amp). Obtain a key at <https://account.ctlogs.dev/>.
The key is sent as a Bearer credential on ctlogs.dev search and detail requests
only, never to crt.sh; it is not included in output. Blank/unset keys use anonymous
access. Keyed access avoids shared anonymous capacity, but speed and quota depend
on the plan: a free key still has a 100 requests/hour limit and a monthly
allowance. This tool retains a ten-page safety cap even with a key. No key is
required, and no key is bundled with the executable.

## Compatibility, builds, and tests

Deployment baseline: **64-bit Windows 10/11 and Windows Server 2016 or newer**.
The x86-64 MSVC build uses a statically linked C runtime and baseline CPU target;
there is no 32-bit build or Windows 7/8 support claim. ARM64 uses the same static
runtime in its own `aarch64-pc-windows-msvc` build. Compatibility is a target,
not a substitute for testing on those systems. Local live validation is Windows
11 x64; the CI matrix tests native x64 and ARM64 runners.

Native Windows builds require current stable Rust MSVC and Visual Studio C++
Build Tools. These are build-machine requirements only. No Python, OpenSSL DLLs,
or VC++ redistributable installation is needed on the target.

```powershell
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

Tests use synthetic metadata based on the live Windows layout, public OCSP
examples, and local HTTP servers for provider fallback. No developer browsing
history is included.

### Cross-compiling Windows releases on Linux

The reusable [build script](../scripts/build-windows.sh) produces MSVC executables
on Linux with **cargo-xwin 0.23.1**, clang/LLD, Microsoft SDK **10.0.26100**, and
CRT **14.44.17.14**. The SDK and CRT are downloaded automatically; Visual Studio
and Wine are not required. Both targets retain the static CRT settings from
`.cargo/config.toml`. The setup below was validated on Debian 12 x86-64 with
clang/LLVM/LLD 14; Actions uses Ubuntu 22.04 with the same LLVM major version.

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm lld cmake ninja-build python3
# Install current stable Rust with rustup first, if it is not already installed.
cargo install --locked cargo-xwin --version 0.23.1
bash scripts/build-windows.sh x86_64-pc-windows-msvc
bash scripts/build-windows.sh aarch64-pc-windows-msvc
```

Run these commands from a Git checkout. Executables are written to
`target/<target>/release/cryptnet-dump.exe`. SDK/CRT downloads are reused under
`~/.cache/cargo-xwin/0.23.1-sdk-10.0.26100-crt-14.44.17.14/xwin` by default.
`XWIN_CACHE_DIR` overrides the base directory; cargo-xwin appends `xwin/` to it.
Use a separate base directory for each SDK/CRT version: cargo-xwin's cache marker
does not check versions when reusing an existing cache. The script installs each
Rust target and handles `ring` 0.17's ARM64 clang include flags; a plain
`cargo xwin build` does not currently suffice for that target with this toolchain.

The [release workflow](https://github.com/truekonrads/ocspcryptneturlcache/blob/main/.github/workflows/build.yml)
cross-builds both executables on Linux, caching cargo-xwin and the SDK/CRT.
Native Windows x64 and ARM64 runners then run formatting, Clippy, and the test
suite, and smoke-test the **exact cross-built executables** against synthetic
cache metadata before packaging them. Pushing a `v*` tag publishes both ZIPs and
SHA-256 checksums to GitHub Releases only after both Windows jobs pass. Branch
builds, pull requests, and manual runs produce downloadable workflow artifacts
without publishing a release.

## Publishing the crate

The same workflow publishes `cryptnet-dump` to **crates.io** after the Windows
builds and GitHub release succeed. Branch builds and pull requests never publish.
The publish step uses the repository Actions secret `CARGO_REGISTRY_TOKEN`; an
Amp secret with that name is separate and is not forwarded to GitHub Actions.
Use a crates.io token with permission to publish this crate, including permission
to create it for its first publication.

For a new release, update `version` in `Cargo.toml`, regenerate `Cargo.lock`,
commit the changes, then push a matching `v<version>` tag, such as `v1.0.1`.
The workflow rejects a crate publish if the tag and package version differ.
Existing tags are not moved or retroactively published; the original `v1` tag
predates crate publishing. crates.io versions cannot be overwritten: publish a
new version rather than rerunning a successful publish for the same version.

The crate includes Rust sources, tests, the license, README, and current docs.
Archived Python files, workflow files, and local screenshots are excluded.
Validate the package before tagging:

```powershell
cargo package --list --locked
cargo publish --dry-run --locked
```

Crate installation requires Rust and a native build toolchain; the downloadable
Windows ZIPs remain the installation-free option for machines being examined.

## Background research

The [original Python write-up and notebook](https://github.com/truekonrads/ocspcryptneturlcache/tree/main/old) are archived in
`old/`. They explain the initial proof of concept and historical example output;
the executable, behavior, and cautions described above are the current approach.
