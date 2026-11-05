# Windows OCSP cache retention

[Read the rendered GitHub Pages version](cache-retention-analysis.html) or
[explore the retention scenarios](cache-retention.html).

## Finding

An OCSP entry in Windows `CryptnetUrlCache` does not have one fixed lifetime.
Windows tracks two separate clocks:

1. **Validation lifetime:** how long the response can satisfy a revocation check.
2. **Physical retention:** how long its `MetaData` and `Content` files can remain
   recoverable.

For a normal, non-prefetched entry, the relevant calculations are:

```text
if the response contains nextUpdate:
    valid_until = min(nextUpdate, certificate.NotAfter)
else:
    valid_until = min(thisUpdate + OcspValiditySeconds, certificate.NotAfter)

flush_base     = max(ExpireTime, LastSyncTime)
flush_eligible = flush_base + flush_exemption
```

The default `OcspValiditySeconds` is **43,200 seconds (12 hours)**. A stored
`dwExemptSeconds` of zero selects the service default, normally **2,419,200
seconds (28 days)**. `0xFFFFFFFF` disables automatic flushing for that entry.

Reaching `flush_eligible` does not delete the files immediately. It makes them
eligible for deletion during a later Cryptnet URL Cache Service scan. The
machine can therefore retain an expired response beyond the calculated time.

[Explore the scenarios interactively](cache-retention.html).

## Reverse-engineering scope

The result was established from these installed Windows 11 binaries, imported
into Ghidra 12.2 with matching Microsoft public symbols:

- `cryptnet.dll`
  - Version: `10.0.26100.9549`
  - SHA-256: `E478DD3D872606A1B0CBB4B50BED941EA8ACA92B71DF4178CA7B164AAFB7428A`
- `cryptsvc.dll`
  - Version: `10.0.26100.1`
  - SHA-256: `078C8645A3F57BBF5ABA4E55C9989C400CC2E6B39B886F9B5A1AD7435B1D1500`

Addresses below apply only to these images. Other Windows releases may differ.

## Response validity

`cryptnet!OcspConvertResponseToCrl` at `0x180009EC0` converts an accepted OCSP
response into the time-valid-object representation used by Windows. It uses the
response's `nextUpdate` when present. If the field is absent, it adds the value
returned by `I_GetOcspValiditySeconds` at `0x18001CC38` to `thisUpdate`. In both
cases it caps the result at the subject certificate's `NotAfter` time.

`I_GetOcspValiditySeconds` reads the `OcspValiditySeconds` DWORD under:

```text
HKLM\Software\Microsoft\Cryptography\OID\EncodingType 0\
  CertDllCreateCertificateChainEngine\Config
```

An absent or invalid value produces the 12-hour default. HTTP
`Cache-Control: max-age`, parsed elsewhere by `cryptnet.dll`, is response and
revalidation metadata; it does not replace OCSP protocol validity.

## On-disk fields that control retention

The current 116-byte metadata prefix contains the following retention fields.
This is an observed implementation layout, not a documented file-format ABI.

| Offset | Field | Use |
| ---: | --- | --- |
| `0x10` | `LastSyncTime` | Last successful cache retrieval/update. |
| `0x18` | Prefetch structure size | Validates the prefetch block. |
| `0x1C` | Prefetch object type | `3` denotes OCSP. |
| `0x20` | Prefetch error | Zero permits active-prefetch handling. |
| `0x28` | Prefetch `ThisUpdateTime` | Status interval start. |
| `0x30` | Prefetch `NextUpdateTime` | Status interval end and refresh input. |
| `0x40` | Flush structure size | Validates the flush block. |
| `0x44` | `dwExemptSeconds` | Post-base retention exemption. |
| `0x48` | `ExpireTime` | Expiry used by the normal flush calculation. |

The flush block corresponds to Microsoft's
[`CRYPTNET_URL_CACHE_FLUSH_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cryptnet_url_cache_flush_info).

## Normal eviction

The deletion decision is made in `cryptsvc!EnumUrlCacheEntryCallback` at
`0x1800020A0`. For a non-active-prefetch entry, the service:

1. Uses the stored exemption, or the machine default when it is zero.
2. Leaves the entry alone when the exemption is `0xFFFFFFFF`.
3. Chooses the later of `ExpireTime` and `LastSyncTime` (with clock-rollback
   handling for a future sync time).
4. Adds the exemption and queues an eligible pair for deletion.

`cryptsvc!InitPreFetchPara` at `0x18000CD20` initializes the default exemption
to `0x24EA00`, or 28 days. A nonzero `CryptnetDefaultFlushExemptSeconds` DWORD
under the chain-engine `Config` key can override it.

Queued entries are deleted by `FlushUrlCacheEntries` at `0x180008E04` during a
service scan. The paired content and metadata files are separate; explicit
deletion removes content first, so interruption or collection timing can leave
an orphaned half-pair.

## Active prefetch

An entry with a valid prefetch block, nonzero object type, zero prefetch error,
and nonzero `NextUpdateTime` follows a different branch. The service creates or
updates a prefetch job instead of placing the entry on the normal flush list.
Successful background refresh can advance `LastSyncTime` and replace validity
metadata without the original application—or malware—running again.

For this reason, the normal formula is not an upper bound for an actively
prefetched entry. If prefetch is unsupported, malformed, or records an error,
the entry falls back to normal time-based flushing.

## Worked forensic windows

Assume the initial cache retrieval occurred at `T0` and the default 28-day
exemption applies:

| Scenario | Validation expiry | Normal deletion eligibility |
| --- | --- | --- |
| `nextUpdate = T0 + 7 days` | About day 7 | About day 35 |
| No `nextUpdate` | About 12 hours after `thisUpdate` | About day 28.5 |
| `nextUpdate = T0 + 60 days` | About day 60 | About day 88 |
| Active prefetch | Refresh advances it | No fixed upper bound |
| Flush disabled (`0xFFFFFFFF`) | Response expires | No automatic flush |

These examples assume `thisUpdate`, retrieval time, and `T0` are close. Use the
actual FILETIME and OCSP values when analysing a real entry.

## Live cache examples

A read-only scan on 2026-11-05 found 60 OCSP-bearing entries in the current
user's cache. The scan used `cryptnet-dump.exe --ocsp-only --json` without
`--resolve`; no certificate serials or URLs were sent to an external service.
Times below are UTC.

### Thirty-day-old normal entry

- Responder: `oneocsp.microsoft.com`
- Cache key:
  `BBD4B1348E8664F092F68378AEE49761_FEB2D449327D68824E2066BF592EFC1B`
- `LastSyncTime`: 2026-10-06 10:20:37
- `ExpireTime` / `NextUpdateTime`: 2026-10-12 20:20:20
- Stored exemption: zero, selecting the 28-day default
- Prefetch error: 50 (`ERROR_NOT_SUPPORTED`), selecting normal flushing
- Normal deletion eligibility: 2026-11-09 20:20:20

The roughly 30-day-old files were still present because the post-expiry
exemption had not elapsed.

### Recent normal entry

- Responder: `ocsp.digicert.com`
- Cache key:
  `8EC9B1D0ABBD7F98B401D425828828CE_0B1450752E8709914F773207984E4A63`
- `LastSyncTime`: 2026-11-04 23:56:35
- `ExpireTime` / `NextUpdateTime`: 2026-11-11 20:21:00
- Prefetch error: 50, selecting normal flushing
- Normal deletion eligibility: 2026-12-09 20:21:00

Here `ExpireTime` exactly matched the OCSP response's `nextUpdate`, and the
default exemption added 28 days.

### Long-lived active-prefetch candidate

- Responder: `ocsps.ssl.com`
- Cache key:
  `161832C90068D02CF65B25D285AB768A_3E5CCA2E9839DA0DDB183F1D9E86F21F`
- `LastSyncTime`: 2026-11-05 00:13:27
- `ExpireTime` / `NextUpdateTime`: 2027-06-07 17:45:56
- Prefetch error: zero, satisfying the active-prefetch status condition
- Normal-formula date, if prefetch were inactive: 2027-07-05 17:45:56

This entry demonstrates both a long responder validity interval and the active
prefetch branch. The normal-formula date is not an upper bound while prefetch
remains active.

## Forensic interpretation

Presence establishes that certificate-related material was cached for that
profile. It does **not** identify the initiating process, prove the inferred
site was contacted, show that TLS succeeded, or establish that malware ran at
`LastSyncTime`. OCSP retrieval may relate to a TLS certificate, intermediate
CA, Authenticode signer, timestamp chain, or another validation operation.

Absence is also weak evidence. The entry may never have been created, may belong
to another profile, may have been cleared manually, may have used stapled OCSP
or another TLS stack, or may already have been scanned and deleted. Treat
`flush_eligible` as a lower bound on automatic deletion, never as a guaranteed
deletion timestamp.

## Sources

- [Microsoft: certificate revocation semantics](https://learn.microsoft.com/en-us/windows/win32/seccrypto/certificate-revocation-list-semantics)
- [Microsoft: `CryptRetrieveObjectByUrlW`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptretrieveobjectbyurlw)
- [Microsoft: `CRYPTNET_URL_CACHE_FLUSH_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cryptnet_url_cache_flush_info)
- [Microsoft: `CRYPTNET_URL_CACHE_RESPONSE_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cryptnet_url_cache_response_info)
- [RFC 6960: Online Certificate Status Protocol](https://www.rfc-editor.org/rfc/rfc6960)
