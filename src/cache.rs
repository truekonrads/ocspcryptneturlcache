use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Deserialize, Serialize)]
pub struct Metadata {
    pub url: String,
    pub last_download_time: String,
    pub last_modified_header: String,
    pub content_size: u32,
    pub etag: String,
}

/// Cryptnet's on-disk metadata has a 116-byte prefix followed by UTF-16LE
/// strings. Sizes include the terminating UTF-16 NUL, and are byte counts.
pub fn parse(data: &[u8]) -> Result<Metadata> {
    if data.len() < 116 {
        bail!("truncated metadata header ({} bytes)", data.len());
    }
    let u32_at = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    let u64_at = |offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    let url_len = u32_at(12) as usize;
    let etag_len = u32_at(100) as usize;
    let mut strings = &data[116..];
    let url = take_string(&mut strings, url_len).context("invalid URL")?;
    if url.is_empty() {
        bail!("metadata URL is empty");
    }
    let etag = take_string(&mut strings, etag_len).context("invalid ETag")?;
    Ok(Metadata {
        url,
        last_download_time: filetime(u64_at(16))?,
        last_modified_header: filetime(u64_at(88))?,
        content_size: u32_at(112),
        etag,
    })
}

fn take_string(data: &mut &[u8], len: usize) -> Result<String> {
    if !len.is_multiple_of(2) || len > data.len() {
        bail!(
            "invalid UTF-16 byte length {len} ({} bytes available)",
            data.len()
        );
    }
    let (text, rest) = data.split_at(len);
    *data = rest;
    if len == 0 {
        return Ok(String::new());
    }
    let units: Vec<u16> = text
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    if units.last() != Some(&0) {
        bail!("missing UTF-16 terminator");
    }
    Ok(String::from_utf16(&units[..units.len() - 1])?)
}

fn filetime(ticks: u64) -> Result<String> {
    let nanos = (i128::from(ticks) - 116_444_736_000_000_000) * 100;
    Ok(OffsetDateTime::from_unix_timestamp_nanos(nanos)?.format(&Rfc3339)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic fixture with the layout observed on live Windows. Never commit
    // user cache files: they may disclose browsing or certificate history.
    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 116];
        let url: Vec<u8> = "https://example.test/é\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let etag: Vec<u8> = "\"abc\"\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes[12..16].copy_from_slice(&(url.len() as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&116_444_736_123_456_789u64.to_le_bytes());
        bytes[100..104].copy_from_slice(&(etag.len() as u32).to_le_bytes());
        bytes[112..116].copy_from_slice(&12345u32.to_le_bytes());
        bytes.extend(url);
        bytes.extend(etag);
        bytes
    }

    #[test]
    fn parses_metadata_without_losing_time_or_unicode() {
        let m = parse(&fixture()).unwrap();
        assert_eq!(m.url, "https://example.test/é");
        assert_eq!(m.etag, "\"abc\"");
        assert_eq!(m.content_size, 12345);
        assert_eq!(m.last_download_time, "1970-01-01T00:00:12.3456789Z");
        assert_eq!(m.last_modified_header, "1601-01-01T00:00:00Z");
    }

    #[test]
    fn rejects_truncation_bad_lengths_and_invalid_utf16() {
        let bytes = fixture();
        for len in 0..bytes.len() {
            assert!(parse(&bytes[..len]).is_err(), "accepted {len} bytes");
        }
        for len in [1, u32::MAX] {
            let mut bad = bytes.clone();
            bad[12..16].copy_from_slice(&len.to_le_bytes());
            assert!(parse(&bad).is_err());
        }
        let mut bad = bytes;
        bad[116..118].copy_from_slice(&0xd800u16.to_le_bytes());
        assert!(parse(&bad).is_err());
    }
}
