//! CT enrichment produces **unverified serial-only name candidates**.
//!
//! Serial numbers are unique only within an issuer. No issuer identity or
//! certificate signature is verified here; callers must label these candidates
//! accordingly, rather than treating them as confirmed connections or hostnames.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::{de::DeserializeOwned, Deserialize};

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

pub fn default_cache_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join("AppData/Local"))
        });
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")));
    base.map(|base| base.join("ocspcryptneturlcache/resolver.cache"))
}

/// Uses ctlogs.dev first, then crt.sh on errors or no names.
pub struct Resolver {
    client: Client,
    ctlogs_base: String,
    crtsh_url: String,
    ctlogs_authorization: Option<HeaderValue>,
    cache_dir: Option<PathBuf>,
    cache: HashMap<String, Vec<String>>,
}

impl Resolver {
    pub fn new(cache_dir: Option<PathBuf>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("building CT HTTP client")?;
        let ctlogs_authorization = match std::env::var("CTLOG_API_KEY") {
            Ok(key) if !key.trim().is_empty() => {
                let mut header = HeaderValue::from_str(&format!("Bearer {}", key.trim()))
                    .context("invalid CTLOG_API_KEY header value")?;
                header.set_sensitive(true);
                Some(header)
            }
            Ok(_) | Err(std::env::VarError::NotPresent) => None,
            Err(_) => bail!("CTLOG_API_KEY must be valid Unicode"),
        };
        Ok(Self {
            client,
            ctlogs_base: "https://api.ctlogs.dev/".to_owned(),
            crtsh_url: "https://crt.sh/".to_owned(),
            ctlogs_authorization,
            cache_dir,
            cache: HashMap::new(),
        })
    }

    /// Returns sorted, deduplicated, unverified serial-only name candidates.
    ///
    /// Accepts hexadecimal serials, ignoring case and leading zeroes. Successful
    /// results are cached in memory; nonempty results persist without expiry
    /// when a cache directory is configured. Errors are never cached.
    /// Names are reported CN/SAN candidates, not necessarily DNS names.
    /// Certificate metadata is fetched, but signatures/issuers are not verified.
    pub fn names(&mut self, serial: &str) -> Result<Vec<String>> {
        let serial = normalize_serial(serial)?;
        if let Some(names) = self.cache.get(&serial) {
            return Ok(names.clone());
        }
        if let Some(dir) = &self.cache_dir {
            match self.cached_names(&serial) {
                Ok(Some(names)) => {
                    self.cache.insert(serial, names.clone());
                    return Ok(names);
                }
                Ok(None) => {}
                Err(error) => eprintln!(
                    "warning: resolver cache {}: {error:#}; querying CT instead",
                    dir.display()
                ),
            }
        }

        let primary = self.ctlogs_names(&serial);
        let names = match primary {
            Ok(names) if !names.is_empty() => names,
            primary => self.crtsh_names(&serial).with_context(|| match primary {
                Ok(_) => "ctlogs.dev returned no names; crt.sh fallback failed".to_owned(),
                Err(error) => format!("ctlogs.dev failed: {error:#}; crt.sh fallback failed"),
            })?,
        };
        if let Some(dir) = &self.cache_dir {
            if let Err(error) = self.store_names(&serial, &names) {
                eprintln!(
                    "warning: resolver cache {}: {error:#}; lookup results retained",
                    dir.display()
                );
            }
        }
        self.cache.insert(serial, names.clone());
        Ok(names)
    }

    fn cached_names(&self, serial: &str) -> Result<Option<Vec<String>>> {
        let path = self
            .cache_dir
            .as_ref()
            .unwrap()
            .join(format!("{serial}.json"));
        let bytes = match crate::read_bounded(&path, MAX_RESPONSE_BYTES) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let names: Vec<String> = serde_json::from_slice(&bytes)?;
        Ok((!names.is_empty()).then_some(names))
    }

    fn store_names(&self, serial: &str, names: &[String]) -> Result<()> {
        // A missing match today may be indexed tomorrow. Only positive results
        // are persisted; they remain useful regardless of certificate expiry.
        if names.is_empty() {
            return Ok(());
        }
        let dir = self.cache_dir.as_ref().unwrap();
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
        // Each serial has its own atomic replacement: concurrent runs cannot
        // truncate a record or lose cached results for other serials.
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer(&mut file, names)?;
        file.persist(dir.join(format!("{serial}.json")))?;
        Ok(())
    }

    fn ctlogs_names(&self, serial: &str) -> Result<Vec<String>> {
        // The API accepts at least four hex digits, even for small serials.
        let url = format!("{}v1/serial/{serial:0>4}", self.ctlogs_base);
        let mut cursor = String::new();
        let mut cursors = BTreeSet::new();
        let mut certificates = BTreeSet::new();
        let mut names = BTreeSet::new();
        // Bound pagination even with a key; anonymous queries also have this service limit.
        for _ in 0..10 {
            let mut request = self.ctlogs_request(&url);
            if !cursor.is_empty() {
                request = request.query(&[("after", &cursor)]);
            }
            let page: CtlogsPage = self.json(request).context("ctlogs.dev serial search")?;
            for row in page.rows {
                if normalize_serial(&row.serial_hex)? != serial
                    || !certificates.insert(row.id.clone())
                {
                    continue;
                }
                let id = percent_encoding::utf8_percent_encode(
                    &row.id,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let cert: CtlogsCertificate = self
                    .json(self.ctlogs_request(&format!("{}v1/cert/{id}", self.ctlogs_base)))
                    .context("ctlogs.dev certificate details")?;
                if normalize_serial(&cert.serial_hex)? != serial {
                    bail!("ctlogs.dev certificate details have a different serial");
                }
                names.extend(
                    cert.subject_cn
                        .into_iter()
                        .chain(cert.san_dns)
                        .map(|name| name.trim().to_owned())
                        .filter(|name| !name.is_empty()),
                );
            }
            if !page.has_next {
                return Ok(names.into_iter().collect());
            }
            if page.next_cursor.is_empty() || !cursors.insert(page.next_cursor.clone()) {
                bail!("ctlogs.dev returned a missing or repeated pagination cursor");
            }
            cursor = page.next_cursor;
        }
        bail!("ctlogs.dev exceeded the resolver's ten-page query limit")
    }

    fn ctlogs_request(&self, url: &str) -> RequestBuilder {
        let request = self.client.get(url);
        match &self.ctlogs_authorization {
            Some(header) => request.header(AUTHORIZATION, header.clone()),
            None => request,
        }
    }

    fn crtsh_names(&self, serial: &str) -> Result<Vec<String>> {
        let entries: Vec<CertificateEntry> = self
            .json(self.client.get(&self.crtsh_url).query(&[
                ("serial", serial),
                ("match", "="),
                ("deduplicate", "Y"),
                ("output", "json"),
            ]))
            .context("crt.sh lookup")?;
        names_from_entries(entries, serial)
    }

    fn json<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let mut response = request.send()?.error_for_status()?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            bail!("CT response exceeds the 8 MiB limit");
        }
        let mut body = Vec::new();
        // Do not trust Content-Length: chunked responses also need a bound.
        response
            .by_ref()
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut body)
            .context("reading CT response")?;
        // A single overflow probe distinguishes an exact-limit body from an
        // oversized one; at most 8 MiB is retained in the response buffer.
        let mut overflow = [0_u8; 1];
        if response
            .read(&mut overflow)
            .context("checking CT response size")?
            != 0
        {
            bail!("CT response exceeds the 8 MiB limit");
        }

        serde_json::from_slice(&body).context("decoding CT JSON response")
    }
}

#[derive(Deserialize)]
struct CtlogsPage {
    rows: Vec<CtlogsRow>,
    has_next: bool,
    next_cursor: String,
}

#[derive(Deserialize)]
struct CtlogsRow {
    id: String,
    serial_hex: String,
}

#[derive(Deserialize)]
struct CtlogsCertificate {
    serial_hex: String,
    subject_cn: Option<String>,
    #[serde(default)]
    san_dns: Vec<String>,
}

#[derive(Deserialize)]
struct CertificateEntry {
    // Deserialize the certificate ID for schema checking, even though names
    // are read directly from the JSON rather than a second certificate fetch.
    #[serde(rename = "id")]
    _id: u64,
    serial_number: String,
    name_value: Option<String>,
    common_name: Option<String>,
}

fn normalize_serial(serial: &str) -> Result<String> {
    if serial.is_empty() || !serial.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("certificate serial must be a nonempty hexadecimal string");
    }
    let serial = serial.trim_start_matches('0');
    Ok(if serial.is_empty() {
        "0".to_owned()
    } else {
        serial.to_ascii_uppercase()
    })
}

fn names_from_entries(entries: Vec<CertificateEntry>, serial: &str) -> Result<Vec<String>> {
    let serial = normalize_serial(serial)?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry_serial = normalize_serial(&entry.serial_number)
            .context("invalid serial_number in crt.sh response")?;
        if entry_serial != serial {
            continue;
        }
        for value in [entry.name_value, entry.common_name].into_iter().flatten() {
            for name in value.lines().map(str::trim).filter(|name| !name.is_empty()) {
                names.insert(name.to_owned());
            }
        }
    }
    Ok(names.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn names_from_json(body: &[u8], serial: &str) -> Result<Vec<String>> {
        names_from_entries(serde_json::from_slice(body)?, serial)
    }

    // Exercise public resolver behavior over real HTTP without external services.
    fn local_resolver(
        handler: impl Fn(&str, &str) -> (u16, serde_json::Value) + Send + 'static,
    ) -> (
        Resolver,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
            sync::mpsc,
            thread,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            while matches!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                let (mut socket, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                let mut headers = String::new();
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
                        break;
                    }
                    headers.push_str(&header);
                }
                let (status, body) = handler(request.split_whitespace().nth(1).unwrap(), &headers);
                let body = body.to_string();
                write!(socket, "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let resolver = Resolver {
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            ctlogs_base: format!("{base}primary/"),
            crtsh_url: format!("{base}fallback"),
            ctlogs_authorization: None,
            cache_dir: None,
            cache: HashMap::new(),
        };
        (resolver, stop, worker)
    }

    #[test]
    fn prefers_ctlogs_and_collects_sans_across_pages_then_caches() {
        let temp = tempfile::tempdir().unwrap();
        let (mut resolver, stop, worker) = local_resolver(|path, headers| {
            assert!(!headers.to_ascii_lowercase().contains("authorization:"));
            let body = if path == "/primary/v1/serial/0ABC" {
                json!({"rows": [{"id":"01","serial_hex":"000abc"}, {"id":"bad","serial_hex":"ABD"}], "has_next":true, "next_cursor":"next/+?"})
            } else if path.starts_with("/primary/v1/serial/0ABC?after=") {
                json!({"rows": [{"id":"02","serial_hex":"ABC"}], "has_next":false, "next_cursor":""})
            } else if path == "/primary/v1/cert/01" {
                json!({"serial_hex":"0abc", "subject_cn":"z.example", "san_dns":["a.example", "z.example"]})
            } else if path == "/primary/v1/cert/02" {
                json!({"serial_hex":"abc", "subject_cn":"b.example", "san_dns":["a.example"]})
            } else {
                // A wrong fallback policy or failure to filter serials is visible.
                return (503, json!({"error":"unexpected request"}));
            };
            (200, body)
        });
        resolver.cache_dir = Some(temp.path().join("resolver.cache"));
        let result = resolver.names("000aBc");
        stop.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(result.unwrap(), vec!["a.example", "b.example", "z.example"]);
        // The server is gone: normalized successful results must be reusable.
        assert_eq!(
            resolver.names("ABC").unwrap(),
            vec!["a.example", "b.example", "z.example"]
        );
        // A newly constructed resolver must hit disk, not this run's memory.
        // Certificate age and cache file age must not expire positive results.
        let file = fs::File::options()
            .write(true)
            .open(temp.path().join("resolver.cache/ABC.json"))
            .unwrap();
        file.set_times(fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .unwrap();
        let mut next_run = Resolver {
            cache: HashMap::new(),
            ..resolver
        };
        assert_eq!(
            next_run.names("00abc").unwrap(),
            vec!["a.example", "b.example", "z.example"]
        );
    }

    #[test]
    fn corrupt_or_unwritable_disk_cache_does_not_discard_lookup_results() {
        for corrupt in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let dir = temp.path().join("resolver.cache");
            if corrupt {
                fs::create_dir(&dir).unwrap();
                fs::write(dir.join("ABC.json"), b"broken JSON").unwrap();
            } else {
                fs::write(&dir, b"not a directory").unwrap();
            }
            let (mut resolver, stop, worker) = local_resolver(|path, _| {
                if path.contains("/serial/") {
                    (
                        200,
                        json!({"rows":[{"id":"01", "serial_hex":"ABC"}], "has_next":false, "next_cursor":""}),
                    )
                } else {
                    (
                        200,
                        json!({"serial_hex":"ABC", "subject_cn":"found.example", "san_dns":[]}),
                    )
                }
            });
            resolver.cache_dir = Some(dir.clone());
            let result = resolver.names("ABC");
            stop.send(()).unwrap();
            worker.join().unwrap();
            assert_eq!(result.unwrap(), vec!["found.example"]);
            if corrupt {
                assert_eq!(
                    serde_json::from_slice::<Vec<String>>(&fs::read(dir.join("ABC.json")).unwrap())
                        .unwrap(),
                    vec!["found.example"]
                );
            }
        }
    }

    #[test]
    fn authenticates_search_and_details_but_never_fallback() {
        let (mut resolver, stop, worker) = local_resolver(|path, headers| {
            if path.starts_with("/fallback?") {
                assert!(!headers.contains("test-key"));
                assert!(!headers.to_ascii_lowercase().contains("authorization:"));
                (
                    200,
                    json!([{ "id": 1, "serial_number": "ABC", "name_value": "fallback.example" }]),
                )
            } else {
                assert!(headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-key\r\n"));
                if path.contains("/serial/") {
                    (
                        200,
                        json!({"rows":[{"id":"01", "serial_hex":"ABC"}], "has_next":false, "next_cursor":""}),
                    )
                } else {
                    // Force fallback after an authenticated details request.
                    (503, json!({"error":"unavailable"}))
                }
            }
        });
        resolver.ctlogs_authorization = Some(HeaderValue::from_static("Bearer test-key"));
        let result = resolver.names("ABC");
        stop.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(result.unwrap(), vec!["fallback.example"]);
    }

    #[test]
    fn falls_back_on_empty_rate_limited_invalid_or_incomplete_primary_results() {
        for scenario in [
            "empty",
            "rate-limit",
            "invalid",
            "detail-error",
            "wrong-serial",
            "cursor-loop",
        ] {
            let (mut resolver, stop, worker) = local_resolver(move |path, _| {
                if path.starts_with("/fallback?") {
                    return (
                        200,
                        json!([{"id":1, "serial_number":"000abc", "name_value":"fallback.example\nalias.example", "common_name":"fallback.example"}]),
                    );
                }
                match scenario {
                    "rate-limit" => (429, json!({"error":"rate limit"})),
                    "invalid" => (200, json!({"unexpected":"schema"})),
                    "empty" => (200, json!({"rows":[], "has_next":false, "next_cursor":""})),
                    "cursor-loop" => (
                        200,
                        json!({"rows":[], "has_next":true, "next_cursor":"same"}),
                    ),
                    _ if path.contains("/v1/serial/") => (
                        200,
                        json!({"rows":[{"id":"01", "serial_hex":"abc"}], "has_next":false, "next_cursor":""}),
                    ),
                    "wrong-serial" => (
                        200,
                        json!({"serial_hex":"ABD", "subject_cn":"unrelated.example", "san_dns":[]}),
                    ),
                    _ => (503, json!({"error":"details unavailable"})),
                }
            });
            let result = resolver.names("ABC");
            stop.send(()).unwrap();
            worker.join().unwrap();
            assert_eq!(
                result.unwrap(),
                vec!["alias.example", "fallback.example"],
                "{scenario}"
            );
        }
    }

    #[test]
    fn reports_both_provider_failures_but_accepts_successful_empty_fallback() {
        for fallback_succeeds in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let cache_dir = temp.path().join("resolver.cache");
            let (mut resolver, stop, worker) = local_resolver(move |path, _| {
                if fallback_succeeds && path.starts_with("/fallback?") {
                    (200, json!([]))
                } else {
                    (503, json!({"error":"unavailable"}))
                }
            });
            resolver.cache_dir = Some(cache_dir.clone());
            let result = resolver.names("ABC");
            stop.send(()).unwrap();
            worker.join().unwrap();
            assert!(
                !cache_dir.exists(),
                "empty results and errors must not persist"
            );
            if fallback_succeeds {
                assert!(result.unwrap().is_empty());
                assert!(resolver.names("000ABC").unwrap().is_empty());
            } else {
                let message = format!("{:#}", result.unwrap_err());
                assert!(message.contains("ctlogs.dev") && message.contains("crt.sh"));
            }
        }
    }

    #[test]
    fn filters_serials_and_collects_sorted_unique_names() {
        let body = serde_json::to_vec(&json!([
            {
                "id": 1,
                "serial_number": "000aBc",
                "name_value": "z.example\na.example\r\n\n a.example ",
                "common_name": "z.example"
            },
            {
                "id": 2,
                "serial_number": "ABC",
                "name_value": null,
                "common_name": "Example Signing CA"
            },
            {
                "id": 3,
                "serial_number": "ABD",
                "name_value": "unrelated.example",
                "common_name": "unrelated.example"
            }
        ]))
        .unwrap();
        assert_eq!(
            names_from_json(&body, "00abc").unwrap(),
            vec!["Example Signing CA", "a.example", "z.example"]
        );
    }

    #[test]
    fn empty_results_are_successful() {
        assert!(names_from_json(b"[]", "AB").unwrap().is_empty());
        let body = serde_json::to_vec(&json!([
            {"id": 1, "serial_number": "AC", "name_value": "other.example"},
            {"id": 2, "serial_number": "AB", "name_value": null, "common_name": "\n "}
        ]))
        .unwrap();
        assert!(names_from_json(&body, "AB").unwrap().is_empty());
    }

    #[test]
    fn malformed_data_is_not_an_empty_result() {
        for body in [
            "not JSON",
            "null",
            "{}",
            r#"[{"id":1,"name_value":"example.test"}]"#,
            r#"[{"id":1,"serial_number":"AB","name_value":42}]"#,
            r#"[{"id":1,"serial_number":"not hex"}]"#,
            r#"[{"serial_number":"AB"}]"#,
        ] {
            assert!(names_from_json(body.as_bytes(), "AB").is_err(), "{body}");
        }
    }

    #[test]
    fn serial_normalization_is_hexadecimal_and_zero_safe() {
        assert_eq!(normalize_serial("000aB").unwrap(), "AB");
        assert_eq!(normalize_serial("0000").unwrap(), "0");
        for invalid in ["", "0xAB", " AB", "AB&output=html", "GG"] {
            assert!(normalize_serial(invalid).is_err());
        }
    }
}
