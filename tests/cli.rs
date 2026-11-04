use std::{fs, path::Path, process::Command};

fn metadata(url: &str) -> Vec<u8> {
    let url: Vec<u8> = url
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut bytes = vec![0; 116];
    bytes[12..16].copy_from_slice(&(url.len() as u32).to_le_bytes());
    bytes.extend(url);
    bytes
}

fn command(path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cryptnet-dump"));
    command.arg("--path").arg(path).arg("--json");
    command
}

#[test]
fn default_table_is_compact_plain_when_redirected_and_preserves_json_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("MetaData");
    fs::create_dir(&dir).unwrap();
    let request = "MFMwUTBPME0wSzAJBgUrDgMCGgUABBRI2smg%2ByvTLU%2Fw3mjS9We3NfmzxAQUFC6zF7dYVsuuUAlA5h%2BvnYsUwsYCEgNJysJh3kjaVPgcXCDHUNNWsA%3D%3D";
    let url = format!("http://ocsp.example.test/{request}");
    fs::write(dir.join("1-ocsp"), metadata(&url)).unwrap();
    fs::write(dir.join("2-crl"), metadata("https://example.test/ca.crl")).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_cryptnet-dump"))
        .arg("--path")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(result.status.success());
    let table = String::from_utf8(result.stdout).unwrap();
    assert!(table.contains("Downloaded (UTC)"));
    assert!(table.contains("ocsp.example.test"));
    assert!(table.contains("example.test/ca.crl"));
    assert!(table.contains("349CAC261DE48DA54F81…"));
    assert!(table.contains('…'));
    assert!(table.contains("! 1 warning(s)"));
    assert!(!table.contains(request));
    assert!(!table.contains('\x1b'));
    assert_eq!(table.matches("Downloaded (UTC)").count(), 1);
    assert_eq!(table.matches("1601-01-01 00:00:00").count(), 2);
    assert!(table.lines().all(|line| line.chars().count() <= 120));
    let result = command(&dir).output().unwrap();
    let row: serde_json::Value =
        serde_json::from_slice(result.stdout.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(row["url"], url);
    assert_eq!(
        row["ocsp"][0]["serial"],
        "349CAC261DE48DA54F81C5C20C750D356B0"
    );
}

#[test]
fn dumps_offline_evidence_and_retains_valid_entries_on_partial_failure() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("MetaData");
    fs::create_dir(&dir).unwrap();
    // LDAP entries are valid cache evidence too, not only HTTP OCSP URLs.
    fs::write(
        dir.join("valid"),
        metadata("ldap://example.test/certificate"),
    )
    .unwrap();
    let result = command(temp.path())
        .arg("--path")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout).unwrap();
    assert_eq!(
        text.lines().count(),
        1,
        "duplicate roots must not duplicate evidence"
    );
    let row: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(row["url"], "ldap://example.test/certificate");
    assert_eq!(row["last_download_time"], "1601-01-01T00:00:00Z");
    assert_eq!(row["ocsp"], serde_json::json!([]));
    assert!(row.get("candidate_names").is_none());
    assert!(row["warnings"][0]
        .as_str()
        .unwrap()
        .contains("content unavailable"));

    fs::write(dir.join("broken"), b"truncated").unwrap();
    let result = command(&dir).output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    let text = String::from_utf8(result.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["url"],
        row["url"]
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("truncated metadata header"));
}

#[test]
fn filters_ocsp_and_never_overwrites_an_existing_output_file() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("MetaData");
    fs::create_dir(&dir).unwrap();
    let request = "MFMwUTBPME0wSzAJBgUrDgMCGgUABBRI2smg%2ByvTLU%2Fw3mjS9We3NfmzxAQUFC6zF7dYVsuuUAlA5h%2BvnYsUwsYCEgNJysJh3kjaVPgcXCDHUNNWsA%3D%3D";
    fs::write(
        dir.join("ocsp"),
        metadata(&format!("http://example.test/{request}")),
    )
    .unwrap();
    fs::write(dir.join("crl"), metadata("http://example.test/ca.crl")).unwrap();
    let output = temp.path().join("dump.jsonl");
    let result = command(&dir)
        .arg("--ocsp-only")
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    let text = fs::read_to_string(&output).unwrap();
    assert_eq!(text.lines().count(), 1);
    let row: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        row["ocsp"][0]["serial"],
        "349CAC261DE48DA54F81C5C20C750D356B0"
    );
    let result = command(&dir).arg("--output").arg(&output).output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read_to_string(output).unwrap(), text);
}

#[test]
fn reopens_collected_json_without_source_cache_and_preserves_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("MetaData");
    fs::create_dir(&dir).unwrap();
    let request = "MFMwUTBPME0wSzAJBgUrDgMCGgUABBRI2smg%2ByvTLU%2Fw3mjS9We3NfmzxAQUFC6zF7dYVsuuUAlA5h%2BvnYsUwsYCEgNJysJh3kjaVPgcXCDHUNNWsA%3D%3D";
    fs::write(
        dir.join("ocsp"),
        metadata(&format!("http://example.test/{request}")),
    )
    .unwrap();
    fs::write(dir.join("crl"), metadata("http://example.test/ca.crl")).unwrap();
    let collected = command(&dir).output().unwrap();
    assert!(collected.status.success());
    let input = temp.path().join("evidence.jsonl");
    fs::write(&input, &collected.stdout).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    let reopen = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cryptnet-dump"));
        cmd.arg("--input").arg(&input).env_remove("USERPROFILE");
        cmd
    };
    let result = reopen().arg("--json").output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, collected.stdout);
    let result = reopen().arg("--ocsp-only").output().unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("349CAC261DE48DA54F81"));
    assert!(!text.contains("ca.crl"));
    let result = reopen().arg("--output").arg(&input).output().unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(&input).unwrap(), collected.stdout);
    for option in ["--path", "--all-users"] {
        let mut cmd = reopen();
        cmd.arg(option);
        if option == "--path" {
            cmd.arg(&dir);
        }
        assert_eq!(cmd.output().unwrap().status.code(), Some(2));
    }
    // A bad record must not hide later valid evidence.
    let mut damaged = b"{broken}\n".to_vec();
    damaged.extend_from_slice(&collected.stdout);
    fs::write(&input, damaged).unwrap();
    let result = reopen().arg("--json").output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stdout, collected.stdout);
    assert!(String::from_utf8_lossy(&result.stderr).contains("JSON record 1"));

    // Saved enrichment can be viewed entirely offline.
    let mut row = String::from_utf8_lossy(&collected.stdout)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|row| !row["ocsp"].as_array().unwrap().is_empty())
        .unwrap();
    row["candidate_names"] = serde_json::json!(["saved.example"]);
    row.as_object_mut().unwrap().remove("warnings");
    fs::write(&input, row.to_string()).unwrap();
    let result = reopen().output().unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("saved.example"));
}

#[test]
fn cli_reuses_disk_cache_without_network_and_can_bypass_it() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("evidence.jsonl");
    fs::write(
        &input,
        serde_json::json!({
            "metadata_path":"missing/source", "url":"http://example.test/ocsp",
            "last_download_time":"2026-11-03T00:00:00Z",
            "last_modified_header":"1601-01-01T00:00:00Z", "content_size":0, "etag":"",
            "ocsp":[{"serial":"000aBc", "hash_algorithm_oid":"1.3.14.3.2.26",
                     "issuer_name_hash":"", "issuer_key_hash":""}]
        })
        .to_string(),
    )
    .unwrap();
    let default_dir = temp.path().join("ocspcryptneturlcache/resolver.cache");
    for custom in [false, true] {
        let dir = if custom {
            temp.path().join("custom-cache")
        } else {
            default_dir.clone()
        };
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("ABC.json"), r#"["cached.example"]"#).unwrap();
        let run = |bypass: bool| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_cryptnet-dump"));
            cmd.arg("--input")
                .arg(&input)
                .arg("--resolve")
                .arg("--json")
                .env("LOCALAPPDATA", temp.path())
                .env("XDG_CACHE_HOME", temp.path())
                .env_remove("CTLOG_API_KEY")
                .env("HTTPS_PROXY", "http://127.0.0.1:9")
                .env("NO_PROXY", "");
            if bypass {
                cmd.arg("--no-resolver-cache");
            } else if custom {
                cmd.arg("--resolver-cache").arg(&dir);
            }
            cmd.output().unwrap()
        };
        let result = run(false);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let row: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            row["candidate_names"],
            serde_json::json!(["cached.example"])
        );
        let result = run(true);
        assert_eq!(
            result.status.code(),
            Some(1),
            "bypassed cache must attempt a network lookup"
        );
        let row: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(row["candidate_names"], serde_json::json!([]));
        assert!(row["warnings"][0].as_str().unwrap().contains("CT lookup"));
        assert_eq!(
            fs::read_to_string(dir.join("ABC.json")).unwrap(),
            r#"["cached.example"]"#
        );
    }
}

#[test]
fn flushes_stdout_and_files_before_a_later_lookup_completes() {
    use std::{
        io::{BufRead, BufReader},
        net::TcpListener,
        process::Stdio,
        sync::mpsc,
        thread,
        time::Duration,
    };

    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("MetaData");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("1-crl"), metadata("http://example.test/ca.crl")).unwrap();
    let request = "MFMwUTBPME0wSzAJBgUrDgMCGgUABBRI2smg%2ByvTLU%2Fw3mjS9We3NfmzxAQUFC6zF7dYVsuuUAlA5h%2BvnYsUwsYCEgNJysJh3kjaVPgcXCDHUNNWsA%3D%3D";
    fs::write(
        dir.join("2-ocsp"),
        metadata(&format!("http://example.test/{request}")),
    )
    .unwrap();
    let collected = command(&dir).output().unwrap();
    assert!(collected.status.success());
    let input = temp.path().join("evidence.jsonl");
    fs::write(&input, collected.stdout).unwrap();
    for (json, file_output, from_json) in [
        (true, false, false),
        (true, true, false),
        (false, false, false),
        (false, true, false),
        (true, false, true),
    ] {
        // Hold the second entry's HTTPS CONNECT locally, without Internet access.
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cryptnet-dump"));
        if from_json {
            cmd.arg("--input").arg(&input).env_remove("USERPROFILE");
        } else {
            cmd.arg("--path").arg(&dir);
        }
        if json {
            cmd.arg("--json");
        }
        cmd.arg("--resolve")
            .arg("--no-resolver-cache")
            .env(
                "HTTPS_PROXY",
                format!("http://{}", proxy.local_addr().unwrap()),
            )
            .env("NO_PROXY", "")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = temp.path().join(format!("stream-{json}.txt"));
        if file_output {
            cmd.arg("--output").arg(&output).arg("--no-progress");
        }
        let mut child = cmd.spawn().unwrap();
        let (connected_tx, connected_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = connected_tx.send(proxy.accept());
        });
        let connected = connected_rx.recv_timeout(Duration::from_secs(5));
        let (line_tx, line_rx) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        thread::spawn(move || {
            let mut text = String::new();
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                text.push_str(&line);
                text.push('\n');
                if text.contains("example.test/ca.crl") {
                    break;
                }
            }
            let _ = line_tx.send(text);
        });
        let text = if file_output {
            fs::read_to_string(&output).unwrap_or_default()
        } else {
            line_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default()
        };
        let still_running = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let result = child.wait_with_output().unwrap();
        assert!(connected.is_ok(), "lookup did not reach local proxy");
        assert!(still_running, "lookup must still be pending");
        if json {
            let row: serde_json::Value =
                serde_json::from_str(&text).expect("first entry must already be flushed");
            assert_eq!(row["url"], "http://example.test/ca.crl");
        } else {
            assert!(
                text.contains("example.test/ca.crl"),
                "table row must already be flushed"
            );
        }
        assert!(
            !result.stderr.contains(&b'\x1b'),
            "redirected stderr must have no progress escapes"
        );
    }
}
