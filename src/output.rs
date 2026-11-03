use crate::Entry;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, ColumnConstraint, Table, Width};
use std::io::{self, Write};

/// Render one fixed-width row at a time: no buffering of evidence during lookups.
pub struct StreamTable {
    widths: [u16; 4],
    color: bool,
    footer: Option<String>,
}

impl StreamTable {
    pub fn new(terminal: bool) -> Self {
        let width = if terminal {
            console::Term::stdout().size().1
        } else {
            120
        }
        .clamp(60, 160);
        // Widths include two spaces of cell padding; five border characters.
        let remaining = width - 5 - 21;
        let endpoint = remaining / 3;
        let serial = (remaining / 4).min(26);
        Self {
            widths: [21, endpoint, serial, remaining - endpoint - serial],
            color: terminal && std::env::var_os("NO_COLOR").is_none(),
            footer: None,
        }
    }

    pub fn write_entry(&mut self, output: &mut dyn Write, entry: &Entry) -> io::Result<()> {
        let endpoint = reqwest::Url::parse(&entry.metadata.url)
            .ok()
            .and_then(|url| {
                let host = url.host_str()?;
                let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
                // OCSP paths often contain huge encoded requests, not useful locations.
                let path = if entry.ocsp.is_empty() {
                    url.path()
                } else {
                    ""
                };
                Some(format!("{host}{port}{path}"))
            })
            .unwrap_or_else(|| entry.metadata.url.clone());
        let serial = match entry.ocsp.first() {
            None => "—".to_owned(),
            Some(id) => {
                let mut value = id.serial.clone();
                if entry.ocsp.len() > 1 {
                    value.push_str(&format!("\n+{} more", entry.ocsp.len() - 1));
                }
                value
            }
        };
        let mut names = match &entry.candidate_names {
            None => "not requested".to_owned(),
            Some(_) if entry.ocsp.is_empty() => "—".to_owned(),
            Some(names) if names.is_empty() => "no names".to_owned(),
            Some(names) => {
                let mut value = names.iter().take(2).cloned().collect::<Vec<_>>().join("\n");
                if names.len() > 2 {
                    value.push_str(&format!("\n+{} more", names.len() - 2));
                }
                value
            }
        };
        if !entry.warnings.is_empty() {
            names.push_str(&format!("\n! {} warning(s)", entry.warnings.len()));
        }
        let timestamp = entry
            .metadata
            .last_download_time
            .chars()
            .take(19)
            .collect::<String>()
            .replace('T', " ");
        let values = [timestamp, endpoint, serial, names];
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_width(self.widths.iter().sum::<u16>() + 5);
        if self.color {
            table.enforce_styling();
        } else {
            table.force_no_tty();
        }
        table.set_header(
            ["Downloaded (UTC)", "Endpoint", "Serial", "Names*"]
                .map(|s| Cell::new(s).fg(Color::Cyan).add_attribute(Attribute::Bold)),
        );
        table.add_row(values.iter().enumerate().map(|(index, value)| {
            let text = value
                .lines()
                .map(|line| {
                    let safe: String = line.chars().filter(|c| !c.is_control()).collect();
                    console::truncate_str(&safe, (self.widths[index] - 2) as usize, "…")
                        .into_owned()
                })
                .collect::<Vec<_>>()
                .join("\n");
            let color = match index {
                1 => Color::Cyan,
                2 => Color::Yellow,
                3 if !entry.warnings.is_empty() => Color::Yellow,
                3 if entry
                    .candidate_names
                    .as_ref()
                    .is_some_and(|n| !n.is_empty()) =>
                {
                    Color::Green
                }
                _ => Color::White,
            };
            Cell::new(text).fg(color)
        }));
        for (column, width) in table.column_iter_mut().zip(self.widths) {
            column.set_constraint(ColumnConstraint::Absolute(Width::Fixed(width)));
        }
        let rendered = table.to_string();
        let lines: Vec<_> = rendered.lines().collect();
        let first = self.footer.is_none();
        if first {
            writeln!(output, "CRYPTNET / cache investigation leads")?;
            writeln!(output, "* Unverified names, not connection history.")?;
            writeln!(output, "… = shortened; --json for full evidence.")?;
        } else {
            writeln!(output, "{}", lines[2])?;
        }
        for line in &lines[if first { 0 } else { 3 }..lines.len() - 1] {
            writeln!(output, "{line}")?;
        }
        self.footer = lines.last().map(|s| (*s).to_owned());
        Ok(())
    }

    pub fn finish(&self, output: &mut dyn Write) -> io::Result<()> {
        match &self.footer {
            Some(footer) => writeln!(output, "{footer}"),
            None => writeln!(output, "No matching cache entries."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_names_and_ids_without_terminal_control_sequences() {
        let id = crate::ocsp::CertificateId {
            serial: "624D0AB311558780B7D5213B9631831".into(),
            hash_algorithm_oid: "1.3.14.3.2.26".into(),
            issuer_name_hash: "not a display field".into(),
            issuer_key_hash: "not a display field".into(),
        };
        let entry = Entry {
            metadata_path: "evidence/MetaData/001".into(),
            metadata: crate::cache::Metadata {
                url: "http://ocsp.example.test/encoded-request".into(),
                last_download_time: "2026-11-03T12:34:56.1234567Z".into(),
                last_modified_header: "2026-11-01T00:00:00Z".into(),
                content_size: 512,
                etag: String::new(),
            },
            ocsp: vec![id.clone(), id],
            candidate_names: Some(vec![
                "*.example.test".into(),
                "example.test\x1b[2J".into(),
                "hidden.example.test".into(),
            ]),
            warnings: vec![],
        };
        let mut table = StreamTable::new(false);
        let mut bytes = Vec::new();
        table.write_entry(&mut bytes, &entry).unwrap();
        table.finish(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("*.example.test"));
        assert!(text.contains("+1 more"));
        assert!(text.contains("2026-11-03 12:34:56"));
        assert!(!text.contains("hidden.example.test"));
        assert!(!text.contains("encoded-request"));
        assert!(!text.contains("not a display field"));
        assert!(!text.contains('\x1b'));
    }
}
