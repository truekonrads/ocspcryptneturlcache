mod cache;
mod ocsp;
mod output;
mod resolve;

use anyhow::{bail, Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{self, BufWriter, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Parser)]
#[command(
    version,
    about = "Turn Windows CryptnetUrlCache into investigation leads, without certutil or Python."
)]
struct Args {
    /// Cache root or MetaData directory; repeat for multiple offline copies
    #[arg(short, long)]
    path: Vec<PathBuf>,
    /// Scan other user and service profiles too (elevate for protected profiles)
    #[arg(long, conflicts_with = "path")]
    all_users: bool,
    /// Resolve via ctlogs.dev, falling back to crt.sh (sends certificate serials)
    #[arg(long)]
    resolve: bool,
    /// Hide the resolution progress bar (also hidden when stderr is redirected)
    #[arg(long)]
    no_progress: bool,
    /// Only emit entries containing OCSP certificate IDs
    #[arg(long)]
    ocsp_only: bool,
    /// Emit full JSON Lines instead of the compact table
    #[arg(long)]
    json: bool,
    /// Write the selected format to a new file instead of stdout (will not overwrite)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Serialize)]
struct Entry {
    metadata_path: PathBuf,
    #[serde(flatten)]
    metadata: cache::Metadata,
    ocsp: Vec<ocsp::CertificateId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        // Piping to a consumer that closes early is not a collection failure.
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
        {
            return;
        }
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn roots(args: &Args) -> Result<Vec<PathBuf>> {
    if !args.path.is_empty() {
        return Ok(args.path.clone());
    }
    let profile =
        PathBuf::from(env::var_os("USERPROFILE").context("USERPROFILE is unset; use --path")?);
    let suffix = Path::new("AppData/LocalLow/Microsoft/CryptnetUrlCache");
    let mut paths = BTreeSet::from([profile.join(suffix)]);
    if args.all_users {
        // Use this user's actual profile parent rather than assuming C:\Users.
        if let Some(parent) = profile.parent() {
            for item in fs::read_dir(parent).context("listing user profiles")? {
                let item = item?;
                if item.file_type()?.is_dir() {
                    paths.insert(item.path().join(suffix));
                }
            }
        }
        let windows = PathBuf::from(env::var_os("SystemRoot").context("SystemRoot is unset")?);
        for service in [
            "System32/config/systemprofile",
            "SysWOW64/config/systemprofile",
            "ServiceProfiles/LocalService",
            "ServiceProfiles/NetworkService",
        ] {
            paths.insert(windows.join(service).join(suffix));
        }
    }
    Ok(paths.into_iter().collect())
}

// Cache inputs are untrusted forensic evidence. Bound reads even if the source
// changes after stat, rather than allocating an attacker-controlled file size.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        bail!("file exceeds {limit} byte limit");
    }
    Ok(data)
}

fn collect(path: &Path) -> Result<Entry> {
    let metadata = cache::parse(&read_bounded(path, 1024 * 1024)?)?;
    let mut ids = ocsp::from_url(&metadata.url);
    let content = path
        .parent()
        .and_then(Path::parent)
        .context("metadata has no cache parent")?
        .join("Content")
        .join(path.file_name().context("metadata has no file name")?);
    let mut warnings = vec![];
    match read_bounded(&content, 32 * 1024 * 1024) {
        Ok(bytes) => {
            for id in ocsp::from_response(&bytes) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        Err(error) => warnings.push(format!("content unavailable: {error:#}")),
    }
    Ok(Entry {
        metadata_path: path.to_owned(),
        metadata,
        ocsp: ids,
        candidate_names: None,
        warnings,
    })
}

fn run(args: Args) -> Result<()> {
    let paths = roots(&args)?;
    let mut resolver = args.resolve.then(resolve::Resolver::new).transpose()?;
    let terminal = args.output.is_none() && io::stdout().is_terminal();
    let mut table = output::StreamTable::new(terminal);
    let mut output: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(BufWriter::new(
            File::create_new(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    let mut scanned = 0;
    let mut emitted = 0;
    let mut failed = 0;
    let mut opened = 0;
    let mut seen = BTreeSet::new();
    for root in paths {
        let dir = if root
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("metadata"))
        {
            root
        } else {
            root.join("MetaData")
        };
        let files = match fs::read_dir(&dir) {
            Ok(files) => files,
            Err(e) if e.kind() == io::ErrorKind::NotFound && args.path.is_empty() => continue,
            Err(e) => {
                eprintln!("warning: {}: {e}", dir.display());
                failed += 1;
                continue;
            }
        };
        let canonical = fs::canonicalize(&dir)?;
        if !seen.insert(canonical) {
            continue;
        }
        opened += 1;
        let mut files = files.collect::<io::Result<Vec<_>>>()?;
        files.sort_by_key(|f| f.file_name());
        let progress = if args.resolve && !args.no_progress && io::stderr().is_terminal() {
            let bar = ProgressBar::new(files.len() as u64);
            bar.set_style(ProgressStyle::with_template(
                "{spinner:.green} {prefix} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} entries (ETA {eta})\n{msg}",
            )?.progress_chars("=>-"));
            bar.set_prefix(format!("Cache {opened}"));
            bar.enable_steady_tick(Duration::from_millis(100));
            bar
        } else {
            ProgressBar::hidden()
        };
        for (index, file) in files.into_iter().enumerate() {
            progress.set_position(index as u64);
            progress.set_message("Reading cache entry");
            if !file.file_type()?.is_file() {
                continue;
            }
            scanned += 1;
            let mut entry = match collect(&file.path()) {
                Ok(entry) => entry,
                Err(e) => {
                    progress.suspend(|| eprintln!("warning: {}: {e:#}", file.path().display()));
                    failed += 1;
                    continue;
                }
            };
            if args.ocsp_only && entry.ocsp.is_empty() {
                continue;
            }
            if let Some(resolver) = &mut resolver {
                let mut names = BTreeSet::new();
                for (index, id) in entry.ocsp.iter().enumerate() {
                    progress.set_message(format!(
                        "Resolving {}/{}: {}",
                        index + 1,
                        entry.ocsp.len(),
                        id.serial
                    ));
                    match resolver.names(&id.serial) {
                        Ok(found) => names.extend(found),
                        Err(e) => {
                            entry
                                .warnings
                                .push(format!("CT lookup for {} failed: {e:#}", id.serial));
                            failed += 1;
                        }
                    }
                }
                entry.candidate_names = Some(names.into_iter().collect());
            }
            progress.suspend(|| -> Result<()> {
                if args.json {
                    serde_json::to_writer(&mut output, &entry)?;
                    writeln!(output)?;
                } else {
                    table.write_entry(&mut output, &entry)?;
                }
                output.flush()?;
                Ok(())
            })?;
            emitted += 1;
        }
        progress.finish_and_clear();
    }
    if !args.json {
        table.finish(&mut output)?;
    }
    output.flush()?;
    eprintln!("Scanned {scanned} files in {opened} cache(s); emitted {emitted} entries; {failed} failures.");
    if failed > 0 {
        bail!("collection incomplete; valid entries were retained");
    }
    if opened == 0 {
        eprintln!(
            "No cache found. Use --path for a collected cache, or --all-users for other profiles."
        );
    }
    Ok(())
}
