mod cache;
mod ocsp;
mod output;
#[cfg(windows)]
mod profiles;
mod resolve;

use anyhow::{bail, Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, IsTerminal, Read, Write},
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
    /// Read previously collected JSON Lines (no access to original cache required)
    #[arg(long, conflicts_with_all = ["path", "all_users"])]
    input: Option<PathBuf>,
    /// Scan other user and service profiles too (elevate for protected profiles)
    #[arg(long, conflicts_with = "path")]
    all_users: bool,
    /// Resolve via ctlogs.dev, falling back to crt.sh (sends serials; optional CTLOG_API_KEY env var)
    #[arg(long)]
    resolve: bool,
    /// Directory for persistent resolved-serial cache (defaults to per-user cache)
    #[arg(long, requires = "resolve", conflicts_with = "no_resolver_cache")]
    resolver_cache: Option<PathBuf>,
    /// Bypass persistent cache reads/writes; query CT again (in-memory deduplication remains)
    #[arg(long, requires = "resolve")]
    no_resolver_cache: bool,
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

#[derive(Deserialize, Serialize)]
struct Entry {
    metadata_path: PathBuf,
    #[serde(flatten)]
    metadata: cache::Metadata,
    ocsp: Vec<ocsp::CertificateId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    if args.all_users {
        #[cfg(windows)]
        {
            return profiles::all_users();
        }
        #[cfg(not(windows))]
        bail!("--all-users requires Windows; use --path for collected profiles");
    }
    let profile =
        PathBuf::from(env::var_os("USERPROFILE").context("USERPROFILE is unset; use --path")?);
    Ok(vec![
        profile.join("AppData/LocalLow/Microsoft/CryptnetUrlCache")
    ])
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
    let mut warnings = vec![];
    let mut ids = match ocsp::from_url(&metadata.url) {
        Ok(ids) => ids,
        Err(error) => {
            warnings.push(error.to_string());
            vec![]
        }
    };
    let content = path
        .parent()
        .and_then(Path::parent)
        .context("metadata has no cache parent")?
        .join("Content")
        .join(path.file_name().context("metadata has no file name")?);
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
    let paths = if args.input.is_some() {
        vec![]
    } else {
        roots(&args)?
    };
    // Open evidence before creating output, including when both paths are identical.
    let input = args
        .input
        .as_ref()
        .map(File::open)
        .transpose()
        .context("opening JSON Lines input")?;
    let mut resolver = if args.resolve {
        let cache_dir = if args.no_resolver_cache {
            None
        } else {
            let dir = args
                .resolver_cache
                .clone()
                .or_else(resolve::default_cache_dir);
            match &dir {
                Some(dir) => eprintln!("Resolver cache: {}", dir.display()),
                None => eprintln!(
                    "warning: no per-user cache directory found; resolver disk cache disabled"
                ),
            }
            dir
        };
        Some(resolve::Resolver::new(cache_dir)?)
    } else {
        None
    };
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
    if let Some(input) = input {
        let mut reader = BufReader::new(input);
        let progress = ProgressBar::hidden();
        loop {
            // Bound each untrusted JSON record, not the entire evidence file.
            let mut line = Vec::new();
            let size = reader
                .by_ref()
                .take(8 * 1024 * 1024 + 1)
                .read_until(b'\n', &mut line)?;
            if size == 0 {
                break;
            }
            scanned += 1;
            if size > 8 * 1024 * 1024 {
                bail!("JSON record {scanned} exceeds 8 MiB limit");
            }
            let entry = match serde_json::from_slice::<Entry>(&line) {
                Ok(entry) => entry,
                Err(error) => {
                    eprintln!("warning: JSON record {scanned}: {error}");
                    failed += 1;
                    continue;
                }
            };
            if args.ocsp_only && entry.ocsp.is_empty() {
                continue;
            }
            failed += emit(
                &args,
                entry,
                &mut resolver,
                &progress,
                &mut table,
                &mut output,
            )?;
            emitted += 1;
        }
    }
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
            let entry = match collect(&file.path()) {
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
            failed += emit(
                &args,
                entry,
                &mut resolver,
                &progress,
                &mut table,
                &mut output,
            )?;
            emitted += 1;
        }
        progress.finish_and_clear();
    }
    if !args.json {
        table.finish(&mut output)?;
    }
    output.flush()?;
    if args.input.is_some() {
        eprintln!("Read {scanned} JSON records; emitted {emitted} entries; {failed} failures.");
    } else {
        eprintln!("Scanned {scanned} files in {opened} cache(s); emitted {emitted} entries; {failed} failures.");
    }
    if failed > 0 {
        bail!("collection incomplete; valid entries were retained");
    }
    if opened == 0 && args.input.is_none() {
        eprintln!(
            "No cache found. Use --path for a collected cache, or --all-users for other profiles."
        );
    }
    Ok(())
}

fn emit(
    args: &Args,
    mut entry: Entry,
    resolver: &mut Option<resolve::Resolver>,
    progress: &ProgressBar,
    table: &mut output::StreamTable,
    output: &mut dyn Write,
) -> Result<usize> {
    let mut failed = 0;
    if let Some(resolver) = resolver {
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
            serde_json::to_writer(&mut *output, &entry)?;
            writeln!(output)?;
        } else {
            table.write_entry(output, &entry)?;
        }
        output.flush()?;
        Ok(())
    })?;
    Ok(failed)
}
