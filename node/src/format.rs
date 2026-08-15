//! Data-directory format version gate.
//!
//! `data/FORMAT_VERSION` stamps the on-disk format a node writes. Breaking
//! changes bump [`CURRENT_FORMAT`]; on startup the node refuses to run
//! against an incompatible data directory (loudly telling the operator to
//! wipe `data/`) rather than silently producing state that no peer can
//! verify.

use std::fs;
use std::path::Path;

use anyhow::{
    Context,
    Result,
    bail,
};

/// The on-disk format version this binary writes. Bump on every breaking
/// change (e.g. the checkpoint `state_hash` becoming a Merkle root, or the
/// per-round `.snap` files being replaced by the Fjall state database).
pub const CURRENT_FORMAT: u32 = 3;

/// The filename of the version stamp inside the data directory.
const FORMAT_VERSION_FILE: &str = "FORMAT_VERSION";

/// Verifies (or initializes) the data directory's format version stamp, to be
/// called before any Fjall partition or checkpoint store is opened.
pub fn check_or_init_data_dir(data_dir: &Path) -> Result<()> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    let version_file = data_dir.join(FORMAT_VERSION_FILE);
    if version_file.exists() {
        let raw = fs::read_to_string(&version_file)
            .with_context(|| format!("reading {}", version_file.display()))?;
        let version: u32 = raw
            .trim()
            .parse()
            .with_context(|| format!("parsing {} (expected an integer)", version_file.display()))?;
        if version != CURRENT_FORMAT {
            bail!(
                "data/ format version {version} is incompatible with this binary \
                 (expects {CURRENT_FORMAT}).\n\
                 Wipe data/ and re-genesis to continue."
            );
        }
    } else {
        fs::write(&version_file, CURRENT_FORMAT.to_string())
            .with_context(|| format!("writing {}", version_file.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn fresh_dir_is_stamped_with_the_current_format() {
        let dir = tempdir().expect("temp dir");
        check_or_init_data_dir(dir.path()).expect("init");
        let stamp = fs::read_to_string(dir.path().join(FORMAT_VERSION_FILE)).expect("stamp");
        assert_eq!(stamp.trim(), CURRENT_FORMAT.to_string());
    }

    #[test]
    fn matching_version_is_accepted() {
        let dir = tempdir().expect("temp dir");
        check_or_init_data_dir(dir.path()).expect("init");
        check_or_init_data_dir(dir.path()).expect("recheck");
    }

    #[test]
    fn mismatched_version_is_rejected() {
        let dir = tempdir().expect("temp dir");
        check_or_init_data_dir(dir.path()).expect("init");
        fs::write(dir.path().join(FORMAT_VERSION_FILE), (CURRENT_FORMAT + 1).to_string())
            .expect("overwrite");
        let err = check_or_init_data_dir(dir.path()).expect_err("mismatch fails");
        assert!(err.to_string().contains("incompatible"), "unexpected error: {err}");
    }
}
