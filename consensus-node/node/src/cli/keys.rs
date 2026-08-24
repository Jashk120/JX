//! Secret-file constants and the hardened secret writer shared by the
//! provisioning subcommands (`init`, `member init`).

use std::path::Path;

use anyhow::{
    Context,
    Result,
};

/// Genesis secret length: consensus signing seed ‖ TLS seed (two independent
/// keys derived from one 64-byte file).
pub(crate) const SECRET_LEN: usize = 64;

/// Dynamic-member secret length: a single 32-byte seed used for BOTH
/// consensus signing and TLS identity.
pub(crate) const SINGLE_SEED_LEN: usize = 32;

/// Writes `bytes` to `path` atomically with `0600` permissions, removing any
/// pre-existing file first (callers refuse overwrites before reaching here).
pub(crate) fn write_secret_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::{
            OpenOptionsExt,
            PermissionsExt,
        };
        if path.exists() {
            std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        let write_res: Result<()> = (|| {
            file.write_all(bytes).with_context(|| format!("writing {}", path.display()))?;
            file.sync_all().with_context(|| format!("sync {}", path.display()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", path.display()))
        {
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}
