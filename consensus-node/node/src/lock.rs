use std::fs::{
    File,
    OpenOptions,
};
use std::path::Path;

use anyhow::{
    Context,
    Result,
    bail,
};
use fs2::FileExt;

pub struct DirLock {
    _file: File,
}

pub fn acquire_data_dir_lock(data_dir: &Path) -> Result<DirLock> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    let lock_path = data_dir.join(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("opening lock file {}", lock_path.display()))?;
    if file.try_lock_exclusive().is_err() {
        bail!(
            "data dir {} is already locked by another jkaind process (pid holding {})",
            data_dir.display(),
            lock_path.display()
        );
    }
    Ok(DirLock { _file: file })
}
