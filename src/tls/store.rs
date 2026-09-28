//! The on-disk certificate store: an owner-only directory holding generated keys, issued
//! certificates and ACME account credentials.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_FILE_SIZE: u64 = 1024 * 1024;

/// A validated, owner-only certificate directory.
#[derive(Clone, Debug)]
pub(crate) struct Store {
    dir: PathBuf,
}

impl Store {
    /// Creates `dir` (`0700` on Unix) if missing, then refuses it unless it is a real
    /// directory, owned by this user, with no group or other access.
    pub(crate) fn open(dir: &Path) -> std::io::Result<Self> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            let _ = builder.mode(0o700);
        }
        builder.create(dir)?;
        validate_directory(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Reads `name`, or `None` if it does not exist.
    pub(crate) fn read(&self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.dir.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} is not a regular file or exceeds 1 MiB", path.display()),
            ));
        }
        fs::read(path).map(Some)
    }

    /// Atomically replaces `name` with `contents`, owner-only from the moment it exists.
    pub(crate) fn write(&self, name: &str, contents: &[u8]) -> std::io::Result<()> {
        write_private_file(&self.dir.join(name), contents)
    }
}

/// Atomically replaces `path` with `contents`, owner-only (`0600` on Unix) from the moment
/// the temporary file is created — no window where a key or credential is readable by others,
/// and a symlink at `path` is replaced rather than followed.
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private file has no parent",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "private file has no name")
    })?;

    for _ in 0..16 {
        let suffix = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            suffix
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = options.mode(0o600);
        }

        let mut file = match options.open(&temp_path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let result = (|| {
            file.write_all(contents)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        return result;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a private temporary file",
    ))
}

fn validate_directory(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "certificate store must be a real directory, not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "certificate store must not grant group or other access",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if metadata.uid() != fs::metadata("/proc/self")?.uid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "certificate store is not owned by the current process user",
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::{Store, write_private_file};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[test]
    fn private_file_replaces_links_atomically_with_owner_only_permissions() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let target = dir.path().join("target");
        let secret = dir.path().join("secret");
        std::fs::write(&target, b"untouched").expect("write target");
        std::os::unix::fs::symlink(&target, &secret).expect("create symlink");

        let contents: [u8; 32] = rand::random();
        write_private_file(&secret, &contents).expect("write private file");

        assert_eq!(std::fs::read(&target).expect("read target"), b"untouched");
        assert_eq!(std::fs::read(&secret).expect("read secret"), contents);
        let metadata = std::fs::symlink_metadata(&secret).expect("inspect private file");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn the_store_refuses_non_files_and_loose_permissions() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let store = dir.path().join("certs");
        let opened = Store::open(&store).expect("fresh store");
        assert!(
            opened
                .read("missing")
                .expect("absent is not an error")
                .is_none()
        );
        std::fs::create_dir(store.join("not-a-file")).expect("mkdir");
        assert!(opened.read("not-a-file").is_err());

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&store, &link).expect("create symlink");
        assert!(Store::open(&link).is_err(), "a symlinked store is refused");

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o750))
            .expect("loosen permissions");
        assert!(Store::open(&store).is_err());
    }
}
