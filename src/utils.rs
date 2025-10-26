use std::fs;
use std::path::{Path, PathBuf};

use semver::Version;

/// Parse a crate filename in the format "{name}-{version}.crate" into its components.
///
/// This function follows cargo's filename format: `format!("{}-{}.crate", id.name(), id.version())`
/// (see cargo/src/cargo/core/package_id.rs)
///
/// It uses the semver crate to validate versions, ensuring we correctly parse:
/// - Crate names ending with digits (e.g., "sec1-0.7.3.crate")
/// - Crate names with dashes and digits (e.g., "foo-1-2.0.crate")
/// - Versions with dashes and plus signs (e.g., "curl-sys-0.4.80+curl-8.12.1.crate")
///
/// The algorithm tries each dash position and validates if what follows is a valid semver version.
pub fn parse_crate_filename(filename: &str) -> Option<(&str, &str)> {
    let stripped = filename.strip_suffix(".crate")?;

    // Try each dash position, looking for a valid semver version after it
    for (idx, _) in stripped.match_indices('-') {
        let potential_name = &stripped[..idx];
        let potential_version = &stripped[idx + 1..];

        // Validate that what follows the dash is a valid semver version
        // This is the canonical way to determine the split point
        if Version::parse(potential_version).is_ok() && !potential_name.is_empty() {
            return Some((potential_name, potential_version));
        }
    }

    None
}

/// Get the local filesystem path for a crate's index file based on cargo's naming convention.
///
/// Cargo uses specific path patterns based on crate name length:
/// - 1 char: index/1/{name}
/// - 2 char: index/2/{name}
/// - 3 char: index/3/{first-char}/{name}
/// - 4+ char: index/{first-2-chars}/{chars-3-4}/{name}
pub fn get_index_path(registry_path: &Path, crate_name: &str) -> PathBuf {
    match crate_name.len() {
        1 => registry_path.join("index").join("1").join(crate_name),
        2 => registry_path.join("index").join("2").join(crate_name),
        3 => registry_path
            .join("index")
            .join("3")
            .join(&crate_name[..1])
            .join(crate_name),
        _ => registry_path
            .join("index")
            .join(&crate_name[..2])
            .join(&crate_name[2..4])
            .join(crate_name),
    }
}

/// Get the crates.io URL for a crate's index file.
pub fn get_crates_io_index_url(crate_name: &str) -> String {
    match crate_name.len() {
        1 => format!("https://index.crates.io/1/{}", crate_name),
        2 => format!("https://index.crates.io/2/{}", crate_name),
        3 => format!(
            "https://index.crates.io/3/{}/{}",
            &crate_name[..1],
            crate_name
        ),
        _ => format!(
            "https://index.crates.io/{}/{}/{}",
            &crate_name[..2],
            &crate_name[2..4],
            crate_name
        ),
    }
}

/// Remove all prior versions of a crate from the registry, keeping only the specified version.
///
/// This is used in "clean" mode to ensure only one version of each crate is stored locally.
pub fn remove_prior_versions(registry_path: &Path, crate_name: &str, keep_version: &str) {
    if let Ok(entries) = fs::read_dir(registry_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if file_name_str.ends_with(".crate")
                && let Some(stripped) = file_name_str.strip_suffix(".crate")
                && let Some(dash_pos) = stripped.rfind('-')
            {
                let file_crate_name = &stripped[..dash_pos];
                let file_version = &stripped[dash_pos + 1..];

                if file_crate_name == crate_name && file_version != keep_version {
                    if let Err(e) = fs::remove_file(entry.path()) {
                        tracing::warn!("Failed to remove old crate file {}: {}", file_name_str, e);
                    } else {
                        tracing::info!(
                            "Removed old crate file: {} (keeping {})",
                            file_name_str,
                            keep_version
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_crate_filename_simple() {
        assert_eq!(
            parse_crate_filename("serde-1.0.130.crate"),
            Some(("serde", "1.0.130"))
        );
    }

    #[test]
    fn test_parse_crate_filename_with_dash_in_version() {
        assert_eq!(
            parse_crate_filename("curl-sys-0.4.80+curl-8.12.1.crate"),
            Some(("curl-sys", "0.4.80+curl-8.12.1"))
        );
    }

    #[test]
    fn test_parse_crate_filename_name_ending_with_digit() {
        assert_eq!(
            parse_crate_filename("sec1-0.7.3.crate"),
            Some(("sec1", "0.7.3"))
        );
    }

    #[test]
    fn test_parse_crate_filename_invalid_no_crate_suffix() {
        assert_eq!(parse_crate_filename("serde-1.0.130"), None);
    }

    #[test]
    fn test_parse_crate_filename_invalid_no_dash() {
        assert_eq!(parse_crate_filename("serde.crate"), None);
    }

    #[test]
    fn test_parse_crate_filename_invalid_no_version() {
        assert_eq!(parse_crate_filename("serde-.crate"), None);
    }

    #[test]
    fn test_parse_crate_filename_invalid_no_name() {
        assert_eq!(parse_crate_filename("-1.0.130.crate"), None);
    }

    #[test]
    fn test_get_index_path_1_char() {
        let registry = PathBuf::from("/tmp/registry");
        assert_eq!(
            get_index_path(&registry, "a"),
            PathBuf::from("/tmp/registry/index/1/a")
        );
    }

    #[test]
    fn test_get_index_path_2_char() {
        let registry = PathBuf::from("/tmp/registry");
        assert_eq!(
            get_index_path(&registry, "ab"),
            PathBuf::from("/tmp/registry/index/2/ab")
        );
    }

    #[test]
    fn test_get_index_path_3_char() {
        let registry = PathBuf::from("/tmp/registry");
        assert_eq!(
            get_index_path(&registry, "abc"),
            PathBuf::from("/tmp/registry/index/3/a/abc")
        );
    }

    #[test]
    fn test_get_index_path_4plus_char() {
        let registry = PathBuf::from("/tmp/registry");
        assert_eq!(
            get_index_path(&registry, "serde"),
            PathBuf::from("/tmp/registry/index/se/rd/serde")
        );
    }

    #[test]
    fn test_get_crates_io_index_url_1_char() {
        assert_eq!(get_crates_io_index_url("a"), "https://index.crates.io/1/a");
    }

    #[test]
    fn test_get_crates_io_index_url_2_char() {
        assert_eq!(
            get_crates_io_index_url("ab"),
            "https://index.crates.io/2/ab"
        );
    }

    #[test]
    fn test_get_crates_io_index_url_3_char() {
        assert_eq!(
            get_crates_io_index_url("abc"),
            "https://index.crates.io/3/a/abc"
        );
    }

    #[test]
    fn test_get_crates_io_index_url_4plus_char() {
        assert_eq!(
            get_crates_io_index_url("serde"),
            "https://index.crates.io/se/rd/serde"
        );
    }
}
