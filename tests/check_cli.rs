extern crate tempfile;

use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use std::process::Command;

use tempfile::TempDir;

fn cmd() -> Command {
    let mut me = env::current_exe().unwrap();
    me.pop();
    if me.ends_with("deps") {
        me.pop();
    }
    me.push("cargo-local-registry");
    Command::new(me)
}

fn run(cmd: &mut Command) -> String {
    let output = cmd.env("RUST_BACKTRACE", "1").output().unwrap();
    if !output.status.success() {
        panic!(
            "failed to run {:?}\n--- stdout\n{}\n--- stderr\n{}",
            cmd,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
#[serial_test::serial]
fn check_registry_no_drift() {
    let td = TempDir::new().unwrap();
    let lock = td.path().join("Cargo.lock");
    let registry = td.path().join("registry");
    fs::create_dir(td.path().join("src")).unwrap();
    File::create(td.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "foo"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.6"
    "#,
        )
        .unwrap();
    File::create(td.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "foo"
version = "0.1.0"
dependencies = [
 "libc 0.2.6 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    run(cmd().arg("create").arg(&registry).arg("--sync").arg(&lock));

    run(cmd().arg("check").arg(&registry).arg(td.path()));
}

#[test]
#[serial_test::serial]
fn check_registry_with_drift() {
    let td = TempDir::new().unwrap();
    let lock = td.path().join("Cargo.lock");
    let registry = td.path().join("registry");
    fs::create_dir(td.path().join("src")).unwrap();
    File::create(td.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "foo"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.6"
    "#,
        )
        .unwrap();
    File::create(td.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "foo"
version = "0.1.0"
dependencies = [
 "libc 0.2.6 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    run(cmd().arg("create").arg(&registry).arg("--sync").arg(&lock));

    File::create(&lock)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "foo"
version = "0.1.0"
dependencies = [
 "libc 0.2.7 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    let output = Command::new(cmd().get_program())
        .args(cmd().get_args())
        .arg("check")
        .arg(&registry)
        .arg(td.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "check should fail when drift is detected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing crate") || stderr.contains("registry has"),
        "error message should mention missing crates or registry inconsistencies"
    );
}

#[test]
#[serial_test::serial]
fn check_registry_missing_crate_file() {
    let td = TempDir::new().unwrap();
    let lock = td.path().join("Cargo.lock");
    let registry = td.path().join("registry");
    fs::create_dir(td.path().join("src")).unwrap();
    File::create(td.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "foo"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.6"
    "#,
        )
        .unwrap();
    File::create(td.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "foo"
version = "0.1.0"
dependencies = [
 "libc 0.2.6 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    run(cmd().arg("create").arg(&registry).arg("--sync").arg(&lock));

    fs::remove_file(registry.join("libc-0.2.6.crate")).unwrap();

    let output = Command::new(cmd().get_program())
        .args(cmd().get_args())
        .arg("check")
        .arg(&registry)
        .arg(td.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "check should fail when crate file is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing crate files"),
        "error should mention missing crate files"
    );
    assert!(
        stderr.contains("libc-0.2.6.crate"),
        "error should list the specific missing crate file"
    );
}

#[test]
#[serial_test::serial]
fn check_registry_missing_index_entry() {
    let td = TempDir::new().unwrap();
    let lock = td.path().join("Cargo.lock");
    let registry = td.path().join("registry");
    fs::create_dir(td.path().join("src")).unwrap();
    File::create(td.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "foo"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.6"
    "#,
        )
        .unwrap();
    File::create(td.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "foo"
version = "0.1.0"
dependencies = [
 "libc 0.2.6 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    run(cmd().arg("create").arg(&registry).arg("--sync").arg(&lock));

    fs::remove_file(registry.join("index/li/bc/libc")).unwrap();

    let output = Command::new(cmd().get_program())
        .args(cmd().get_args())
        .arg("check")
        .arg(&registry)
        .arg(td.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "check should fail when index entry is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing index entries"),
        "error should mention missing index entries"
    );
    assert!(
        stderr.contains("libc version 0.2.6"),
        "error should list the specific missing index entry"
    );
}

#[test]
#[serial_test::serial]
fn check_registry_extra_crates() {
    let td = TempDir::new().unwrap();
    let lock = td.path().join("Cargo.lock");
    let registry = td.path().join("registry");
    fs::create_dir(td.path().join("src")).unwrap();
    File::create(td.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "foo"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.6"
    "#,
        )
        .unwrap();
    File::create(td.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "foo"
version = "0.1.0"
dependencies = [
 "libc 0.2.6 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    run(cmd().arg("create").arg(&registry).arg("--sync").arg(&lock));

    File::create(registry.join("serde-1.0.0.crate"))
        .unwrap()
        .write_all(b"fake crate")
        .unwrap();

    let output = Command::new(cmd().get_program())
        .args(cmd().get_args())
        .arg("check")
        .arg(&registry)
        .arg(td.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "check should fail when extra crates exist"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("extra crates"),
        "error should mention extra crates"
    );
    assert!(
        stderr.contains("serde-1.0.0.crate"),
        "error should list the specific extra crate"
    );
}

#[test]
#[serial_test::serial]
fn check_registry_multiple_projects() {
    let td1 = TempDir::new().unwrap();
    let td2 = TempDir::new().unwrap();
    let registry = TempDir::new().unwrap();

    let lock1 = td1.path().join("Cargo.lock");
    fs::create_dir(td1.path().join("src")).unwrap();
    File::create(td1.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "project1"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.6"
    "#,
        )
        .unwrap();
    File::create(td1.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock1)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "project1"
version = "0.1.0"
dependencies = [
 "libc 0.2.6 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    let lock2 = td2.path().join("Cargo.lock");
    fs::create_dir(td2.path().join("src")).unwrap();
    File::create(td2.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "project2"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.7"
    "#,
        )
        .unwrap();
    File::create(td2.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock2)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "project2"
version = "0.1.0"
dependencies = [
 "libc 0.2.7 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    run(cmd()
        .arg("--no-delete")
        .arg("create")
        .arg(registry.path())
        .arg("--sync")
        .arg(&lock1));
    run(cmd()
        .arg("--no-delete")
        .arg("create")
        .arg(registry.path())
        .arg("--sync")
        .arg(&lock2));

    run(cmd()
        .arg("check")
        .arg(registry.path())
        .arg(td1.path())
        .arg(td2.path()));
}

#[test]
#[serial_test::serial]
fn check_registry_multiple_projects_with_drift() {
    let td1 = TempDir::new().unwrap();
    let td2 = TempDir::new().unwrap();
    let registry = TempDir::new().unwrap();

    let lock1 = td1.path().join("Cargo.lock");
    fs::create_dir(td1.path().join("src")).unwrap();
    File::create(td1.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "project1"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.6"
    "#,
        )
        .unwrap();
    File::create(td1.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock1)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "project1"
version = "0.1.0"
dependencies = [
 "libc 0.2.6 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    let lock2 = td2.path().join("Cargo.lock");
    fs::create_dir(td2.path().join("src")).unwrap();
    File::create(td2.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "project2"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.7"
    "#,
        )
        .unwrap();
    File::create(td2.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock2)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "project2"
version = "0.1.0"
dependencies = [
 "libc 0.2.7 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    run(cmd()
        .arg("create")
        .arg(registry.path())
        .arg("--sync")
        .arg(&lock1));

    let output = Command::new(cmd().get_program())
        .args(cmd().get_args())
        .arg("check")
        .arg(registry.path())
        .arg(td1.path())
        .arg(td2.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "check should fail when one project's dependencies are missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("libc-0.2.7.crate"),
        "error should mention the missing crate from project2"
    );
}

#[test]
#[serial_test::serial]
fn check_registry_missing_version_in_index() {
    let td = TempDir::new().unwrap();
    let lock = td.path().join("Cargo.lock");
    let registry = td.path().join("registry");
    fs::create_dir(td.path().join("src")).unwrap();
    File::create(td.path().join("Cargo.toml"))
        .unwrap()
        .write_all(
            br#"
        [package]
        name = "foo"
        version = "0.1.0"
        authors = []

        [dependencies]
        libc = "0.2.6"
    "#,
        )
        .unwrap();
    File::create(td.path().join("src/lib.rs"))
        .unwrap()
        .write_all(b"")
        .unwrap();
    File::create(&lock)
        .unwrap()
        .write_all(
            br#"
[[package]]
name = "foo"
version = "0.1.0"
dependencies = [
 "libc 0.2.6 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "libc"
version = "0.2.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

    run(cmd().arg("create").arg(&registry).arg("--sync").arg(&lock));

    let index_path = registry.join("index/li/bc/libc");
    let mut content = fs::read_to_string(&index_path).unwrap();
    content = content.replace("0.2.6", "0.2.5");
    fs::write(&index_path, content).unwrap();

    let output = Command::new(cmd().get_program())
        .args(cmd().get_args())
        .arg("check")
        .arg(&registry)
        .arg(td.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "check should fail when index has wrong version"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing index entries"),
        "error should mention missing index entries"
    );
    assert!(
        stderr.contains("libc version 0.2.6"),
        "error should mention the correct version needed"
    );
}
