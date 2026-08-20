use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../.git/HEAD");

    let output =
        Command::new("git").args(["rev-parse", "--short", "HEAD"]).current_dir("../").output();

    match output {
        Ok(o) if o.status.success() => {
            let hash = String::from_utf8_lossy(&o.stdout).trim().to_string();
            println!("cargo:rustc-env=JKAIN_GIT_HASH={hash}");
        }
        _ => {
            println!("cargo:rustc-env=JKAIN_GIT_HASH=unknown");
        }
    }
}
