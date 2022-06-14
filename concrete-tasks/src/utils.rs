use log::{debug, info};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering::Relaxed;

pub type Environment = HashMap<&'static str, &'static str>;

pub fn execute(cmd: &str, env: Option<&Environment>, cwd: Option<&PathBuf>) -> Result<(), Error> {
    info!("Executing {}", cmd);
    debug!("Env {:?}", env);
    debug!("Cwd {:?}", cwd);
    if crate::DRY_RUN.load(Relaxed) {
        info!("Skipping execution because of --dry-run mode");
        return Ok(());
    }
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit());
    if let Some(env) = env {
        for (key, val) in env.iter() {
            command.env(&key, &val);
        }
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output()?;
    if !output.status.success() {
        Err(Error::new(
            ErrorKind::Other,
            "Command exited with nonzero status.",
        ))
    } else {
        Ok(())
    }
}

pub fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}

pub fn get_nightly_toolchain() -> Result<&'static str, Error> {
    if cfg!(target_os = "macos") {
        // Here we are on mac OS, but we don't yet know if it's an x86 or M1 CPU.
        // The issue is that with the toolchain override recommended to build concrete, we need to
        // check with uname at runtime if we are running on an M1 CPU as rosetta2 fakes CPU
        // informations (for good reasons)
        let mut command = Command::new("sh");
        command.arg("-c").arg("uname -a");
        let output = command.output()?;
        if !output.status.success() {
            Err(Error::new(
                ErrorKind::Other,
                "Command exited with nonzero status.",
            ))
        } else {
            let uname_output_as_str = std::str::from_utf8(&output.stdout).unwrap();
            let uname_output_lower = uname_output_as_str.to_lowercase();

            // See here for M1 sample uname output:
            // https://developer.apple.com/forums/thread/668206
            // The ARM64 part is present both under rosetta2 and native calls.

            let is_arm64 = uname_output_lower.contains("arm64");

            // For now we don't support native M1 compilation, so ask to use the x86_64 toolchain.
            if is_arm64 {
                Ok("+nightly-x86_64-apple-darwin")
            } else {
                // Otherwise it's an x86 mac so just keep the default nightly toolchain
                Ok("+nightly")
            }
        }
    } else {
        Ok("+nightly")
    }
}
