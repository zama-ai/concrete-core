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
            command.env(key, val);
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

pub fn get_nightly_toolchain() -> Result<String, Error> {
    // Check if nightly toolchain is properly installed
    execute(
        "make check_tasks_rust_toolchain",
        None,
        Some(&project_root()),
    )
    .expect("Tasks toolchain is not installed. Please run: make install_tasks_rust_toolchain\n\n");

    let toolchain_txt = project_root().join("concrete-tasks/toolchain.txt");
    let content = std::fs::read_to_string(toolchain_txt).unwrap();
    let (toolchain_base, _) = content.split_once('\n').unwrap();
    let toolchain_arg = format!("+{}", toolchain_base);

    Ok(toolchain_arg)
}

pub fn get_build_toolchain() -> Result<String, Error> {
    // aarch64 currently requires nightly feature stdsimd for some operators
    if cfg!(target_arch = "aarch64") || cfg!(target_arch = "x86_64") {
        Ok("+stable".to_string())
    } else {
        // For other arch by default we use the nightly toolchain as it has a better chance of
        // working out of the gates
        info!(
            "Unknown target_arch to the concrete-core project, using frozen nightly toolchain as \
        build toolchain. Consider contributing to the project to enhance support for it."
        );
        get_nightly_toolchain()
    }
}

pub fn get_target_arch_feature_for_core() -> Result<&'static str, Error> {
    if cfg!(target_arch = "x86_64") {
        Ok("x86_64")
    } else if cfg!(target_arch = "aarch64") {
        Ok("aarch64")
    } else {
        Err(Error::new(
            ErrorKind::Other,
            "The current target architecture currently has no feature flag (like 'x86_64' or \
            'aarch64' e.g.) in concrete-core and will not compile with this cargo xtask command. \
            You can create your own feature flag for this target architecture or compile manually \
            specifying the features you want to enable.",
        ))
    }
}

pub fn get_target_arch_feature_for_doc() -> Result<&'static str, Error> {
    get_target_arch_feature_for_core()
}
