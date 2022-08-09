use log::{debug, info};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering::Relaxed;

pub type Environment = HashMap<&'static str, &'static str>;

pub fn execute(
    cmd: &str,
    env: Option<&Environment>,
    cwd: Option<&PathBuf>,
    stdin: Option<Stdio>,
    stderr: Option<Stdio>,
    stdout: Option<Stdio>,
    return_handle: bool,
) -> Result<Option<Child>, Error> {
    info!("Executing {}", cmd);
    debug!("Env {:?}", env);
    debug!("Cwd {:?}", cwd);
    if crate::DRY_RUN.load(Relaxed) {
        info!("Skipping execution because of --dry-run mode");
        return Ok(None);
    }
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .stdin(stdin.unwrap_or_else(Stdio::piped))
        .stderr(stderr.unwrap_or_else(Stdio::inherit))
        .stdout(stdout.unwrap_or_else(Stdio::inherit));
    if let Some(env) = env {
        for (key, val) in env.iter() {
            command.env(&key, &val);
        }
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }

    // We cannot match on Stdio value for stdin since when output() is called on child process,
    // it defaults to Stdio::piped(). Since one might want retrieve the child handle, to be able to
    // write on stdin per say, we have to use a trick to know if user want to get the child or
    // instead simply wait on process to finish before returning.
    if return_handle {
        let child = command.spawn()?;
        return Ok(Some(child));
    }
    let output = command.output()?;
    if !output.status.success() {
        Err(Error::new(
            ErrorKind::Other,
            "Command exited with nonzero status.",
        ))
    } else {
        Ok(None)
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
        None,
        None,
        None,
        false,
    )
    .expect("Tasks toolchain is not installed. Please run: make install_tasks_rust_toolchain\n\n");

    let toolchain_txt = project_root().join("concrete-tasks/toolchain.txt");
    let content = std::fs::read_to_string(toolchain_txt).unwrap();
    let (toolchain_base, _) = content.split_once('\n').unwrap();
    let toolchain_arg = format!("+{}", toolchain_base);

    if cfg!(target_os = "macos") {
        // For now we don't support Apple Silicon, always use the x86_64 toolchain for tasks
        Ok(format!("{}-x86_64-apple-darwin", toolchain_arg))
    } else {
        Ok(toolchain_arg)
    }
}
