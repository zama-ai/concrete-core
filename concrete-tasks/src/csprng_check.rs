use crate::utils::Environment;
use crate::{cmd, ENV_TARGET_NATIVE, ROOT_DIR};
use clap::ArgMatches;
use log::{debug, info};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, Error as IoError, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::{fs, time};

fn execute<T: Into<Stdio>>(
    cmd: &str,
    args: Option<&[String]>,
    env: Option<&Environment>,
    cwd: Option<&PathBuf>,
    stdin: T,
    stderr: T,
    stdout: T,
) -> std::io::Result<Child> {
    info!(
        "Executing `{}` with args `{}`",
        cmd,
        args.unwrap_or(&["".to_string()]).join(" ")
    );
    debug!("Env {:?}", env);
    debug!("Cwd {:?}", cwd);

    let mut command = Command::new(cmd);
    command.stdin(stdin).stderr(stderr).stdout(stdout);
    if let Some(args) = args {
        command.args(args);
    }
    if let Some(env) = env {
        for (key, val) in env.iter() {
            command.env(&key, &val);
        }
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }

    let child = command.spawn()?;
    Ok(child)
}

/// Generate byte file filled with random numbers using concrete-csprng.
///
///  concrete_path: path to directory containing concrete-core git repository
/// duration: execution duration in seconds of concrete-csprng
fn generate_random_numbers(
    build_path: &Path,
    nist_path: &Path,
    duration: u64,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(build_path)?;
    let build_cmd = format!(
        "cargo {} {} -p concrete-csprng --bin generate --features=\"seeder_x86_64_rdseed generator_x86_64_aesni\" --target-dir {}",
        "build", "--release", build_path.display()
    );
    info!("Building concrete-csprng");
    cmd!(<ENV_TARGET_NATIVE> &build_cmd)?;
    info!("Successfully built concrete-csprng");

    let sleep_duration = time::Duration::from_secs(duration);
    // TODO Maybe chain join() calls to make path fully plateform independant?
    let results_path = nist_path.join("data/csprng_results");
    let result_file = File::create(results_path)?;
    // The binary output from `cargo build` is directly used since `cargo run` would spawn
    // the program as a child process. Thus doing Child.kill() would only kill `cargo run` command
    // but not the underlying program that is being executed. As a consequence, concrete-csprng
    // would run indefinitely.
    let exec_path = build_path.join("release/generate");
    info!("Generating random numbers from concrete-csprng");
    let mut proc = execute(
        &exec_path.display().to_string(),
        None,
        Some(&*ENV_TARGET_NATIVE),
        Some(&*ROOT_DIR),
        Stdio::inherit(),
        Stdio::inherit(),
        result_file.into(),
    )?;
    // Wait for enough data to be generated.
    sleep(sleep_duration);
    proc.kill()?;
    info!("Random numbers were generated for {duration} seconds");

    Ok(())
}

/// Run NIST statistical test suite.
///
/// sequence_length: number of bits per sequence
/// bitstreams: number of repetition of the tests
fn run_test_suite(
    nist_path: &Path,
    sequence_length: u64,
    bitstreams: u64,
) -> Result<(), Box<dyn Error>> {
    let cmd_args = vec![sequence_length.to_string()];
    let data_source = 0;
    let input_file = nist_path.join("data/csprng_results");
    let do_run_all_tests = 1;
    let parameter_adjustments = 0;
    let file_format = 1;
    let inputs = [
        data_source.to_string(),
        input_file.display().to_string(),
        do_run_all_tests.to_string(),
        parameter_adjustments.to_string(),
        bitstreams.to_string(),
        file_format.to_string(),
    ];

    info!("Run NIST statistical tests suite");
    let mut proc = execute(
        "./assess",
        Some(&cmd_args),
        None,
        Some(&nist_path.to_path_buf()),
        Stdio::piped(),
        Stdio::piped(),
        Stdio::piped(),
    )?;
    let mut stdin = proc.stdin.take().expect("Failed to get stdin");
    let half_a_sec = time::Duration::from_millis(500);
    for value in inputs {
        stdin.write_all(format!("{}\n", value).as_bytes())?;
        stdin.flush()?;
        // Give some time for the input to be processed.
        sleep(half_a_sec);
    }

    proc.wait()?;
    info!("NIST statistical test suite complete");
    Ok(())
}

/// Parse NIST statistical tests suite.
fn parse_results(nist_path: &Path) -> Result<(), IoError> {
    // TODO Maybe chain join() calls to make path fully plateform independant ?
    let analysis_results = nist_path.join("experiments/AlgorithmTesting/finalAnalysisReport.txt");
    let mut failed_tests: u64 = 0;
    let file = File::open(analysis_results)
        .map_err(|_| IoError::new(ErrorKind::Other, "Failed to parse NIST tool results."))?;
    for line in io::BufReader::new(file).lines().flatten() {
        info!("{}", line);
        if line.contains('*') {
            failed_tests += 1;
        }
    }

    if failed_tests > 0 {
        info!(
            "Summary: {failed_tests} statistical tests failed, check for '*' char in lines above"
        );
        return Err(IoError::new(
            ErrorKind::Other,
            "concrete-csprng behavior check failed",
        ));
    } else {
        info!("Summary: concrete-csprng behavior check succeed")
    }

    Ok(())
}

fn parse_arg(args: &ArgMatches, name: &str) -> Result<u64, IoError> {
    let parsed = args.value_of(name).unwrap().parse::<u64>().map_err(|_| {
        IoError::new(
            ErrorKind::Other,
            format!("Failed to parse argument {name} into u64."),
        )
    })?;
    Ok(parsed)
}

/// Check concrete-csprng behavior using a statistical approach provided by NIST test suite tool.
pub fn check(args: &ArgMatches) -> Result<(), IoError> {
    let generate_duration = parse_arg(args, "generate_duration")?;
    let sequence_length = parse_arg(args, "sequence_length")?;
    let bitstreams = parse_arg(args, "bitstreams")?;
    let nist_tool_path = Path::new(args.value_of("nist_tool_dir").unwrap());
    let build_path = Path::new("./csprng_check_build/");

    let result = generate_random_numbers(build_path, nist_tool_path, generate_duration);
    fs::remove_dir_all(build_path)
        .map_err(|_| IoError::new(ErrorKind::Other, "Failed to remove build directory."))?;
    if result.is_err() {
        return Err(IoError::new(
            ErrorKind::Other,
            "Failed to generate random numbers.",
        ));
    }

    run_test_suite(nist_tool_path, sequence_length, bitstreams).map_err(|_| {
        IoError::new(
            ErrorKind::Other,
            "Failed to parse NIST tool statistical test suite.",
        )
    })?;
    parse_results(nist_tool_path)?;

    Ok(())
}
