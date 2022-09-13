use crate::{cmd, utils, ENV_TARGET_NATIVE};
use clap::{Arg, ArgMatches};
use log::{error, info};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead, Error as IoError, ErrorKind, Write};
use std::path::Path;
use std::process::Stdio;

pub fn command_args() -> clap::Command<'static> {
    let command = clap::Command::new("check_csprng")
        .about("Checks concrete-csprng behavior with statistical approach")
        .arg(
            Arg::new("nist_tool_dir")
                .short('n')
                .long("nist_tool_dir")
                .takes_value(true)
                .required(true)
                .help("Path to NIST statistical tool directory"),
        )
        .arg(
            Arg::new("sequence_length")
                .short('s')
                .long("sequence_length")
                .takes_value(true)
                .default_value("400000")
                .help("Number of bits per sequence passed to NIST tests suite"),
        )
        .arg(
            Arg::new("bitstreams")
                .short('b')
                .long("bitstreams")
                .takes_value(true)
                .default_value("200")
                .help("The size of the sample per key"),
        );
    command
}

/// Generate byte file filled with random numbers using concrete-csprng.
///
/// build_path: path to build artifacts
/// concrete_path: path to directory containing concrete-core git repository
/// bytes_length: number of bytes to be generated in concrete-csprng
fn generate_random_numbers(
    build_path: &Path,
    nist_path: &Path,
    bytes_length: u64,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(build_path)?;

    let build_cmd = format!(
        "cargo build --release -p concrete-csprng --bin generate --features=seeder_x86_64_rdseed,generator_x86_64_aesni,cli --target-dir {}",
        build_path.to_str().unwrap()
    );
    info!("Building concrete-csprng");
    cmd!(<ENV_TARGET_NATIVE> &build_cmd)?;
    info!("Successfully built concrete-csprng");

    let results_path = nist_path.join("data/csprng_results");
    let result_file = File::create(results_path)?;
    let run_cmd = format!(
        "{} -b {}",
        build_path.join("release/generate").to_str().unwrap(),
        bytes_length
    );
    info!("Generating random numbers from concrete-csprng");
    cmd!(<ENV_TARGET_NATIVE> &run_cmd, &utils::project_root(), Stdio::inherit(), Stdio::inherit(), result_file.into(), false)?;
    info!("{} random bytes were generated", bytes_length);

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
    let exec_path = match nist_path.join("assess").to_str() {
        Some(path) => path.to_owned(),
        None => {
            error!(
                "NIST path '{}' contains non_utf8 characters",
                nist_path.display()
            );
            return Err(Box::new(IoError::new(
                ErrorKind::Other,
                "path conversion failed",
            )));
        }
    };
    let cmd = format!("{} {}", exec_path, sequence_length);
    let data_source = 0;
    let input_file = nist_path.join("data/csprng_results");
    let do_run_all_tests = 1;
    let parameter_adjustments = 0;
    let file_format = 1;
    let inputs = [
        data_source.to_string(),
        input_file.display().to_string(), // Here Path is guaranteed to contain only valid utf8
        do_run_all_tests.to_string(),
        parameter_adjustments.to_string(),
        bitstreams.to_string(),
        file_format.to_string(),
    ];

    info!("Run NIST statistical tests suite");
    let mut proc = cmd!(<ENV_TARGET_NATIVE> &cmd, &nist_path.to_path_buf(), Stdio::piped(), Stdio::piped(), Stdio::piped(), true)?.unwrap();
    let mut stdin = proc.stdin.take().expect("Failed to get stdin");
    for value in inputs {
        stdin.write_all(format!("{}\n", value).as_bytes())?;
        stdin.flush()?;
    }
    proc.wait()?;
    info!("NIST statistical test suite complete");
    Ok(())
}

/// Parse NIST statistical tests suite.
fn parse_results(nist_path: &Path) -> Result<(), IoError> {
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
    let sequence_length = parse_arg(args, "sequence_length")?;
    let bitstreams = parse_arg(args, "bitstreams")?;
    let nist_tool_path = Path::new(args.value_of("nist_tool_dir").unwrap());
    let build_path = Path::new("./csprng_check_builds/");

    let result = generate_random_numbers(build_path, nist_tool_path, sequence_length * bitstreams);
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
