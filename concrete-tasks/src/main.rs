#[macro_use]
extern crate lazy_static;
use clap::{Arg, Command};
use log::LevelFilter;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};
use std::collections::HashMap;
use std::env::consts::OS;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;

mod build;
mod check;
mod chore;
mod format_latex_doc;
mod test;
mod utils;

// -------------------------------------------------------------------------------------------------
// CONSTANTS
// -------------------------------------------------------------------------------------------------
lazy_static! {
    static ref DRY_RUN: AtomicBool = AtomicBool::new(false);
    static ref ROOT_DIR: PathBuf = utils::project_root();
    static ref ENV_TARGET_NATIVE: utils::Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTFLAGS", "-Ctarget-cpu=native");
        env
    };
}

// -------------------------------------------------------------------------------------------------
// MACROS
// -------------------------------------------------------------------------------------------------

#[macro_export]
macro_rules! cmd {
    (<$env: ident> $cmd: expr) => {
        $crate::utils::execute($cmd, Some(&*$env), Some(&*$crate::ROOT_DIR))
    };
    ($cmd: expr) => {
        $crate::utils::execute($cmd, None, Some(&*$crate::ROOT_DIR))
    };
}

// -------------------------------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------------------------------

fn main() -> Result<(), std::io::Error> {
    // This is to manage rustup 1.25 which apparently now chooses to fix RUSTC and RUSTDOC...
    // Breaking xtask-like workflows
    std::env::remove_var("RUSTC");
    std::env::remove_var("RUSTDOC");

    // We check whether the current os is supported
    if !(OS == "linux" || OS == "macos") {
        panic!("Concrete tasks are only supported on linux and macos.")
    }

    // We parse the input args
    let matches = Command::new("concrete-tasks")
        .about("Performs concrete-core plumbing tasks")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Prints debug messages"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Do not execute the commands"),
        )
        .subcommand(Command::new("test").about("Executes all available tests in native mode"))
        .subcommand(Command::new("cov").about("Computes test coverage in native mode"))
        .subcommand(Command::new("build").about("Builds the crates in all available mode"))
        .subcommand(Command::new("check").about("Performs all the available checks"))
        .subcommand(
            Command::new("test_core").about("Tests the `concrete-core` crate in native mode"),
        )
        .subcommand(
            Command::new("test_csprng").about("Tests the `concrete-csprng` crate in native mode"),
        )
        .subcommand(Command::new("test_npe").about("Tests the `concrete-npe` crate in native mode"))
        .subcommand(Command::new("test_crates").about("Tests all the crates in native mode"))
        .subcommand(
            Command::new("test_and_cov_crates")
                .about("Compute tests coverage of all crates in native mode"),
        )
        .subcommand(
            Command::new("test_cuda")
                .about("Tests the `concrete-core` crate with the cuda backend"),
        )
        .subcommand(Command::new("build_debug_crates").about("Build all the crates in debug mode"))
        .subcommand(
            Command::new("build_release_crates").about("Build all the crates in release mode"),
        )
        .subcommand(Command::new("build_simd_crates").about("Build all the crates in simd mode"))
        .subcommand(Command::new("build_benches").about("Build the benchmarks in release mode"))
        .subcommand(
            Command::new("check_doc").about("Checks that the doc compiles without warnings"),
        )
        .subcommand(Command::new("check_clippy").about("Checks that clippy runs without warnings"))
        .subcommand(
            Command::new("check_clippy_cuda")
                .about("Checks that clippy runs without warnings on the cuda backend"),
        )
        .subcommand(Command::new("check_fmt").about("Checks that rustfmt runs without warnings"))
        .subcommand(Command::new("chore_format").about("Format the codebase with rustfmt"))
        .subcommand(
            Command::new("chore_format_latex_doc").about("Escape underscores in latex equations"),
        )
        .arg_required_else_help(true)
        .get_matches();

    // We initialize the logger with proper verbosity
    let verb = if matches.contains_id("verbose") {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    CombinedLogger::init(vec![TermLogger::new(
        verb,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .unwrap();

    // We set the dry-run mode if present
    if matches.contains_id("dry-run") {
        DRY_RUN.store(true, Relaxed);
    }

    // We execute the task.
    if matches.subcommand_matches("test").is_some() {
        test::crates()?;
    }
    if matches.subcommand_matches("cov").is_some() {
        test::cov_crates()?;
    }
    if matches.subcommand_matches("build").is_some() {
        build::debug::benches()?;
        build::debug::crates()?;
        build::debug::doctests()?;
        build::debug::tests()?;
        build::release::benches()?;
        build::release::crates()?;
        build::release::doctests()?;
        build::release::tests()?;
        build::simd::benches()?;
        build::simd::crates()?;
        build::simd::doctests()?;
        build::simd::tests()?;
    }
    if matches.subcommand_matches("check").is_some() {
        check::doc()?;
        check::clippy()?;
        check::fmt()?;
    }
    if matches.subcommand_matches("test_core").is_some() {
        test::core()?;
    }
    if matches.subcommand_matches("test_csprng").is_some() {
        test::csprng()?;
    }
    if matches.subcommand_matches("test_npe").is_some() {
        test::npe()?;
    }
    if matches.subcommand_matches("test_crates").is_some() {
        test::crates()?;
    }
    if matches.subcommand_matches("test_and_cov_crates").is_some() {
        test::cov_crates()?;
    }
    if matches.subcommand_matches("test_cuda").is_some() {
        test::cuda()?;
    }
    if matches.subcommand_matches("build_debug_crates").is_some() {
        build::debug::crates()?;
    }
    if matches.subcommand_matches("build_release_crates").is_some() {
        build::release::crates()?;
    }
    if matches.subcommand_matches("build_simd_crates").is_some() {
        build::simd::crates()?;
    }
    if matches.subcommand_matches("build_benches").is_some() {
        build::release::benches()?;
    }
    if matches.subcommand_matches("check_doc").is_some() {
        check::doc()?;
    }
    if matches.subcommand_matches("check_clippy").is_some() {
        check::clippy()?;
    }
    if matches.subcommand_matches("check_clippy_cuda").is_some() {
        check::cuda_clippy()?;
    }
    if matches.subcommand_matches("check_fmt").is_some() {
        check::fmt()?;
    }
    if matches.subcommand_matches("chore_format").is_some() {
        chore::format()?;
    }
    if matches
        .subcommand_matches("chore_format_latex_doc")
        .is_some()
    {
        chore::format_latex_doc()?;
    }

    Ok(())
}
