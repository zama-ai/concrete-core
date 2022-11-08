use concrete_core_representation::load_ccr;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub mod generation;
pub mod prune;

fn main() -> Result<(), String> {
    // We load the neighbouring ccr
    let mut ccr = load_ccr(get_concrete_core_root());

    // We prune the ccir from unneeded nodes
    prune::prune(&mut ccr);

    // We generate the binding
    let binding = generation::generate_binding(&ccr).to_string();

    // We format the binding with rustfmt
    let formatted_binding = format_binding(binding)?;

    // We write the binding to a `__gen.rs` file
    write_gen_rs(&formatted_binding);

    Ok(())
}

fn write_gen_rs(binding: &str) {
    let path = out_dir().join("__gen.rs");
    let mut file = File::create(path).unwrap();
    file.write_all(binding.as_bytes()).unwrap();
}

fn out_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").unwrap())
}

fn get_concrete_core_root() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .canonicalize()
        .unwrap()
        .join("concrete-core/src/lib.rs")
}

fn format_binding(input: String) -> Result<String, String> {
    let mut rustfmt = Command::new("rustfmt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute child");
    let mut stdin = rustfmt
        .stdin
        .take()
        .ok_or_else(|| "Failed to take stdin".to_string())?;
    std::thread::spawn(move || {
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");
    });
    let output = rustfmt
        .wait_with_output()
        .map_err(|e| format!("Failed to gather rustfmt output: {}", e))?;
    if !output.status.success() {
        return Err("Failed to format binding.".to_string());
    }
    String::from_utf8(output.stdout).map_err(|e| format!("Failed to read rustfmt output: {}", e))
}
