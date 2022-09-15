use concrete_core_representation::{format_rust_string, get_concrete_core_root, load_ccr};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

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
    let formatted_binding = format_rust_string(binding.as_str())?;

    // We write the binding to a `__gen.rs` file
    write_gen_rs(&formatted_binding);

    Ok(())
}

fn write_gen_rs(binding: &str) {
    let path = out_dir().join("__gen.rs");
    let mut file = File::create(&path).unwrap();
    file.write_all(binding.as_bytes()).unwrap();
}

fn out_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").unwrap())
}
