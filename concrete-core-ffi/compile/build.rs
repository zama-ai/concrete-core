// concrete-core-ffi/build.rs
extern crate cbindgen;
extern crate core;

use concrete_core_representation::{format_rust_string, get_concrete_core_root, load_ccr};
use std::io::Write;
use std::path::PathBuf;

pub mod generation;
pub mod prune;

fn main() -> Result<(), String> {
    // We load the neighbouring ccr
    let mut ccr = load_ccr(get_concrete_core_root());

    // We prune the ccir from the unavailable nodes
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
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(binding.as_bytes()).unwrap();
}

fn out_dir() -> PathBuf {
    PathBuf::from(std::env::var("OUT_DIR").unwrap())
}

// fn main() {
//     let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
//     let package_name = env::var("CARGO_PKG_NAME").unwrap();
//     let output_file = target_dir()
//         .join(format!("{}.h", package_name))
//         .display()
//         .to_string();
//
//     cbindgen::generate(&crate_dir)
//         .unwrap()
//         .write_to_file(&output_file);
// }
//
// /// Find the location of the `target/` directory. Note that this may be
// /// overridden by `cmake`, so we also need to check the `CARGO_TARGET_DIR`
// /// variable.
// fn target_dir() -> PathBuf {
//     if let Ok(target) = env::var("CARGO_TARGET_DIR") {
//         PathBuf::from(target)
//     } else {
//         PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../target/release")
//     }
// }
