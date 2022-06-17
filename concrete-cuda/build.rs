use std::env;
use std::process::Command;

fn main() {
    if let Ok(_f) = env::var("CARGO_FEATURE__CI_DO_NOT_COMPILE") {
        println!("cargo:warning=concrete-cuda is in CI fake mode, and is not really built");
    } else if let Err(_e) = env::var("CARGO_FEATURE__CI_DO_NOT_COMPILE") {
        println!("Build concrete-cuda");
        if env::consts::OS == "linux" {
            let output = Command::new("./get_os_name.sh").output().unwrap();
            let distribution = String::from_utf8(output.stdout).unwrap();
            if distribution != "Ubuntu\n" {
                println!(
                    "cargo:warning=This Linux platform is not officially supported, concrete-cuda \
            build may fail\n"
                );
            }
            let dest = cmake::build("cuda");
            println!("cargo:rustc-link-search=native={}", dest.display());
            println!("cargo:rustc-link-lib=static=concrete_cuda");
            println!("cargo:rustc-link-search=native=/usr/local/cuda/lib64");
            println!("cargo:rustc-link-lib=cudart");
            println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu/");
            println!("cargo:rustc-link-lib=stdc++");
        } else {
            panic!(
                "Error: platform not supported, concrete-cuda not built (only Linux is supported)"
            );
        }
    }
}
