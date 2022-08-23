use std::path::PathBuf;

pub fn get_concrete_core_root() -> PathBuf {
    PathBuf::from(file!())
        .parent()
        .unwrap()
        .join("../..")
        .canonicalize()
        .unwrap()
        .join("concrete-core/src/lib.rs")
}
