use concrete_core_representation::{dump_ccr_to_file, load_ccr};

mod root;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("/tmp/ccr_dump.json"));
    dump_ccr_to_file(path.as_str(), load_ccr(root::get_concrete_core_root()));
}
