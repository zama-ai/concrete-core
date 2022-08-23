use concrete_core_representation::{load_ccr, print_ccr};

mod root;

fn main() {
    let ccr = load_ccr(root::get_concrete_core_root());
    print_ccr(&ccr);
}
