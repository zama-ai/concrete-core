//! A module that evaluates cfg expressions.
//!
//! Important note:
//! ---------------
//!
//! The goal of this evaluation is to prune branches of the ccr that won't be available during the
//! build. For now we only support evaluating feature options, and we assume that the relevant
//! features of `concrete-core` will be replicated in the `concrete-core-ffi` crate.

use concrete_core_representation::{CfgOption, CfgPredicate};

pub fn eval_cfg(expr: &CfgPredicate) -> bool {
    match expr {
        CfgPredicate::Option(option) => eval_cfg_option(option),
        CfgPredicate::All(_) => {}
        CfgPredicate::Any(_) => {}
        CfgPredicate::Not(_) => {}
    }
}

fn eval_cfg_option(option: &CfgOption) -> bool {
    if option
}
