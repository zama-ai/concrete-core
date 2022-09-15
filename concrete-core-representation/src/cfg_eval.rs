//! A module that evaluates cfg expressions.
use crate::{CfgAll, CfgAny, CfgNot, CfgOption, CfgPredicate};
use concrete_core_representation::{CfgAll, CfgAny, CfgNot, CfgOption, CfgPredicate};
use quote::ToTokens;

/// Evaluates a cfg predicate based on the current compilation context.
///
/// Important Notes:
/// ----------------
///
/// + For now the only options that can be evaluated are "feature".
/// + The evaluation of feature options is based on cargo set environment variables. This means that
///   when called from a different crate than `concrete-core`, it is the variables of this crate
///   that will be used for evaluation, and __not__ the resolution of `concrete-core` features
///   induced by the local features.
pub fn eval_cfg(expr: &CfgPredicate) -> bool {
    match expr {
        CfgPredicate::Option(option) => eval_cfg_option(option),
        CfgPredicate::All(all) => eval_cfg_all(all),
        CfgPredicate::Any(any) => eval_cfg_any(any),
        CfgPredicate::Not(not) => eval_cfg_not(not),
    }
}

fn eval_cfg_option(option: &CfgOption) -> bool {
    if option.identifier != "feature" {
        panic!("Encountered non-feature cfg option: {:?}", option);
    }
    if option.litteral.is_none() || option.equal.is_none() {
        panic!("Malformed feature cfg option: {:?}", option);
    }
    let feature_flag = option
        .litteral
        .as_ref()
        .unwrap()
        .to_token_stream()
        .to_string();
    let env_feature_flag = feature_flag
        .to_ascii_uppercase()
        .replace("-", "_")
        .replace("\"", "");
    let env_var = format!("CARGO_FEATURE_{env_feature_flag}");
    std::env::var(env_var).is_ok()
}

fn eval_cfg_not(not: &CfgNot) -> bool {
    !eval_cfg(&not.pred)
}

fn eval_cfg_any(any: &CfgAny) -> bool {
    any.content.iter().any(eval_cfg)
}

fn eval_cfg_all(all: &CfgAll) -> bool {
    all.content.iter().all(eval_cfg)
}
