//! A module that contains functions to prune the ccr based on activated feature flags.
use concrete_core_representation::{eval_cfg, ConcreteCore, EngineTraitImplArg};

/// Prunes the input ccr from the branches not available due to activated feature flags.
pub fn prune(ccr: &mut ConcreteCore) {
    prune_backends(ccr);
    prune_entities(ccr);
    prune_configs(ccr);
    prune_engines(ccr);
    prune_engine_trait_impls(ccr);
    prune_unknown_args(ccr);
}

fn prune_backends(ccr: &mut ConcreteCore) {
    ccr.backends
        .retain(|backend| eval_cfg(&backend.cfg.cfg_expr()))
}

fn prune_engines(ccr: &mut ConcreteCore) {
    for backend in ccr.backends.iter_mut() {
        backend
            .engines
            .retain(|eng| eval_cfg(&eng.definition.cfg.cfg_expr()))
    }
}

fn prune_entities(ccr: &mut ConcreteCore) {
    for backend in ccr.backends.iter_mut() {
        backend
            .entities
            .retain(|ent| eval_cfg(&ent.definition.cfg.cfg_expr()))
    }
}

fn prune_configs(ccr: &mut ConcreteCore) {
    for backend in ccr.backends.iter_mut() {
        backend
            .configs
            .retain(|conf| eval_cfg(&conf.cfg.cfg_expr()))
    }
}

fn prune_engine_trait_impls(ccr: &mut ConcreteCore) {
    for backend in ccr.backends.iter_mut() {
        for eng in backend.engines.iter_mut() {
            eng.engine_impls
                .retain(|_impl| eval_cfg(&_impl.cfg.cfg_expr()))
        }
    }
}

fn prune_unknown_args(ccr: &mut ConcreteCore) {
    for backend in ccr.backends.iter_mut() {
        for eng in backend.engines.iter_mut() {
            eng.engine_impls.retain(|_impl| {
                _impl
                    .checked_method
                    .args()
                    .iter()
                    .any(|arg| matches!(arg, EngineTraitImplArg::Unknown(_)))
            })
        }
    }
}
