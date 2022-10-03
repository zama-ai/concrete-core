//! This module contains a function that prunes the ccr to only keep the elements that we want to
//! expose in the wasm api.
use concrete_core_representation::{
    ConcreteCore, EngineTraitImplArg, EngineTraitImplReturn, EntityOwnership,
};

const BLACKLISTED_BACKENDS: [&str; 1] = ["cuda"];

/// A function that prunes a concrete-core representation from the nodes we do not want in the wasm
/// api
pub fn prune(ccr: &mut ConcreteCore) {
    prune_blacklisted_backends(ccr);
    prune_unavailable_entities(ccr);
    prune_unavailable_engine_impls(ccr);
}

/// Prunes the blacklisted backends from the ccr
fn prune_blacklisted_backends(ccr: &mut ConcreteCore) {
    ccr.backends.retain(|backend| {
        !BLACKLISTED_BACKENDS
            .iter()
            .any(|blacklisted| backend.ident == *blacklisted)
    });
}

/// Prunes the unavailable entities from the ccr (views and mut views)
fn prune_unavailable_entities(ccr: &mut ConcreteCore) {
    for backend in ccr.backends.iter_mut() {
        backend
            .entities
            .retain(|entity| matches!(entity.definition.ownership, EntityOwnership::Owned))
    }
}

/// Prunes the engine trait impls that take unavailable arguments.
fn prune_unavailable_engine_impls(ccr: &mut ConcreteCore) {
    for engine in ccr
        .backends
        .iter_mut()
        .flat_map(|backend| backend.engines.iter_mut())
    {
        engine.engine_impls.retain(|impl_| {
            let args_available = impl_.checked_method.args().iter().all(|arg| match arg {
                EngineTraitImplArg::OwnedEntity(_, _) => true,
                EngineTraitImplArg::OwnedEntityRef(_, _) => true,
                EngineTraitImplArg::OwnedEntityRefMut(_, _) => true,
                EngineTraitImplArg::ViewEntity(_, _) => false,
                EngineTraitImplArg::ViewEntityRef(_, _) => false,
                EngineTraitImplArg::MutViewEntity(_, _) => false,
                EngineTraitImplArg::MutViewEntityRefMut(_, _) => false,
                EngineTraitImplArg::Config(_, _) => true,
                EngineTraitImplArg::ConfigRef(_, _, _) => true,
                EngineTraitImplArg::ConfigSlice(_, _, _) => true,
                EngineTraitImplArg::Parameter(_, _) => true,
                EngineTraitImplArg::Dispersion(_, _) => true,
                EngineTraitImplArg::Numeric(_, _) => true,
                EngineTraitImplArg::NumericRef(_, _, _) => true,
                EngineTraitImplArg::NumericRefMut(_, _, _) => false,
                EngineTraitImplArg::NumericSlice(_, _, _) => true,
                EngineTraitImplArg::NumericSliceMut(_, _, _) => false,
                EngineTraitImplArg::NumericVec(_, _, _) => true,
                EngineTraitImplArg::Unknown(_, _) => false,
            });
            let return_available = match impl_.checked_method.return_() {
                EngineTraitImplReturn::OwnedEntity(_) => true,
                EngineTraitImplReturn::ViewEntity(_) => false,
                EngineTraitImplReturn::MutViewEntity(_) => false,
                EngineTraitImplReturn::Config(_) => false,
                EngineTraitImplReturn::Numeric(_) => true,
                EngineTraitImplReturn::NumericSlice(_) => false,
                EngineTraitImplReturn::NumericSliceMut(_) => false,
                EngineTraitImplReturn::NumericVec(_) => true,
                EngineTraitImplReturn::Unit(_) => true,
                EngineTraitImplReturn::Unknown(_) => false,
            };
            args_available && return_available
        });
    }
}
