//! A module containing a representation for the concrete-core repository.
use serde::Serialize;
use std::fmt::Debug;
use std::path::Path;

mod abstract_engine_trait_impl;
mod abstract_entity_trait_impl;
mod backend;
mod cfg_lang;
mod cfg_stack;
mod concrete_core;
mod config;
mod engine;
mod engine_trait_impl;
mod engine_trait_impl_arg;
mod engine_trait_impl_checked_method;
mod engine_trait_impl_generic_argument;
mod engine_trait_impl_return;
mod engine_trait_impl_unchecked_method;
mod engine_type_definition;
mod entity;
mod entity_ownership;
mod entity_trait_impl;
mod entity_type_definition;
mod inline;
mod misc;
mod struct_definition;

pub use abstract_engine_trait_impl::*;
pub use abstract_entity_trait_impl::*;
pub use backend::*;
pub use cfg_lang::*;
pub use cfg_stack::*;
pub use concrete_core::*;
pub use config::*;
pub use engine::*;
pub use engine_trait_impl::*;
pub use engine_trait_impl_arg::*;
pub use engine_trait_impl_checked_method::*;
pub use engine_trait_impl_generic_argument::*;
pub use engine_trait_impl_return::*;
pub use engine_trait_impl_unchecked_method::*;
pub use engine_type_definition::*;
pub use entity::*;
pub use entity_ownership::*;
pub use entity_trait_impl::*;
pub use entity_type_definition::*;
pub(crate) use misc::*;
pub(crate) use struct_definition::*;

/// Builds a representation of concrete-core from the path of the root file.
pub fn load_ccr<P: AsRef<Path>>(path: P) -> ConcreteCore {
    let root = inline::read_crate(path);
    let empty_cfg_stack = CfgStack::empty();
    ConcreteCore::extract(&empty_cfg_stack, &root)
}

// TODO: Once reintegrated into concrete-core, those parameters should be parsed from the sources as
// well.
const PARAMETERS_IDENTS: [&str; 25] = [
    "PlaintextCount",
    "EncoderCount",
    "CleartextCount",
    "CiphertextCount",
    "LweCiphertextCount",
    "LweCiphertextIndex",
    "LweCiphertextRange",
    "GlweCiphertextCount",
    "GswCiphertextCount",
    "GgswCiphertextCount",
    "LweSize",
    "LweDimension",
    "GlweSize",
    "GlweDimension",
    "PolynomialSize",
    "PolynomialSizeLog",
    "PolynomialCount",
    "MonomialDegree",
    "MonomialIndex",
    "DecompositionBaseLog",
    "DecompositionLevelCount",
    "LutCountLog",
    "ModulusSwitchOffset",
    "DeltaLog",
    "ExtractedBitsCount",
];

const DISPERSION_IDENTS: [&str; 3] = ["LogStandardDev", "StandardDev", "Variance"];

const NUMERIC_IDENTS: [&str; 12] = [
    "u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128", "f32", "f64",
];
