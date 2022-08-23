use super::*;
use serde::Serialize;

/// A node representing a generic argument of an implementation of an `*Engine` trait.
#[derive(Serialize, Clone, Debug)]
pub enum EngineTraitImplGenericArgument {
    /// The generic argument is an owned entity
    #[serde(serialize_with = "serialize_with_token_string")]
    OwnedEntity(syn::Type),
    /// The generic argument is a view entity
    #[serde(serialize_with = "serialize_with_token_string")]
    ViewEntity(syn::Type),
    /// The generic argument is a mut view entity
    #[serde(serialize_with = "serialize_with_token_string")]
    MutViewEntity(syn::Type),
    /// The generic argument is a config
    #[serde(serialize_with = "serialize_with_token_string")]
    Config(syn::Type),
    /// The generic argument is a numeric
    #[serde(serialize_with = "serialize_with_token_string")]
    Numeric(syn::Type),
    /// The generic argument is a numeric slice
    #[serde(serialize_with = "serialize_with_token_string")]
    NumericSlice(syn::Type),
    /// The generic argument is a numeric mutable slice
    #[serde(serialize_with = "serialize_with_token_string")]
    NumericSliceMut(syn::Type),
    /// The generic argument is a numeric vec
    #[serde(serialize_with = "serialize_with_token_string")]
    NumericVec(syn::Type),
    // The generic argument can not be properly parsed into a category.
    #[serde(serialize_with = "serialize_with_token_string")]
    Unknown(syn::Type),
}

impl EngineTraitImplGenericArgument {
    /// Returns `syn` node pointing to the generic argument.
    pub fn get_type(&self) -> &syn::Type {
        match self {
            EngineTraitImplGenericArgument::OwnedEntity(t) => t,
            EngineTraitImplGenericArgument::ViewEntity(t) => t,
            EngineTraitImplGenericArgument::MutViewEntity(t) => t,
            EngineTraitImplGenericArgument::Config(t) => t,
            EngineTraitImplGenericArgument::Numeric(t) => t,
            EngineTraitImplGenericArgument::NumericSlice(t) => t,
            EngineTraitImplGenericArgument::NumericSliceMut(t) => t,
            EngineTraitImplGenericArgument::NumericVec(t) => t,
            EngineTraitImplGenericArgument::Unknown(t) => t,
        }
    }
}
