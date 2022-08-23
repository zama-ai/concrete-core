use super::*;
use serde::Serialize;

/// A node representing the return type of an implementation of an `*Engine` trait.
#[derive(Serialize, Clone, Debug)]
pub enum EngineTraitImplReturn {
    /// The return type is an owned entity
    #[serde(serialize_with = "serialize_with_token_string")]
    OwnedEntity(syn::Type),
    /// The return type is a view entity
    #[serde(serialize_with = "serialize_with_token_string")]
    ViewEntity(syn::Type),
    /// The return type is a mutable view entity
    #[serde(serialize_with = "serialize_with_token_string")]
    MutViewEntity(syn::Type),
    /// The return type is a config
    #[serde(serialize_with = "serialize_with_token_string")]
    Config(syn::Type),
    /// The return type is a numeric
    #[serde(serialize_with = "serialize_with_token_string")]
    Numeric(syn::Type),
    /// The return type is a numeric slice
    #[serde(serialize_with = "serialize_with_token_string")]
    NumericSlice(syn::Type),
    /// The return type is a numeric mutable slice
    #[serde(serialize_with = "serialize_with_token_string")]
    NumericSliceMut(syn::Type),
    /// The return type is a numeric vec
    #[serde(serialize_with = "serialize_with_token_string")]
    NumericVec(syn::Type),
    /// The return type is the unit type
    #[serde(serialize_with = "serialize_with_token_string")]
    Unit(syn::Type),
    /// The return type can not be properly parsed
    #[serde(serialize_with = "serialize_with_token_string")]
    Unknown(syn::Type),
}

impl EngineTraitImplReturn {
    /// Returns the `syn` node pointing to the return type.
    pub fn type_(&self) -> &syn::Type {
        match self {
            EngineTraitImplReturn::OwnedEntity(ty) => ty,
            EngineTraitImplReturn::ViewEntity(ty) => ty,
            EngineTraitImplReturn::MutViewEntity(ty) => ty,
            EngineTraitImplReturn::Config(ty) => ty,
            EngineTraitImplReturn::Numeric(ty) => ty,
            EngineTraitImplReturn::NumericSlice(ty) => ty,
            EngineTraitImplReturn::NumericSliceMut(ty) => ty,
            EngineTraitImplReturn::NumericVec(ty) => ty,
            EngineTraitImplReturn::Unit(ty) => ty,
            EngineTraitImplReturn::Unknown(ty) => ty,
        }
    }
}
