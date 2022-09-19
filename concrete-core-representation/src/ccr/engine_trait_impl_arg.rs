use super::*;
use serde::Serialize;

/// A node representing a function argument of an implementation of an `*Engine` trait.
#[derive(Serialize, Clone, Debug)]
pub enum EngineTraitImplArg {
    // The argument is an owned entity passed by value.
    #[serde(serialize_with = "serialize_with_token_string_2")]
    OwnedEntity(syn::PatIdent, syn::Type),
    // The argument is an owned entity passed by reference.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    OwnedEntityRef(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is an owned entity passed by mutable reference.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    OwnedEntityRefMut(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a view entity passed by value.
    #[serde(serialize_with = "serialize_with_token_string_2")]
    ViewEntity(syn::PatIdent, syn::Type),
    // The argument is a view entity passed by reference.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    ViewEntityRef(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a mutable view entity passed by value.
    #[serde(serialize_with = "serialize_with_token_string_2")]
    MutViewEntity(syn::PatIdent, syn::Type),
    // The argument is a mutable view entity passed by mutable reference.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    MutViewEntityRefMut(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a config passed by value.
    #[serde(serialize_with = "serialize_with_token_string_2")]
    Config(syn::PatIdent, syn::Type),
    // The argument is a config passed by reference.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    ConfigRef(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a slice of configs.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    ConfigSlice(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a commons parameter.
    #[serde(serialize_with = "serialize_with_token_string_2")]
    Parameter(syn::PatIdent, syn::Type),
    // The argument is a commons dispersion.
    #[serde(serialize_with = "serialize_with_token_string_2")]
    Dispersion(syn::PatIdent, syn::Type),
    // The argument is a rust numeric type passed by value.
    #[serde(serialize_with = "serialize_with_token_string_2")]
    Numeric(syn::PatIdent, syn::Type),
    // The argument is a rust numeric type passed by reference.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    NumericRef(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a rust numeric type passed by mutable reference.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    NumericRefMut(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a slice of rust numeric types.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    NumericSlice(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a mutable slice of rust numeric types.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    NumericSliceMut(syn::PatIdent, syn::Type, syn::Ident),
    // The argument is a vec of rust numeric types.
    #[serde(serialize_with = "serialize_with_token_string_3")]
    NumericVec(syn::PatIdent, syn::Type, syn::Ident),
    // The argument can not be properly parsed into a category.
    #[serde(serialize_with = "serialize_with_token_string_2")]
    Unknown(syn::PatIdent, syn::Type),
}

impl EngineTraitImplArg {
    /// Returns the left hand side of the argument (the pattern).
    pub fn pat_ident(&self) -> &syn::PatIdent {
        macro_rules! _impl {
            ($($variant:ident,)*) => {
                match self {
                    $(
                        EngineTraitImplArg::$variant(pi, ..) => pi,
                    )*
                }
            };
        }
        _impl!(
            OwnedEntity,
            OwnedEntityRef,
            OwnedEntityRefMut,
            ViewEntity,
            ViewEntityRef,
            MutViewEntity,
            MutViewEntityRefMut,
            Config,
            ConfigRef,
            ConfigSlice,
            Parameter,
            Dispersion,
            Numeric,
            NumericRef,
            NumericRefMut,
            NumericSlice,
            NumericSliceMut,
            NumericVec,
            Unknown,
        )
    }

    /// Returns the right hand side of the argument (the type).
    pub fn type_(&self) -> &syn::Type {
        macro_rules! _impl {
            ($($variant:ident,)*) => {
                match self {
                    $(
                        EngineTraitImplArg:: $variant (_, ty, ..) => ty,
                    )*
                }
            };
        }
        _impl!(
            OwnedEntity,
            OwnedEntityRef,
            OwnedEntityRefMut,
            ViewEntity,
            ViewEntityRef,
            MutViewEntity,
            MutViewEntityRefMut,
            Config,
            ConfigRef,
            ConfigSlice,
            Parameter,
            Dispersion,
            Numeric,
            NumericRef,
            NumericRefMut,
            NumericSlice,
            NumericSliceMut,
            NumericVec,
            Unknown,
        )
    }
}
