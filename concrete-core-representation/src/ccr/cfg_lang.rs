//! A module containing parsing functions for the cfg mini language.
//!
//! Syn does not parse the `cfg` mini language. It is thus not possible to evaluate cfg expressions
//! without this parsing.
//!
//! This module implement the parsing following the notation of the following page:
//! https://doc.rust-lang.org/reference/conditional-compilation.html.
use super::*;
use serde::Serialize;
use syn::{parenthesized, Token};

/// A temporary structure used to parse predicates first enclosed in parenthesis.
///
/// This is necessary, because the `token` field of the `syn::Attribute` type returns a token stream
/// that contains the enclosing parenthesis -_-' .
#[derive(Debug, Serialize, Clone)]
pub(crate) struct CfgParenPredicate {
    pub predicate: CfgPredicate,
}

impl syn::parse::Parse for CfgParenPredicate {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let paren_input;
        parenthesized!(paren_input in input);
        let predicate = paren_input.parse()?;
        Ok(CfgParenPredicate { predicate })
    }
}

/// A rebinding node representing all predicate kinds.
///
/// See https://doc.rust-lang.org/reference/conditional-compilation.html.
#[derive(Debug, Serialize, Clone)]
pub enum CfgPredicate {
    Option(CfgOption),
    All(Box<CfgAll>),
    Any(Box<CfgAny>),
    Not(Box<CfgNot>),
}

impl syn::parse::Parse for CfgPredicate {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        if input.fork().parse::<CfgAll>().is_ok() {
            Ok(CfgPredicate::All(Box::new(input.parse::<CfgAll>()?)))
        } else if input.fork().parse::<CfgAny>().is_ok() {
            Ok(CfgPredicate::Any(Box::new(input.parse::<CfgAny>()?)))
        } else if input.fork().parse::<CfgNot>().is_ok() {
            Ok(CfgPredicate::Not(Box::new(input.parse::<CfgNot>()?)))
        } else if input.fork().parse::<CfgOption>().is_ok() {
            Ok(CfgPredicate::Option(input.parse::<CfgOption>()?))
        } else {
            Err(input.error("Unexpected input."))
        }
    }
}

/// A node representing an option predicate.
///
/// See https://doc.rust-lang.org/reference/conditional-compilation.html.
#[derive(Debug, Serialize, Clone)]
pub struct CfgOption {
    #[serde(serialize_with = "serialize_with_token_string")]
    pub identifier: syn::Ident,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub equal: Option<Token![=]>,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub litteral: Option<syn::LitStr>,
}

impl syn::parse::Parse for CfgOption {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let identifier = input.parse()?;
        let (equal, litteral) = if input.peek(syn::token::Paren) {
            (None, None)
        } else {
            let eq = input.parse()?;
            let lit = input.parse()?;
            (Some(eq), Some(lit))
        };
        Ok(CfgOption {
            identifier,
            equal,
            litteral,
        })
    }
}

/// A node representing an all predicate.
///
/// See https://doc.rust-lang.org/reference/conditional-compilation.html.
#[derive(Debug, Serialize, Clone)]
pub struct CfgAll {
    #[serde(serialize_with = "serialize_with_token_string")]
    pub all: syn::Ident,
    #[serde(serialize_with = "serialize_punctuated")]
    pub content: syn::punctuated::Punctuated<CfgPredicate, Token![,]>,
}

impl syn::parse::Parse for CfgAll {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let all: syn::Ident = input.parse()?;
        if all != "all" {
            return Err(syn::Error::new(all.span(), ""));
        }
        let paren_input;
        parenthesized!(paren_input in input);
        let content = paren_input.parse_terminated(CfgPredicate::parse)?;
        Ok(CfgAll { all, content })
    }
}

/// A node representing an any predicate.
///
/// See https://doc.rust-lang.org/reference/conditional-compilation.html.
#[derive(Debug, Serialize, Clone)]
pub struct CfgAny {
    #[serde(serialize_with = "serialize_with_token_string")]
    pub any: syn::Ident,
    #[serde(serialize_with = "serialize_punctuated")]
    pub content: syn::punctuated::Punctuated<CfgPredicate, Token![,]>,
}

impl syn::parse::Parse for CfgAny {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let any: syn::Ident = input.parse()?;
        if any != "any" {
            return Err(syn::Error::new(any.span(), ""));
        }
        let paren_input;
        parenthesized!(paren_input in input);
        let content = paren_input.parse_terminated(CfgPredicate::parse)?;
        Ok(CfgAny { any, content })
    }
}

/// A node representing a not predicate.
///
/// See https://doc.rust-lang.org/reference/conditional-compilation.html.
#[derive(Debug, Serialize, Clone)]
pub struct CfgNot {
    #[serde(serialize_with = "serialize_with_token_string")]
    pub not: syn::Ident,
    pub pred: CfgPredicate,
}

impl syn::parse::Parse for CfgNot {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let not: syn::Ident = input.parse()?;
        if not != "not" {
            return Err(syn::Error::new(not.span(), ""));
        }
        let paren_input;
        parenthesized!(paren_input in input);
        let pred = paren_input.parse()?;
        Ok(CfgNot { not, pred })
    }
}
