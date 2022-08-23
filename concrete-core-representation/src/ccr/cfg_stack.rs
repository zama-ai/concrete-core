use super::*;
use serde::Serialize;

/// A node representing a stack of `cfg` attributes.
///
/// As we go deeper in the nesting of modules and items, we apply more and more cfg attributes. This
/// structure represents that.
#[derive(Serialize, Clone, Debug)]
pub struct CfgStack(#[serde(serialize_with = "serialize_vec_with_token_string")] Vec<TokenStream2>);

impl CfgStack {
    /// Creates an empty stack.
    pub fn empty() -> CfgStack {
        CfgStack(Vec::new())
    }

    /// Creates a stack from a slice of syn attributes.
    pub fn from_attr(attrs: &[syn::Attribute]) -> Self {
        let mut stack = Self::empty();
        stack.push_attrs(attrs);
        stack
    }

    /// Adds a set of syn attributes to an existing stack.
    pub fn push_attrs(&mut self, attrs: &[syn::Attribute]) {
        attrs
            .iter()
            .filter_map(|att| {
                probe!(
                    Some(att),
                    att >> att.path.get_ident(),
                    ident ?> *ident == "cfg",
                    X> Some(att.tokens.clone())
                )
            })
            .for_each(|ts| self.0.push(ts));
    }

    /// Creates a new stack which is a copy of the current stack, to which the `attrs` attributes
    /// were pushed.
    pub fn concat_attrs(&self, attrs: &[syn::Attribute]) -> CfgStack {
        let mut output = self.clone();
        output.push_attrs(attrs);
        output
    }
}
