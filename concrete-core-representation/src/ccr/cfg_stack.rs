use super::*;
use crate::ccr::cfg_lang::{CfgAll, CfgParenPredicate, CfgPredicate};
use serde::{Serialize, Serializer};

/// A node representing a stack of `cfg` attributes.
///
/// As we go deeper in the nesting of modules and items, we apply more and more cfg attributes. This
/// structure represents that.
#[derive(Clone, Debug)]
pub struct CfgStack(Vec<CfgPredicate>);

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
                    X> Some(att.tokens.clone()),
                    tokens -> syn::parse2::<CfgParenPredicate>(tokens.to_owned()).unwrap().predicate
                )
            })
            .for_each(|pd| self.0.push(pd));
    }

    /// Creates a new stack which is a copy of the current stack, to which the `attrs` attributes
    /// were pushed.
    pub fn concat_attrs(&self, attrs: &[syn::Attribute]) -> CfgStack {
        let mut output = self.clone();
        output.push_attrs(attrs);
        output
    }

    /// Parses the cfg stack into one big cfg expression, which can then be evaluated.
    pub fn cfg_expr(&self) -> CfgPredicate {
        if self.0.is_empty() {
            unreachable!()
        } else if self.0.len() == 1 {
            self.0.first().unwrap().to_owned()
        } else {
            let mut output = CfgAll {
                all: syn::Ident::new("all", syn::__private::Span::call_site()),
                content: syn::punctuated::Punctuated::new(),
            };
            for pred in self.0.iter() {
                output.content.push(pred.to_owned())
            }
            CfgPredicate::All(Box::new(output))
        }
    }
}

impl Serialize for CfgStack {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.cfg_expr().serialize(serializer)
    }
}
