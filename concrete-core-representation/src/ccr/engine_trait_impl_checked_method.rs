use super::*;
use serde::Serialize;

/// A node representing the checked method of an implementation of an `*Engine` trait.
#[derive(Serialize, Clone, Debug)]
pub struct EngineTraitImplCheckedMethod {
    pub cfg: CfgStack,
    pub(crate) args: ReadyOrNot<Vec<EngineTraitImplArg>, syn::Signature>,
    pub(crate) return_: ReadyOrNot<EngineTraitImplReturn, syn::Signature>,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub ident: syn::Ident,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub body: syn::Block,
}

impl EngineTraitImplCheckedMethod {
    /// From an `ItemImpl` syn ast node, pointing to an engine trait impl block, extracts the
    /// `EngineTraitImplCheckedMethod`.
    pub fn extract(
        cfg_stack_so_far: &CfgStack,
        impl_block: &syn::ItemImpl,
    ) -> EngineTraitImplCheckedMethod {
        // INVARIANT: The checked entry point is the only safe method.
        impl_block
            .items
            .iter()
            .find_map(|impl_item| {
                probe!(
                    Some(impl_item),
                    syn::ImplItem::Method(method) => method,
                    method ?> method.sig.unsafety.is_none(),
                    method -> EngineTraitImplCheckedMethod{
                        cfg: cfg_stack_so_far.to_owned(),
                        args: ReadyOrNot::Not(method.sig.clone()),
                        return_: ReadyOrNot::Not(method.sig.clone()),
                        ident: method.sig.ident.clone(),
                        body: method.block.clone()
                    }
                )
            })
            .unwrap()
    }

    /// Returns the arguments of the checked method.
    pub fn args(&self) -> &[EngineTraitImplArg] {
        self.args.as_ref().unwrap()
    }

    /// Returns the return type of the checked method.
    pub fn return_(&self) -> &EngineTraitImplReturn {
        self.return_.as_ref().unwrap()
    }
}
