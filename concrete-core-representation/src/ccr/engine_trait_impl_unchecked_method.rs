use super::*;
use serde::Serialize;

/// A node representing the unchecked method of an implementation of an `*Engine` trait.
#[derive(Serialize, Clone, Debug)]
pub struct EngineTraitImplUncheckedMethod {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub method: syn::ImplItemMethod,
}

impl EngineTraitImplUncheckedMethod {
    /// From an `ItemImpl` syn ast node, pointing to an engine trait impl block, extracts the
    /// `EngineTraitImplUncheckedMethod`.
    pub fn extract(
        cfg_stack_so_far: &CfgStack,
        impl_block: &syn::ItemImpl,
    ) -> EngineTraitImplUncheckedMethod {
        // INVARIANT: The unchecked entry point is the first unsafe method.
        impl_block
            .items
            .iter()
            .find_map(|impl_item| {
                probe!(
                    Some(impl_item),
                    syn::ImplItem::Method(method) => method,
                    method ?> method.sig.unsafety.is_some(),
                    method -> EngineTraitImplUncheckedMethod{
                        cfg: cfg_stack_so_far.to_owned(),
                        method: method.to_owned()
                    }
                )
            })
            .unwrap()
    }
}
