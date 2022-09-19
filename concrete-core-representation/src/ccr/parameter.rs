use super::*;
use serde::Serialize;

/// A node representing an parameter newtype.
#[derive(Serialize, Clone, Debug)]
pub struct Parameter {
    #[serde(serialize_with = "serialize_with_token_string")]
    pub item_struct: syn::ItemStruct,
}

impl Parameter {
    /// From an `ItemMod` syn ast node, pointing to the `specification/parameters` module, extracts
    /// a vec of `Parameter`.
    pub(crate) fn extract_all(parameters_module: &syn::ItemMod) -> Vec<Parameter> {
        // INVARIANT: All public structs in the `specificaiton/parameters` module, are parameters.
        parameters_module
            .content
            .as_ref()
            .expect("The `specification/parameters` module has no content...")
            .1
            .iter()
            .filter_map(|item| {
                probe!(
                    Some(item),
                    syn::Item::Struct(item_struct) => item_struct,
                    item_struct ?> matches!(item_struct.vis, syn::Visibility::Public(_)),
                    item_struct -> Parameter{ item_struct: item_struct.to_owned()}
                )
            })
            .collect()
    }
}
