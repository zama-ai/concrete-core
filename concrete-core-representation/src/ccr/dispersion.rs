use super::*;
use serde::Serialize;

/// A node representing an dispersion newtype.
#[derive(Serialize, Clone, Debug)]
pub struct Dispersion {
    #[serde(serialize_with = "serialize_with_token_string")]
    pub item_struct: syn::ItemStruct,
}

impl Dispersion {
    /// From an `ItemMod` syn ast node, pointing to the `specification/dispersion` module, extracts
    /// a vec of `Dispersion`.
    pub(crate) fn extract_all(dispersion_module: &syn::ItemMod) -> Vec<Dispersion> {
        // INVARIANT: All public structs in the `specificaiton/dispersion` module, are dispersions.
        dispersion_module
            .content
            .as_ref()
            .expect("The `specification/dispersion` module has no content...")
            .1
            .iter()
            .filter_map(|item| {
                probe!(
                    Some(item),
                    syn::Item::Struct(item_struct) => item_struct,
                    item_struct ?> matches!(item_struct.vis, syn::Visibility::Public(_)),
                    item_struct -> Dispersion { item_struct: item_struct.to_owned()}
                )
            })
            .collect()
    }
}
