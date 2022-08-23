use super::*;

/// A temporary structure that stores a struct definition before it is casted to a `ccr` node.
#[derive(Clone)]
pub(crate) struct StructDefinition {
    pub(crate) cfg: CfgStack,
    pub(crate) item_struct: syn::ItemStruct,
}

impl StructDefinition {
    /// From a `ItemMod` syn ast node, pointing to a module in a backend, recursively extract all
    /// the public structure definitions.
    pub(crate) fn extract_all(
        cfg_stack_so_far: &CfgStack,
        module: &syn::ItemMod,
    ) -> Vec<StructDefinition> {
        // INVARIANT: concrete-core items are publicly visible.
        let mut output = Vec::new();
        if module.content.is_none() {
            return output;
        }

        for item in module.content.as_ref().unwrap().1.iter() {
            // If the item is a module, we recurse:
            if let syn::Item::Mod(item_mod) = item {
                output.extend(
                    StructDefinition::extract_all(
                        &cfg_stack_so_far.concat_attrs(item_mod.attrs.as_slice()),
                        item_mod,
                    )
                    .into_iter(),
                );
                continue;
            }

            // If the item is a pub struct, we add it.
            let maybe_struct = probe!(
                Some(item),
                syn::Item::Struct(item_struct) => item_struct,
                item_struct ?> matches!(item_struct.vis, syn::Visibility::Public(_)),
                item_struct -> item_struct
            );
            if let Some(item_struct) = maybe_struct {
                output.push(StructDefinition {
                    cfg: cfg_stack_so_far.concat_attrs(item_struct.attrs.as_slice()),
                    item_struct: item_struct.to_owned(),
                });
            }
        }
        output
    }
}
