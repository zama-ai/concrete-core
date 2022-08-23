use super::*;
use serde::Serialize;

/// A node representing a config object.
#[derive(Serialize, Clone, Debug)]
pub struct Config {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub item_struct: syn::ItemStruct,
}

impl Config {
    /// From an `ItemMod` syn ast node, pointing to a module in a backend, recursively extracts all
    /// the `Config`.
    pub fn extract_all(cfg_stack_so_far: &CfgStack, module: &syn::ItemMod) -> Vec<Config> {
        // INVARIANT: All the config objects contain `Config` in their names.
        // INVARIANT: All the config objects are declared with `pub` visibility.

        // Gather all struct definitions
        let struct_definitions = StructDefinition::extract_all(cfg_stack_so_far, module);
        struct_definitions
            .into_iter()
            .filter_map(|struct_def| {
                probe!(
                    Some(struct_def),
                    struct_def ?> struct_def.item_struct.ident.to_string().contains("Config"),
                    struct_def -> Config{
                        cfg: struct_def.cfg,
                        item_struct: struct_def.item_struct
                    }
                )
            })
            .collect()
    }
}
