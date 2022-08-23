use super::*;
use serde::Serialize;

/// A node representing the definition of an engine type.
#[derive(Serialize, Clone, Debug)]
pub struct EngineTypeDefinition {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub item_struct: syn::ItemStruct,
}

impl EngineTypeDefinition {
    /// From an `ItemMod` syn ast node, pointing to a module in a backend, recursively extracts all
    /// the `Engine` type definitions.
    pub fn extract_all(
        cfg_stack_so_far: &CfgStack,
        module: &syn::ItemMod,
    ) -> Vec<EngineTypeDefinition> {
        // INVARIANT: All the engine objects contain `Engine` in their names.
        // INVARIANT: All the engine objects are declared with `pub` visibility.

        // Gather all struct definitions
        let struct_definitions = StructDefinition::extract_all(cfg_stack_so_far, module);
        struct_definitions
            .into_iter()
            .filter_map(|struct_def| {
                probe!(
                    Some(struct_def),
                    struct_def ?> struct_def.item_struct.ident.to_string().contains("Engine"),
                    struct_def -> EngineTypeDefinition{
                        cfg: struct_def.cfg,
                        item_struct: struct_def.item_struct
                    }
                )
            })
            .collect()
    }

    /// Returns the `syn` node pointing to the engine identifier.
    pub fn get_name(&self) -> &syn::Ident {
        &self.item_struct.ident
    }
}
