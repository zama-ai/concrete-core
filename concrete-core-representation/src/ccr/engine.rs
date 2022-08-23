use super::*;
use serde::Serialize;

/// A node representing a `concrete-core` engine.
#[derive(Serialize, Clone, Debug)]
pub struct Engine {
    pub definition: EngineTypeDefinition,
    pub abstract_engine_impl: AbstractEngineTraitImpl,
    pub engine_impls: Vec<EngineTraitImpl>,
}

impl Engine {
    /// From an `ItemMod` syn ast node, pointing to a module in a backend, recursively extracts all
    /// the `Engine`.
    pub fn extract_all(cfg_stack_so_far: &CfgStack, module: &syn::ItemMod) -> Vec<Engine> {
        // INVARIANT: All the engine objects contain `Engine` in their names.
        // INVARIANT: All the engine objects are declared with `pub` visibility.

        // Gather abstract engine impls
        let abstract_engine_impls = AbstractEngineTraitImpl::extract_all(cfg_stack_so_far, module);
        // Gather all struct definitions
        let mut engine_definitions = EngineTypeDefinition::extract_all(cfg_stack_so_far, module);
        // Gather engine impls
        let mut engine_impls = EngineTraitImpl::extract_all(cfg_stack_so_far, module);

        // Match the definitions, abstract engine impls and engine impls
        abstract_engine_impls
            .into_iter()
            .map(|abstract_engine_impl| {
                let engine_impls = pull_all_matches(&mut engine_impls, |engine_impl| {
                    engine_impl.engine_type_ident == abstract_engine_impl.engine_type_ident
                });
                let definition = pull_first_match(&mut engine_definitions, |engine_def| {
                    engine_def.item_struct.ident == abstract_engine_impl.engine_type_ident
                });
                Engine {
                    engine_impls,
                    abstract_engine_impl,
                    definition,
                }
            })
            .collect()
    }
}
