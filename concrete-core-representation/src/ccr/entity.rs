use super::*;
use serde::Serialize;

/// A node representing a `concrete-core` entity.
#[derive(Serialize, Clone, Debug)]
pub struct Entity {
    pub definition: EntityTypeDefinition,
    pub abstract_entity_impl: AbstractEntityTraitImpl,
    pub entity_impl: EntityTraitImpl,
}

impl Entity {
    /// From an `ItemMod` syn ast node, pointing to a backend module, extracts all the `Entity`
    /// nodes.
    pub(crate) fn extract_all(cfg_stack_so_far: &CfgStack, module: &syn::ItemMod) -> Vec<Entity> {
        // Gather all struct definitions
        let mut struct_definitions = StructDefinition::extract_all(cfg_stack_so_far, module);
        // Gather abstract entity trait impls
        let abstract_entity_trait_impls =
            AbstractEntityTraitImpl::extract_all(cfg_stack_so_far, module);
        // Gather entity trait impls
        let mut entity_trait_impls = EntityTraitImpl::extract_all(cfg_stack_so_far, module);

        // Match the different pieces of the entities
        abstract_entity_trait_impls
            .into_iter()
            .map(|abstract_entity_impl| {
                let entity_impl = pull_first_match(&mut entity_trait_impls, |entity_impl| {
                    entity_impl.item_impl.self_ty == abstract_entity_impl.item_impl.self_ty
                });
                let definition = pull_first_match(&mut struct_definitions, |definition| {
                    if let syn::Type::Path(type_path) =
                        abstract_entity_impl.item_impl.self_ty.as_ref()
                    {
                        type_path.path.segments.last().unwrap().ident
                            == definition.item_struct.ident
                    } else {
                        false
                    }
                });
                let ownership = if definition.item_struct.ident.to_string().contains("MutView") {
                    EntityOwnership::MutView
                } else if definition.item_struct.ident.to_string().contains("View") {
                    EntityOwnership::View
                } else {
                    EntityOwnership::Owned
                };
                let definition = EntityTypeDefinition {
                    cfg: definition.cfg,
                    item_struct: definition.item_struct,
                    ownership,
                };
                Entity {
                    entity_impl,
                    abstract_entity_impl,
                    definition,
                }
            })
            .collect()
    }
}
