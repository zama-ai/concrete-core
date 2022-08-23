use super::*;
use serde::Serialize;

/// A node representing an implementation of an `*Entity` trait.
#[derive(Serialize, Clone, Debug)]
pub struct EntityTraitImpl {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub item_impl: syn::ItemImpl,
}

impl EntityTraitImpl {
    /// From an `ItemMod` syn ast node, pointing to a module inside a backend, recursively extract
    /// all the `EntityTraitImpl` nodes.
    pub fn extract_all(cfg_stack_so_far: &CfgStack, module: &syn::ItemMod) -> Vec<EntityTraitImpl> {
        // INVARIANT: entity types are identified with their original identifier in the entity impl,
        // not with a path, nor an alias.
        // INVARIANT: the entity trait is identified by its original identifier containing `Entity`
        let mut output = Vec::new();
        if module.content.is_none() {
            return output;
        }

        let module_items = &module.content.as_ref().unwrap().1;
        for item in module_items.iter() {
            // If the item is a module, we recurse.
            if let syn::Item::Mod(item_mod) = item {
                output.extend(
                    EntityTraitImpl::extract_all(
                        &cfg_stack_so_far.concat_attrs(item_mod.attrs.as_slice()),
                        item_mod,
                    )
                    .into_iter(),
                );
                continue;
            }

            // If the item is an entity impl, we add it to the output.
            let maybe_item_impl = probe!(
                Some(item),
                syn::Item::Impl(item_impl) => item_impl
            );
            let maybe_entity_impl = probe!(
                maybe_item_impl,
                item_impl >> item_impl.trait_.as_ref(),
                trait_ >> trait_.1.segments.first(),
                trait_path -> &trait_path.ident,
                trait_ident ?> *trait_ident != "AbstractEntity",
                trait_ident ?> trait_ident.to_string().contains("Entity"),
                X> maybe_item_impl,
                item_impl -> item_impl.self_ty.as_ref(),
                syn::Type::Path(self_path) => self_path,
                self_path ?> self_path.path.segments.len() == 1,
                X> maybe_item_impl,
                item_impl -> EntityTraitImpl {
                        cfg: cfg_stack_so_far.concat_attrs(item_impl.attrs.as_slice()),
                        item_impl: item_impl.to_owned(),
                    }
            );
            if let Some(node) = maybe_entity_impl {
                output.push(node);
                continue;
            }
        }
        output
    }
}
