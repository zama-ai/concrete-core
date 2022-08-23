use super::*;
use serde::Serialize;

/// A node representing an implementation of the `AbstractEntity` trait.
#[derive(Serialize, Clone, Debug)]
pub struct AbstractEntityTraitImpl {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub item_impl: syn::ItemImpl,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub entity_type_ident: syn::Ident,
}

impl AbstractEntityTraitImpl {
    /// From an `ItemMod` syn ast node, pointing to a module in a backend, recursively extracts all
    /// the `AbstractEntityTraitImpl`.
    pub(crate) fn extract_all(
        cfg_stack_so_far: &CfgStack,
        module: &syn::ItemMod,
    ) -> Vec<AbstractEntityTraitImpl> {
        // INVARIANT: entity types are identified with their original identifier in the abstract
        // entity impl, not with a path, nor an alias.
        // INVARIANT: the abstract entity trait is identified by its original identifier
        // `AbstractEntity`

        let mut output = Vec::new();
        if module.content.is_none() {
            return output;
        }

        for item in module.content.as_ref().unwrap().1.iter() {
            // If the item is a module, we recurse.
            if let syn::Item::Mod(item_mod) = item {
                output.extend(AbstractEntityTraitImpl::extract_all(
                    &cfg_stack_so_far.concat_attrs(item_mod.attrs.as_slice()),
                    item_mod,
                ));
                continue;
            }

            // If the item is an abstract entity impl, we add it to the output.
            let maybe_item_impl = probe!(
                Some(item),
                syn::Item::Impl(item_impl) => item_impl
            );
            let maybe_abstract_entity_impl = probe!(
                maybe_item_impl,
                item_impl >> item_impl.trait_.as_ref(),
                trait_ >> trait_.1.segments.first(),
                trait_path -> &trait_path.ident,
                trait_ident ?> *trait_ident == "AbstractEntity",
                X> maybe_item_impl,
                item_impl -> item_impl.self_ty.as_ref(),
                syn::Type::Path(self_path) => self_path,
                self_path ?> self_path.path.segments.len() == 1,
                self_path >> self_path.path.segments.first(),
                self_segment -> &self_segment.ident,
                self_ident >> pack_somes!(Some(self_ident), maybe_item_impl),
                tuple -> {
                    let (entity_type_ident, item_impl) = tuple;
                    AbstractEntityTraitImpl{
                        cfg: cfg_stack_so_far.concat_attrs(item_impl.attrs.as_slice()),
                        item_impl: item_impl.to_owned(),
                        entity_type_ident: entity_type_ident.to_owned()
                    }
                }
            );
            if let Some(node) = maybe_abstract_entity_impl {
                output.push(node);
            }
        }
        output
    }
}
