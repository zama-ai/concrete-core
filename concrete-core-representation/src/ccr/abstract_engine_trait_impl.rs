use super::*;
use serde::Serialize;

/// A node representing an implementation of the `AbstractEngine` trait.
#[derive(Serialize, Clone, Debug)]
pub struct AbstractEngineTraitImpl {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub item_impl: syn::ItemImpl,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub engine_type_ident: syn::Ident,
}

impl AbstractEngineTraitImpl {
    /// From an `ItemMod` syn ast node, pointing to a module in a backend, recursively extracts all
    /// the `AbstractEngineTraitImpl`.
    pub fn extract_all(
        cfg_stack_so_far: &CfgStack,
        module: &syn::ItemMod,
    ) -> Vec<AbstractEngineTraitImpl> {
        // INVARIANT: engine types are identified with their original identifier in the abstract
        // engine impl, not with a path, nor an alias.
        // INVARIANT: the abstract engine trait is identified by its original identifier
        // `AbstractEngine`
        let mut output = Vec::new();
        if module.content.is_none() {
            return output;
        }

        for item in module.content.as_ref().unwrap().1.iter() {
            // If the item is a module, we recurse:
            if let syn::Item::Mod(item_mod) = item {
                output.extend(
                    AbstractEngineTraitImpl::extract_all(
                        &cfg_stack_so_far.concat_attrs(item_mod.attrs.as_slice()),
                        item_mod,
                    )
                    .into_iter(),
                );
                continue;
            }

            // If the item is an abstract engine impl, we add it.
            let maybe_item_impl = probe!(
                Some(item),
                syn::Item::Impl(item_impl) => item_impl
            );
            let maybe_abstract_engine_impl = probe!(
                maybe_item_impl,
                item_impl >> item_impl.trait_.as_ref(),
                trait_ >> trait_.1.segments.first(),
                trait_path -> &trait_path.ident,
                trait_ident ?> *trait_ident == "AbstractEngine",
                X> maybe_item_impl,
                item_impl -> item_impl.self_ty.as_ref(),
                syn::Type::Path(self_path) => self_path,
                self_path ?> self_path.path.segments.len() == 1,
                self_path >> self_path.path.segments.first(),
                self_segment -> &self_segment.ident,
                self_ident >> pack_somes!(Some(self_ident), maybe_item_impl),
                tuple -> {
                    let (engine_type_ident, item_impl) = tuple;
                    AbstractEngineTraitImpl{
                        cfg: cfg_stack_so_far.concat_attrs(item_impl.attrs.as_slice()),
                        item_impl: item_impl.to_owned(),
                        engine_type_ident: engine_type_ident.to_owned()
                    }
                }
            );
            if let Some(abstract_engine_trait_impl) = maybe_abstract_engine_impl {
                output.push(abstract_engine_trait_impl);
            }
        }
        output
    }

    /// Returns the `syn` node pointing to the constructor of the implementation.
    pub fn get_constructor(&self) -> &syn::ImplItemMethod {
        // INVARIANT: The constructor is called `new`
        self.item_impl
            .items
            .iter()
            .find_map(|item| {
                probe!(
                    Some(item),
                    syn::ImplItem::Method(impl_item_method) => impl_item_method,
                    impl_item_method ?> impl_item_method.sig.ident == "new"
                )
            })
            .unwrap()
    }

    /// Returns the `syn` node pointing to the `Parameters` associated type of the implementation.
    pub fn get_parameters_associated_type(&self) -> &syn::Type {
        // INVARIANT: The constructor take a single parameter whose type is the associated
        // `Parameters` type.
        // INVARIANT: The `Parameters` type is either a Path or a tuple of paths.
        self.item_impl
            .items
            .iter()
            .find_map(|item| {
                probe!(
                    Some(item),
                    syn::ImplItem::Type(impl_item_type) => impl_item_type,
                    impl_item_type ?> impl_item_type.ident == "Parameters",
                    impl_item_type -> &impl_item_type.ty
                )
            })
            .unwrap()
    }
}
