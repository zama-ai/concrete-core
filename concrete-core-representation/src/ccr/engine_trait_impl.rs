use super::*;
use serde::Serialize;

/// A node representing an implementation of an `*Engine` trait.
#[derive(Serialize, Clone, Debug)]
pub struct EngineTraitImpl {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub engine_trait_ident: syn::Ident,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub engine_type_ident: syn::Ident,
    pub checked_method: EngineTraitImplCheckedMethod,
    pub unchecked_method: EngineTraitImplUncheckedMethod,
    pub(crate) engine_trait_parameters:
        ReadyOrNot<Vec<EngineTraitImplGenericArgument>, syn::AngleBracketedGenericArguments>,
}

impl EngineTraitImpl {
    /// Return the generic parameters of the engine trait.
    pub fn engine_trait_parameters(&self) -> &[EngineTraitImplGenericArgument] {
        self.engine_trait_parameters.as_ref().unwrap().as_slice()
    }
}

impl EngineTraitImpl {
    /// From an `ItemMod` syn ast node, pointing to a module in a backend, recursively extracts all
    /// the `EngineTraitImpl`.
    pub fn extract_all(cfg_stack_so_far: &CfgStack, module: &syn::ItemMod) -> Vec<EngineTraitImpl> {
        // INVARIANT: engine types are identified with their original identifier in the engine impl,
        // not with a path, nor an alias.
        // INVARIANT: the engine trait is identified by its original identifier containing `Engine`
        let mut output = Vec::new();
        if module.content.is_none() {
            return output;
        }

        for item in module.content.as_ref().unwrap().1.iter() {
            // If the item is a module, we recurse:
            if let syn::Item::Mod(item_mod) = item {
                output.extend(
                    EngineTraitImpl::extract_all(
                        &cfg_stack_so_far.concat_attrs(item_mod.attrs.as_slice()),
                        item_mod,
                    )
                    .into_iter(),
                );
                continue;
            }

            // If the item is an engine impl, we add it.
            let maybe_item_impl = probe!(
                Some(item),
                syn::Item::Impl(item_impl) => item_impl
            );
            let maybe_engine_impl = probe!(
                maybe_item_impl,
                item_impl >> item_impl.trait_.as_ref(),
                trait_ >> trait_.1.segments.first(),
                trait_path -> &trait_path.ident,
                trait_ident ?> *trait_ident != "AbstractEngine",
                trait_ident ?> *trait_ident != "AbstractEngineSeal",
                trait_ident ?> trait_ident.to_string().contains("Engine"),
                X> maybe_item_impl
            );
            let maybe_engine_trait_ident = probe!(
                maybe_engine_impl,
                item_impl >> item_impl.trait_.as_ref(),
                trait_ >> trait_.1.segments.last(),
                trait_segment -> trait_segment.ident.to_owned()
            );
            let maybe_engine_type_ident = probe!(
                maybe_engine_impl,
                item_impl -> item_impl.self_ty.as_ref(),
                syn::Type::Path(self_ty_path) => self_ty_path,
                self_ty_path >> self_ty_path.path.segments.first(),
                self_segment -> self_segment.ident.to_owned()
            );
            let maybe_checked_method = probe!(
                maybe_engine_impl,
                item_impl -> EngineTraitImplCheckedMethod::extract(cfg_stack_so_far, item_impl)
            );
            let maybe_unchecked_method = probe!(
                maybe_engine_impl,
                item_impl -> EngineTraitImplUncheckedMethod::extract(cfg_stack_so_far, item_impl)
            );
            // The generic arguments can not be processed right away, because we don't yet
            // know all the items exported by the backend (hence we can not properly sort
            // them).
            let maybe_engine_trait_parameters = probe!(
                maybe_engine_impl,
                item_impl >> item_impl.trait_.as_ref(),
                trait_ >> trait_.1.segments.last(),
                trait_segment -> &trait_segment.arguments,
                syn::PathArguments::AngleBracketed(generics) => generics,
                generics -> ReadyOrNot::Not(generics.to_owned())
            );
            let maybe_engine_trait_impl = probe!(
                pack_somes!(
                    maybe_engine_impl,
                    maybe_engine_trait_ident,
                    maybe_checked_method,
                    maybe_unchecked_method,
                    maybe_engine_trait_parameters,
                    maybe_engine_type_ident
                ),
                tuple -> {
                    let (
                        engine_impl,
                        engine_trait_ident,
                        checked_method,
                        unchecked_method,
                        engine_trait_parameters,
                        engine_type_ident
                    ) = tuple;
                    EngineTraitImpl{
                        cfg: cfg_stack_so_far.concat_attrs(engine_impl.attrs.as_slice()),
                        engine_trait_ident,
                        checked_method,
                        unchecked_method,
                        engine_trait_parameters,
                        engine_type_ident
                    }
                }
            );
            if let Some(engine_trait_impl) = maybe_engine_trait_impl {
                output.push(engine_trait_impl);
                continue;
            }
        }
        output
    }
}
