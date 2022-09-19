use super::*;

/// The top node of the `ccr`, representing a whole `concrete-core` repository.
#[derive(Serialize, Clone, Debug)]
pub struct ConcreteCore {
    pub backends: Vec<Backend>,
    pub dispersions: Vec<Dispersion>,
    pub parameters: Vec<Parameter>,
}

/// A private enum used to classify the identifiers.
enum IdentKind {
    OwnedEntity(syn::Ident),
    ViewEntity(syn::Ident),
    MutViewEntity(syn::Ident),
    Config(syn::Ident),
    Parameter(syn::Ident),
    Dispersion(syn::Ident),
    Numeric(syn::Ident),
    Unknown(syn::Ident),
}

impl ConcreteCore {
    /// From a `File` syn ast node, pointing to the root file of the `concrete-core` sources,
    /// extract the top `ConcreteCore` node.
    pub(crate) fn extract(cfg_stack_so_far: &CfgStack, root: &syn::File) -> ConcreteCore {
        // INVARIANT: The root module contains a `backend` module
        // INVARIANT: Two backends can not export items with the same name

        // Gather the backends
        let backends_module = root
            .items
            .iter()
            .cloned()
            .find_map(|item| {
                if let syn::Item::Mod(item_mod) = item {
                    if item_mod.ident == "backends" {
                        return Some(item_mod);
                    }
                }
                None
            })
            .expect("Failed to retrieve the `backends` module.");
        let mut backends = Backend::extract_all(cfg_stack_so_far, &backends_module);

        // Gather the dispersions
        let dispersion_module = root
            .items
            .iter()
            .cloned()
            .find_map(|item| {
                if let syn::Item::Mod(item_mod) = item {
                    if item_mod.ident == "specification" {
                        return Some(item_mod);
                    }
                }
                None
            })
            .expect("Failed to retrieve the `specification` module.")
            .content
            .unwrap()
            .1
            .iter()
            .find_map(|item| {
                if let syn::Item::Mod(item_mod) = item {
                    if item_mod.ident == "dispersion" {
                        return Some(item_mod);
                    }
                }
                None
            })
            .expect("Failed to retrieve the `dispersion` module.")
            .to_owned();
        let dispersions = Dispersion::extract_all(&dispersion_module);

        // Gather the parameters
        let parameters_module = root
            .items
            .iter()
            .cloned()
            .find_map(|item| {
                if let syn::Item::Mod(item_mod) = item {
                    if item_mod.ident == "specification" {
                        return Some(item_mod);
                    }
                }
                None
            })
            .expect("Failed to retrieve the `specification` module.")
            .content
            .unwrap()
            .1
            .iter()
            .find_map(|item| {
                if let syn::Item::Mod(item_mod) = item {
                    if item_mod.ident == "parameters" {
                        return Some(item_mod);
                    }
                }
                None
            })
            .expect("Failed to retrieve the `parameters` module.")
            .to_owned();
        let parameters = Parameter::extract_all(&parameters_module);

        // Now that we have gathered all the items of the different backends, we can push the
        // analysis further
        let all_entities: Vec<Entity> = backends
            .iter()
            .flat_map(|backend| backend.entities.iter().cloned())
            .collect();

        let all_config: Vec<Config> = backends
            .iter()
            .flat_map(|backend| backend.configs.iter().cloned())
            .collect();
        let mut all_engines: Vec<&mut Engine> = backends
            .iter_mut()
            .flat_map(|backend| backend.engines.iter_mut())
            .collect();
        let ident_classifier = |ident: &syn::Ident| -> IdentKind {
            if all_entities
                .iter()
                .filter(|ent| matches!(ent.definition.ownership, EntityOwnership::Owned))
                .any(|ent| ident == ent.definition.get_ident())
            {
                IdentKind::OwnedEntity(ident.to_owned())
            } else if all_entities
                .iter()
                .filter(|ent| matches!(ent.definition.ownership, EntityOwnership::View))
                .any(|ent| ident == ent.definition.get_ident())
            {
                IdentKind::ViewEntity(ident.to_owned())
            } else if all_entities
                .iter()
                .filter(|ent| matches!(ent.definition.ownership, EntityOwnership::MutView))
                .any(|ent| ident == ent.definition.get_ident())
            {
                IdentKind::MutViewEntity(ident.to_owned())
            } else if all_config
                .iter()
                .any(|conf| ident == &conf.item_struct.ident)
            {
                IdentKind::Config(ident.to_owned())
            } else if parameters
                .iter()
                .any(|param| *ident == param.item_struct.ident)
            {
                IdentKind::Parameter(ident.to_owned())
            } else if dispersions
                .iter()
                .any(|disp| *ident == disp.item_struct.ident)
            {
                IdentKind::Dispersion(ident.to_owned())
            } else if NUMERIC_IDENTS.iter().any(|num| ident == num) {
                IdentKind::Numeric(ident.to_owned())
            } else {
                IdentKind::Unknown(ident.to_owned())
            }
        };

        // Perform classification of engine impl generic args
        classify_engine_trait_impl_generic_args(&mut all_engines, ident_classifier);
        // Perform classification of checked method args
        classify_engine_trait_impl_args(&mut all_engines, ident_classifier);
        // Perform classification of checked method return
        classify_engine_trait_impl_return(&mut all_engines, ident_classifier);

        ConcreteCore {
            backends,
            dispersions,
            parameters,
        }
    }
}

fn classify_engine_trait_impl_generic_args(
    engines: &mut [&mut Engine],
    classifier: impl FnOnce(&syn::Ident) -> IdentKind + Copy,
) {
    // INVARIANT: Config and entity types generic arguments are provided as identifiers in the
    // engine trait impls.
    for engine_impl in engines
        .iter_mut()
        .flat_map(|eng| eng.engine_impls.iter_mut())
    {
        engine_impl.engine_trait_parameters.prepare(|param| {
            param.args.iter().map(|arg| {
                // We check if the argument is an owned entity
                let maybe_owned_entity = probe!(
                    Some(arg),
                    syn::GenericArgument::Type(type_) => type_,
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment -> &segment.ident,
                    ident -> classifier(ident),
                    IdentKind::OwnedEntity(_) => (),
                    X> Some(arg),
                    syn::GenericArgument::Type(arg) => arg,
                    arg -> EngineTraitImplGenericArgument::OwnedEntity(arg.to_owned())
                );
                if let Some(owned_entity) = maybe_owned_entity {return owned_entity }

                // We check if the argument is a view entity
                let maybe_view_entity = probe!(
                    Some(arg),
                    syn::GenericArgument::Type(type_) => type_,
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment -> &segment.ident,
                    ident -> classifier(ident),
                    IdentKind::ViewEntity(_) => (),
                    X> Some(arg),
                    syn::GenericArgument::Type(arg) => arg,
                    arg -> EngineTraitImplGenericArgument::ViewEntity(arg.to_owned())
                );
                if let Some(view_entity) = maybe_view_entity {return view_entity }

                // We check if the argument is a mut view entity
                let maybe_mut_view_entity = probe!(
                    Some(arg),
                    syn::GenericArgument::Type(type_) => type_,
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment -> &segment.ident,
                    ident -> classifier(ident),
                    IdentKind::MutViewEntity(_) => (),
                    X> Some(arg),
                    syn::GenericArgument::Type(arg) => arg,
                    arg -> EngineTraitImplGenericArgument::MutViewEntity(arg.to_owned())
                );
                if let Some(mut_view_entity) = maybe_mut_view_entity {return mut_view_entity }

                // We check if the argument is a config
                let maybe_config = probe!(
                    Some(arg),
                    syn::GenericArgument::Type(type_) => type_,
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment -> &segment.ident,
                    ident -> classifier(ident),
                    IdentKind::Config(_) => (),
                    X> Some(arg),
                    syn::GenericArgument::Type(arg) => arg,
                    arg -> EngineTraitImplGenericArgument::Config(arg.to_owned())
                );
                if let Some(config) = maybe_config {return config }

                // We check if the argument is a numeric
                let maybe_numeric = probe!(
                    Some(arg),
                    syn::GenericArgument::Type(type_) => type_,
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment -> &segment.ident,
                    ident -> classifier(ident),
                    IdentKind::Numeric(_) => (),
                    X> Some(arg),
                    syn::GenericArgument::Type(arg) => arg,
                    arg -> EngineTraitImplGenericArgument::Numeric(arg.to_owned())
                );
                if let Some(numeric) = maybe_numeric {return numeric }

                // We check if the argument is a slice of numeric
                let maybe_numeric_slice = probe!(
                    Some(arg),
                    syn::GenericArgument::Type(type_) => type_,
                    syn::Type::Reference(ref_) => ref_,
                    ref_ ?> ref_.mutability.is_none(),
                    ref_ -> ref_.elem.as_ref(),
                    syn::Type::Slice(slice) => slice,
                    slice -> slice.elem.as_ref(),
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment -> &segment.ident,
                    ident -> classifier(ident),
                    IdentKind::Numeric(_) => (),
                    X> Some(arg),
                    syn::GenericArgument::Type(arg) => arg,
                    arg -> EngineTraitImplGenericArgument::NumericSlice(arg.to_owned())
                );
                if let Some(numeric_slice) = maybe_numeric_slice {return numeric_slice }

                // We check if the argument is a mut slice of numeric
                let maybe_numeric_slice_mut = probe!(
                    Some(arg),
                    syn::GenericArgument::Type(type_) => type_,
                    syn::Type::Reference(ref_) => ref_,
                    ref_ ?> ref_.mutability.is_some(),
                    ref_ -> ref_.elem.as_ref(),
                    syn::Type::Slice(slice) => slice,
                    slice -> slice.elem.as_ref(),
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment -> &segment.ident,
                    ident -> classifier(ident),
                    IdentKind::Numeric(_) => (),
                    X> Some(arg),
                    syn::GenericArgument::Type(arg) => arg,
                    arg -> EngineTraitImplGenericArgument::NumericSliceMut(arg.to_owned())
                );
                if let Some(numeric_slice_mut) = maybe_numeric_slice_mut {return numeric_slice_mut }

                // We check if the argument is a mut slice of numeric
                let maybe_numeric_vec = probe!(
                    Some(arg),
                    syn::GenericArgument::Type(type_) => type_,
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment ?> segment.ident == "Vec",
                    segment -> &segment.arguments,
                    syn::PathArguments::AngleBracketed(v) => v,
                    arguments >> arguments.args.first(),
                    syn::GenericArgument::Type(v) => v,
                    syn::Type::Path(path) => path,
                    path >> path.path.segments.last(),
                    segment -> &segment.ident,
                    ident -> classifier(ident),
                    IdentKind::Numeric(_) => (),
                    X> Some(arg),
                    syn::GenericArgument::Type(arg) => arg,
                    arg -> EngineTraitImplGenericArgument::NumericVec(arg.to_owned())
                );
                if let Some(numeric_vec) = maybe_numeric_vec {return numeric_vec }

                // We could not recognize the argument :(
                if let syn::GenericArgument::Type(arg) = arg {
                    EngineTraitImplGenericArgument::Unknown(arg.to_owned())
                } else {
                    panic!("Only types are allowed to be passed as generic argument to the trait in an *Engine trait implementation.")
                }
            }).collect()
        });
    }
}

fn classify_engine_trait_impl_args(
    engines: &mut [&mut Engine],
    classifier: impl FnOnce(&syn::Ident) -> IdentKind + Copy,
) {
    // INVARIANT: Config and entity types arguments are provided as identifiers in the checked
    // method. INVARIANT: The pattern side of the argument is an identifier (not a pattern).
    // INVARIANT: Entities and config arguments to checked method  can only appear as path or
    // reference.

    // We loop through the engines impl blocks
    for engine_impl in engines
        .iter_mut()
        .flat_map(|eng| eng.engine_impls.iter_mut())
    {
        // We finish the analysis
        engine_impl.checked_method.args.prepare(|sig| {
            sig.inputs
                .iter()
                .filter_map(|arg| {
                    if let syn::FnArg::Receiver(_) = arg {
                        // The argument is &mut self, we don't treat this one.
                        return None;
                    }

                    let pat_type = probe!(Some(arg), syn::FnArg::Typed(n) => n).unwrap();
                    let pat_ident =
                        probe!(Some(pat_type.pat.as_ref()), syn::Pat::Ident(p) => p).unwrap();

                    // Detect if the argument is an owned entity
                    let maybe_owned_entity = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Path(path) => path,
                        path >> path.path.segments.last(),
                        segment -> classifier(&segment.ident),
                        IdentKind::OwnedEntity(_) =>
                            EngineTraitImplArg::OwnedEntity(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone()
                            )
                    );
                    if maybe_owned_entity.is_some() {
                        return maybe_owned_entity;
                    }

                    // Detect if the argument is a view entity
                    let maybe_view_entity = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Path(path) => path,
                        path >> path.path.segments.last(),
                        segment -> classifier(&segment.ident),
                        IdentKind::ViewEntity(_) =>
                            EngineTraitImplArg::ViewEntity(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone()
                            )
                    );
                    if maybe_view_entity.is_some() {
                        return maybe_view_entity;
                    }

                    // Detect if the argument is a mut view entity
                    let maybe_mut_view_entity = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Path(path) => path,
                        path >> path.path.segments.last(),
                        segment -> classifier(&segment.ident),
                        IdentKind::MutViewEntity(_) =>
                            EngineTraitImplArg::MutViewEntity(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone()
                            )
                    );
                    if maybe_mut_view_entity.is_some() {
                        return maybe_mut_view_entity;
                    }

                    // Detect if the argument is a parameter
                    let maybe_parameter = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Path(path) => path,
                        path >> path.path.segments.last(),
                        segment -> classifier(&segment.ident),
                        IdentKind::Parameter(_) =>
                            EngineTraitImplArg::Parameter(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone()
                            )
                    );
                    if maybe_parameter.is_some() {
                        return maybe_parameter;
                    }

                    // Detect if the argument is a dispersion
                    let maybe_dispersion = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Path(path) => path,
                        path >> path.path.segments.last(),
                        segment -> classifier(&segment.ident),
                        IdentKind::Dispersion(_) =>
                            EngineTraitImplArg::Dispersion(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone()
                            )
                    );
                    if maybe_dispersion.is_some() {
                        return maybe_dispersion;
                    }

                    // Detect if the argument is a numeric
                    let maybe_numeric = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Path(path) => path,
                        path >> path.path.segments.last(),
                        segment -> classifier(&segment.ident),
                        IdentKind::Numeric(_) =>
                            EngineTraitImplArg::Numeric(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone()
                            )
                    );
                    if maybe_numeric.is_some() {
                        return maybe_numeric;
                    }

                    // Detect if the argument is a vec of numeric
                    let maybe_numeric_vec = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Path(path) => path,
                        path >> path.path.segments.last(),
                        segment ?> segment.ident == "Vec",
                        segment -> &segment.arguments,
                        syn::PathArguments::AngleBracketed(v) => v,
                        arguments >> arguments.args.first(),
                        syn::GenericArgument::Type(v) => v,
                        syn::Type::Path(v) => v,
                        path >> path.path.segments.last(),
                        segment -> classifier(&segment.ident),
                        IdentKind::Numeric(ident) =>
                            EngineTraitImplArg::NumericVec(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone(),
                                ident
                            )
                    );
                    if maybe_numeric_vec.is_some() {
                        return maybe_numeric_vec;
                    }

                    // Detect if the argument is a numeric mut ref.
                    let maybe_numeric_mut_ref = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_some(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Path(ref_type) => ref_type,
                        ref_type >> ref_type.path.segments.last(),
                        ref_type -> &ref_type.ident,
                        ref_type_ident -> classifier(ref_type_ident),
                        IdentKind::Numeric(ident) =>
                            EngineTraitImplArg::NumericRefMut(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone(),
                                ident
                            )
                    );
                    if maybe_numeric_mut_ref.is_some() {
                        return maybe_numeric_mut_ref;
                    }

                    // Detect if the argument is a owned entity mut ref.
                    let maybe_owned_entity_mut_ref = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_some(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Path(ref_type) => ref_type,
                        ref_type >> ref_type.path.segments.last(),
                        ref_type -> &ref_type.ident,
                        ref_type_ident -> classifier(ref_type_ident),
                        IdentKind::OwnedEntity(ident) =>
                            EngineTraitImplArg::OwnedEntityRefMut(
                                        pat_ident.to_owned(),
                                        *pat_type.ty.clone(),
                                        ident
                            )
                    );
                    if maybe_owned_entity_mut_ref.is_some() {
                        return maybe_owned_entity_mut_ref;
                    }

                    // Detect if the argument is a mut view entity mut ref.
                    let maybe_owned_entity_mut_ref = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_some(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Path(ref_type) => ref_type,
                        ref_type >> ref_type.path.segments.last(),
                        ref_type -> &ref_type.ident,
                        ref_type_ident -> classifier(ref_type_ident),
                        IdentKind::MutViewEntity(ident) =>
                            EngineTraitImplArg::MutViewEntityRefMut(
                                        pat_ident.to_owned(),
                                        *pat_type.ty.clone(),
                                         ident
                            )
                    );
                    if maybe_owned_entity_mut_ref.is_some() {
                        return maybe_owned_entity_mut_ref;
                    }

                    // Detect if the argument is a numeric ref.
                    let maybe_numeric_ref = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_none(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Path(ref_type) => ref_type,
                        ref_type >> ref_type.path.segments.last(),
                        ref_type -> &ref_type.ident,
                        ref_type_ident -> classifier(ref_type_ident),
                        IdentKind::Numeric(ident) =>
                            EngineTraitImplArg::NumericRef(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone(),
                                ident
                            )
                    );
                    if maybe_numeric_ref.is_some() {
                        return maybe_numeric_ref;
                    }

                    // Detect if the argument is an owned entity ref.
                    let maybe_owned_entity_ref = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_none(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Path(ref_type) => ref_type,
                        ref_type >> ref_type.path.segments.last(),
                        ref_type -> &ref_type.ident,
                        ref_type_ident -> classifier(ref_type_ident),
                        IdentKind::OwnedEntity(ident) =>
                            EngineTraitImplArg::OwnedEntityRef(
                                        pat_ident.to_owned(),
                                        *pat_type.ty.clone(),
                                        ident
                            )
                    );
                    if maybe_owned_entity_ref.is_some() {
                        return maybe_owned_entity_ref;
                    }

                    // Detect if the argument is a view entity ref.
                    let maybe_view_entity_ref = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_none(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Path(ref_type) => ref_type,
                        ref_type >> ref_type.path.segments.last(),
                        ref_type -> &ref_type.ident,
                        ref_type_ident -> classifier(ref_type_ident),
                        IdentKind::ViewEntity(ident) =>
                            EngineTraitImplArg::ViewEntityRef(
                                        pat_ident.to_owned(),
                                        *pat_type.ty.clone(),
                                        ident
                            )
                    );
                    if maybe_view_entity_ref.is_some() {
                        return maybe_view_entity_ref;
                    }

                    // Detect if the argument is a config ref.
                    let maybe_config_ref = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_none(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Path(ref_type) => ref_type,
                        ref_type >> ref_type.path.segments.last(),
                        ref_type -> &ref_type.ident,
                        ref_type_ident -> classifier(ref_type_ident),
                        IdentKind::Config(ident) =>
                            EngineTraitImplArg::ConfigRef(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone(),
                                ident
                            )
                    );
                    if maybe_config_ref.is_some() {
                        return maybe_config_ref;
                    }

                    // Detect if the argument is a numeric mut slice.
                    let maybe_numeric_mut_slice = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_some(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Slice(slice_type) => slice_type,
                        slice_type -> slice_type.elem.as_ref(),
                        syn::Type::Path(slice_type) => slice_type,
                        slice_type >> slice_type.path.segments.last(),
                        slice_type -> &slice_type.ident,
                        slice_type_ident -> classifier(slice_type_ident),
                        IdentKind::Numeric(ident) =>
                            EngineTraitImplArg::NumericSliceMut(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone(),
                                ident
                            )
                    );
                    if maybe_numeric_mut_slice.is_some() {
                        return maybe_numeric_mut_slice;
                    }

                    // Detect if the argument is a numeric slice.
                    let maybe_numeric_slice = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_none(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Slice(slice_type) => slice_type,
                        slice_type -> slice_type.elem.as_ref(),
                        syn::Type::Path(slice_type) => slice_type,
                        slice_type >> slice_type.path.segments.last(),
                        slice_type -> &slice_type.ident,
                        slice_type_ident -> classifier(slice_type_ident),
                        IdentKind::Numeric(ident) =>
                            EngineTraitImplArg::NumericSlice(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone(),
                                ident
                            )
                    );
                    if maybe_numeric_slice.is_some() {
                        return maybe_numeric_slice;
                    }

                    // Detect if the argument is a numeric slice.
                    let maybe_config_slice = probe!(
                        Some(pat_type.ty.as_ref()),
                        syn::Type::Reference(ref_) => ref_,
                        ref_ ?> ref_.mutability.is_none(),
                        ref_ -> ref_.elem.as_ref(),
                        syn::Type::Slice(slice_type) => slice_type,
                        slice_type -> slice_type.elem.as_ref(),
                        syn::Type::Path(slice_type) => slice_type,
                        slice_type >> slice_type.path.segments.last(),
                        slice_type -> &slice_type.ident,
                        slice_type_ident -> classifier(slice_type_ident),
                        IdentKind::Config(ident) =>
                            EngineTraitImplArg::ConfigSlice(
                                pat_ident.to_owned(),
                                *pat_type.ty.clone(),
                                ident
                            )
                    );
                    if maybe_config_slice.is_some() {
                        return maybe_config_slice;
                    }

                    // We did not recognize the argument :(
                    Some(EngineTraitImplArg::Unknown(
                        pat_ident.to_owned(),
                        *pat_type.ty.clone(),
                    ))
                })
                .collect()
        });
    }
}

fn classify_engine_trait_impl_return(
    engines: &mut [&mut Engine],
    classifier: impl FnOnce(&syn::Ident) -> IdentKind + Copy,
) {
    // INVARIANT: Config and entity types arguments are provided as identifiers in the checked
    // method. INVARIANT: Checked method always return a Result written as an identifier.
    for engine_impl in engines
        .iter_mut()
        .flat_map(|eng| eng.engine_impls.iter_mut())
    {
        engine_impl.checked_method.return_.prepare(|sig| {
            // We retrieve the ok type of the return result.
            let ok_type = probe!(
                Some(&sig),
                sig -> &sig.output,
                syn::ReturnType::Type(_, n) => n,
                return_type -> return_type.as_ref(),
                syn::Type::Path(p) => p,
                path -> &path.path.segments.last().unwrap().arguments,
                syn::PathArguments::AngleBracketed(args) => args.args.first().unwrap(),
                syn::GenericArgument::Type(t) => t
            )
            .unwrap();

            // Detects if the ok type is the unit type.
            let maybe_unit = probe!(
                Some(&ok_type),
                syn::Type::Tuple(tuple) => tuple,
                tuple ?> tuple.elems.is_empty(),
                X> Some(ok_type),
                ok_type -> EngineTraitImplReturn::Unit(ok_type.to_owned())
            );
            if let Some(v) = maybe_unit {
                return v;
            }

            // Detects if the ok type is an owned entity
            let maybe_owned_entity = probe!(
                Some(&ok_type),
                syn::Type::Path(path) => path,
                path >> path.path.segments.last(),
                segment -> &segment.ident,
                ident -> classifier(ident),
                IdentKind::OwnedEntity(_) => EngineTraitImplReturn::OwnedEntity(ok_type.to_owned())
            );
            if let Some(v) = maybe_owned_entity {
                return v;
            }

            // Detects if the ok type is a view entity
            let maybe_view_entity = probe!(
                Some(&ok_type),
                syn::Type::Path(path) => path,
                path >> path.path.segments.last(),
                segment -> &segment.ident,
                ident -> classifier(ident),
                IdentKind::ViewEntity(_) => EngineTraitImplReturn::ViewEntity(ok_type.to_owned())
            );
            if let Some(v) = maybe_view_entity {
                return v;
            }

            // Detects if the ok type is a mut view entity
            let maybe_mut_view_entity = probe!(
                Some(&ok_type),
                syn::Type::Path(path) => path,
                path >> path.path.segments.last(),
                segment -> &segment.ident,
                ident -> classifier(ident),
                IdentKind::MutViewEntity(_) => EngineTraitImplReturn::MutViewEntity(ok_type.to_owned())
            );
            if let Some(v) = maybe_mut_view_entity {
                return v;
            }

            // Detects if the ok type is a config
            let maybe_config = probe!(
                Some(&ok_type),
                syn::Type::Path(path) => path,
                path >> path.path.segments.last(),
                segment -> &segment.ident,
                ident -> classifier(ident),
                IdentKind::Config(_) => EngineTraitImplReturn::Config(ok_type.to_owned())
            );
            if let Some(v) = maybe_config {
                return v;
            }

            // Detects if the ok type is a numeric
            let maybe_numeric = probe!(
                Some(&ok_type),
                syn::Type::Path(path) => path,
                path >> path.path.segments.last(),
                segment -> &segment.ident,
                ident -> classifier(ident),
                IdentKind::Numeric(_) => EngineTraitImplReturn::Numeric(ok_type.to_owned())
            );
            if let Some(v) = maybe_numeric {
                return v;
            }

            // Detects if the ok type is a numeric vec
            let maybe_numeric_vec = probe!(
                Some(&ok_type),
                syn::Type::Path(path) => path,
                path >> path.path.segments.last(),
                segment ?> segment.ident == "Vec",
                segment -> &segment.arguments,
                syn::PathArguments::AngleBracketed(args) => args,
                args >> args.args.last(),
                syn::GenericArgument::Type(t) => t,
                syn::Type::Path(p) => p,
                path >> path.path.segments.last(),
                arg -> classifier(&arg.ident),
                IdentKind::Numeric(_) => EngineTraitImplReturn::NumericVec(ok_type.to_owned())
            );
            if let Some(v) = maybe_numeric_vec {
                return v;
            }

            // Detects if the ok type is a numeric mut slice
            let maybe_numeric_slice_mut = probe!(
                Some(&ok_type),
                syn::Type::Reference(ref_) => ref_,
                ref_ ?> ref_.mutability.is_some(),
                ref_ -> ref_.elem.as_ref(),
                syn::Type::Slice(slice_type) => slice_type,
                slice_type -> slice_type.elem.as_ref(),
                syn::Type::Path(slice_type) => slice_type,
                slice_type >> slice_type.path.segments.last(),
                slice_type -> &slice_type.ident,
                slice_type_ident -> classifier(slice_type_ident),
                IdentKind::Numeric(_) =>
                    EngineTraitImplReturn::NumericSliceMut(
                        ok_type.to_owned()
                    )
            );
            if let Some(v) = maybe_numeric_slice_mut {
                return v;
            }

            // Detects if the ok type is a numeric slice
            let maybe_numeric_slice = probe!(
                Some(&ok_type),
                syn::Type::Reference(ref_) => ref_,
                ref_ ?> ref_.mutability.is_none(),
                ref_ -> ref_.elem.as_ref(),
                syn::Type::Slice(slice_type) => slice_type,
                slice_type -> slice_type.elem.as_ref(),
                syn::Type::Path(slice_type) => slice_type,
                slice_type >> slice_type.path.segments.last(),
                slice_type -> &slice_type.ident,
                slice_type_ident -> classifier(slice_type_ident),
                IdentKind::Numeric(_) =>
                    EngineTraitImplReturn::NumericSlice(
                        ok_type.to_owned()
                    )
            );
            if let Some(v) = maybe_numeric_slice {
                return v;
            }

            // We did not recognize the return type :(
            EngineTraitImplReturn::Unknown(ok_type.to_owned())
        });
    }
}
