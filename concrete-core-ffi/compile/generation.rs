use concrete_core_representation::{
    probe, ConcreteCore, Engine, EngineTraitImpl, EngineTraitImplArg, EntityOwnership,
};
use concrete_core_representation::{Entity, ToNameFragment};
use quote::{format_ident, quote, ToTokens};
use syn::__private::TokenStream2;
use syn::parse_quote;

pub fn generate_binding(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    output.extend(generate_all_engine_constructors(ccr));
    output.extend(generate_all_engine_destructors(ccr));
    output.extend(generate_all_entity_destructors(ccr));
    output.extend(generate_all_entity_clones(ccr));
    output.extend(generate_all_engine_impls(ccr));
    output
}

fn generate_all_engine_impls(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for engine_impl in ccr
        .backends
        .iter()
        .flat_map(|bck| bck.engines.iter())
        .flat_map(|eng| eng.engine_impls.iter())
    {
        output.extend(generate_checked_engine_impl(engine_impl));
        output.extend(generate_unchecked_engine_impl(engine_impl));
    }
    output
}

fn generate_checked_engine_impl(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    let engine_type = &engine_impl.engine_type_ident;
    let engine_method_name = &engine_impl.checked_method.ident;
    let name = generate_checked_engine_impl_name(engine_impl);
    let public_args = generate_checked_engine_impl_args(engine_impl);
    let public_ret = quote!();
    let private_exprs = quote!();
    let private_assign = quote!();
    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            engine: *mut #engine_type,
            #public_args
            #public_ret
        ) -> c_int {
            catch_panic(|| {
                let engine = get_mut_checked(engine).unwrap();
                let ret = engine
                    .#engine_method_name(#private_exprs)
                    .or_else(engine_error_as_readable_string)
                    .unwrap();
                #private_assign
            })
        }
    )
}

fn generate_checked_engine_impl_args(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for arg in engine_impl.checked_method.args().iter() {
        let arg = match arg {
            EngineTraitImplArg::OwnedEntity(pat_ident, typ) => quote!(#pat_ident: #typ, ),
            EngineTraitImplArg::OwnedEntityRef(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *const #inner_typ,)
            }
            EngineTraitImplArg::OwnedEntityRefMut(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: &mut #inner_typ,)
            }
            EngineTraitImplArg::ViewEntity(pat_ident, typ) => quote!(#pat_ident: #typ,),
            EngineTraitImplArg::ViewEntityRef(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *const #inner_typ,)
            }
            EngineTraitImplArg::MutViewEntity(pat_ident, typ) => {
                quote!(#pat_ident: #typ,)
            }
            EngineTraitImplArg::MutViewEntityRefMut(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *mut #inner_typ,)
            }
            EngineTraitImplArg::Config(pat_ident, typ) => {
                quote!(#pat_ident: #typ,)
            }
            EngineTraitImplArg::ConfigRef(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *const *inner_typ,)
            }
            EngineTraitImplArg::ConfigSlice(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *const RustSlice<#inner_typ>,)
            }
            EngineTraitImplArg::Parameter(pat_ident, typ) => {
                quote!(#pat_ident: #typ,)
            }
            EngineTraitImplArg::Dispersion(pat_ident, typ) => {
                quote!(#pat_ident: #typ,)
            }
            EngineTraitImplArg::Numeric(pat_ident, typ) => {
                quote!(#pat_ident: #typ,)
            }
            EngineTraitImplArg::NumericRef(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *const inner_typ,)
            }
            EngineTraitImplArg::NumericRefMut(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *mut #inner_typ,)
            }
            EngineTraitImplArg::NumericSlice(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *const RustSlice<#inner_typ>,)
            }
            EngineTraitImplArg::NumericSliceMut(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: *mut RustMutSlice<#inner_typ>,)
            }
            EngineTraitImplArg::NumericVec(pat_ident, _, inner_typ) => {
                quote!(#pat_ident: RustVec<#inner_typ>)
            }
            EngineTraitImplArg::Unknown(_, _) => {
                panic!("Encountered an unknown argument in {:?}", engine_impl)
            }
        };
        output.extend(arg);
    }
    output
}

fn generate_checked_engine_impl_name(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    format_ident!(
        "{}_{}",
        engine_impl.checked_method.ident,
        engine_impl
            .engine_trait_parameters()
            .iter()
            .map(ToNameFragment::to_fragment)
            .collect::<Vec<_>>()
            .join("_")
    )
    .into_token_stream()
}

fn generate_unchecked_engine_impl(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    quote!()
}

fn generate_all_entity_clones(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for entity in ccr.backends.iter().flat_map(|bck| bck.entities.iter()) {
        if matches!(entity.definition.ownership, EntityOwnership::Owned) {
            output.extend(generate_checked_entity_clone(entity));
            output.extend(generate_unchecked_entity_clone(entity));
        }
    }
    output
}

fn generate_checked_entity_clone(entity: &Entity) -> TokenStream2 {
    let name = format_ident!("clone_{}", entity.definition.to_fragment());
    let entity_type = &entity.definition.item_struct.ident;
    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            entity: *const #entity_type,
            result: *mut *mut #entity_type,
        ) -> c_int {
            catch_panic(|| {
                check_ptr_is_non_null_and_aligned(result).unwrap();
                *result = std::ptr::null_mut();
                let entity = get_ref_checked(entity).unwrap();
                let heap_allocated_entity_clone = Box::new(entity.clone());
                *result = Box::into_raw(heap_allocated_entity_clone);
            })
        }
    )
}

fn generate_unchecked_entity_clone(entity: &Entity) -> TokenStream2 {
    let name = format_ident!("clone_{}_unchecked", entity.definition.to_fragment());
    let entity_type = &entity.definition.item_struct.ident;
    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            entity: *const #entity_type,
            result: *mut *mut #entity_type,
        ) -> c_int {
            catch_panic(|| {
                *result = std::ptr::null_mut();
                let entity = &(*entity);
                let heap_allocated_entity_clone = Box::new(entity.clone());
                *result = Box::into_raw(heap_allocated_entity_clone);
            })
        }
    )
}

fn generate_all_entity_destructors(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for entity in ccr.backends.iter().flat_map(|bck| bck.entities.iter()) {
        output.extend(generate_checked_entity_destructor(entity));
        output.extend(generate_unchecked_entity_destructor(entity));
    }
    output
}

fn generate_checked_entity_destructor(entity: &Entity) -> TokenStream2 {
    let name = format_ident!("destroy_{}", entity.definition.to_fragment());
    let entity_type = &entity.definition.item_struct.ident;
    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            entity: *mut #entity_type,
        ) -> c_int {
            catch_panic(|| {
                check_ptr_is_non_null_and_aligned(entity).unwrap();
                Box::from_raw(entity);
            })
        }
    )
}

fn generate_unchecked_entity_destructor(entity: &Entity) -> TokenStream2 {
    let name = format_ident!("destroy_{}_unchecked", entity.definition.to_fragment());
    let entity_type = &entity.definition.item_struct.ident;
    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            entity: *mut #entity_type,
        ) -> c_int {
            catch_panic(|| {
                Box::from_raw(entity);
            })
        }
    )
}

fn generate_all_engine_destructors(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for engine in ccr.backends.iter().flat_map(|bck| bck.engines.iter()) {
        output.extend(generate_checked_engine_destructor(engine));
        output.extend(generate_unchecked_engine_destructor(engine));
    }
    output
}

fn generate_checked_engine_destructor(engine: &Engine) -> TokenStream2 {
    let name = format_ident!("destroy_{}", engine.definition.to_fragment());
    let engine_type = &engine.definition.item_struct.ident;
    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(engine: *mut #engine_type) -> c_int {
            catch_panic(|| {
                check_ptr_is_non_null_and_aligned(engine).unwrap();
                Box::from_raw(engine);
            })
        }
    )
}

fn generate_unchecked_engine_destructor(engine: &Engine) -> TokenStream2 {
    let name = format_ident!("destroy_{}_unchecked", engine.definition.to_fragment());
    let engine_type = &engine.definition.item_struct.ident;
    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(engine: *mut #engine_type) -> c_int {
            catch_panic(|| {
                Box::from_raw(engine);
            })
        }
    )
}

fn generate_all_engine_constructors(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for engine in ccr.backends.iter().flat_map(|bck| bck.engines.iter()) {
        output.extend(generate_checked_engine_constructor(engine));
        output.extend(generate_unchecked_engine_constructor(engine));
    }
    output
}

fn generate_checked_engine_constructor(engine: &Engine) -> TokenStream2 {
    let name = format_ident!("new_{}", engine.definition.to_fragment());
    let public_args = generate_checked_engine_constructor_public_args(
        engine.abstract_engine_impl.get_parameters_associated_type(),
    );
    let private_exprs = generate_checked_engine_constructor_private_exprs(
        engine.abstract_engine_impl.get_parameters_associated_type(),
    );
    let engine_type = &engine.definition.item_struct.ident;

    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            #public_args
            result: *mut *mut #engine_type,
        ) -> c_int {
            catch_panic(|| {
                check_ptr_is_non_null_and_aligned(result).unwrap();
                *result = std::ptr::null_mut();
                let heap_allocated_engine = Box::new(#engine_type::new(#private_exprs).unwrap());
                *result = Box::into_raw(heap_allocated_engine);
            })
        }
    )
}

fn generate_checked_engine_constructor_public_args(
    parameter_associated_type: &syn::Type,
) -> TokenStream2 {
    // INVARIANT: The parameter associated type is either a path or a tuple of paths.

    // If the parameter is a `Box<dyn Seeder>`
    let test_ast: syn::TypePath = parse_quote!(Box<dyn Seeder>);
    let maybe_seeder = probe!(
        Some(parameter_associated_type),
        syn::Type::Path(p) => p,
        p ?> *p == &test_ast
    );
    if let Some(_seeder) = maybe_seeder {
        return quote!(seeder_builder: *mut SeederBuilder,);
    }

    // If the parameter is the empty type
    let maybe_empty = probe!(
        Some(parameter_associated_type),
        syn::Type::Tuple(t) => t,
        t ?> t.elems.is_empty()
    );
    if let Some(_path) = maybe_empty {
        return quote!();
    }

    panic!("Failed to generate checked public constructor args.");
}

fn generate_checked_engine_constructor_private_exprs(
    parameter_associated_type: &syn::Type,
) -> TokenStream2 {
    // INVARIANT: The parameter associated type is either a path or a tuple of paths.

    // If the parameter is a `Box<dyn Seeder>`
    let test_ast: syn::TypePath = parse_quote!(Box<dyn Seeder>);
    let maybe_seeder = probe!(
        Some(parameter_associated_type),
        syn::Type::Path(p) => p,
        p ?> *p == &test_ast
    );
    if let Some(_seeder) = maybe_seeder {
        return quote!(get_mut_checked(seeder_builder)
            .unwrap()
            .create_seeder()
            .unwrap());
    }

    // If the parameter is the empty type
    let maybe_empty = probe!(
        Some(parameter_associated_type),
        syn::Type::Tuple(t) => t,
        t ?> t.elems.is_empty()
    );
    if let Some(_path) = maybe_empty {
        return quote!(());
    }

    panic!("Failed to generate checked public constructor args.");
}

fn generate_unchecked_engine_constructor(engine: &Engine) -> TokenStream2 {
    let name = format_ident!("new_{}_unchecked", engine.definition.to_fragment());
    let public_args = generate_unchecked_engine_constructor_public_args(
        engine.abstract_engine_impl.get_parameters_associated_type(),
    );
    let private_exprs = generate_unchecked_engine_constructor_private_exprs(
        engine.abstract_engine_impl.get_parameters_associated_type(),
    );
    let engine_type = &engine.definition.item_struct.ident;

    quote!(
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            #public_args
            result: *mut *mut #engine_type,
        ) -> c_int {
            catch_panic(|| {
                *result = std::ptr::null_mut();
                let heap_allocated_engine = Box::new(#engine_type::new(#private_exprs).unwrap());
                *result = Box::into_raw(heap_allocated_engine);
            })
        }
    )
}

fn generate_unchecked_engine_constructor_public_args(
    parameter_associated_type: &syn::Type,
) -> TokenStream2 {
    // INVARIANT: The parameter associated type is either a Box<dyn Seeder> or the empty type.

    // If the parameter is a `Box<dyn Seeder>`
    let test_ast: syn::TypePath = parse_quote!(Box<dyn Seeder>);
    let maybe_seeder = probe!(
        Some(parameter_associated_type),
        syn::Type::Path(p) => p,
        p ?> *p == &test_ast
    );
    if let Some(_seeder) = maybe_seeder {
        return quote!(seeder_builder: *mut SeederBuilder,);
    }

    // If the parameter is the empty type
    let maybe_empty = probe!(
        Some(parameter_associated_type),
        syn::Type::Tuple(t) => t,
        t ?> t.elems.is_empty()
    );
    if let Some(_path) = maybe_empty {
        return quote!();
    }

    panic!("Failed to generate unchecked public constructor args.");
}

fn generate_unchecked_engine_constructor_private_exprs(
    parameter_associated_type: &syn::Type,
) -> TokenStream2 {
    // INVARIANT: The parameter associated type is either a Box<dyn Seeder> or the empty type.

    // If the parameter is a `Box<dyn Seeder>`
    let test_ast: syn::TypePath = parse_quote!(Box<dyn Seeder>);
    let maybe_seeder = probe!(
        Some(parameter_associated_type),
        syn::Type::Path(p) => p,
        p ?> *p == &test_ast
    );
    if let Some(_seeder) = maybe_seeder {
        return quote!((*seeder_builder).create_seeder().unwrap());
    }

    // If the parameter is the empty type
    let maybe_empty = probe!(
        Some(parameter_associated_type),
        syn::Type::Tuple(t) => t,
        t ?> t.elems.is_empty()
    );
    if let Some(_path) = maybe_empty {
        return quote!(());
    }

    panic!("Failed to generate unchecked public constructor args.");
}
