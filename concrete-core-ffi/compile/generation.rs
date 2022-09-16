use concrete_core_representation::{probe, ConcreteCore, Engine};
use concrete_core_representation::{Entity, ToNameFragment};
use quote::{format_ident, quote};
use syn::__private::TokenStream2;
use syn::{parse_quote, Token};

pub fn generate_binding(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    output.extend(generate_all_engine_constructors(ccr));
    output.extend(generate_all_engine_destructors(ccr));
    output.extend(generate_all_entity_destructors(ccr));
    output
}

fn generate_all_entity_destructors(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for entity in ccr.backends.iter().flat_map(|bck| bck.entities.iter()) {
        output.extend(generate_checked_entity_destructor(entity));
    }
    output
}

fn generate_checked_entity_destructor(entity: &Entity) -> TokenStream2 {
    let name = format_ident!("destroy_{}", entity.definition.to_name);
    let entity_type;
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
