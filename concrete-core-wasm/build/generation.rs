//! This module contains a function that generates the binding token stream from the pruned ccr.
use concrete_core_representation::{ConcreteCore, *};
use quote::{quote, ToTokens};
use syn::__private::{Span, TokenStream2};
use syn::{parse_quote, Ident, Type};

/// Generate the whole binding from the pruned ccr.
pub fn generate_binding(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    output.extend(generate_all_entities(ccr));
    output.extend(generate_all_configs(ccr));
    output.extend(generate_all_engines(ccr));
    output
}

fn generate_all_entities(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for entity in ccr
        .backends
        .iter()
        .flat_map(|backend| backend.entities.iter())
    {
        output.extend(generate_entity_definition(entity).into_iter());
    }
    output
}

fn generate_entity_definition(entity: &Entity) -> TokenStream2 {
    // INVARIANT: entities are available in the `concrete_core::prelude` module
    // INVARIANT: views are not exported
    let ident = entity.definition.item_struct.ident.clone();
    quote! {
        #[wasm_bindgen]
        pub struct #ident(pub(crate) concrete_core::prelude::#ident);
    }
}

fn generate_all_configs(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for config in ccr
        .backends
        .iter()
        .flat_map(|backend| backend.configs.iter())
    {
        output.extend(generate_config_definition(config).into_iter());
        output.extend(generate_config_constructor(config).into_iter());
        output.extend(generate_config_converter(config).into_iter());
    }
    output
}

fn generate_config_definition(config: &Config) -> TokenStream2 {
    let config_ident = &config.item_struct.ident;
    let fields = &config
        .item_struct
        .fields
        .iter()
        .map(|field| {
            let ident = field.ident.clone().unwrap();
            let type_ = field.ty.clone();
            quote!(pub #ident: #type_)
        })
        .collect::<Vec<_>>();
    quote! {
        #[wasm_bindgen]
        #[derive(Serialize, Deserialize)]
        pub struct #config_ident{
            #(#fields),*
        }
    }
}

fn generate_config_constructor(config: &Config) -> TokenStream2 {
    let config_ident = &config.item_struct.ident;
    let args = &config
        .item_struct
        .fields
        .iter()
        .map(|field| {
            let ident = field.ident.clone().unwrap();
            let type_ = field.ty.clone();
            quote!(#ident: #type_)
        })
        .collect::<Vec<_>>();
    let fields = &config
        .item_struct
        .fields
        .iter()
        .map(|field| {
            let ident = field.ident.clone().unwrap();
            quote!(#ident)
        })
        .collect::<Vec<_>>();
    quote! {
        #[wasm_bindgen]
        impl #config_ident{
            #[wasm_bindgen(constructor)]
            pub fn new(#(#args),*) -> #config_ident {
                #config_ident{
                    #(#fields),*
                }
            }
        }
    }
}

fn generate_config_converter(config: &Config) -> TokenStream2 {
    let config_ident = &config.item_struct.ident;
    let fields = &config
        .item_struct
        .fields
        .iter()
        .map(|field| {
            let ident = field.ident.clone().unwrap();
            quote!(#ident)
        })
        .collect::<Vec<_>>();
    quote! {
        impl #config_ident{
            fn to_concrete_core_type(&self) -> concrete_core::prelude::#config_ident {
                concrete_core::prelude::#config_ident{
                    #(#fields: self.#fields),*
                }
            }
        }
    }
}

fn generate_all_engines(ccr: &ConcreteCore) -> TokenStream2 {
    let mut output = TokenStream2::new();
    for engine in ccr
        .backends
        .iter()
        .flat_map(|backend| backend.engines.iter())
    {
        output.extend(generate_engine_definition(engine));
        output.extend(generate_engine_constructor(engine));
        for engine_impl in engine.engine_impls.iter() {
            output.extend(generate_engine_method(engine_impl));
        }
    }
    output
}

fn generate_engine_definition(engine: &Engine) -> TokenStream2 {
    // INVARIANT: engines are available in the `concrete_core::prelude` module
    let ident = engine.definition.item_struct.ident.clone();
    quote! {
        #[wasm_bindgen]
        pub struct #ident(pub(crate) concrete_core::prelude::#ident);
    }
}

fn generate_engine_constructor(engine: &Engine) -> TokenStream2 {
    // INVARIANT: the constructor parameter is either a path or a tuple of path.
    // INVARIANT: one constructor parameter may be a `Box<dyn Seeder>`
    // INVARIANT: type paths in the constructor parameters only contain a single value.
    let engine_ident = engine.definition.get_name();
    let public_constructor_args = generate_public_constructor_args(
        engine.abstract_engine_impl.get_parameters_associated_type(),
    );
    let private_constructor_exprs = generate_private_constructor_exprs(
        engine.abstract_engine_impl.get_parameters_associated_type(),
    );
    quote! {
        #[wasm_bindgen]
        impl #engine_ident{
            #[wasm_bindgen(constructor)]
            pub fn new(#public_constructor_args) -> Result<#engine_ident, JsError> {
                std::panic::set_hook(Box::new(console_error_panic_hook::hook));
                concrete_core::prelude::#engine_ident::new(#private_constructor_exprs)
                    .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
                    .map(#engine_ident)
            }
        }
    }
}

fn generate_public_constructor_args(parameter_associated_type: &Type) -> TokenStream2 {
    // INVARIANT: The parameter associated type is either a Box<dyn Seeder> or the empty type.

    // If the parameter is a `Box<dyn Seeder>`
    let test_ast: syn::TypePath = parse_quote!(Box<dyn Seeder>);
    let maybe_seeder = probe!(
        Some(parameter_associated_type),
        syn::Type::Path(p) => p,
        p ?> *p == &test_ast
    );
    if let Some(_seeder) = maybe_seeder {
        return quote!(seeder: crate::JsFunctionSeeder);
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

    panic!("Failed to generate public constructor args.");
}

fn generate_private_constructor_exprs(parameter_associated_type: &Type) -> TokenStream2 {
    // INVARIANT: The parameter associated type is either a Box<dyn seeder> or the empty type.

    // If the parameter is a `Box<dyn Seeder>`
    let test_ast: syn::TypePath = parse_quote!(Box<dyn Seeder>);
    let maybe_seeder = probe!(
        Some(parameter_associated_type),
        syn::Type::Path(p) => p,
        p ?> *p == &test_ast
    );
    if let Some(_seeder) = maybe_seeder {
        return quote!(Box::new(seeder));
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

    // If the parameter is a tuple of paths
    panic!("Failed to generate public constructor args.");
}

fn generate_engine_method(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    let engine_ident = &engine_impl.engine_type_ident;
    let method_ident = generate_engine_method_ident(engine_impl);
    let method_args = generate_engine_method_args(engine_impl);
    let method_return = generate_engine_method_return_type(engine_impl);
    let method_body = generate_engine_method_body(engine_impl);
    let method_return_map = generate_engine_method_return_map(engine_impl);
    quote! {
        #[wasm_bindgen]
        impl #engine_ident {
            pub fn #method_ident(&mut self, #method_args) -> Result<#method_return, JsError>{
                #method_body
                    .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
                    #method_return_map
            }
        }
    }
}

fn generate_engine_method_return_map(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    match engine_impl.checked_method.return_() {
        EngineTraitImplReturn::OwnedEntity(v) => {
            quote!(.map(#v))
        }
        EngineTraitImplReturn::Numeric(_) => {
            quote!()
        }
        EngineTraitImplReturn::NumericVec(_) => {
            quote!()
        }
        EngineTraitImplReturn::Unit(_) => {
            quote!()
        }
        _ => panic!(
            "Unexpected return type: {:?}",
            engine_impl.checked_method.return_()
        ),
    }
}

fn generate_engine_method_body(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    let mut blocks = TokenStream2::new();
    engine_impl.checked_method.args().iter().for_each(|arg| {
        if let EngineTraitImplArg::ConfigSlice(pat, _, config_ident) = arg {
            let block = quote! {
                let #pat = #pat
                    .iter()
                    .map(|jsval| serde_wasm_bindgen::from_value(jsval.to_owned()))
                    .collect::<Result<Vec<#config_ident>, _>>()
                    .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))?;
                let #pat = #pat.into_iter().map(|t| t.to_concrete_core_type()).collect::<Vec<_>>();
            };
            blocks.extend(block)
        }
    });

    let mut args = TokenStream2::new();
    engine_impl
        .checked_method
        .args()
        .iter()
        .for_each(|arg| match arg {
            EngineTraitImplArg::OwnedEntity(pat, _) => args.extend(quote!(#pat.0,)),
            EngineTraitImplArg::OwnedEntityRef(pat, _, _) => args.extend(quote!(& #pat.0,)),
            EngineTraitImplArg::OwnedEntityRefMut(pat, _, _) => args.extend(quote!(&mut #pat.0,)),
            EngineTraitImplArg::Config(pat, _) => {
                args.extend(quote!(#pat.to_concrete_core_type(),))
            }
            EngineTraitImplArg::ConfigRef(pat, _, _) => {
                args.extend(quote!(& #pat.to_concrete_core_type(),))
            }
            EngineTraitImplArg::ConfigSlice(pat, _, _) => args.extend(quote!(
                #pat.as_slice(),
            )),
            EngineTraitImplArg::Parameter(pat, _) => args.extend(quote!(#pat.0,)),
            EngineTraitImplArg::Dispersion(pat, _) => args.extend(quote!(#pat.0,)),
            EngineTraitImplArg::Numeric(pat, _) => args.extend(quote!(#pat,)),
            EngineTraitImplArg::NumericRef(pat, _, _) => args.extend(quote!(& #pat,)),
            EngineTraitImplArg::NumericSlice(pat, _, _) => args.extend(quote!(#pat,)),
            EngineTraitImplArg::NumericSliceMut(pat, _, _) => args.extend(quote!(#pat,)),
            EngineTraitImplArg::NumericVec(pat, _, _) => args.extend(quote!(#pat,)),
            _ => {
                panic!("Unexpected arg: {:?}", arg)
            }
        });
    let method_name = &engine_impl.checked_method.ident;
    quote!(
        #blocks
        self.0.#method_name(#args)
    )
}

fn generate_engine_method_return_type(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    let return_type = engine_impl.checked_method.return_().type_();
    quote!(#return_type)
}

fn generate_engine_method_args(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    let mut output = TokenStream2::new();
    engine_impl
        .checked_method
        .args()
        .iter()
        .for_each(|arg| match arg {
            EngineTraitImplArg::NumericRef(pat_ident, _, num_ident) => {
                output.extend(quote! {#pat_ident: #num_ident,});
            }
            EngineTraitImplArg::ConfigSlice(pat_ident, _, _) => {
                output.extend(quote! {#pat_ident: Box<[JsValue]>,});
            }
            arg => {
                let pat_ident = arg.pat_ident();
                let type_ = arg.type_();
                output.extend(quote! {#pat_ident: #type_,});
            }
        });
    output
}

fn generate_engine_method_ident(engine_impl: &EngineTraitImpl) -> TokenStream2 {
    let output = format!(
        "{}_{}",
        engine_impl.checked_method.to_fragment(),
        engine_impl
            .engine_trait_parameters()
            .iter()
            .map(ToNameFragment::to_fragment)
            .collect::<Vec<_>>()
            .join("_")
    );
    Ident::new(output.as_str(), Span::call_site()).to_token_stream()
}
