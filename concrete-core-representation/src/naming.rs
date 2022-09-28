use crate::{
    probe, EngineTraitImpl, EngineTraitImplCheckedMethod, EngineTraitImplGenericArgument,
    EngineTypeDefinition, EntityTypeDefinition,
};

/// A helper trait for name mangling.
pub trait ToNameFragment {
    /// Returns a name fragment from self
    fn to_fragment(&self) -> String;
}

impl ToNameFragment for EngineTraitImpl {
    fn to_fragment(&self) -> String {
        format!(
            "{}_{}_{}",
            camel_case_to_snake_case(self.engine_type_ident.to_string().as_str()),
            self.checked_method.ident.to_string(),
            self.engine_trait_parameters()
                .iter()
                .map(ToNameFragment::to_fragment)
                .collect::<Vec<_>>()
                .join("_")
        )
    }
}

impl ToNameFragment for EntityTypeDefinition {
    fn to_fragment(&self) -> String {
        camel_case_to_snake_case(self.item_struct.ident.to_string().as_str())
    }
}

impl ToNameFragment for EngineTypeDefinition {
    fn to_fragment(&self) -> String {
        camel_case_to_snake_case(self.item_struct.ident.to_string().as_str())
    }
}

impl ToNameFragment for EngineTraitImplCheckedMethod {
    fn to_fragment(&self) -> String {
        self.ident.to_string()
    }
}

impl ToNameFragment for EngineTraitImplGenericArgument {
    fn to_fragment(&self) -> String {
        match self {
            EngineTraitImplGenericArgument::OwnedEntity(_)
            | EngineTraitImplGenericArgument::ViewEntity(_)
            | EngineTraitImplGenericArgument::MutViewEntity(_)
            | EngineTraitImplGenericArgument::Config(_) => probe!(
                Some(self.get_type()),
                syn::Type::Path(t) => t,
                t >> t.path.segments.first(),
                t -> t.ident.to_string(),
                t -> camel_case_to_snake_case(&t)
            )
            .unwrap(),
            EngineTraitImplGenericArgument::Numeric(t) => probe!(
                Some(t),
                syn::Type::Path(t) => t,
                t >> t.path.segments.first(),
                t -> t.ident.to_string()
            )
            .unwrap(),
            EngineTraitImplGenericArgument::NumericSlice(t) => probe!(
                Some(t),
                syn::Type::Reference(r) => r,
                r -> r.elem.as_ref(),
                syn::Type::Slice(s) => s,
                s -> s.elem.as_ref(),
                syn::Type::Path(p) => p,
                t >> t.path.segments.first(),
                t -> format!("{}_slice", t.ident)
            )
            .unwrap(),
            EngineTraitImplGenericArgument::NumericSliceMut(t) => probe!(
                Some(t),
                syn::Type::Reference(r) => r,
                r -> r.elem.as_ref(),
                syn::Type::Slice(s) => s,
                s -> s.elem.as_ref(),
                syn::Type::Path(p) => p,
                t >> t.path.segments.first(),
                t -> format!("{}_mut_slice", t.ident)
            )
            .unwrap(),
            EngineTraitImplGenericArgument::NumericVec(t) => probe!(
                Some(t),
                syn::Type::Path(p) => p,
                p >> p.path.segments.first(),
                s -> &s.arguments,
                syn::PathArguments::AngleBracketed(a) => a,
                a >> a.args.first(),
                syn::GenericArgument::Type(t) => t,
                syn::Type::Path(p) => p,
                t >> t.path.segments.first(),
                t -> format!("{}_vec", t.ident)
            )
            .unwrap(),
            EngineTraitImplGenericArgument::Unknown(_) => {
                panic!()
            }
        }
    }
}

fn camel_case_to_snake_case(input: &str) -> String {
    let mut output = String::new();
    let mut iter = input.chars().peekable();
    loop {
        match (iter.next(), iter.peek()) {
            (Some(ch), _) if !ch.is_ascii_alphanumeric() => {
                panic!()
            }
            (Some(ch), Some(nch)) if ch.is_ascii_uppercase() && nch.is_ascii_lowercase() => {
                output.push(ch.to_ascii_lowercase())
            }
            (Some(ch), Some(nch)) if ch.is_ascii_uppercase() && nch.is_ascii_uppercase() => {
                output.push(ch.to_ascii_lowercase());
                output.push('_')
            }
            (Some(ch), Some(nch)) if nch.is_ascii_uppercase() => {
                output.push(ch);
                output.push('_')
            }
            (Some(ch), _) => output.push(ch.to_ascii_lowercase()),
            (None, None) => break,
            _ => panic!("Failed to transform case of `{}`", input),
        }
    }
    output
}
