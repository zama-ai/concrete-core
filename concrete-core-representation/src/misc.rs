use crate::{Backend, ConcreteCore, Engine, EngineTraitImpl, Entity};
use quote::ToTokens;
use std::borrow::Borrow;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Dumps the `ccr` to a json file. For debugging purpose.
pub fn dump_ccr_to_file<P: AsRef<Path>, CC: Borrow<ConcreteCore>>(path: P, ccr: CC) {
    let mut file = File::create(path.as_ref()).unwrap();
    let output = serde_json::to_string(ccr.borrow()).unwrap();
    file.write_all(output.as_bytes()).unwrap();
}

/// Dumps the `ccr` to a "/tmp/ccr_dump.json" file. For debugging purpose.
pub fn dump_ccr<CC: Borrow<ConcreteCore>>(ccr: CC) {
    dump_ccr_to_file("/tmp/ccr_dump.json", ccr);
}

/// Prints a human-readable summary of the input `ccr` to the output.
pub fn print_ccr<CC: Borrow<ConcreteCore>>(ccr: CC) {
    println!("Concrete Core");
    println!("=============");
    println!();
    for backend in ccr.borrow().backends.iter() {
        print_backend(1, backend)
    }
}

fn print_backend(indent: usize, backend: &Backend) {
    let indent_str = "    ".repeat(indent);
    let backend_title = format!("{} backend", backend.ident);
    println!("{}{}", indent_str, backend_title);
    println!("{}{}", indent_str, "-".repeat(backend_title.len()));
    println!();
    print_all_engines(indent + 1, &backend.engines);
    println!();
    print_all_entities(indent + 1, &backend.entities);
    println!();
}

fn print_all_engines(indent: usize, engines: &[Engine]) {
    let indent_str = "    ".repeat(indent);
    let engine_title = format!("Engines ({}):", engines.len());
    println!("{}{}", indent_str, engine_title);
    for engine in engines.iter() {
        print_engine(indent + 1, engine);
    }
}

fn print_all_entities(indent: usize, entities: &[Entity]) {
    let indent_str = "    ".repeat(indent);
    let entity_title = format!("Entities ({}):", entities.len());
    println!("{}{}", indent_str, entity_title);
    for entity in entities.iter() {
        print_entity(indent + 1, entity);
    }
}

fn print_engine(indent: usize, engine: &Engine) {
    let indent_str = "    ".repeat(indent);
    let engine_title = format!("=> {}", engine.definition.item_struct.ident);
    println!("{}{}", indent_str, engine_title);
    for engine_impl in engine.engine_impls.iter() {
        print_engine_impl(indent + 1, engine_impl);
    }
}

fn print_engine_impl(indent: usize, engine_impl: &EngineTraitImpl) {
    let indent_str = "    ".repeat(indent);
    let engine_title = format!(
        "+ {}<{}>",
        engine_impl.engine_trait_ident.to_string().replace(' ', ""),
        engine_impl
            .engine_trait_parameters
            .as_ref()
            .unwrap()
            .iter()
            .fold(String::new(), |mut st, param| {
                st.push_str(param.get_type().to_token_stream().to_string().as_str());
                st.push(',');
                st
            })
            .replace(' ', "")
    )
    .replace(",>", ">");
    println!("{}{}", indent_str, engine_title);
}

fn print_entity(indent: usize, entity: &Entity) {
    let indent_str = "    ".repeat(indent);
    let entity_title = format!("=> {}", entity.definition.item_struct.ident);
    println!("{}{}", indent_str, entity_title);
}
