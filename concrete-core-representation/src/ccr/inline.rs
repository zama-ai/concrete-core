//! A module containing functions to load a crate as a syn ast, and inline all modules.
use std::fs::File;
use std::io::Read;
use std::path::Path;
use syn::spanned::Spanned;
use syn::token::Brace;

pub(crate) fn read_crate<P: AsRef<Path>>(path: P) -> syn::File {
    read_file_and_inline_modules(path, |path| {
        let forbidden_files = ["/commons", "/private"];
        for f in forbidden_files.iter() {
            if path.as_os_str().to_str().unwrap().contains(f) {
                return false;
            }
        }
        true
    })
}

fn read_file_and_inline_modules<P>(path: P, filter: fn(&Path) -> bool) -> syn::File
where
    P: AsRef<Path>,
{
    let mut file = File::open(&path).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    let mut ast = syn::parse_file(&content).unwrap();

    for item in ast.items.iter_mut() {
        if let syn::Item::Mod(ref mut module) = item {
            if module.content.is_none() {
                *module = inline_module(path.as_ref(), module, filter);
            }
        }
    }

    ast
}

fn inline_module<P>(
    super_file_path: P,
    input: &syn::ItemMod,
    filter: fn(&Path) -> bool,
) -> syn::ItemMod
where
    P: AsRef<Path>,
{
    let mut output = input.to_owned();
    let super_folder_path = super_file_path.as_ref().parent().unwrap();
    let as_file_path = super_folder_path.join(format!("{}.rs", input.ident));
    let as_folder_path = super_folder_path.join(format!("{}/mod.rs", input.ident));
    let module_path = if as_file_path.exists() {
        as_file_path
    } else {
        as_folder_path
    };
    if !filter(module_path.as_path()) {
        return output;
    }

    let ast = read_file_and_inline_modules(module_path, filter);
    let brace = Brace { span: ast.span() };
    output.content.replace((brace, ast.items));

    output
}
