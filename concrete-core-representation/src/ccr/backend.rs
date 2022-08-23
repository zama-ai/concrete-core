use super::*;
use serde::Serialize;

/// A node representing a concrete-core backend.
#[derive(Serialize, Clone, Debug)]
pub struct Backend {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub ident: syn::Ident,
    pub engines: Vec<Engine>,
    pub entities: Vec<Entity>,
    pub configs: Vec<Config>,
}

impl Backend {
    /// From an `ItemMod` syn ast node, pointing to the `backends` module, extracts a vec of
    /// `Backend`.
    pub(crate) fn extract_all(
        cfg_stack_so_far: &CfgStack,
        backends_module: &syn::ItemMod,
    ) -> Vec<Backend> {
        // INVARIANT: All modules in the `backends` module, are backends.
        backends_module
            .content
            .as_ref()
            .expect("The `backends` module has no content...")
            .1
            .iter()
            .filter_map(|item| {
                if let syn::Item::Mod(item_mod) = item {
                    Some(Backend::extract_one(cfg_stack_so_far, item_mod))
                } else {
                    None
                }
            })
            .collect()
    }

    /// From an `ItemMod` syn ast node, pointing to a backend module, extract a `Backend`.
    pub(crate) fn extract_one(
        cfg_stack_so_far: &CfgStack,
        backend_module: &syn::ItemMod,
    ) -> Backend {
        // INVARIANT: The attributes of the backend modules are cfg feature configurations
        let cfg = cfg_stack_so_far.concat_attrs(backend_module.attrs.as_slice());
        let ident = backend_module.ident.clone();

        // Gather the entity items
        let entities = Entity::extract_all(&cfg, backend_module);
        // Gather the config items
        let configs = Config::extract_all(&cfg, backend_module);
        // Gather the engine items
        let engines = Engine::extract_all(&cfg, backend_module);

        Backend {
            cfg,
            ident,
            configs,
            engines,
            entities,
        }
    }
}
