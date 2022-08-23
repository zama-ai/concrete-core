use super::*;
use serde::Serialize;

/// A node representing the definition of an entity type.
#[derive(Serialize, Clone, Debug)]
pub struct EntityTypeDefinition {
    pub cfg: CfgStack,
    #[serde(serialize_with = "serialize_with_token_string")]
    pub item_struct: syn::ItemStruct,
    pub ownership: EntityOwnership,
}

impl EntityTypeDefinition {
    /// Returns the `syn` node pointing to the identifier of the entity.
    pub fn get_ident(&self) -> &syn::Ident {
        &self.item_struct.ident
    }
}
