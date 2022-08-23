use serde::Serialize;

/// A node representing the ownership of an entity.
///
/// When generating some apis, different entities must be treated differently depending on their
/// ownership:
/// + In the wasm api, we don't want to expose views and mut views because it does not work with
///   wasm_bindgen.
/// + In the c api, we have to expose a lifetime parameter when we expose a view, but not when we
///   expose a owned entity.

#[derive(Serialize, Clone, Debug)]
pub enum EntityOwnership {
    /// The entity has the ownership of the underlying memory.
    Owned,
    /// The entity borrows the underlying memory.
    View,
    /// The entity mutably borrows the underlying memory.
    MutView,
}
