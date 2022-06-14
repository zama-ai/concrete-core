# Ciphertext Entities

`concrete-core` has several types of ciphertexts like LWE, GLWE, GGSW just to name a few. These ciphertexts are called entities in the `concrete-core` API (there are other types of entities, like keys for example, but here we focus on ciphertexts).

Entities all have an underlying container type that holds the data of the ciphertext. These containers may or may not own the data, we will explain why in the next sections and you can choose what suits your use case best, though 99%+ of the time you probably can just use [entities owning their memory](#entities-owning-their-memory) and will be fine with that choice.

## Entities owning their memory

For LWE ciphertext entities, example of such owning entities are `LweCiphertext32` and `LweCiphertext64`. At the time of writing the underlying implementations use a `Vec` holding `u32`s and `u64`s respectively. You should not rely on the ciphertext using a `Vec` in your usage of concrete-core, this is just to illustrate the fact that `LweCiphertext32` and `LweCiphertext64` have containers that own their memory.

Some engines return freshly allocated ciphertexts like `LweCiphertextEncryptionEngine` whose entry point is `encrypt_lwe_ciphertext` (or `encrypt_lwe_ciphertext_unchecked` in its unchecked form).

On the other hand some engines require to have an already allocated ciphertext entity, like `LweCiphertextDiscardingEncryptionEngine` whose entry point is `discard_encrypt_lwe_ciphertext`. In that case you can use one of the `LweCiphertextCreationEngine` variants available in the default backend for example (entry point `create_lwe_ciphertext`) providing a properly sized `Vec` (which will be consumed) to create an owning `LweCiphertext32` or `LweCiphertext64`. This entity can then be used in the `discard_encrypt_lwe_ciphertext` call.

## Entities borrowing their memory

WARNING:

We would advise against using the view API if you don't need it. The reason being that the original goal was to provide functionality required by the `concrete-compiler`. This means that the view API is currently not as extensively supported in existing engines as the historical owned memory API.

There are cases where you may want to allocate memory ahead of time or manage memory allocation in a manual way and give pieces of that memory to certain ciphertext entities.

This is for example a requirement for the `concrete-compiler` to use an MLIR bufferization pass.

To that end, a restricted set of ciphertext entities (at the time of writing `LweCiphertextEntity` and `GlweCiphertextEntity`) can be instantiated in `MutView` and `View` variants, which borrow their memory.

The following paragraphs also apply to GLWE ciphertexts, so you can replace "LWE" by "GLWE" and the following text should remain correct.

To instantiate an `LweCiphertextMutView32` or `LweCiphertextMutView64` you can call the proper variant of `LweCiphertextCreationEngine` (entry point `create_lwe_ciphertext`), providing a mutable slice of the proper scalar type (`u32` or `u64`). You can refer to the `concrete-core` documentation on [docs.rs](https://docs.rs) where example usage are provided for `LweCiphertextCreationEngine`.

`LweCiphertextView32` and `LweCiphertextView64` can be instantiated in the same way, the requirement being that the slices passed to the `create_lwe_ciphertext` function have to be immutable.

One current pain point of the view API is that you cannot create a mutable view and an immutable view from the same piece of memory, which is normal given Rust borrowing rules.

Converting from a `LweCiphertextMutView` to a `LweCiphertextView` is possible, it requires using the `LweCiphertextConsumingRetrievalEngine` (entry point `consume_retrieve_lwe_ciphertext`) to get the underlying slice from the `LweCiphertextMutView`, and then creating a new `LweCiphertextView` using the righ variant of `LweCiphertextCreationEngine`.

Converting from `MutView` to `View` is an operation you are very likely to perform if you first write output data in a mutable memory zone and then want to use that same memory zone as an immutable input to another computation.

The conversion from `View` to `MutView` is not possible without unsafe code (using some potentially dangerous Rust primitives) and can very easily generate unsound code that does not comply with Rust borrowing rules. Use at your own risk.
