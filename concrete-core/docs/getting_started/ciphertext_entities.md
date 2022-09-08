# Ciphertext Entities

`concrete-core` has several types of ciphertexts like LWE, GLWE, GGSW just to name a few. These ciphertexts are called entities in the `concrete-core` API (there are other types of entities, like keys for example, but here we focus on ciphertexts).

Entities all have an underlying container type that holds the data of the ciphertext. These containers may or may not own the data, we will explain why in the next sections and you can choose what suits your use case best, though 99%+ of the time you probably can just use [entities owning their memory](#entities-owning-their-memory) and will be fine with that choice.

## Entities owning their memory

For LWE ciphertext entities, example of such owning entities are `LweCiphertext32` and `LweCiphertext64`. At the time of writing the underlying implementations use a `Vec` holding `u32`s and `u64`s respectively. You should not rely on the ciphertext using a `Vec` in your usage of concrete-core, this is just to illustrate the fact that `LweCiphertext32` and `LweCiphertext64` have containers that own their memory.

Some engines return freshly allocated ciphertexts like `LweCiphertextEncryptionEngine` whose entry point is `encrypt_lwe_ciphertext` (or `encrypt_lwe_ciphertext_unchecked` in its unchecked form).

On the other hand some engines require to have an already allocated ciphertext entity, like `LweCiphertextDiscardingEncryptionEngine` whose entry point is `discard_encrypt_lwe_ciphertext`. In that case you can use one of the `LweCiphertextCreationEngine` variants available in the default backend for example (entry point `create_lwe_ciphertext_from`) providing a properly sized `Vec` (which will be consumed) to create an owning `LweCiphertext32` or `LweCiphertext64`. This entity can then be used in the `discard_encrypt_lwe_ciphertext` call.

## Entities borrowing their memory

{% hint style="warning" %}
We would advise against using the view API if you don't need it. The reason being that the original goal was to provide functionality required by the `concrete-compiler`. This means that the view API is currently not as extensively supported in existing engines as the historical owned memory API.
{% endhint %}

There are cases where you may want to allocate memory ahead of time or manage memory allocation in a manual way and give pieces of that memory to certain ciphertext entities.

This is for example a requirement for the `concrete-compiler` to use an MLIR bufferization pass.

To that end, a restricted set of ciphertext entities (at the time of writing `LweCiphertextEntity` and `GlweCiphertextEntity`) can be instantiated in `MutView` and `View` variants, which borrow their memory.

The following paragraphs also apply to GLWE ciphertexts, so you can replace "LWE" by "GLWE" and the following text should remain correct.

To instantiate an `LweCiphertextMutView32` or `LweCiphertextMutView64` you can call the proper variant of `LweCiphertextCreationEngine` (entry point `create_lwe_ciphertext_from`), providing a mutable slice of the proper scalar type (`u32` or `u64`). You can refer to the `concrete-core` documentation on [docs.rs](https://docs.rs) where example usage are provided for `LweCiphertextCreationEngine`.

`LweCiphertextView32` and `LweCiphertextView64` can be instantiated in the same way, the requirement being that the slices passed to the `create_lwe_ciphertext_from` function have to be immutable.

One current pain point of the view API is that you cannot create a mutable view and an immutable view from the same piece of memory, which is normal given Rust borrowing rules.

Converting from a `LweCiphertextMutView` to a `LweCiphertextView` is possible, it requires using the `LweCiphertextConsumingRetrievalEngine` (entry point `consume_retrieve_lwe_ciphertext`) to get the underlying slice from the `LweCiphertextMutView`, and then creating a new `LweCiphertextView` using the righ variant of `LweCiphertextCreationEngine`. You can learn more about `RetrievalEngines` in the [next section](#retrieving-the-container-of-a-ciphertext).

Converting from `MutView` to `View` is an operation you are very likely to perform if you first write output data in a mutable memory zone and then want to use that same memory zone as an immutable input to another computation.

The conversion from `View` to `MutView` is not possible without unsafe code (using some potentially dangerous Rust primitives) and can very easily generate unsound code that does not comply with Rust borrowing rules. Use at your own risk.

## Retrieving the container of a ciphertext

As quickly touched upon in the previous section, it is possible for some ciphertexts (currently the ones with views variants) to retrieve the underlying container of an entity. The retrieval engines consume the input entity and return the container it used for storing data.

The view API was not primarily created for Rust developers and one of its current shortcomings is the fact it's not easy to re-use an output `MutView` to be used as an immutable input `View` to a subsequent operation.

It is possible to do that by using the retrieval engines. The following example is taken from a docstring of `concrete-core` to see how to perform the `MutView` -> `View` transformation using the retrieval engine:

```rust
use concrete_core::prelude::Variance;
use concrete_core::prelude::LweDimension;
use concrete_core::prelude::*;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    let lwe_dimension = LweDimension(2);

    // Here a hard-set encoding is applied (shift by 50 bits)
    let input = 3_u64 << 50;
    let noise = Variance(2_f64.powf(-25.));

    // Unix seeder must be given a secret input.
    // Here we just give it 0, which is totally unsafe.
    const UNSAFE_SECRET: u128 = 0;
    let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;

    // Crate an LWE secret key
    let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;

    // Prepare the plaintext
    let plaintext = engine.create_plaintext_from(&input)?;

    // Prepare the container and create an LWE ciphertext mut view
    let mut raw_ciphertext = vec![0_u64; key.lwe_dimension().to_lwe_size().0];
    let mut ciphertext_mut_view: LweCiphertextMutView64 =
        engine.create_lwe_ciphertext_from(&mut raw_ciphertext[..])?;

    // Perform the encryption
    engine.discard_encrypt_lwe_ciphertext(&key, &mut ciphertext_mut_view, &plaintext, noise)?;

    // Convert MutView to View by retrieving the mutable slice and passing it as immutable to
    // create_lwe_ciphertext_from
    let raw_ciphertext = engine.consume_retrieve_lwe_ciphertext(ciphertext_mut_view)?;
    let ciphertext_view: LweCiphertextView64 = engine.create_lwe_ciphertext_from(&raw_ciphertext[..])?;
    let decrypted_plaintext = engine.decrypt_lwe_ciphertext(&key, &ciphertext_view)?;

    // Destroy entities
    engine.destroy(key)?;
    engine.destroy(plaintext)?;
    engine.destroy(ciphertext_view)?;
    engine.destroy(decrypted_plaintext)?;

    Ok(())
}
```
