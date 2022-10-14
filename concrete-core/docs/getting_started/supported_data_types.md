# Supported Data Types

The FHE data types supported by Concrete-core belong to several categories, described below.

## Encryption keys

The supported encryption keys are GLWE secret keys, LWE secret keys and LWE public keys.

## Keyswitch keys

A number of keyswitch key types are supported:

* The LWE keyswitch key and its compressed version (the seeded LWE keyswitch key).
* The LWE packing keyswitch key
* The LWE private functional packing keyswitch key
* The list of LWE private functional packing keyswitch keys for circuit bootstrapping

## Evaluation keys

`Concrete-core` exposes a type for the LWE bootstrap key and its compressed equivalent.

## Ciphertexts

`Concrete-core` currently supports LWE ciphertexts and their compressed equivalent (the seeded LWE ciphertexts). It also exposes types for GLWE ciphertexts and their compressed equivalent, and for GGSW ciphertexts and their compressed equivalent. All those ciphertext types are also exposed in their `Vector` form, which corresponds to lists of such objects that are contiguous in memory. Having those vector types is useful to send batches of data to a given hardware, for example.

## Encoders

`Concrete-core` currently supports an encoder type and its vector form.

## Non-encrypted data

Two types of non-encrypted data are exposed in the form of types in the API (aside from cryptographic parameters types):

* Plaintexts (and their vector form): unsigned integers in 32 or 64 bits representation that should contain an encoded message ready for encryption;
* Cleartexts (and their vector form): data of arbitrary type that is used in clear during a homomorphic computation (it is not encoded, and may be a float, a signed integer, etc.).

## Full list of supported types

The full list of supported data types in `Concrete-core` is available in the [specification page](https://docs.rs/concrete-core/1.0.0/concrete\_core/specification/entities/index.html#traits) of the Rust documentation. The cryptographic content of each type is described in the Rust documentation itself. For example, the description of the keyswitch key can be found [here](https://docs.rs/concrete-core/1.0.0/concrete\_core/specification/entities/trait.LweCiphertextKeyswitchKeyEntity.html).

Head out to the page about [supported operations](supported\_operations.md) to get to know them.
