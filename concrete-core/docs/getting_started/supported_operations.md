# Supported Operations

These operations belong to several categories, described below.

## Basic FHE operations

`Concrete-core` supports a number of basic FHE operations, like encryption, decryption, encoding, and key generation functions for different types of ciphertexts and keys. Keys can be secret (LWE secret key, GLWE secret key, etc.) or public (LWE public key, keyswitch key, bootstrap key, etc.). Note that symmetric and asymmetric encryption are supported for the LWE scheme, while only asymmetric encryption is supported for the GLWE scheme. Ciphertexts and public keys can be generated in their compressed versions, the seeded ciphertexts and keys, and can be decompressed into their classical counterparts from just the original seed used to create them.

Other basic operations are the transformation of an LWE secret key into a GLWE secret key and vice versa, and the keyswitch to change the underlying secret key of an LWE ciphertext (to change the LWE dimension, for example).

## Linear algebra

`Concrete-core` supports a number of leveled operations that make it possible to perform homomorphic linear algebra computations. Such operations are the addition and subtraction between ciphertexts, the negation of a ciphertext, the multiplication of a ciphertext with a cleartext, etc.

## Bootstrapping

`Concrete-core` supports a number of operations related to TFHE's programmable bootstrap: the programmable bootstrap itself, the Cmux, the external product, the circuit bootstrap (that transforms an LWE ciphertext into a GGSW ciphertext), the vertical packing, and the bit extraction. The cryptographic description of each of these can be found in the Rust documentation itself (see the [bootstrap](https://docs.rs/concrete-core/1.0.1/concrete\_core/specification/engines/trait.LweCiphertextDiscardingBootstrapEngine.html#formal-definition)).

## Data management

Finally, a number of operations in `Concrete-core` help with data management. For example, it is possible to create cleartexts, plaintexts, ciphertexts and ciphertext arrays by wrapping containers, and to retrieve those containers as well. Conversion functions are also exposed that make it possible to convert a given type from one representation to another (this can correspond to a copy onto a GPU or to the conversion of a GLWE ciphertext from the standard to the Fourier domain).

## Full list of operations

The full list of supported operations in `Concrete-core` is available in the [specification page](https://docs.rs/concrete-core/1.0.1/concrete\_core/specification/engines/index.html#traits) of the Rust documentation. The cryptographic content of each operation is described in a `Formal definition` in the Rust documentation itself. For example, the description of the keyswitch can be found [here](https://docs.rs/concrete-core/1.0.1/concrete\_core/specification/engines/trait.LweCiphertextDiscardingKeyswitchEngine.html#formal-definition). A code snippet for each implementation of these operations in the various supported backends is available in the Rust documentation.
