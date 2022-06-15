# Introduction

Welcome to the developer guide for `concrete-core-ffi`!

For general infos on writing a C FFI in Rust you can check the following:

- Some infos from the nomicon: https://doc.rust-lang.org/nomicon/ffi.html#calling-rust-code-from-c
- The cbindgen tool to generate a C API: https://github.com/eqrion/cbindgen/blob/master/docs.md

If some programming concepts are unclear in the next sections you probably missed some paragraphs from the Rust nomicon. If we forgot to define something don't hesitate to open an issue/submit a PR to improve this documentation!

In the next few guides we will see how to extend the `concrete-core-ffi` by analyzing how some functionalities are exposed in `concrete-core-ffi`.

## Source structure

The `src/backends` directory mirrors the source organization of `concrete-core`. Wrappers for the C FFI can be expected to be found in the same sub-tree in `concrete-core-ffi` as in `concrete-core` without the `implementation` part of the path, i.e. `concrete-core/src/backends/default/implementation/engines/lwe_ciphertext_discarding_encryption.rs` C FFI wrappers can be found in `concrete-core-ffi/src/backends/default/engines/lwe_ciphertext_discarding_encryption.rs`.

## Memory origin

Currently, to fulfill the needs of the `concrete-compiler` which relies on MLIR, the ciphertexts used for computation use memory allocated by the foreign language calling into `concrete-core-ffi` instead of using memory allocated by `concrete-core-ffi`.

The two versions of the exposed APIs called `view_buffers` and `raw_ptr_buffers` are explained in greater detail [here](../api/api.md#concrete-core-ffi).

Other structures like keys are allocated on the heap by `concrete-core-ffi`.

## Common utils

There are a few common utils defined in the crate that are used throughout the crate, they are found in `src/utils.rs`.

- `catch_panic`: executes a closure and returns a `c_int`; 0 if there were no panics, 1 otherwise
- `check_ptr_is_non_null_and_aligned`: does what it says, verifies a pointer is not `NULL` (generally in C `#define NULL 0`) and properly aligned for the expected type for the given pointer
- `get_mut_checked`: performs the non null and alignment check and returns a mutable reference from the pointer
- `get_ref_checked`: performs the non null and alignment check and returns an immutable reference from the pointer
- `engine_error_as_readable_string`: allows to turn an `EngineError` from `concrete-core` into a readable string in case of a failure

## Patterns for the FFI

- [Instantiating and destroying objects](../dev/instantiating_and_destroying_objects.md)
