# Object instantiation and destruction through the FFI boundary

This tutorial is provided to manually extend the existing FFI, but do note that there are plan to automatize the generation of this `C` FFI.

## Opaque values

The first thing to note is that as long as a structure is not marked `#[repr(C)]` in Rust, its memory layout will be unknown to the `C` caller (and also potentially unstable between compilations in Rust itself) and is therefore considered opaque.

Opaque values can only be manipulated through pointers that point to memory allocated on the heap.

## Some useful `Box` methods

Rust's `Box` has a method (akin to `C++`'s `std::unique_ptr::release`), called `into_raw`, to leak the underlying pointer to a heap allocated object. This pointer can then be returned to the `C` caller for later manipulations.

Rust's `Box` also has a method, `from_raw`, to recreate a box from a raw pointer (that was previously leaked using `into_raw`) to finally free the memory. This allows to write functions to free a heap allocated object from the raw pointer passed by the caller.

## Example of how `FftEngine` was added to the FFI

### Opaque struct instantiation

For opaque structs intantiation we need a set of two methods:
- a creation method, in this crate it will be named `new` followed by the snake cased struct name
- a symmetric destruction method, in this crate it will be named `destroy` followed by the snake cased struct name

We also provide unchecked versions of each function, these unchecked functions have the same name as the checked function with `_unchecked` appended.

You can read more about `checked` vs `unchecked` APIs [here](../api/api.md#concrete-core-ffi).

Here we will look at how `new_fft_engine`, `new_fft_engine_unchecked`, `destroy_fft_engine` and `destroy_fft_engine_unchecked` were constructed. If you want you can check out these functions in `src/backends/fft/engines/mod.rs`.

The first important thing is that to expose the `new_fft_engine` unchanged to the `C` caller, we need to use the `#[no_mangle]` attribute on it and declare it as `extern "C"` so that the [ABI](https://en.wikipedia.org/wiki/Application_binary_interface) allows it to be called by `C` code.

Here is what the empty function would looke like empty:

```rust
#[no_mangle]
pub unsafe extern "C" fn new_fft_engine(result: *mut *mut FftEngine) -> c_int {}
//|      | |        |                            |__________________|_ out parameter to be filled
//|      | |        |
//|      | |________|_ https://doc.rust-lang.org/std/keyword.extern.html
//|      |
//|      |_ manipulating raw pointers is unsafe
//|
//|_ required to be exported
```

Note that, `result`, the out parameter, is a pointer to pointer. We will return a pointer to a Boxed/heap allocated `FftEngine`, in essence a `*mut FftEngine`. To be able to return this value we need a pointer to a memory location pointing to such a pointer, i.e. a `*mut *mut FftEngine`.

We adopted the convention of always returning a `c_int` as an error/status code.

All return values are returned through out parameters like the one described just above.

Panicking across the FFI boundary is undefined behavior, we therefore make use of the `catch_panic` function made available in the crate's utils module:

```rust
#[no_mangle]
pub unsafe extern "C" fn new_fft_engine(result: *mut *mut FftEngine) -> c_int {
    catch_panic(|| {})
}
```

Note: apparently Rust will abort in functions marked `extern` https://github.com/rust-lang/rust/issues/52652, this is currently feature-gated (and therefore probably requires nightly, see [here](https://github.com/rust-lang/rust/issues/52652#issuecomment-1011313711)).

`catch_panic` already returns a `c_int` value. If the closure passed to the function panics it returns 1 indicating a failure otherwise it returns 0 indicating normal operation.

All code in the FFI functions are wrapped in `catch_panic` in a closure taking no parameters. This also allows to bubble up errors on `unwrap`, a bit like `C++` exceptions, and have a human readable backtrace if something went wrong.

This is the checked version of the function, so we verify that the `result` pointer we were given is valid. This means checking it is not `NULL` and that it's well aligned. To do that we use `check_ptr_is_non_null_and_aligned` also provided in the `utils` module of the crate.

```rust
#[no_mangle]
pub unsafe extern "C" fn new_fft_engine(result: *mut *mut FftEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();
    })
}
```

We call `unwrap` to be able to bubble the potential error up.

```rust
#[no_mangle]
pub unsafe extern "C" fn new_fft_engine(result: *mut *mut FftEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();
    })
}
```

We start by filling the output pointer with a `NULL` value to mimic `C` malloc behavior.

```rust
#[no_mangle]
pub unsafe extern "C" fn new_fft_engine(result: *mut *mut FftEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_fft_engine = Box::new(FftEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_fft_engine);
    })
}
```

We allocate the new `FftEngine` on the heap thanks to `Box`, we `unwrap` to bubble potential errors up. `C` does not know about `Box`, so we leak the underlying pointer using `Box::into_raw` and store it in the previously checked result pointer. The `C` caller can then use `*result` as an `FftEngine *` through the FFI boundary.

The unchecked version of the function is the same without the verification of the result pointer:

```rust
#[no_mangle]
pub unsafe extern "C" fn new_fft_engine_unchecked(result: *mut *mut FftEngine) -> c_int {
    catch_panic(|| {
        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let heap_allocated_fft_engine = Box::new(FftEngine::new(()).unwrap());
        *result = Box::into_raw(heap_allocated_fft_engine);
    })
}
```

### Opaque struct destruction

For the symmetric destruction function, the empty function looks like this:

```rust
pub unsafe extern "C" fn destroy_fft_engine(engine: *mut FftEngine) -> c_int {}
//                                                   |_____________|_ no pointer to pointer
```

Here we only need a pointer to be able to use the object as we won't be returning a result.

Catch panic pattern is the same as in the previous section.

```rust
#[no_mangle]
pub unsafe extern "C" fn destroy_fft_engine(engine: *mut FftEngine) -> c_int {
    catch_panic(|| {})
}
```

We check the pointer we were given, calling `unwrap` to bubble errors up:

```rust
#[no_mangle]
pub unsafe extern "C" fn destroy_fft_engine(engine: *mut FftEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();
    })
}
```

And then we actually destroy the passed struct:

```rust
#[no_mangle]
pub unsafe extern "C" fn destroy_fft_engine(engine: *mut FftEngine) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(engine).unwrap();

        // Reconstruct the box and drop it
        drop(Box::from_raw(engine));
    })
}
```

The unchecked version of the function is the same without the verification of the engine pointer:

```rust
#[no_mangle]
pub unsafe extern "C" fn destroy_fft_engine_unchecked(engine: *mut FftEngine) -> c_int {
    catch_panic(|| {
        // Reconstruct the box and drop it
        drop(Box::from_raw(engine);
    })
}
```
