# Creating a Backend

Everything's been made easy for anyone to create their own backend in `concrete-core`! Implementations targeting specific hardware are thus easy to plug with Concrete. The main steps to create your backend are:

1. [Add an optional feature in the Cargo.toml](creating\_backends.md#add-an-optional-feature)
2. [Build the structure for the new backend](creating\_backends.md#build-the-structure-for-the-new-backend)
3. [Implement some entities and engine traits of your choice](creating\_backends.md#implement-the-entity-and-engine-traits-of-your-choice)

Let's see how to do this in more detail. For the sake of this tutorial, we're going to add a GPU backend to `concrete-core`, but it could be any other hardware.

## Prerequisites

Before following any of the steps shown in this tutorial, you actually have to create a crate that exposes some hardware-accelerated functions you want to use in `concrete-core`. For example, your Rust crate could actually be wrapping some C/C++ code.

So, let's imagine you've created a crate `fhe-gpu` that exposes some Rust functions to allocate and copy data to a GPU. In an actual backend, you'd have to implement some operations ( ciphertext addition, keyswitch, bootstrap) and the data copy from GPU to CPU to get the results back. Here, we'll only consider four functions:

* `get_number_of_gpus`: returns the number of GPUs detected on the machine;
* `malloc`: takes a size as input and returns a pointer with memory allocated with this size;
* `copy_to_gpu`: takes a pointer as input, together with a pointer to data on the CPU and a size, and copies the CPU data to the GPU;
* `cuda_drop`: takes a pointer as input and calls a function to clean memory.

The functions listed above would actually be wrapping C/C++ functions (with some OpenCL or Cuda code for the GPU programming). What we need to do is to pass some pointers and integers from Rust to the `malloc`, `copy_to_gpu` and `cuda_drop` functions.

Now, let's start actually modifying `concrete-core` to plug your crate with it!

## Add an optional feature

The first step is to configure `concrete-core`'s manifest to recognize your backend, and be able to optionally activate it.

Open `concrete-core`'s `Cargo.toml` file and edit the following section:

```ini
[features]
default = ["backend_default"]
doc = []
backend_default = []
slow-csprng = ["concrete-csprng/slow"]
multithread = ["rayon", "concrete-csprng/multithread"]
```

Add this line at the end of it:

```ini
backend_gpu = ["fhe_gpu"]
```

...and an optional dependency to the crate `fhe_gpu`:

```ini
[dependencies]
fhe-gpu = { version = "0.0.1", optional = true }
```

Now, you'll be able to:

```shell
cargo build -p concrete-core --release --features=backend_gpu
```

...which will build `concrete-core` with the features `backend_default` and `backend_gpu`.

## Build the structure for the new backend

### Create some new directories.

To build the structure for the new backend, first create some empty directories:

```shell
mkdir /path/to/concrete-core/src/backends/gpu
mkdir /path/to/concrete-core/src/backends/gpu/implementation
mkdir /path/to/concrete-core/src/backends/gpu/implementation/engines
mkdir /path/to/concrete-core/src/backends/gpu/implementation/entities
mkdir /path/to/concrete-core/src/backends/gpu/private
```

The `private` module is where you'll be putting the code you don't want to expose in the backend itself. Edit `concrete-core/src/backends/mod.rs` to add the following lines:

```rust
#[cfg(feature = "backend_gpu")]
pub mod gpu;
```

Edit also the prelude (`concrete-core/src/prelude.rs`) to add these lines:

```rust
#[cfg(feature = "backend_gpu")]
pub use super::backends::gpu::engines::*;
#[cfg(feature = "backend_gpu")]
pub use super::backends::gpu::entities::*;
```

With this in the prelude, it'll be possible for the user to import all they need with just one line:

```rust
use concrete_core::prelude::*;
```

### Create new modules.

Start with `concrete-core/src/backends/gpu/mod.rs`, which should contain the following:

```rust
//! A module containing the GPU backend implementation.
//!
//! This module contains GPU implementations of some functions of the concrete specification.

#[doc(hidden)]
pub mod private;

pub(crate) mod implementation;

pub use implementation::{engines, entities};
```

Then, `concrete-core/src/backends/gpu/implementation/mod.rs` should contain:

```rust
pub mod engines;
pub mod entities;
```

Create also two empty modules for engines and entities at `concrete-core/src/backends/gpu/implementation/engines/mod.rs` and `concrete-core/src/backends/gpu/implementation/entities/mod.rs`

## Implement the entity and engine traits of your choice

### Entities.

Start by implementing the entities you'll be using. Here, we want to allocate and copy data corresponding to LWE ciphertext vectors on the GPU. We need to create a new file: `concrete-core/src/backends/gpu/implementation/entities/lwe_ciphertext_vector.rs` Modify the entity module file, `concrete-core/src/backends/gpu/implementation/entities/mod.rs`, to actually link it to the rest of the sources:

```rust
//! A module containing all the [entities](crate::specification::entities) exposed by the GPU
//! backend.

mod lwe_ciphertext_vector;

pub use lwe_ciphertext_vector::*;
```

Now, let's implement that entity. What we want is to implement a `GpuLweCiphertextVector64` entity for the `LweCiphertextVectorEntity` trait in the specification.

A proposition of implementation is to have `GpuLweCiphertextVector64` wrap a structure containing a void pointer for the data on the GPU and some metadata (LWE dimension, etc.). To do this, create a new `lwe.rs` file in the `private` module, containing:

```rust
// Fields with `d_` are data in the GPU
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GpuLweList<T: UnsignedInteger> {
    // Pointer to GPU data
    pub(crate) d_ptr: *mut c_void,
    // Number of ciphertexts in the array
    pub(crate) lwe_ciphertext_count: LweCiphertextCount,
    // Lwe dimension
    pub(crate) lwe_dimension: LweDimension,
    // Field to hold type T
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: Numeric> Drop for GpuLweList<T> {
  fn drop(&mut self) {
    unsafe { cuda_drop(self.d_ptr) };
  }
}
```

Here the `GpuLweList` structure is made generic over the ciphertext modulus logarithm, so that it's easy to support different integer precisions. Memory is automatically dropped on the GPU when that structure goes out of scope thanks to the implementation of the `Drop` trait.

Do not forget to modify the `concrete-core/src/backends/gpu/private/mod.rs` file to add:

```rust
pub mod lwe;
```

Now, we can actually implement the entity trait:

```rust
use std::fmt::Debug;

use concrete_core::prelude::{LweCiphertextCount, LweDimension};

use crate::backends::cuda::private::crypto::lwe::list::GpuLweList;
use crate::specification::entities::markers::LweCiphertextVectorKind;
use crate::specification::entities::{AbstractEntity, LweCiphertextVectorEntity};

/// A structure representing a vector of LWE ciphertexts with 64 bits of precision on the GPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuLweCiphertextVector64(pub(crate) GpuLweList<u64>);

impl AbstractEntity for GpuLweCiphertextVector64 {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for GpuLweCiphertextVector64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count()
    }
}
```

You can do this for all the entity traits you need in your backend.

### Engines.

Now that we have some entities, let's do something with them. For this GPU backend example, we're going to allocate data on the GPU and copy the LWE ciphertext vector from the CPU to the GPU.

First, let's create the main engine in `concrete-core/src/backends/gpu/implementation/engines/mod.rs`. This `GpuEngine` is only successfully created when the `get_number_of_gpus` function finds at least one GPU. Otherwise, an error is returned: this example also shows you how to define error cases and their display to the user.

```rust
use crate::prelude::sealed::AbstractEngineSeal;
use crate::prelude::AbstractEngine;
use std::error::Error;
use std::fmt::{Display, Formatter};

use fhe_gpu::get_number_of_gpus;

#[derive(Debug)]
pub enum GpuError {
    DeviceNotFound,
}

impl Display for GpuError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuError::DeviceNotFound => {
                write!(f, "No GPU detected on the machine.")
            }
        }
    }
}

impl Error for GpuError {}

/// The main engine exposed by the GPU backend.
///
#[derive(Debug, Clone)]
pub struct GpuEngine {}

impl AbstractEngineSeal for GpuEngine {}

impl AbstractEngine for GpuEngine {
    type EngineError = GpuError;

    fn new() -> Result<Self, Self::EngineError> {
        let number_of_gpus = unsafe { get_number_of_gpus() as usize };
        if number_of_gpus == 0 {
            Err(GpuError::DeviceNotFound)
        } else {
            Ok(GpuEngine {})
        }
    }
}

mod lwe_ciphertext_vector_conversion;
```

As you see at the bottom of the previous code block, we're going to implement one engine trait, to copy the LWE ciphertext vector from the CPU to the GPU.

Create the file `concrete-core/src/backends/gpu/implementation/engines/lwe_ciphertext_vector_conversion.rs`. It should contain:

```rust
use crate::backends::core::implementation::entities::LweCiphertextVector64;
use crate::commons::crypto::lwe::LweList;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::backends::gpu::implementation::engines::{GpuEngine, GpuError};
use crate::backends::gpu::implementation::entities::{
    GpuLweCiphertextVector64,
};
use crate::backends::gpu::private::crypto::lwe::list::GpuLweList;
use crate::specification::engines::{
    LweCiphertextVectorConversionEngine, LweCiphertextVectorConversionError,
};
use crate::specification::entities::LweCiphertextVectorEntity;
use fhe_gpu::{copy_to_gpu, malloc};

impl From<GpuError> for LweCiphertextVectorConversionError<GpuError> {
    fn from(err: GpuError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 64 bits of precision from CPU to GPU.
///
impl LweCiphertextVectorConversionEngine<LweCiphertextVector64, GpuLweCiphertextVector64>
for GpuEngine
{
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> Result<GpuLweCiphertextVector64, LweCiphertextVectorConversionError<GpuError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> GpuLweCiphertextVector64 {
        let alloc_size = input.lwe_ciphertext_count().0 * input.lwe_dimension().to_lwe_size().0;
        let input_slice = input.0.as_tensor().as_slice();
        let d_ptr = malloc::<u64>(alloc_size as u64);
        copy_to_gpu::<u64>(d_ptr, input_slice, alloc_size);

        GpuLweCiphertextVector64(GpuLweList::<u64> {
            d_ptr,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
            _phantom: Default::default(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext vector with 64 bits of precision from GPU to CPU.
impl LweCiphertextVectorConversionEngine<GpuLweCiphertextVector64, LweCiphertextVector64>
for GpuEngine
{
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &GpuLweCiphertextVector64,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorConversionError<GpuError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GpuLweCiphertextVector64,
    ) -> LweCiphertextVector64 {
        let mut output = vec![0u64; input.lwe_dimension().to_lwe_size().0 * input.lwe_ciphertext_count().0];
        copy_to_cpu::<u64>(output, input.0.get_ptr(GpuIndex(gpu_index as u64)).0);
        LweCiphertextVector64(LweList::from_container(
            output,
            input.lwe_dimension().to_lwe_size(),
        ))
    }
}
```

Now, a user is able to write:

```rust
use concrete_core::prelude::*;

// DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
let lwe_dimension = LweDimension(6);
// Here a hard-set encoding is applied (shift by 20 bits)
let input = vec![3_u64 << 20; 3];
let noise = Variance(2_f64.powf(-25.));

let mut default_engine = DefaultEngine::new().unwrap();
let h_key: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension).unwrap();
let h_plaintext_vector: PlaintextVector64 = default_engine.create_plaintext_vector_from(&input).unwrap();
let mut h_ciphertext_vector: LweCiphertextVector64 =
default_engine.encrypt_lwe_ciphertext_vector(&h_key, &h_plaintext_vector, noise).unwrap();

let mut gpu_engine = GpuEngine::new().unwrap();
let d_ciphertext_vector: GpuLweCiphertextVector64 =
gpu_engine.convert_lwe_ciphertext_vector(&h_ciphertext_vector).unwrap();
let h_output_ciphertext_vector: LweCiphertextVector64 =
gpu_engine.convert_lwe_ciphertext_vector(&d_ciphertext_vector).unwrap();

assert_eq!(d_ciphertext_vector.lwe_dimension(), lwe_dimension);
assert_eq!(
    d_ciphertext_vector.lwe_ciphertext_count(),
    LweCiphertextCount(3)
);
```

And this converts an LWE ciphertext vector from the CPU to the GPU! Next step is to test your backend. For this, head to the [tests tutorial](testing\_backends.md).
