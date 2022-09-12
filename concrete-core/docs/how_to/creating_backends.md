# How to create your own backend

Everything's been made easy for anyone to create their own backend in `concrete-core`!
Implementations targeting specific hardware are thus easy to plug with Concrete. The main steps to
create your backend are:

1. [Add an optional feature in the Cargo.toml](#add-an-optional-feature)
2. [Build the structure for the new backend](#build-the-structure-for-the-new-backend)
3. [Implement some entities and engine traits of your choice](#implement-the-entity-and-engine-traits-of-your-choice)

Let's see how to do this in more details. For the sake of this tutorial, we're going to add a GPU
backend to
`concrete-core`, but it could be any other hardware.

## Prerequisites

Before following any of the steps shown in this tutorial, you actually have to create a crate that
exposes some hardware-accelerated functions you want to use in `concrete-core`. For example, your
Rust crate could actually be wrapping some C/C++ code.

So, let's imagine you've created a crate `fhe-gpu` that exposes some Rust functions to allocate and
copy data to a GPU. In an actual backend, you'd have to implement some operation-s (
ciphertext addition, keyswitch, bootstrap), and the data copy from GPU to CPU to get the results
back. Here we'll only consider four functions:

- `get_number_of_gpus`: returns the number of GPUs detected on the machine;
- `malloc`: takes a size as input, and returns a pointer with memory allocated with this size;
- `copy_to_gpu`: takes a pointer as input, together with a pointer to data on the CPU and a size,
  and copies the CPU data to the GPU;
- `cuda_drop`: takes a pointer as input, and calls a function to clean memory.

The functions listed above would actually be wrapping C/C++ functions (with some OpenCL or Cuda code
for the GPU programming). What we need to do is to pass some pointers and integers from Rust to
the `malloc`, `copy_to_gpu` and `cuda_drop` functions.

Now, let's start actually modifying `concrete-core` to plug your crate with it!

## Add an optional feature

The first step is to configure `concrete-core`'s manifest to recognize your backend, and be able to
optionally activate it.

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

and an optional dependency to the crate `fhe_gpu`:

```ini
[dependencies]
fhe-gpu = { version = "0.0.1", optional = true }
```

Now, you'll be able to:

```shell
cargo build -p concrete-core --release --features=backend_gpu
```

which will build `concrete-core` with the features `backend_default` and `backend_gpu`.

## Build the structure for the new backend

### Create some new directories

Now we're going to build the structure for the new backend. First, create some empty directories:

```shell
mkdir /path/to/concrete-core/src/backends/gpu
mkdir /path/to/concrete-core/src/backends/gpu/implementation
mkdir /path/to/concrete-core/src/backends/gpu/implementation/engines
mkdir /path/to/concrete-core/src/backends/gpu/implementation/entities
mkdir /path/to/concrete-core/src/backends/gpu/private
```

The `private` module is where you'll be putting the code you don't want to expose in the backend
itself. Edit `concrete-core/src/backends/mod.rs` to add the following lines:

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

### Create new modules

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

Create also two empty modules for engines and entities
at `concrete-core/src/backends/gpu/implementation/engines/mod.rs`
and `concrete-core/src/backends/gpu/implementation/entities/mod.rs`

## Implement the entity and engine traits of your choice

### Entities

Start by implementing the entities you'll be using. Here, we want to allocate and copy data
corresponding to LWE ciphertext arrays on the GPU. We need to create a new file:
`concrete-core/src/backends/gpu/implementation/entities/lwe_ciphertext_array.rs`
Modify the entity module file, `concrete-core/src/backends/gpu/implementation/entities/mod.rs`, to
actually link it to the rest of the sources:

```rust
//! A module containing all the [entities](crate::specification::entities) exposed by the GPU
//! backend.

mod lwe_ciphertext_array;

pub use lwe_ciphertext_array::*;
```

Now, let's implement that entity. What we want is to implement a `GpuLweCiphertextArray32` entity
for the `LweCiphertextArrayEntity` trait in the specification.

A proposition of implementation is to have `GpuLweCiphertextArray32` wrap a structure containing a
void pointer for the data on the GPU, and some metadata (LWE dimension, etc.). To do this, create a
new `lwe.rs` file in the `private` module, containing:

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

impl<T: UnsignedInteger> GpuLweList<T> {
    pub(crate) fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.lwe_ciphertext_count
    }

    pub(crate) fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    /// Returns a mut pointer to the GPU data on a chosen GPU
    #[allow(dead_code)]
    pub(crate) unsafe fn get_ptr(&self) -> GpuLweCiphertextArrayPointer {
        self.d_ptr
    }
}
```

Do not forget to modify the `concrete-core/src/backends/gpu/private/mod.rs` file to add:

```rust
pub mod lwe;
```

Now, we can actually implement the entity trait:

```rust
use std::fmt::Debug;

use concrete_core::prelude::{LweCiphertextCount, LweDimension};

use crate::backends::cuda::private::crypto::lwe::list::GpuLweList;
use crate::specification::entities::markers::{BinaryKeyDistribution, LweCiphertextArrayKind};
use crate::specification::entities::{AbstractEntity, LweCiphertextArrayEntity};

/// A structure representing an array of LWE ciphertexts with 32 bits of precision on the GPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuLweCiphertextArray32(pub(crate) GpuLweList<u32>);

impl AbstractEntity for GpuLweCiphertextArray32 {
    type Kind = LweCiphertextArrayKind;
}

impl LweCiphertextArrayEntity for GpuLweCiphertextArray32 {
    type KeyDistribution = BinaryKeyDistribution;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.0.lwe_ciphertext_count()
    }
}
```

You can do this for all the entity traits you need in your backend.

### Engines

Now we have some entities, let's actually do something with them. For this GPU backend example,
we're going to allocate data on the GPU and copy the LWE ciphertext array from the CPU to the GPU.

First, let's create the main engine
in `concrete-core/src/backends/gpu/implementation/engines/mod.rs`. This `GpuEngine` is only
successfully created when the `get_number_of_gpus` function finds at least one GPU. Otherwise, an
error is returned: this example also shows you how to define error cases and their display to the
user.

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

mod destruction;
mod lwe_ciphertext_array_conversion;
```

As you see at the bottom of the previous code block, we're going to implement two engine traits: one
to copy the LWE ciphertext array from the CPU to the GPU, and one to destroy data on the GPU.
Create the files `concrete-core/src/backends/gpu/implementation/engines/destruction.rs`
and `concrete-core/src/backends/gpu/implementation/engines/lwe_ciphertext_array_conversion.rs`.
The `destruction.rs` file is going to look like this:

```rust
use crate::backends::gpu::implementation::engines::GpuEngine;
use crate::backends::gpu::implementation::entities::{
    GpuLweCiphertextArray32,
};
use crate::specification::engines::{DestructionEngine, DestructionError};
use fhe_gpu::cuda_drop;

impl DestructionEngine<GpuLweCiphertextArray32> for GpuEngine {
    fn destroy(
        &mut self,
        entity: GpuLweCiphertextArray32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: GpuLweCiphertextArray32) {
        // Here deallocate the Gpu memory
        cuda_drop(entity.0.get_ptr().0).unwrap();
    }
}
}
```

Finally, the `lwe_ciphertext_array_conversion.rs` file is going to contain:

```rust
use crate::backends::core::implementation::entities::LweCiphertextArray32;
use crate::commons::crypto::lwe::LweList;
use crate::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::backends::gpu::implementation::engines::{GpuEngine, GpuError};
use crate::backends::gpu::implementation::entities::{
    GpuLweCiphertextArray32,
};
use crate::backends::gpu::private::crypto::lwe::list::GpuLweList;
use crate::specification::engines::{
    LweCiphertextArrayConversionEngine, LweCiphertextArrayConversionError,
};
use crate::specification::entities::LweCiphertextArrayEntity;
use fhe_gpu::{copy_to_gpu, malloc};

impl From<GpuError> for LweCiphertextArrayConversionError<GpuError> {
    fn from(err: GpuError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
/// Convert an LWE ciphertext array with 32 bits of precision from CPU to GPU.
///
impl LweCiphertextArrayConversionEngine<LweCiphertextArray32, GpuLweCiphertextArray32>
for GpuEngine
{
    fn convert_lwe_ciphertext_array(
        &mut self,
        input: &LweCiphertextArray32,
    ) -> Result<GpuLweCiphertextArray32, LweCiphertextArrayConversionError<GpuError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &LweCiphertextArray32,
    ) -> GpuLweCiphertextArray32 {
        let alloc_size = input.lwe_ciphertext_count().0 * input.lwe_dimension().to_lwe_size().0;
        let input_slice = input.0.as_tensor().as_slice();
        let d_ptr = malloc::<u32>(alloc_size as u32);
        copy_to_gpu::<u32>(d_ptr, input_slice, alloc_size);

        GpuLweCiphertextArray32(GpuLweList::<u32> {
            d_ptr,
            lwe_ciphertext_count: input.lwe_ciphertext_count(),
            lwe_dimension: input.lwe_dimension(),
            _phantom: Default::default(),
        })
    }
}

/// # Description
/// Convert an LWE ciphertext array with 32 bits of precision from GPU to CPU.
impl LweCiphertextArrayConversionEngine<GpuLweCiphertextArray32, LweCiphertextArray32>
for GpuEngine
{
    fn convert_lwe_ciphertext_array(
        &mut self,
        input: &GpuLweCiphertextArray32,
    ) -> Result<LweCiphertextArray32, LweCiphertextArrayConversionError<GpuError>> {
        Ok(unsafe { self.convert_lwe_ciphertext_array_unchecked(input) })
    }

    unsafe fn convert_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &GpuLweCiphertextArray32,
    ) -> LweCiphertextArray32 {
        let mut output = vec![0u32; input.lwe_dimension().to_lwe_size().0 * input.lwe_ciphertext_count().0];
        copy_to_cpu::<u32>(output, input.0.get_ptr(GpuIndex(gpu_index as u32)).0);
        LweCiphertextArray32(LweList::from_container(
            output,
            input.lwe_dimension().to_lwe_size(),
        ))
    }
}

```

Now, a user is able to write:

```rust
use concrete_core::prelude::Variance;
use concrete_core::prelude::{LweCiphertextCount, LweDimension};
use concrete_core::prelude::*;

// DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
let lwe_dimension = LweDimension(6);
// Here a hard-set encoding is applied (shift by 20 bits)
let input = vec![3_u32 << 20; 3];
let noise = Variance(2_f64.powf(-25.));

let mut default_engine = DefaultEngine::new().unwrap();
let h_key: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension).unwrap();
let h_plaintext_array: PlaintextArray32 = default_engine.create_plaintext_array_from(&input).unwrap();
let mut h_ciphertext_array: LweCiphertextArray32 =
default_engine.encrypt_lwe_ciphertext_array(&h_key, &h_plaintext_array, noise).unwrap();

let mut gpu_engine = GpuEngine::new().unwrap();
let d_ciphertext_array: GpuLweCiphertextArray32 =
gpu_engine.convert_lwe_ciphertext_array(&h_ciphertext_array).unwrap();
let h_output_ciphertext_array: LweCiphertextArray32 =
gpu_engine.convert_lwe_ciphertext_array(&d_ciphertext_array).unwrap();

assert_eq!(d_ciphertext_array.lwe_dimension(), lwe_dimension);
assert_eq!(
    d_ciphertext_array.lwe_ciphertext_count(),
    LweCiphertextCount(3)
);

default_engine.destroy(h_key).unwrap();
default_engine.destroy(h_plaintext_array).unwrap();
default_engine.destroy(h_ciphertext_array).unwrap();
gpu_engine.destroy(d_ciphertext_array).unwrap();
default_engine.destroy(h_output_ciphertext_array).unwrap();
```

And this converts an LWE ciphertext array from the CPU to the GPU! Next step is to test your
backend, for this head to the [tests tutorial](testing_backends.md)!
