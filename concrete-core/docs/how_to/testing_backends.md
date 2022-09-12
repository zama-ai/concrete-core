# How to test your backend

Once you've implemented your backend, the first thing you need to do is to test it.
The `concrete-core-test` crate has been developed for this purpose. It relies on
the `concrete-core-fixture` crate, that implements generic functions to sample and test engines.

Let's continue with our GPU backend example. We now have a `GpuEngine` that implements a conversion
engine for LWE ciphertext arrays from the CPU to the GPU, and back. For this engine, we can easily
check that the ciphertext copied back from the GPU is identical to the original one on the CPU.
However, for more complex engines like the keyswitch, the bootstrap, etc., we need to make sure that
the amount of noise introduced by the operation corresponds to what's expected, i.e. that it matches
the noise formula implemented in the `concrete-npe` crate. For the sake of this tutorial, let us
continue with the simple conversion engines that copy data back and forth between the CPU and the
GPU, and then implement this verification.

For this, we're going to use the available fixture for LWE ciphertext array conversion. The only
thing we need to implement in `concrete-core-fixture` is the synthesis stage, where data will be
copied to the GPU, and back again. Then we'll use the existing fixture for LWE ciphertext array
conversion to execute the test.

## Add the GPU backend in the fixtures

Let's first add the GPU backend as a feature for the fixtures: edit the `Cargo.toml` file
of `concrete-core-fixture` to add the following lines in the dependencies and features sections:

```
[features]
backend_gpu = ["concrete-core/backend_gpu"]
```

Then, we need to add the `GpuEngine` to the `Maker` structure that's defined
in `concrete-core-fixture/src/generation/mod.rs`:

```rust
pub struct Maker {
    default_engine: concrete_core::backends::default::engines::DefaultEngine,
    #[cfg(feature = "backend_gpu")]
    gpu_engine: concrete_core::backends::gpu::engines::GpuEngine,
}

impl Default for Maker {
    fn default() -> Self {
        Maker {
            default_engine: concrete_core::backends::default::engines::DefaultEngine::new().unwrap(),
            #[cfg(feature = "backend_gpu")]
            gpu_engine: concrete_core::backends::gpu::engines::GpuEngine::new().unwrap(),
        }
    }
}
```

Now, in `concrete-core-fixture/src/generation/synthesizing/lwe_ciphertext_array.rs`, let us
introduce the necessary implementations to copy data to the GPU, retrieve and destroy it:

```rust
#[cfg(feature = "backend_gpu")]
mod backend_gpu {
    use crate::generation::prototypes::{
        ProtoBinaryLweCiphertextArray32,
    };
    use crate::generation::synthesizing::SynthesizesLweCiphertextArray;
    use crate::generation::{Maker, Precision32};
    use concrete_core::prelude::{
        GpuLweCiphertextArray32, DestructionEngine,
        LweCiphertextArrayConversionEngine,
    };

    impl SynthesizesLweCiphertextArray<Precision32, GpuLweCiphertextArray32> for Maker {
        fn synthesize_lwe_ciphertext_array(
            &mut self,
            prototype: &Self::LweCiphertextArrayProto,
        ) -> GpuLweCiphertextArray32 {
            self.gpu_engine
                .convert_lwe_ciphertext_array(&prototype.0)
                .unwrap()
        }
        fn unsynthesize_lwe_ciphertext_array(
            &mut self,
            entity: &GpuLweCiphertextArray32,
        ) -> Self::LweCiphertextArrayProto {
            let proto = self
                .gpu_engine
                .convert_lwe_ciphertext_array(entity)
                .unwrap();
            ProtoBinaryLweCiphertextArray32(proto)
        }
        fn destroy_lwe_ciphertext_array(&mut self, entity: GpuLweCiphertextArray32) {
            self.gpu_engine.destroy(entity).unwrap();
        }
    }
}
```

That's all we need to do on the fixtures side.

## Add the test in `concrete-core-test`

Now, let's add our test in `concrete-core-test`. Let's first edit the `Cargo.toml` to add a
dependency to our `fhe_gpu` crate, and a GPU feature:

```
[dependencies]
concrete-core = { path="../concrete-core" }
concrete-core-fixture = { path="../concrete-core-fixture" }
fhe-gpu = { version = "0.0.1", optional = true }
paste = "1.0"

[features]
backend_default = ["concrete-core/backend_default", "concrete-core-fixture/backend_default"]
backend_gpu = ["concrete-core/backend_gpu", "concrete-core-fixture/backend_gpu"]
```

Let's add a `cuda.rs` module to `concrete-core-test`. Create the file `gpu.rs`
in `concrete-core-test/src`
and edit `cocnrete-core-test/src/lib.rs` to add the following lines:

```rust
#[cfg(all(test, feature = "backend_gpu"))]
pub mod gpu;
```

The `gpu.rs` module should contain:

```rust
use crate::{REPETITIONS, SAMPLE_SIZE};
use concrete_core::prelude::*;
use concrete_core_fixture::fixture::*;
use concrete_core_fixture::generation::{Maker, Precision32};

pub fn test_lwe_ciphertext_array_conversion_32() {
    let mut criterion = Criterion::default().configure_from_args();
    let mut maker = Maker::default();
    let mut engine = GpuEngine::new().unwrap();
    let test_result = <LweCiphertextArrayConversionFixture as Fixture<Precision32, GpuEngine, (
        GpuLweCiphertextArray, LweCiphertextArray),
    >>::stress_all_parameters(
        &mut maker,
        engine,
        REPETITIONS,
        SAMPLE_SIZE,
    );
    assert!(test_result);
}
```

Finally, let's run our test!

## Execute the test

The command to run the tests for the GPU backend is:

```
cargo test -p concrete-core-test --features=backend_gpu,backend_default --release
```

You can filter it to execute a specific engine only:

```
cargo test -p concrete-core-test --features=backend_gpu,backend_default --release -- --test conversion
```

You should get as the output:

```
     Running unittests (target/release/deps/concrete_core_test-c662f8b6b8aa1434)

running 1 test
test cuda::test_lwe_ciphertext_array_conversion_fixture_precision32_cuda_lwe_ciphertext_array32_lwe_ciphertext_array32 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 42.33s

   Doc-tests concrete-core-test

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The next step is to benchmark your backend. For this, head to
the [benchmarks tutorial](benchmarking_backends.md)!
