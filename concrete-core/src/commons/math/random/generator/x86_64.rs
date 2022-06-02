use super::RandomGenerator;
use concrete_csprng::generators::{
    AesniRandomGenerator, DynamicRandomGenerator,
    InstantiatesRandomGenerator as InstantiatesByteRandomGenerator, RandomGeneratorImplementation,
};
use concrete_csprng::seeders::Seed;
use std::marker::PhantomData;

impl RandomGenerator<AesniRandomGenerator> {
    pub fn new(seed: Seed) -> Self {
        RandomGenerator(
            <DynamicRandomGenerator as InstantiatesByteRandomGenerator>::new(
                RandomGeneratorImplementation::Aesni,
                seed,
            )
            .unwrap(),
            PhantomData,
        )
    }
}
