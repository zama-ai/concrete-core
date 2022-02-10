use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use concrete_core::prelude::{
    AbstractEngine, CoreEngine, GgswCiphertextComplex64, GlweCiphertext64,
};
use concrete_core_fixture::fixture::{
    Fixture, GlweCiphertextGgswCiphertextExternalProductFixture,
    GlweCiphertextGgswCiphertextExternalProductParameters,
};
use concrete_core_fixture::generation::{IntegerPrecision, Maker, Precision64};
use concrete_core_fixture::raw::generation::RawUnsignedIntegers;
use concrete_core_fixture::SampleSize;

fn main() {
    let mut maker = Maker::default();
    let mut engine = CoreEngine::new().unwrap();
    type Precision = Precision64;

    // The output is a vec containing polynomials with integer coefficients (here u64).
    let output: Vec<Vec<_>> = <GlweCiphertextGgswCiphertextExternalProductFixture as Fixture<
        Precision,
        CoreEngine,
        (GlweCiphertext64, GgswCiphertextComplex64, GlweCiphertext64),
    >>::sample(
        &mut maker,
        &mut engine,
        &GlweCiphertextGgswCiphertextExternalProductParameters {
            ggsw_noise: Variance(0.0001),
            glwe_noise: Variance(0.0001),
            glwe_dimension: GlweDimension(100),
            poly_size: PolynomialSize(256),
            dec_level_count: DecompositionLevelCount(7),
            dec_base_log: DecompositionBaseLog(3),
        },
        &(
            <Precision as IntegerPrecision>::Raw::uniform(),
            // ^ Sampling of the raw message put in the ggsw
            <Precision as IntegerPrecision>::Raw::uniform_vec(256),
            // ^ Sampling of the raw messages put in the glwe coefficients
        ),
        SampleSize(10),
    )
    .into_iter()
    .map(|(v,)| v)
    .collect();

    // You can now save the output the way you want
}
