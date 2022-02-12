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
use f64;

#[derive(Debug)]
struct NotABit(u64);

fn minimal_variance_for_security_64(k: GlweDimension, size: PolynomialSize) -> f64 {
    f64::max(
        f64::powf(
            2.,
            -2. * 0.026374888765705498 * k.0 as f64 * size.0 as f64 + 2. * 2.012143923330495,
        ),
        f64::powi(2., -(2 * 64 - 2 * 2)),
    )
}

fn mean(data: &[i64]) -> Option<f64> {
    // adapted from https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html
    let sum = data.iter().sum::<i64>() as f64;
    let count = data.len();

    match count {
        positive if positive > 0 => Some(sum / count as f64),
        _ => None,
    }
}

fn std_deviation(data: &[i64]) -> Option<f64> {
    // from https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html
    match (mean(data), data.len()) {
        (Some(data_mean), count) if count > 0 => {
            let variance = data
                .iter()
                .map(|value| {
                    let diff = data_mean - (*value as f64);

                    diff * diff
                })
                .sum::<f64>()
                / count as f64;

            Some(variance.sqrt())
        }
        _ => None,
    }
}

fn compute_error(output: &[u64], input: &[u64], bit: u64) -> Result<Vec<i64>, NotABit> {
    match bit {
        1 => Ok(output
            .iter()
            .zip(input.iter())
            .map(|(out, inp)| (out.wrapping_sub(*inp)) as i64)
            .collect()),
        0 => Ok(output.iter().map(|out| *out as i64).collect()),
        _ => Err(NotABit(bit)),
    }
}

fn main() {
    let sample_size = SampleSize(10);
    let mut maker = Maker::default();
    let mut engine = CoreEngine::new().unwrap();
    type Precision = Precision64;

    let glwe_dimension = GlweDimension(1);
    let poly_size = PolynomialSize(1024);
    let dec_level_count = DecompositionLevelCount(3);
    let dec_base_log = DecompositionBaseLog(7);
    let ggsw_noise =
        Variance::from_variance(minimal_variance_for_security_64(glwe_dimension, poly_size));
    let glwe_noise =
        Variance::from_variance(minimal_variance_for_security_64(glwe_dimension, poly_size));

    let parameters = GlweCiphertextGgswCiphertextExternalProductParameters {
        ggsw_noise,
        glwe_noise,
        glwe_dimension,
        poly_size,
        dec_level_count,
        dec_base_log,
    };

    let raw_inputs = (
        1 as u64,
        // <Precision as IntegerPrecision>::Raw::uniform(),
        // ^ Sampling of the raw message put in the ggsw
        <Precision as IntegerPrecision>::Raw::uniform_n_msb_vec(3, poly_size.0),
        // ^ Sampling of the raw messages put in the glwe coefficients
    );

    // The output is a vec containing polynomials with integer coefficients (here u64).
    let output: Vec<Vec<_>> = <GlweCiphertextGgswCiphertextExternalProductFixture as Fixture<
        Precision,
        CoreEngine,
        (GlweCiphertext64, GgswCiphertextComplex64, GlweCiphertext64),
    >>::sample(
        &mut maker,
        &mut engine,
        &parameters,
        &raw_inputs,
        sample_size,
    )
    .into_iter()
    .map(|(v,)| v)
    .collect();

    let input_bit = raw_inputs.0;
    let input_polynomial = raw_inputs.1;

    // let err = output
    //     .iter()
    //     .map(|a| {
    //         a.iter()
    //             .zip(input_polynomial.iter())
    //             .map(|(out, inp)| (out - inp) as i64)
    //             .collect()
    //     })
    //     .collect();

    let err: Vec<i64> = output
        .iter()
        .map(|out| compute_error(out, &input_polynomial, raw_inputs.0).unwrap())
        .into_iter()
        .flatten()
        .collect();

    let mean_err = mean(&err).unwrap();
    let std_err = std_deviation(&err).unwrap();
    println!(
        "-> Mean: {} \n-> Log2StdDev: {}",
        mean_err,
        f64::log2(std_err)
    );

    // let err: Vec<i64> = output[0]
    //     .iter()
    //     .zip(input_polynomial.iter())
    //     .map(|(out, inp)| (out.wrapping_sub(*inp)) as i64)
    //     .collect();

    // let res = raw_inputs.1 - output;
    let a = 0;
    // println!("{:?}", res);

    // You can now save the output the way you want
}
