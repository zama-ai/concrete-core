use crate::backends::ntt::private::math::transform::Ntt;
use crate::commons::crypto::glwe::GlweCiphertext;
use crate::commons::math::torus::UnsignedTorus;
use crate::commons::numeric::UnsignedInteger;
use crate::prelude::{GlweSize, PolynomialSize};

pub struct BootstrapBuffers<Scalar, NttScalar: UnsignedInteger> {
    pub ntt: Ntt<NttScalar>,
    // Those buffers are also used to store the lut and the rounded input during the bootstrap.
    pub lut_buffer: GlweCiphertext<Vec<Scalar>>,
    pub rounded_buffer: GlweCiphertext<Vec<Scalar>>,
}

impl<Scalar, NttScalar> BootstrapBuffers<Scalar, NttScalar>
where
    Scalar: UnsignedTorus,
    NttScalar: UnsignedInteger,
{
    pub fn new(poly_size: PolynomialSize, glwe_size: GlweSize, ntt: Ntt<NttScalar>) -> Self {
        let lut_buffer = GlweCiphertext::allocate(Scalar::ZERO, poly_size, glwe_size);
        let rounded_buffer = GlweCiphertext::allocate(Scalar::ZERO, poly_size, glwe_size);

        Self {
            ntt,
            lut_buffer,
            rounded_buffer,
        }
    }
}
