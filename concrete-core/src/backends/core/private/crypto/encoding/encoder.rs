use crate::backends::core::private::math::tensor::{AsMutTensor, AsRefTensor};
use crate::backends::core::private::math::torus::{FromTorus, IntoTorus, UnsignedTorus};

use super::{Cleartext, CleartextList, Plaintext, PlaintextList};
use concrete_commons::numeric::{FloatingPoint, Numeric};
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use crate::backends::core::private::math::decomposition::SignedDecomposer;

/// A trait for types that encode cleartext to plaintext.
///
/// Examples use the [`RealEncoder'] type.
pub trait Encoder<Enc: Numeric> {
    /// The type of the cleartexts.
    type Raw: Numeric;

    /// Encodes a single cleartext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_core::backends::core::private::crypto::encoding::*;
    /// let encoder = RealEncoder {
    ///     offset: 1. as f32,
    ///     delta: 10.,
    /// };
    /// let cleartext = Cleartext(7. as f32);
    /// let encoded: Plaintext<u32> = encoder.encode(cleartext.clone());
    /// let decoded = encoder.decode(encoded);
    /// assert!((cleartext.0 - decoded.0).abs() < 0.1);
    /// ```
    fn encode(&self, raw: Cleartext<Self::Raw>) -> Plaintext<Enc>;

    /// Decodes a single encoded value.
    ///
    /// See [`Encoder::encode`] for an example.
    fn decode(&self, encoded: Plaintext<Enc>) -> Cleartext<Self::Raw>;

    /// Encodes a list of cleartexts to a list of plaintexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_core::backends::core::private::crypto::encoding::*;
    /// let encoder = RealEncoder {
    ///     offset: 1. as f32,
    ///     delta: 10.,
    /// };
    /// let clear_values = CleartextList::from_container(vec![7. as f32; 100]);
    /// let mut plain_values = PlaintextList::from_container(vec![0 as u32; 100]);
    /// encoder.encode_list(&mut plain_values, &clear_values);
    /// let mut decoded_values = CleartextList::from_container(vec![0. as f32; 100]);
    /// encoder.decode_list(&mut decoded_values, &plain_values);
    /// for (clear, decoded) in clear_values
    ///     .cleartext_iter()
    ///     .zip(decoded_values.cleartext_iter())
    /// {
    ///     assert!((clear.0 - decoded.0).abs() < 0.1);
    /// }
    /// ```
    fn encode_list<RawCont, EncCont>(
        &self,
        encoded: &mut PlaintextList<EncCont>,
        raw: &CleartextList<RawCont>,
    ) where
        CleartextList<RawCont>: AsRefTensor<Element = Self::Raw>,
        PlaintextList<EncCont>: AsMutTensor<Element = Enc>;

    /// Decodes a list of plaintexts into a list of cleartexts.
    ///
    /// See [`Encoder::encode_list`] for an example.
    fn decode_list<RawCont, EncCont>(
        &self,
        raw: &mut CleartextList<RawCont>,
        encoded: &PlaintextList<EncCont>,
    ) where
        CleartextList<RawCont>: AsMutTensor<Element = Self::Raw>,
        PlaintextList<EncCont>: AsRefTensor<Element = Enc>;
}

/// An encoder for real cleartexts
pub struct RealEncoder<T: FloatingPoint> {
    /// The offset of the encoding
    pub offset: T,
    /// The delta of the encoding
    pub delta: T,
}

impl<RawScalar, EncScalar> Encoder<EncScalar> for RealEncoder<RawScalar>
where
    EncScalar: UnsignedTorus + FromTorus<RawScalar> + IntoTorus<RawScalar>,
    RawScalar: FloatingPoint,
{
    type Raw = RawScalar;
    fn encode(&self, raw: Cleartext<RawScalar>) -> Plaintext<EncScalar> {
        Plaintext(<EncScalar as FromTorus<RawScalar>>::from_torus(
            (raw.0 - self.offset) / self.delta,
        ))
    }
    fn decode(&self, encoded: Plaintext<EncScalar>) -> Cleartext<RawScalar> {
        let mut e: RawScalar = encoded.0.into_torus();
        e *= self.delta;
        e += self.offset;
        Cleartext(e)
    }
    fn encode_list<RawCont, EncCont>(
        &self,
        encoded: &mut PlaintextList<EncCont>,
        raw: &CleartextList<RawCont>,
    ) where
        CleartextList<RawCont>: AsRefTensor<Element = RawScalar>,
        PlaintextList<EncCont>: AsMutTensor<Element = EncScalar>,
    {
        encoded
            .as_mut_tensor()
            .fill_with_one(raw.as_tensor(), |r| self.encode(Cleartext(*r)).0);
    }
    fn decode_list<RawCont, EncCont>(
        &self,
        raw: &mut CleartextList<RawCont>,
        encoded: &PlaintextList<EncCont>,
    ) where
        CleartextList<RawCont>: AsMutTensor<Element = RawScalar>,
        PlaintextList<EncCont>: AsRefTensor<Element = EncScalar>,
    {
        raw.as_mut_tensor()
            .fill_with_one(encoded.as_tensor(), |e| self.decode(Plaintext(*e)).0);
    }
}

#[derive(Debug, PartialEq)]
pub struct CryptoApiEncoder{
    pub o: f64,     // with margin between 1 and 0
    pub delta: f64, // with margin between 1 and 0
    pub nb_bit_precision: usize,
    pub nb_bit_padding: usize,
    pub round: bool,
}

impl<EncScalar> Encoder<EncScalar> for CryptoApiEncoder where
    EncScalar: UnsignedTorus + FromTorus<f64> + IntoTorus<f64>,
{
    type Raw = f64;

    fn encode(&self, raw: Cleartext<Self::Raw>) -> Plaintext<EncScalar> {
        if raw.0 < self.o || raw.0 > self.o + self.delta {
            panic!("Message outside interval error.");
        }
        if !(self.nb_bit_precision == 0 || self.delta <= 0.) {
            panic!("Invalid encoder error.")
        }
        let mut res: EncScalar =
            <EncScalar as FromTorus<f64>>::from_torus(
                (raw.0 - self.o) / self.delta,
            );
        if self.round{
            let decomposer = SignedDecomposer::<EncScalar>::new(
                DecompositionBaseLog(self.nb_bit_precision),
                DecompositionLevelCount(1),
            );
            res = decomposer.closest_representable(res);
        }
        if self.nb_bit_padding > 0 {
            res >>= self.nb_bit_padding;
        }
        Plaintext(res)
    }

    fn decode(&self, encoded: Plaintext<EncScalar>) -> Cleartext<Self::Raw> {
        if !(self.nb_bit_precision == 0 || self.delta <= 0.) {
            panic!("Invalid encoder error.")
        }
        let mut tmp: EncScalar = if self.round {
            let decomposer = SignedDecomposer::<EncScalar>::new(
                DecompositionBaseLog(self.nb_bit_precision + self.nb_bit_padding),
                DecompositionLevelCount(1),
            );
            decomposer.closest_representable(encoded.0)
        } else {
            encoded.0
        };

        // remove padding
        if self.nb_bit_padding > 0 {
            tmp <<= self.nb_bit_padding;
        }

        // round if round is set to false and if in the security margin
        let starting_value_security_margin: EncScalar = ((EncScalar::ONE << (self.nb_bit_precision + 1)) - EncScalar::ONE)
            << (<EncScalar as Numeric>::BITS - self.nb_bit_precision);
        let decomposer = SignedDecomposer::<EncScalar>::new(
            DecompositionBaseLog(self.nb_bit_precision),
            DecompositionLevelCount(1),
        );
        tmp = if tmp > starting_value_security_margin {
            decomposer.closest_representable(tmp)
        } else {
            tmp
        };

        let mut e: f64 = tmp.into_torus();
        e *= self.delta;
        e += self.o;
        Cleartext(e)
    }

    fn encode_list<RawCont, EncCont>(&self, _encoded: &mut PlaintextList<EncCont>, _raw: &CleartextList<RawCont>) where CleartextList<RawCont>: AsRefTensor<Element=Self::Raw>, PlaintextList<EncCont>: AsMutTensor<Element=EncScalar> {
        panic!()
    }

    fn decode_list<RawCont, EncCont>(&self, _raw: &mut CleartextList<RawCont>, _encoded: &PlaintextList<EncCont>) where CleartextList<RawCont>: AsMutTensor<Element=Self::Raw>, PlaintextList<EncCont>: AsRefTensor<Element=EncScalar> {
        panic!()
    }
}