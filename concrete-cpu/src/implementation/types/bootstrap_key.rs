use crate::implementation::{Container, ContainerMut, Split};

use super::{
    DecompositionBaseLog, DecompositionLevelCount, GgswCiphertext, GlweDimension, LweDimension,
    PolynomialSize,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[readonly::make]
pub struct BootstrapKey<C: Container> {
    pub data: C,
    pub polynomial_size: PolynomialSize,
    pub glwe_dimension: GlweDimension,
    pub decomposition_level_count: DecompositionLevelCount,
    pub input_lwe_dimension: LweDimension,

    pub decomposition_base_log: DecompositionBaseLog,
}

impl<C: Container> BootstrapKey<C> {
    pub fn data_len(
        polynomial_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        decomposition_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
    ) -> usize {
        polynomial_size.0
            * glwe_dimension.as_glwe_size().0
            * glwe_dimension.as_glwe_size().0
            * decomposition_level_count.0
            * input_lwe_dimension.0
    }

    pub fn new(
        data: C,
        polynomial_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        decomposition_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Self {
        debug_assert_eq!(
            data.len(),
            Self::data_len(
                polynomial_size,
                glwe_dimension,
                decomposition_level_count,
                input_lwe_dimension
            ),
        );
        Self {
            data,
            polynomial_size,
            glwe_dimension,
            decomposition_level_count,
            input_lwe_dimension,
            decomposition_base_log,
        }
    }

    pub fn as_view(&self) -> BootstrapKey<&[C::Item]> {
        BootstrapKey {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
            decomposition_level_count: self.decomposition_level_count,
            input_lwe_dimension: self.input_lwe_dimension,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> BootstrapKey<&mut [C::Item]>
    where
        C: ContainerMut,
    {
        BootstrapKey {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_dimension: self.glwe_dimension,
            decomposition_level_count: self.decomposition_level_count,
            input_lwe_dimension: self.input_lwe_dimension,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = GgswCiphertext<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.input_lwe_dimension.0)
            .map(move |slice| {
                GgswCiphertext::new(
                    slice,
                    self.polynomial_size,
                    self.glwe_dimension,
                    self.decomposition_level_count,
                    self.decomposition_base_log,
                )
            })
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.glwe_dimension.0 * self.polynomial_size.0)
    }
}
