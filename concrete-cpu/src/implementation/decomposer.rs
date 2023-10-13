use super::types::*;

#[derive(Copy, Clone, Debug)]
#[readonly::make]
pub struct SignedDecomposer {
    pub decomposition_base_log: usize,
    pub decomposition_level_count: usize,
}

impl SignedDecomposer {
    /// Creates a new decomposer.
    pub fn new(
        base_log: DecompositionBaseLog,
        level_count: DecompositionLevelCount,
    ) -> SignedDecomposer {
        debug_assert!(
            u64::BITS as usize > base_log.0 * level_count.0,
            "Decomposed bits exceeds the size of the integer to be decomposed"
        );
        SignedDecomposer {
            decomposition_base_log: base_log.0,
            decomposition_level_count: level_count.0,
        }
    }

    /// Returns the closet value representable by the decomposition.
    #[inline]
    pub fn closest_representable(&self, input: u64) -> u64 {
        // The closest number representable by the decomposition can be computed by performing
        // the rounding at the appropriate bit.

        // We compute the number of least significant bits which can not be represented by the
        // decomposition
        let non_rep_bit_count: usize =
            u64::BITS as usize - self.decomposition_level_count * self.decomposition_base_log;
        // We generate a mask which captures the non representable bits
        let non_rep_mask = 1_u64 << (non_rep_bit_count - 1);
        // We retrieve the non representable bits
        let non_rep_bits = input & non_rep_mask;
        // We extract the msb of the  non representable bits to perform the rounding
        let non_rep_msb = non_rep_bits >> (non_rep_bit_count - 1);
        // We remove the non-representable bits and perform the rounding
        let res = input >> non_rep_bit_count;
        let res = res + non_rep_msb;
        res << non_rep_bit_count
    }
}
