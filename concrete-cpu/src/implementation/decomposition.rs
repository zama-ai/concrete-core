use core::iter::Map;
use core::slice::IterMut;

use super::types::*;
use dyn_stack::{DynArray, DynStack};

pub struct TensorSignedDecompositionLendingIter<'buffers> {
    // The base log of the decomposition
    base_log: usize,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: u64,
    // The internal states of each decomposition
    states: DynArray<'buffers, u64>,
    // A flag which stores whether the iterator is a fresh one (for the recompose method).
    fresh: bool,
}

impl<'buffers> TensorSignedDecompositionLendingIter<'buffers> {
    #[inline]
    pub(crate) fn new(
        input: impl Iterator<Item = u64>,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        stack: DynStack<'buffers>,
    ) -> (Self, DynStack<'buffers>) {
        let shift = u64::BITS as usize - base_log.0 * level.0;
        let (states, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, input.map(|i| i >> shift));
        (
            TensorSignedDecompositionLendingIter {
                base_log: base_log.0,
                current_level: level.0,
                mod_b_mask: (1_u64 << base_log.0) - 1_u64,
                states,
                fresh: true,
            },
            stack,
        )
    }

    // inlining this improves perf of external product by about 25%, even in LTO builds
    #[inline]
    pub fn next_term<'short>(
        &'short mut self,
    ) -> Option<(
        DecompositionLevel,
        DecompositionBaseLog,
        Map<IterMut<'short, u64>, impl FnMut(&'short mut u64) -> u64>,
    )> {
        // The iterator is not fresh anymore.
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        let current_level = self.current_level;
        let base_log = self.base_log;
        let mod_b_mask = self.mod_b_mask;
        self.current_level -= 1;

        Some((
            DecompositionLevel(current_level),
            DecompositionBaseLog(self.base_log),
            self.states
                .iter_mut()
                .map(move |state| decompose_one_level(base_log, state, mod_b_mask)),
        ))
    }
}

#[inline]
fn decompose_one_level(base_log: usize, state: &mut u64, mod_b_mask: u64) -> u64 {
    let res = *state & mod_b_mask;
    *state >>= base_log;
    let mut carry = (res.wrapping_sub(1_u64) | *state) & res;
    carry >>= base_log - 1;
    *state += carry;
    res.wrapping_sub(carry << base_log)
}
