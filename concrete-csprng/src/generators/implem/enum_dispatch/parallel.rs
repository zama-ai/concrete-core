use super::DynamicRandomGenerator;
#[cfg(feature = "generator_x86_64_aesni")]
use crate::generators::ParallelAesniChildrenIterator;
#[cfg(feature = "generator_soft")]
use crate::generators::ParallelSoftwareChildrenIterator;
use crate::generators::{BytesPerChild, ChildrenCount, ForkError, ParallelRandomGenerator};
use rayon::iter::plumbing::{Consumer, ProducerCallback, UnindexedConsumer};
use rayon::prelude::{IndexedParallelIterator, ParallelIterator};

#[allow(clippy::large_enum_variant)]
pub enum DynamicRandomGeneratorParChildrenIterator {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni(ParallelAesniChildrenIterator),
    #[cfg(feature = "generator_soft")]
    Software(ParallelSoftwareChildrenIterator),
}

impl ParallelIterator for DynamicRandomGeneratorParChildrenIterator {
    type Item = DynamicRandomGenerator;
    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGeneratorParChildrenIterator::Aesni(inner) => inner
                .map(DynamicRandomGenerator::Aesni)
                .drive_unindexed(consumer),
            #[cfg(feature = "generator_soft")]
            DynamicRandomGeneratorParChildrenIterator::Software(inner) => inner
                .map(DynamicRandomGenerator::Software)
                .drive_unindexed(consumer),
        }
    }
}

impl IndexedParallelIterator for DynamicRandomGeneratorParChildrenIterator {
    fn len(&self) -> usize {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGeneratorParChildrenIterator::Aesni(inner) => inner.len(),
            #[cfg(feature = "generator_soft")]
            DynamicRandomGeneratorParChildrenIterator::Software(inner) => inner.len(),
        }
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGeneratorParChildrenIterator::Aesni(inner) => {
                inner.map(DynamicRandomGenerator::Aesni).drive(consumer)
            }
            #[cfg(feature = "generator_soft")]
            DynamicRandomGeneratorParChildrenIterator::Software(inner) => {
                inner.map(DynamicRandomGenerator::Software).drive(consumer)
            }
        }
    }

    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGeneratorParChildrenIterator::Aesni(inner) => inner
                .map(DynamicRandomGenerator::Aesni)
                .with_producer(callback),
            #[cfg(feature = "generator_soft")]
            DynamicRandomGeneratorParChildrenIterator::Software(inner) => inner
                .map(DynamicRandomGenerator::Software)
                .with_producer(callback),
        }
    }
}

impl ParallelRandomGenerator for DynamicRandomGenerator {
    type ParChildrenIter = DynamicRandomGeneratorParChildrenIterator;

    fn par_try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<DynamicRandomGeneratorParChildrenIterator, ForkError> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGenerator::Aesni(inner) => {
                Ok(DynamicRandomGeneratorParChildrenIterator::Aesni(
                    inner.par_try_fork(n_children, n_bytes)?,
                ))
            }
            #[cfg(feature = "generator_soft")]
            DynamicRandomGenerator::Software(inner) => {
                Ok(DynamicRandomGeneratorParChildrenIterator::Software(
                    inner.par_try_fork(n_children, n_bytes)?,
                ))
            }
        }
    }
}
