use super::RandomGenerator;
use crate::commons::math::random::ByteRandomGenerator;
use concrete_csprng::generators::{
    BytesPerChild, ChildrenCount, DynamicRandomGeneratorParChildrenIterator, ForkError,
    ParallelRandomGenerator as ParallelByteRandomGenerator,
};
use rayon::iter::plumbing::{Consumer, ProducerCallback, UnindexedConsumer};
use rayon::prelude::*;
use std::marker::PhantomData;

/// Parallel counter-part of [`super::RandomGeneratorChildrenIterator`].
pub struct RandomGeneratorParChildrenIterator<G: ByteRandomGenerator>(
    DynamicRandomGeneratorParChildrenIterator,
    PhantomData<G>,
);

impl<G: ByteRandomGenerator + Send> ParallelIterator for RandomGeneratorParChildrenIterator<G> {
    type Item = RandomGenerator<G>;
    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        self.0
            .map(|gen| RandomGenerator::<G>(gen, PhantomData))
            .drive_unindexed(consumer)
    }
}

impl<G: ByteRandomGenerator + Send> IndexedParallelIterator
    for RandomGeneratorParChildrenIterator<G>
{
    fn len(&self) -> usize {
        self.0.len()
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        self.0
            .map(|gen| RandomGenerator::<G>(gen, PhantomData))
            .drive(consumer)
    }

    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        self.0
            .map(|gen| RandomGenerator::<G>(gen, PhantomData))
            .with_producer(callback)
    }
}

/// Parallel random generation functions.
impl<G> RandomGenerator<G>
where
    G: ByteRandomGenerator + Send,
{
    /// Tries to fork the current generator into `n_child` generator bounded to `bytes_per_child`,
    /// as a parallel iterator.
    ///
    /// If `n_child*bytes_per_child` exceeds the bound of the current generator, the method
    /// returns `None`.
    ///
    /// # Notes
    ///
    /// This method necessitates the "parallel" feature to be used.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::commons::math::random::RandomGenerator;
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let children = generator.try_fork(5, 50).unwrap().collect::<Vec<_>>();
    /// ```
    pub fn par_try_fork(
        &mut self,
        n_child: usize,
        bytes_per_child: usize,
    ) -> Result<RandomGeneratorParChildrenIterator<G>, ForkError> {
        Ok(RandomGeneratorParChildrenIterator(
            self.0
                .par_try_fork(ChildrenCount(n_child), BytesPerChild(bytes_per_child))?,
            PhantomData,
        ))
    }
}
