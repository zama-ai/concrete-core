#[cfg(feature = "generator_x86_64_aesni")]
use crate::generators::{AesniChildrenIterator, AesniRandomGenerator};
use crate::generators::{ByteCount, BytesPerChild, ChildrenCount, ForkError, RandomGenerator};
#[cfg(feature = "generator_soft")]
use crate::generators::{SoftwareChildrenIterator, SoftwareRandomGenerator};
use crate::seeders::Seed;

#[cfg(feature = "parallel")]
mod parallel;
#[cfg(feature = "parallel")]
pub use parallel::*;

/// This enum makes it possible to use runtime dispatch for types implementing the
/// [`RandomGenerator`] trait.
///
/// The [`RandomGenerator`] trait is not object safe, which means we cannot use a `Box<dyn>` on top
/// of it and use trait object dispatch with a vtable. For concrete-core this is important, since
/// runtime dispatch is our only alternative to implementing one backend per [`RandomGenerator`]
/// implementation, with the sequential and parallel implementations each.
///
/// Note: the enum triggers `clippy::large_enum_variant` (silenced in this crate) depending on which
/// generators are enabled. If we were using generics this would not be an issue and each variant
/// would just take up some stack space in their respective implementation, here as an enum is just
/// a tagged union clippy warns about the fact that the worst case size is always the one allocated
/// on the stack. As variants in this case can have significantly different sizes it warns that it
/// may be inefficient. If this is a concern to you and can do without this
/// [`DynamicRandomGenerator`] you may want to use generics instead of this mechanism.
#[allow(clippy::large_enum_variant)]
pub enum DynamicRandomGenerator {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni(AesniRandomGenerator),
    #[cfg(feature = "generator_soft")]
    Software(SoftwareRandomGenerator),
}

impl Iterator for DynamicRandomGenerator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGenerator::Aesni(inner) => inner.next(),
            #[cfg(feature = "generator_soft")]
            DynamicRandomGenerator::Software(inner) => inner.next(),
        }
    }
}

impl RandomGenerator for DynamicRandomGenerator {
    type ChildrenIter = DynamicRandomGeneratorChildrenIterator;

    /// This `new` function is voluntarily left unimplemented as it's not suited to choose which
    /// variant of [`DynamicRandomGenerator`] to use. Instead use
    /// [`InstantiatesRandomGenerator::new`] as [`DynamicRandomGenerator`] implements
    /// [`InstantiatesRandomGenerator`].
    fn new(_seed: Seed) -> Self {
        unimplemented!(
            "To instantiate a specific variant of the CSPRNG enum please use the `new` \
            function from the `InstantiatesRandomGenerator` trait. This function is voluntarily \
            left unimplemented."
        )
    }

    fn next_byte(&mut self) -> Option<u8> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGenerator::Aesni(inner) => inner.next_byte(),
            #[cfg(feature = "generator_soft")]
            DynamicRandomGenerator::Software(inner) => inner.next_byte(),
        }
    }

    fn remaining_bytes(&self) -> ByteCount {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGenerator::Aesni(inner) => inner.remaining_bytes(),
            #[cfg(feature = "generator_soft")]
            DynamicRandomGenerator::Software(inner) => inner.remaining_bytes(),
        }
    }

    fn try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<DynamicRandomGeneratorChildrenIterator, ForkError> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGenerator::Aesni(inner) => {
                let children_iterator = inner.try_fork(n_children, n_bytes)?;
                Ok(DynamicRandomGeneratorChildrenIterator::Aesni(
                    children_iterator,
                ))
            }
            #[cfg(feature = "generator_soft")]
            DynamicRandomGenerator::Software(inner) => {
                let children_iterator = inner.try_fork(n_children, n_bytes)?;
                Ok(DynamicRandomGeneratorChildrenIterator::Software(
                    children_iterator,
                ))
            }
        }
    }

    fn is_available() -> bool {
        true
    }
}

#[derive(Debug)]
pub enum InstantiatesRandomGeneratorError {
    RandomGeneratorIsUnavailable,
}

impl std::fmt::Display for InstantiatesRandomGeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RandomGeneratorIsUnavailable => {
                write!(
                    f,
                    "The requested generator cannot be instantiated as it is not available on the \
                    current machine, check feature/platform/hardware requirements."
                )
            }
        }
    }
}

impl std::error::Error for InstantiatesRandomGeneratorError {}

/// Enum used to identify the different implementations of [`RandomGenerator`] from this crate
/// available through enum dispatch.
pub enum RandomGeneratorImplementation {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni,
    #[cfg(feature = "generator_soft")]
    Software,
}

impl RandomGeneratorImplementation {
    pub fn is_available(&self) -> bool {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            RandomGeneratorImplementation::Aesni => AesniRandomGenerator::is_available(),
            #[cfg(feature = "generator_soft")]
            RandomGeneratorImplementation::Software => SoftwareRandomGenerator::is_available(),
        }
    }
}

/// Objects able to instatiate various [`RandomGenerator`] implementations should implement this
/// trait.
pub trait InstantiatesRandomGenerator {
    fn new(
        backend: RandomGeneratorImplementation,
        seed: Seed,
    ) -> Result<Self, InstantiatesRandomGeneratorError>
    where
        Self: Sized;
}

impl InstantiatesRandomGenerator for DynamicRandomGenerator {
    fn new(
        backend: RandomGeneratorImplementation,
        seed: Seed,
    ) -> Result<DynamicRandomGenerator, InstantiatesRandomGeneratorError> {
        if !backend.is_available() {
            return Err(InstantiatesRandomGeneratorError::RandomGeneratorIsUnavailable);
        }

        match backend {
            #[cfg(feature = "generator_x86_64_aesni")]
            RandomGeneratorImplementation::Aesni => Ok(DynamicRandomGenerator::Aesni(
                AesniRandomGenerator::new(seed),
            )),
            #[cfg(feature = "generator_soft")]
            RandomGeneratorImplementation::Software => Ok(DynamicRandomGenerator::Software(
                SoftwareRandomGenerator::new(seed),
            )),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum DynamicRandomGeneratorChildrenIterator {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni(AesniChildrenIterator),
    #[cfg(feature = "generator_soft")]
    Software(SoftwareChildrenIterator),
}

impl Iterator for DynamicRandomGeneratorChildrenIterator {
    type Item = DynamicRandomGenerator;
    fn next(&mut self) -> Option<DynamicRandomGenerator> {
        match self {
            #[cfg(feature = "generator_x86_64_aesni")]
            DynamicRandomGeneratorChildrenIterator::Aesni(inner) => {
                inner.next().map(DynamicRandomGenerator::Aesni)
            }
            #[cfg(feature = "generator_soft")]
            DynamicRandomGeneratorChildrenIterator::Software(inner) => {
                inner.next().map(DynamicRandomGenerator::Software)
            }
        }
    }
}
