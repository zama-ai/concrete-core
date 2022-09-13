pub use concrete_fft::c64;
use core::mem::MaybeUninit;
use std::slice::{ChunksExact, ChunksExactMut};

pub mod crypto;
pub mod math;

pub trait Container: AsRef<[Self::Element]> {
    type Element;

    fn container_len(&self) -> usize {
        self.as_ref().len()
    }
}

pub trait ContainerOwned: Container + AsMut<[Self::Element]> {
    fn collect<I: Iterator<Item = Self::Element>>(iter: I) -> Self;
}

impl<T> Container for aligned_vec::ABox<[T]> {
    type Element = T;
}

impl ContainerOwned for aligned_vec::ABox<[c64]> {
    fn collect<I: Iterator<Item = Self::Element>>(iter: I) -> Self {
        aligned_vec::AVec::<c64, _>::from_iter(0, iter).into_boxed_slice()
    }
}

impl<'a, T> Container for &'a [T] {
    type Element = T;
}

impl<'a, T> Container for &'a mut [T] {
    type Element = T;
}

pub trait IntoChunks {
    type Chunks: DoubleEndedIterator<Item = Self> + ExactSizeIterator<Item = Self>;

    fn into_chunks(self, chunk_size: usize) -> Self::Chunks;
    fn split_into(self, chunk_count: usize) -> Self::Chunks;
}

impl<'a, T> IntoChunks for &'a [T] {
    type Chunks = ChunksExact<'a, T>;

    #[inline]
    fn into_chunks(self, chunk_size: usize) -> Self::Chunks {
        debug_assert_eq!(self.len() % chunk_size, 0);
        self.chunks_exact(chunk_size)
    }
    #[inline]
    fn split_into(self, chunk_count: usize) -> Self::Chunks {
        debug_assert_eq!(self.len() % chunk_count, 0);
        self.chunks_exact(self.len() / chunk_count)
    }
}

impl<'a, T> IntoChunks for &'a mut [T] {
    type Chunks = ChunksExactMut<'a, T>;

    #[inline]
    fn into_chunks(self, chunk_size: usize) -> Self::Chunks {
        debug_assert_eq!(self.len() % chunk_size, 0);
        self.chunks_exact_mut(chunk_size)
    }
    #[inline]
    fn split_into(self, chunk_count: usize) -> Self::Chunks {
        debug_assert_eq!(self.len() % chunk_count, 0);
        self.chunks_exact_mut(self.len() / chunk_count)
    }
}

/// Convert a mutable slice reference to an uninitialized mutable slice reference.
///
/// # Safety
///
/// No uninitialized values must be written into the output slice by the time the borrow ends
#[inline]
pub unsafe fn as_mut_uninit<T>(slice: &mut [T]) -> &mut [MaybeUninit<T>] {
    let len = slice.len();
    let ptr = slice.as_mut_ptr();
    // SAFETY: T and MaybeUninit<T> have the same layout
    core::slice::from_raw_parts_mut(ptr as *mut _, len)
}

/// Convert an uninitialized mutable slice reference to an initialized mutable slice reference.
///
/// # Safety
///
/// All the elements of the input slice must be initialized and in a valid state.
#[inline]
pub unsafe fn assume_init_mut<T>(slice: &mut [MaybeUninit<T>]) -> &mut [T] {
    let len = slice.len();
    let ptr = slice.as_mut_ptr();
    // SAFETY: T and MaybeUninit<T> have the same layout
    core::slice::from_raw_parts_mut(ptr as *mut _, len)
}

#[inline]
fn assert_same_len(a: (usize, Option<usize>), b: (usize, Option<usize>)) {
    debug_assert_eq!(a.1, Some(a.0));
    debug_assert_eq!(b.1, Some(b.0));
    debug_assert_eq!(a.0, b.0);
}

/// Returns a Zip iterator, but checks that the two components have the same length.
pub trait ZipChecked: IntoIterator + Sized {
    #[inline]
    fn zip_checked<B: IntoIterator>(
        self,
        b: B,
    ) -> core::iter::Zip<<Self as IntoIterator>::IntoIter, <B as IntoIterator>::IntoIter> {
        let a = self.into_iter();
        let b = b.into_iter();
        assert_same_len(a.size_hint(), b.size_hint());
        core::iter::zip(a, b)
    }
}

impl<A: IntoIterator> ZipChecked for A {}

// https://docs.rs/itertools/0.7.8/src/itertools/lib.rs.html#247-269
macro_rules! izip {
    // eg. __izip_closure!(((a, b), c) => (a, b, c) , dd , ee )
    (@ __closure @ $p:pat => $tup:expr) => {
        |$p| $tup
    };

    // The "b" identifier is a different identifier on each recursion level thanks to hygiene.
    (@ __closure @ $p:pat => ( $($tup:tt)* ) , $_iter:expr $( , $tail:expr )*) => {
        $crate::backends::fft::private::izip!(@ __closure @ ($p, b) => ( $($tup)*, b ) $( , $tail )*)
    };

    ( $first:expr $(,)?) => {
        {
            #[allow(unused_imports)]
            use $crate::backends::fft::private::ZipChecked;
            ::core::iter::IntoIterator::into_iter($first)
        }
    };
    ( $first:expr, $($rest:expr),+ $(,)?) => {
        {
            #[allow(unused_imports)]
            use $crate::backends::fft::private::ZipChecked;
            ::core::iter::IntoIterator::into_iter($first)
                $(.zip_checked($rest))*
                .map($crate::backends::fft::private::izip!(@ __closure @ a => (a) $( , $rest )*))
        }
    };
}

pub(crate) use izip;
