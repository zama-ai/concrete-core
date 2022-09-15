use quote::ToTokens;
use serde::ser::{SerializeSeq, SerializeTupleVariant};
use serde::Serialize;
use std::fmt::Debug;

/// A type used as a placeholder for a piece of data that can not be placed just yet.
///
/// # Example use
///
/// The `EngineTraitImpl` node represents a code region such as:
/// ```rust,ignore
/// impl LweCiphertextCreationEngine<Vec<32>, LweCiphertext32> for DefaultEngine {
///     ...
/// }
/// ```
///
/// We want to be able to classify the generic arguments `<Vec<32>, LweCiphertext32>` for what they
/// are (a certain number of cases exist, for instance here, a vec of numeric and an entity).
///
/// The thing is, we can only say what kind of object a generic parameter is, once all the code
/// regions of interests have been extracted from the codebase. For instance, we need to have
/// gathered all the EntityTypeDefinition to know the identifier of all the entities in the crate,
/// before we can say if this or that generic parameter is an entity.
///
/// For this reason, this classification can only happen in a second time. For the time being
/// though, we can store the `syn::AngleBracketedGenericArguments` node, which correspond to the
/// `<Vec<32>, LweCiphertext32>` region, so as to be able to classify the content after.
#[derive(Serialize, Clone, Debug)]
pub(crate) enum ReadyOrNot<R, N> {
    Ready(R),
    #[serde(skip)]
    Not(N),
}

impl<R, N> ReadyOrNot<R, N> {
    /// Borrows the content of the `ReadyOrNot` and wrap it in the corresponding variant of a new
    /// one.
    pub fn as_ref(&self) -> ReadyOrNot<&R, &N> {
        match self {
            ReadyOrNot::Ready(r) => ReadyOrNot::Ready(r),
            ReadyOrNot::Not(n) => ReadyOrNot::Not(n),
        }
    }
}

impl<R, N: Debug> ReadyOrNot<R, N> {
    /// If the content is read, reaturn the content, and panic otherwise.
    pub fn unwrap(self) -> R {
        match self {
            ReadyOrNot::Ready(r) => r,
            ReadyOrNot::Not(n) => panic!("Tried to unwrap a ReadyOrNot::Not value: {:?}", n),
        }
    }
}

impl<R: Debug, N: Clone> ReadyOrNot<R, N> {
    /// Turns a `ReadyOrNot::Not` variant into a `ReadyOrNot::Ready` variant by applying a closure.
    pub fn prepare<F: FnOnce(N) -> R>(&mut self, f: F) {
        match self {
            ReadyOrNot::Ready(r) => panic!("Tried to finish a ReadyOrNot::Ready value: {:?}", r),
            ReadyOrNot::Not(n) => *self = ReadyOrNot::Ready(f(n.to_owned())),
        }
    }
}

/// Removes the first item matching a filter from a vec, and returns it.
pub(crate) fn pull_first_match<T, F>(vec: &mut Vec<T>, f: F) -> T
where
    F: Fn(&T) -> bool,
{
    let index = vec.iter().position(f).unwrap();
    vec.remove(index)
}

/// Removes all the items matching a filter from a vec, and returns them.
pub(crate) fn pull_all_matches<T, F>(vec: &mut Vec<T>, f: F) -> Vec<T>
where
    F: Fn(&T) -> bool,
{
    let mut output = Vec::new();
    for index in (0..vec.len()).rev() {
        if f(&vec[index]) {
            output.push(vec.remove(index));
        }
    }
    output
}

pub(crate) fn serialize_vec_with_token_string<T, S>(
    input: &Vec<T>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: ToTokens,
{
    let mut tv = serializer.serialize_seq(Some(input.len()))?;
    for elm in input.iter() {
        tv.serialize_element(&elm.to_token_stream().to_string())?;
    }
    tv.end()
}

pub(crate) fn serialize_punctuated<T, C, S>(
    input: &syn::punctuated::Punctuated<T, C>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Serialize,
{
    let mut tv = serializer.serialize_seq(Some(input.len()))?;
    for elm in input.iter() {
        tv.serialize_element(&elm)?;
    }
    tv.end()
}

pub(crate) fn serialize_with_token_string<T, S>(input: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: ToTokens,
{
    serializer.serialize_str(&input.to_token_stream().to_string())
}

pub(crate) fn serialize_with_token_string_2<T1, T2, S>(
    input1: &T1,
    input2: &T2,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T1: ToTokens,
    T2: ToTokens,
{
    let mut tv = serializer.serialize_tuple_variant("", 0, "", 2)?;
    tv.serialize_field(&input1.to_token_stream().to_string())?;
    tv.serialize_field(&input2.to_token_stream().to_string())?;
    tv.end()
}

pub(crate) fn serialize_with_token_string_3<T1, T2, T3, S>(
    input1: &T1,
    input2: &T2,
    input3: &T3,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T1: ToTokens,
    T2: ToTokens,
    T3: ToTokens,
{
    let mut tv = serializer.serialize_tuple_variant("", 0, "", 3)?;
    tv.serialize_field(&input1.to_token_stream().to_string())?;
    tv.serialize_field(&input2.to_token_stream().to_string())?;
    tv.serialize_field(&input3.to_token_stream().to_string())?;
    tv.end()
}

/// A macro that packs multiple options if they are all `Some` and returns `None` otherwise.
///
/// # Example
/// ```rust
/// # use concrete_core_representation::pack_somes;
/// assert_eq!(Some((1,2,3)), pack_somes!(Some(1), Some(2), Some(3)));
/// assert_eq!(None, pack_somes!(None, Some(2), Some(3)));
/// assert_eq!(None, pack_somes!(Some(1), None, Some(3)));
/// assert_eq!(None, pack_somes!(Some(1), Some(2), None));
#[macro_export]
macro_rules! pack_somes {
    ($i: expr, $ii:expr) => {
        if let (Some(i), Some(ii)) = ($i, $ii) {
            Some((i, ii))
        } else {
            None
        }
    };
    ($i: expr, $ii:expr, $iii:expr) => {
        if let (Some(i), Some(ii), Some(iii)) = ($i, $ii, $iii) {
            Some((i, ii, iii))
        } else {
            None
        }
    };
    ($i: expr, $ii:expr, $iii:expr, $iv:expr) => {
        if let (Some(i), Some(ii), Some(iii), Some(iv)) = ($i, $ii, $iii, $iv) {
            Some((i, ii, iii, iv))
        } else {
            None
        }
    };
    ($i: expr, $ii:expr, $iii:expr, $iv:expr, $v:expr) => {
        if let (Some(i), Some(ii), Some(iii), Some(iv), Some(v)) = ($i, $ii, $iii, $iv, $v) {
            Some((i, ii, iii, iv, v))
        } else {
            None
        }
    };
    ($i: expr, $ii:expr, $iii:expr, $iv:expr, $v:expr, $vi:expr) => {
        if let (Some(i), Some(ii), Some(iii), Some(iv), Some(v), Some(vi)) =
            ($i, $ii, $iii, $iv, $v, $vi)
        {
            Some((i, ii, iii, iv, v, vi))
        } else {
            None
        }
    };
}
pub(crate) use pack_somes;

/// A macro to write compact queries on deeply nested data structures (such as asts).
///
/// A `syn` ast is a deeply nested structure, that is based on a combination of struct with
/// optional and non-optional fields, rebinding enums, and potentially empty collections. It quickly
/// gets tedious (and boring) to extract the relevant pieces of the ast given this deep nesting. The
/// same tasks got repeated over and over again:
///     - following trails of non-optional fields
///     - checking for existence of optional fields
///     - checking for emptyness of collections
///     - properly matching the rebinding enumerations along the way
///
/// The code can get really messy really quick.
///
/// To simplify this situation, we provide the `probe` macro, which allows to write compact queries
/// over nested structures.
///
/// # Gist
///
/// The `probe` macro takes an `Option` as input, applies a serie of _pipes_, and returns an
/// `Option` as output. The output will be `Some(value)`, if the input was `Some`, and all the pipes
/// executed along the way were successful:
/// ```rust
/// # use concrete_core_representation::probe;
/// enum IntegerParity{
///     Even(usize),
///     Odd(usize)
/// }
/// let output = probe!(
///     Some(10),
///     val -> val * 2,                            // Applying a map pipe.
///     new_val ?> new_val % 2 == 0,               // Applying a filter pipe.
///     X> Some(IntegerParity::Odd(9))             // Applying a reboot pipe.
///     IntegerParity::Odd(val) => val,            // Applying the variant pipe.
///     val >> val.checked_add(55),                // Applying a then pipe.
/// );
/// assert_eq!(output, Some(64));
/// ```
///
/// ## `->` : Map pipe
///
/// The map pipe applies a function to the content of a `Some` variant:
/// ```rust
/// # use concrete_core_representation::probe;
/// let output = probe!(
///     Some(10),
///     val -> val*2
/// );
/// assert_eq!(output, Some(20));
///
/// let output = probe!(
///     None,
///     val -> val*2
/// );
/// assert_eq!(output, None);
/// ```
///
/// ## `?>` : filter pipe
///
/// The filter pipe verifies that a `Some` variant verifies a given condition:
/// ```rust
/// # use concrete_core_representation::probe;
/// let output = probe!(
///     Some(10),
///     val ?> val < 20
/// );
/// assert_eq!(output, Some(10));
///
/// let output = probe!(
///     Some(10),
///     val ?> val > 20
/// );
/// assert_eq!(output, None);
///
/// let output = probe!(
///     None,
///     val ?> val > 20
/// );
/// assert_eq!(output, None);
/// ```
///
/// ## `>>` : then pipe
///
/// The then pipe applies an option-returning function to the content of a `Some` variant:
/// ```rust
/// # use concrete_core_representation::probe;
/// let output = probe!(Some(i32::MAX), val >> val.checked_mul(1));
/// assert_eq!(output, Some(i32::MAX));
///
/// let output = probe!(Some(i32::MAX), val >> val.checked_mul(2));
/// assert_eq!(output, None);
///
/// let output = probe!(None, val >> val.checked_mul(2));
/// assert_eq!(output, None);
/// ```
///
/// ## `=>` : variant pipe
///
/// The variant pipe unwraps a given variant of an enumeration:
/// ```rust
/// # use concrete_core_representation::probe;
/// enum MyEnum{
///     First(usize),
///     Second(())
/// }
/// let output = probe!(
///     Some(MyEnum::First(5)),
///     MyEnum::First(val) => val
/// );
/// assert_eq!(output, Some(5));
///
/// let output = probe!(
///     Some(MyEnum::First(5)),
///     MyEnum::Second(val) => val
/// );
/// assert_eq!(output, None);
///
/// let output = probe!(
///     None,
///     MuEnum::Second(val) => val
/// );
/// assert_eq!(output, None);
/// ```
///
/// ## `X>` : reboot pipe
///
/// The reboot pipe allows to replace the current value with a new option if the previous one was
/// `Some`:
/// ```rust
/// # use concrete_core_representation::probe;
/// let output = probe!(Some(1), X > Some(2));
/// assert_eq!(output, Some(2));
///
/// let output = probe!(Some(1), X > None);
/// assert_eq!(output, None);
///
/// let output = probe!(None, X > Some(2));
/// assert_eq!(output, None);
/// ```
#[macro_export]
macro_rules! probe {
    ($($tail:tt)*) => {
        __probe!($($tail)*)
    };
}
pub(crate) use probe;

#[doc(hidden)]
#[macro_export]
macro_rules! __probe {
    ($init: expr, $($tail:tt)*) => {
        {
            let local = || -> Option<_>{
                let running = $init;
                __probe!(running @ $($tail)*)
            };
            local()
        }
    };
    ($running:ident @ $pattern:pat => $exp:expr) => {
            if let $pattern = $running? {
                Some($exp)
            } else {
                None
            }
    };
    ($running:ident @ $pattern:pat => $exp:expr, $($tail:tt)*) => {
        {
            let running = if let $pattern = $running? {
                Some($exp)
            } else {
                None
            };
            __probe!(running @ $($tail)*)
        }
    };
    ($running:ident @ $ident:ident -> $exp:expr) => {
            $running.map(|$ident| {
                $exp
            })
    };
    ($running:ident @ $ident:ident -> $exp:expr, $($tail:tt)*) => {
        {
            let running = $running.map(|$ident| {
                $exp
            });
            __probe!(running @ $($tail)*)
        }
    };
    ($running:ident @ $ident:ident >> $exp:expr) => {
            $running.and_then(|$ident| {
                $exp
            })
    };
    ($running:ident @ $ident:ident >> $exp:expr, $($tail:tt)*) => {
        {
            let running = $running.and_then(|$ident| {
                $exp
            });
            __probe!(running @ $($tail)*)
        }
    };
    ($running:ident @ $ident:ident ?> $exp:expr) => {
            $running.filter(|$ident| {
                $exp
            })
    };
    ($running:ident @ $ident:ident ?> $exp:expr, $($tail:tt)*) => {
        {
            let running = $running.filter(|$ident| {
                $exp
            });
            __probe!(running @ $($tail)*)
        }
    };
    ($running:ident @ X> $exp:expr) => {
        $running.and($exp)
    };
    ($running:ident @ X> $exp:expr, $($tail:tt)*) => {
        {
            let running = $running.and($exp);
            __probe!(running @ $($tail)*)
        }
    };

}
pub(crate) use __probe;
