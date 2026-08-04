//! Structured Field Values for HTTP ([RFC 9651]) — a typed-header layer.
//!
//! Every header standardised since roughly 2019 is a Structured Field:
//! `Priority`, `Cache-Status`, `Signature-Input`, `Reporting-Endpoints`,
//! `Available-Dictionary`, `Unencoded-Digest`, the `Secure-Session-*` family.
//! Most frameworks hand you a `&str` and let you write a regex. This module
//! gives you the real data model — [`Item`], [`List`], [`Dictionary`] — plus
//! [`StructuredHeader`], which turns a malformed field into a `400` before your
//! handler ever runs.
//!
//! Parsing and serialisation come from the [`sfv`] crate;
//! this module adds the request-side plumbing: header joining,
//! a size bound, typed extraction, and rejection.
//!
//! ```rust
//! use tachyon_web::http::sfv;
//!
//! let dict = sfv::parse_dictionary(b"u=1, i").expect("valid field");
//! assert_eq!(sfv::dict_integer(&dict, "u"), Some(1));
//! assert_eq!(sfv::dict_boolean(&dict, "i"), Some(true));
//! ```
//!
//! Typed headers are declared with [`sfv_dictionary!`](crate::sfv_dictionary), which generates a
//! parser that pulls exactly the keys you name straight out of the input:
//!
//! ```rust
//! use tachyon_web::http::sfv::FromStructuredHeader;
//! use tachyon_web::sfv_dictionary;
//!
//! sfv_dictionary! {
//!     /// RFC 9218 `Priority`.
//!     pub struct MyPriority for "priority" {
//!         "u" => urgency: i64 = 3,
//!         "i" => incremental: bool = false,
//!     }
//! }
//!
//! let p = MyPriority::parse_field(b"u=5, i").expect("valid field");
//! assert_eq!((p.urgency, p.incremental), (5, true));
//! ```
//!
//! # Cost
//!
//! [`sfv_dictionary!`](crate::sfv_dictionary) parses through [`sfv`]'s visitor API, so a typed header
//! never builds the intermediate [`Dictionary`] map: keys you did not declare
//! are validated and dropped, and declared keys are written straight into the
//! struct. Only `String` and `Vec<u8>` fields allocate, and only for the keys
//! that are actually present. Repeated header lines are joined into a 256-byte
//! inline buffer that only spills to the heap for unusually long fields.
//!
//! Input is capped at [`MAX_INPUT`] bytes before parsing starts, so a peer that
//! sends many copies of a header cannot turn one request into unbounded
//! parsing work. The grammar itself is non-recursive — inner lists cannot nest
//! — so there is no parser depth to bound.
//!
//! [RFC 9651]: https://www.rfc-editor.org/rfc/rfc9651

use smallvec::SmallVec;
use std::cell::Cell;
use std::fmt;

/// The underlying RFC 9651 implementation, re-exported so callers can use its
/// serialisers and lower-level types without adding the dependency themselves.
pub use sfv;

pub use sfv::{
    BareItem, BareItemFromInput, Date, Decimal, Dictionary, InnerList, Integer, Item, Key, KeyRef,
    List, ListEntry, Parameters, Parser, StringRef, Token, TokenRef,
};

/// Maximum accepted length, in bytes, of a single structured field.
///
/// Fields longer than this are rejected without being parsed. Real structured
/// fields are tens of bytes; this sits far above any legitimate use and far
/// below the point where per-request parsing work becomes interesting to an
/// attacker.
pub const MAX_INPUT: usize = 16 * 1024;

/// Why a structured-field header was rejected.
#[derive(Debug)]
#[non_exhaustive]
pub enum SfvError {
    /// The field (after joining repeated lines) exceeded [`MAX_INPUT`].
    TooLong {
        /// Length of the offending field, in bytes.
        len: usize,
    },
    /// The field is not well-formed per RFC 9651.
    Parse(sfv::Error),
    /// A key required by the typed header was absent.
    MissingKey {
        /// The absent key.
        key: &'static str,
    },
    /// A key was present but held a value of the wrong type.
    WrongType {
        /// The offending key.
        key: &'static str,
        /// What the field definition expected there.
        expected: &'static str,
    },
    /// A key was present but held an inner list where a single item was expected.
    UnexpectedInnerList {
        /// The offending key.
        key: &'static str,
    },
    /// Internal placeholder used to unwind out of [`sfv`]'s parser.
    ///
    /// [`sfv`] converts any visitor error into a stringified [`sfv::Error`] via
    /// a blanket `impl<E: std::error::Error> From<E> for Repr`, which loses the
    /// original variant. [`sfv_dictionary!`](crate::sfv_dictionary)-generated visitors instead stash
    /// the real error in a side channel and return this placeholder purely to
    /// abort parsing; callers replace it with the stashed error before it is
    /// ever observed. It should never reach a caller of this module.
    #[doc(hidden)]
    Aborted,
}

impl fmt::Display for SfvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { len } => {
                write!(f, "field is {len} bytes, over the {MAX_INPUT}-byte limit")
            }
            Self::Parse(e) => write!(f, "{e}"),
            Self::MissingKey { key } => write!(f, "missing required key \"{key}\""),
            Self::WrongType { key, expected } => {
                write!(f, "key \"{key}\" must be {expected}")
            }
            Self::UnexpectedInnerList { key } => {
                write!(f, "key \"{key}\" must be a single item, not an inner list")
            }
            Self::Aborted => write!(f, "aborted (internal placeholder error escaped)"),
        }
    }
}

impl std::error::Error for SfvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            _ => None,
        }
    }
}

impl From<sfv::Error> for SfvError {
    fn from(e: sfv::Error) -> Self {
        Self::Parse(e)
    }
}

impl From<SfvError> for crate::http::error::Error {
    fn from(e: SfvError) -> Self {
        Self::Rejection {
            status: hyper::StatusCode::BAD_REQUEST,
            message: format!("malformed structured field: {e}"),
        }
    }
}

impl crate::http::response::IntoResponse for SfvError {
    fn into_response(self) -> hyper::Response<crate::http::response::Body> {
        crate::http::error::Error::from(self).into_response()
    }
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, SfvError>;

/// Checks the size bound before handing bytes to the parser.
const fn checked(input: &[u8]) -> Result<&[u8]> {
    if input.len() > MAX_INPUT {
        return Err(SfvError::TooLong { len: input.len() });
    }
    Ok(input)
}

/// Parses a dictionary-typed field.
///
/// # Errors
///
/// Returns [`SfvError`] if the field is oversized or not a well-formed
/// `sf-dictionary`.
pub fn parse_dictionary(input: &[u8]) -> Result<Dictionary> {
    Ok(Parser::new(checked(input)?).parse_dictionary()?)
}

/// Parses a list-typed field.
///
/// # Errors
///
/// Returns [`SfvError`] if the field is oversized or not a well-formed `sf-list`.
pub fn parse_list(input: &[u8]) -> Result<List> {
    Ok(Parser::new(checked(input)?).parse_list()?)
}

/// Parses an item-typed field.
///
/// # Errors
///
/// Returns [`SfvError`] if the field is oversized or not a well-formed `sf-item`.
pub fn parse_item(input: &[u8]) -> Result<Item> {
    Ok(Parser::new(checked(input)?).parse_item()?)
}

/// The integer at `key`, if the key is present and holds an integer item.
#[must_use]
pub fn dict_integer(dict: &Dictionary, key: &str) -> Option<i64> {
    match dict.get(key)? {
        ListEntry::Item(item) => item.bare_item.as_integer().map(i64::from),
        ListEntry::InnerList(_) => None,
    }
}

/// The boolean at `key`, if the key is present and holds a boolean item.
///
/// Note that a bare key (`i` rather than `i=?1`) is a boolean `true`.
#[must_use]
pub fn dict_boolean(dict: &Dictionary, key: &str) -> Option<bool> {
    match dict.get(key)? {
        ListEntry::Item(item) => item.bare_item.as_boolean(),
        ListEntry::InnerList(_) => None,
    }
}

/// The text at `key`, if the key is present and holds a string, token or
/// display-string item.
#[must_use]
pub fn dict_str<'a>(dict: &'a Dictionary, key: &str) -> Option<&'a str> {
    let ListEntry::Item(item) = dict.get(key)? else {
        return None;
    };
    match &item.bare_item {
        BareItem::String(s) => Some(s.as_str()),
        BareItem::Token(t) => Some(t.as_str()),
        BareItem::DisplayString(s) => Some(s.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Typed extraction
// ---------------------------------------------------------------------------

/// A Rust type a bare item can be converted into.
///
/// Implemented for `i64`, `bool`, `f64`, [`Decimal`], `String`, `Vec<u8>`,
/// `Date` and `Option<T>`. [`sfv_dictionary!`](crate::sfv_dictionary) dispatches through this.
pub trait FromSfvValue: Sized {
    /// What this type expects, for the rejection message ("an integer", ...).
    const EXPECTED: &'static str;

    /// Converts a bare item taken straight from the input.
    ///
    /// # Errors
    ///
    /// Returns [`SfvError::WrongType`] if the item holds another type.
    fn from_bare_item(item: BareItemFromInput<'_>, key: &'static str) -> Result<Self>;

    /// Produces a value for an absent key. Only `Option<T>` succeeds here.
    ///
    /// # Errors
    ///
    /// Returns [`SfvError::MissingKey`] unless the type has a natural empty value.
    fn missing(key: &'static str) -> Result<Self> {
        Err(SfvError::MissingKey { key })
    }
}

macro_rules! impl_from_sfv_value {
    ($ty:ty, $expected:literal, |$item:ident, $key:ident| $body:expr) => {
        impl FromSfvValue for $ty {
            const EXPECTED: &'static str = $expected;

            fn from_bare_item($item: BareItemFromInput<'_>, $key: &'static str) -> Result<Self> {
                $body.ok_or(SfvError::WrongType {
                    key: $key,
                    expected: $expected,
                })
            }
        }
    };
}

impl_from_sfv_value!(i64, "an integer", |item, _key| item
    .as_integer()
    .map(i64::from));
impl_from_sfv_value!(bool, "a boolean", |item, _key| item.as_boolean());
impl_from_sfv_value!(Decimal, "a decimal", |item, _key| item.as_decimal());
impl_from_sfv_value!(f64, "a decimal", |item, _key| item.as_decimal().map(|d| {
    #[allow(clippy::cast_precision_loss)]
    let scaled = i64::from(d.as_integer_scaled_1000()) as f64;
    scaled / 1000.0
}));
impl_from_sfv_value!(Date, "a date", |item, _key| item.as_date());
impl_from_sfv_value!(String, "a string or token", |item, _key| match item {
    BareItemFromInput::String(s) => Some(s.as_str().to_owned()),
    BareItemFromInput::Token(t) => Some(t.as_str().to_owned()),
    BareItemFromInput::DisplayString(s) => Some(s.into_owned()),
    _ => None,
});
impl_from_sfv_value!(Vec<u8>, "a byte sequence", |item, _key| match item {
    BareItemFromInput::ByteSequence(b) => Some(b),
    _ => None,
});

impl<T: FromSfvValue> FromSfvValue for Option<T> {
    const EXPECTED: &'static str = T::EXPECTED;

    fn from_bare_item(item: BareItemFromInput<'_>, key: &'static str) -> Result<Self> {
        T::from_bare_item(item, key).map(Some)
    }

    fn missing(_key: &'static str) -> Result<Self> {
        Ok(None)
    }
}

/// Object-safe sink used by [`sfv_dictionary!`](crate::sfv_dictionary) to write one parsed value into
/// the field it belongs to.
///
/// Being object-safe is what lets the generated dictionary visitor return a
/// *single* entry-visitor type for fields of differing Rust types, without an
/// enum whose variants a `macro_rules!` macro cannot name.
#[doc(hidden)]
pub trait SlotSink {
    /// Stores a value parsed for `key`, replacing any earlier one (RFC 9651
    /// requires last-wins for duplicate keys).
    fn accept(&mut self, item: BareItemFromInput<'_>, key: &'static str) -> Result<()>;
}

impl<T: FromSfvValue> SlotSink for Option<T> {
    fn accept(&mut self, item: BareItemFromInput<'_>, key: &'static str) -> Result<()> {
        *self = Some(T::from_bare_item(item, key)?);
        Ok(())
    }
}

/// Side channel [`sfv_dictionary!`](crate::sfv_dictionary)-generated visitors use to carry the real
/// [`SfvError`] out of [`sfv`]'s parser.
///
/// [`sfv`] converts any visitor error into a stringified [`sfv::Error`] via a
/// blanket `impl<E: std::error::Error> From<E> for Repr`, and the visitor
/// itself is dropped on the error path — so by the time `parse_dictionary_with_visitor`
/// returns, the original [`SfvError`] is unrecoverable through its return
/// value alone. Stashing it here, in a cell the caller keeps a reference to
/// independently of the (consumed) visitor, is what lets [`parse_with_visitor`]
/// recover it: see [`capture`].
pub type ErrorSlot = Cell<Option<SfvError>>;

/// Runs `result`, and if it is `Err`, stashes the error in `errors` and
/// returns [`SfvError::Aborted`] in its place so [`sfv`]'s parser unwinds
/// immediately without stringifying the real error.
///
/// Pairs with reading `errors` back out once parsing returns control to the
/// caller of [`parse_with_visitor`].
#[doc(hidden)]
pub fn capture<T>(errors: &ErrorSlot, result: Result<T>) -> Result<T> {
    result.map_err(|e| {
        errors.set(Some(e));
        SfvError::Aborted
    })
}

/// The entry visitor handed one declared dictionary key.
#[doc(hidden)]
pub struct Slot<'a> {
    sink: &'a mut dyn SlotSink,
    key: &'static str,
    errors: &'a ErrorSlot,
}

impl fmt::Debug for Slot<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slot")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl<'a> Slot<'a> {
    /// Builds a slot for `key` writing into `sink`, stashing any error in
    /// `errors` before it crosses back into [`sfv`]'s parser.
    pub fn new(sink: &'a mut dyn SlotSink, key: &'static str, errors: &'a ErrorSlot) -> Self {
        Self { sink, key, errors }
    }
}

impl<'de> sfv::visitor::EntryVisitor<'de> for Slot<'_> {
    type Error = SfvError;

    fn item(self) -> Result<impl sfv::visitor::ItemVisitor<'de>> {
        let Self { sink, key, errors } = self;
        Ok(
            move |item: BareItemFromInput<'de>| -> Result<sfv::visitor::Ignored> {
                capture(errors, sink.accept(item, key))?;
                // Parameters on a declared key are validated by the parser but
                // carry no meaning for a scalar field, so they are discarded.
                Ok(sfv::visitor::Ignored)
            },
        )
    }

    fn inner_list(self) -> Result<impl sfv::visitor::InnerListVisitor<'de>> {
        let Self { key, errors, .. } = self;
        capture::<sfv::visitor::Never>(errors, Err(SfvError::UnexpectedInnerList { key }))
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __sfv_missing {
    ($ty:ty, $key:literal) => {
        <$ty as $crate::http::sfv::FromSfvValue>::missing($key)
    };
    ($ty:ty, $key:literal, $default:expr) => {
        ::core::result::Result::<$ty, $crate::http::sfv::SfvError>::Ok($default)
    };
}

/// Declares a struct that parses itself from a structured-field dictionary
/// header, with per-key types, defaults, and automatic rejection.
///
/// Each field names the dictionary key it reads, its Rust type, and optionally
/// a default for when the key is absent. Without a default, an absent key is a
/// rejection — unless the type is `Option<T>`, which maps absence to `None`. A
/// key holding the wrong type, or an inner list, is always a rejection.
/// Undeclared keys are still syntax-checked, then ignored, as RFC 9651
/// requires of extension keys.
///
/// The generated parser drives [`sfv`]'s visitor API, so no intermediate
/// dictionary is built.
///
/// ```rust
/// use tachyon_web::http::sfv::FromStructuredHeader;
/// use tachyon_web::sfv_dictionary;
///
/// sfv_dictionary! {
///     /// A made-up session header.
///     #[derive(Clone)]
///     pub struct SessionState for "secure-session-state" {
///         "id" => id: String,
///         "ttl" => ttl: i64 = 0,
///         "note" => note: Option<String>,
///     }
/// }
///
/// let s = SessionState::parse_field(b"id=\"abc\", ttl=30, ext=1").expect("valid");
/// assert_eq!((s.id.as_str(), s.ttl, s.note), ("abc", 30, None));
/// assert!(SessionState::parse_field(b"ttl=30").is_err()); // `id` is required
/// ```
#[macro_export]
macro_rules! sfv_dictionary {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident for $header:literal {
            $(
                $(#[$fmeta:meta])*
                $key:literal => $field:ident : $ty:ty $(= $default:expr)?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug)]
        $vis struct $name {
            $(
                $(#[$fmeta])*
                /// Parsed from the dictionary key named in the declaration.
                $vis $field: $ty,
            )*
        }

        const _: () = {
            // Collects the declared keys during parsing; every slot is `None`
            // until the key is seen, so defaults and required-key errors are
            // resolved once the whole field is known to be valid.
            //
            // Borrows the caller's `ErrorSlot` rather than owning one, since
            // `sfv` drops this builder on the error path — that borrow is what
            // lets typed rejections survive the trip through `sfv`'s parser.
            struct Builder<'sfv_e> {
                $( $field: ::core::option::Option<$ty>, )*
                errors: &'sfv_e $crate::http::sfv::ErrorSlot,
            }

            impl<'sfv_e> Builder<'sfv_e> {
                const fn new(errors: &'sfv_e $crate::http::sfv::ErrorSlot) -> Self {
                    Self {
                        $( $field: ::core::option::Option::None, )*
                        errors,
                    }
                }
            }

            impl<'de, 'sfv_e> $crate::http::sfv::sfv::visitor::DictionaryVisitor<'de> for Builder<'sfv_e> {
                type Out = $name;
                type Error = $crate::http::sfv::SfvError;

                fn entry(
                    &mut self,
                    key: &'de $crate::http::sfv::KeyRef,
                ) -> ::core::result::Result<
                    impl $crate::http::sfv::sfv::visitor::EntryVisitor<'de>,
                    Self::Error,
                > {
                    let slot = match key.as_str() {
                        $(
                            $key => $crate::http::sfv::Slot::new(&mut self.$field, $key, self.errors),
                        )*
                        // Unknown keys are still parsed and validated, then dropped.
                        _ => return ::core::result::Result::Ok(::core::option::Option::None),
                    };
                    ::core::result::Result::Ok(::core::option::Option::Some(slot))
                }

                fn finish(self) -> ::core::result::Result<Self::Out, Self::Error> {
                    ::core::result::Result::Ok($name {
                        $(
                            $field: match self.$field {
                                ::core::option::Option::Some(v) => v,
                                ::core::option::Option::None => {
                                    $crate::http::sfv::capture(
                                        self.errors,
                                        $crate::__sfv_missing!($ty, $key $(, $default)?),
                                    )?
                                }
                            },
                        )*
                    })
                }
            }

            impl $crate::http::sfv::FromStructuredHeader for $name {
                const HEADER_NAME: &'static str = $header;

                fn parse_field(
                    bytes: &[u8],
                ) -> ::core::result::Result<Self, $crate::http::sfv::SfvError> {
                    let errors: $crate::http::sfv::ErrorSlot = ::core::default::Default::default();
                    match $crate::http::sfv::parse_with_visitor(bytes, Builder::new(&errors)) {
                        ::core::result::Result::Ok(v) => ::core::result::Result::Ok(v),
                        // `fallback` is `sfv`'s stringified error; prefer the typed
                        // error `capture` stashed, if parsing got that far.
                        ::core::result::Result::Err(fallback) => {
                            ::core::result::Result::Err(errors.take().unwrap_or(fallback))
                        }
                    }
                }
            }
        };
    };
}

/// Runs a dictionary visitor over `input`, applying the [`MAX_INPUT`] bound.
///
/// Used by [`sfv_dictionary!`](crate::sfv_dictionary); call it directly to hand-write a typed header
/// whose shape the macro does not cover.
///
/// [`sfv`] stringifies any error a visitor returns rather than preserving it
/// (it converts through `std::error::Error` into its own error type), so a
/// [`SfvError`] your visitor returns here comes back as [`SfvError::Parse`],
/// not the original variant. To preserve it, stash the real error in an
/// [`ErrorSlot`] your visitor borrows and return [`SfvError::Aborted`] via
/// [`capture`] in its place, then recover it from the slot after this
/// function returns — see the code [`sfv_dictionary!`](crate::sfv_dictionary) generates.
///
/// # Errors
///
/// Returns [`SfvError`] if the field is oversized, malformed, or the visitor
/// rejects it.
pub fn parse_with_visitor<'de, V>(input: &'de [u8], visitor: V) -> Result<V::Out>
where
    V: sfv::visitor::DictionaryVisitor<'de, Error = SfvError>,
{
    Ok(Parser::new(checked(input)?).parse_dictionary_with_visitor(visitor)?)
}

/// A typed header parsed from a structured field.
///
/// Implemented by [`sfv_dictionary!`](crate::sfv_dictionary), or by hand (via [`parse_with_visitor`]
/// or the parse helpers) for headers the macro does not cover.
pub trait FromStructuredHeader: Sized {
    /// The lowercase name of the header this type is parsed from.
    const HEADER_NAME: &'static str;

    /// Parses the header's value bytes, already joined across repeated lines.
    ///
    /// # Errors
    ///
    /// Returns [`SfvError`] if the field is malformed, oversized, or a required
    /// key is missing or mistyped.
    fn parse_field(bytes: &[u8]) -> Result<Self>;
}

/// Extractor for a typed structured-field header.
///
/// A missing header, a malformed field, a missing required key or a mistyped
/// value all reject with `400 Bad Request` before the handler runs. Wrap it in
/// `Option` if the header itself is optional.
///
/// ```rust,no_run
/// use tachyon_web::http::sfv::{Priority, StructuredHeader};
///
/// async fn handler(StructuredHeader(p): StructuredHeader<Priority>) -> String {
///     format!("urgency {}", p.urgency())
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct StructuredHeader<T>(pub T);

impl<T> StructuredHeader<T> {
    /// Unwraps the parsed header.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for StructuredHeader<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Buffer for joined repeated header lines. 256 bytes covers every realistic
/// field without touching the heap.
type JoinBuf = SmallVec<[u8; 256]>;

/// Concatenates repeated header lines with `", "`, as RFC 9110 §5.3 requires
/// before a structured field is parsed.
///
/// Returns `None` if the header is absent, and stops joining once the result
/// would exceed [`MAX_INPUT`], so a peer sending many copies of a header cannot
/// make the server build a large buffer only to reject it afterwards.
fn join_header<'a>(
    headers: &'a hyper::HeaderMap,
    name: &str,
    buf: &'a mut JoinBuf,
) -> Option<std::result::Result<&'a [u8], SfvError>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    let Some(second) = values.next() else {
        return Some(Ok(first.as_bytes()));
    };
    let mut len = first.len();
    buf.extend_from_slice(first.as_bytes());
    for v in std::iter::once(second).chain(values) {
        len = len.saturating_add(v.len()).saturating_add(2);
        if len > MAX_INPUT {
            return Some(Err(SfvError::TooLong { len }));
        }
        buf.extend_from_slice(b", ");
        buf.extend_from_slice(v.as_bytes());
    }
    Some(Ok(buf.as_slice()))
}

impl<S, T> crate::routing::extract::FromRequestParts<S> for StructuredHeader<T>
where
    T: FromStructuredHeader + Send,
{
    type Rejection = crate::http::error::Error;

    fn from_request_parts(
        parts: &mut hyper::http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        let mut buf = JoinBuf::new();
        let bytes = join_header(&parts.headers, T::HEADER_NAME, &mut buf).ok_or_else(|| {
            crate::http::error::Error::Rejection {
                status: hyper::StatusCode::BAD_REQUEST,
                message: format!("missing `{}` header", T::HEADER_NAME),
            }
        })??;
        T::parse_field(bytes)
            .map(Self)
            .map_err(crate::http::error::Error::from)
    }
}

/// Parses `T`'s header leniently: a missing or malformed field yields
/// `T::default()` rather than an error.
///
/// [`StructuredHeader`] is the right choice for a header the request is
/// invalid without; this is for the advisory kind, like [`Priority`], where a
/// client sending a garbled value should fall back to normal handling rather
/// than have its request rejected over a hint.
#[must_use]
pub fn header_or_default<T>(headers: &hyper::HeaderMap) -> T
where
    T: FromStructuredHeader + Default,
{
    let mut buf = JoinBuf::new();
    join_header(headers, T::HEADER_NAME, &mut buf)
        .and_then(std::result::Result::ok)
        .and_then(|bytes| T::parse_field(bytes).ok())
        .unwrap_or_default()
}

sfv_dictionary! {
    /// RFC 9218 `Priority`: `u` is the urgency (0 highest, 7 lowest, 3 the
    /// default) and `i` requests incremental delivery.
    ///
    /// Out-of-range urgencies are deliberately *not* rejected — RFC 9218 says
    /// to ignore them and use the default — so read [`Priority::urgency`]
    /// rather than the raw field when scheduling on it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct Priority for "priority" {
        /// The raw `u` value, exactly as sent.
        "u" => raw_urgency: i64 = DEFAULT_URGENCY,
        /// The `i` flag.
        "i" => incremental: bool = false,
    }
}

/// RFC 9218's default urgency, used when `u` is absent or out of range.
const DEFAULT_URGENCY: i64 = 3;

impl Priority {
    /// The urgency, with out-of-range values replaced by the RFC 9218 default
    /// of 3.
    #[must_use]
    pub const fn urgency(&self) -> u8 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        if self.raw_urgency < 0 || self.raw_urgency > 7 {
            DEFAULT_URGENCY as u8
        } else {
            self.raw_urgency as u8
        }
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self {
            raw_urgency: DEFAULT_URGENCY,
            incremental: false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::routing::extract::FromRequestParts;

    #[test]
    fn parses_dictionary_shapes() {
        let d = parse_dictionary(b"a=1, b=?0, c, d=\"x\", e=(1 2);q, f=@1659578233").unwrap();
        assert_eq!(dict_integer(&d, "a"), Some(1));
        assert_eq!(dict_boolean(&d, "b"), Some(false));
        assert_eq!(dict_boolean(&d, "c"), Some(true));
        assert_eq!(dict_str(&d, "d"), Some("x"));
        let Some(ListEntry::InnerList(inner)) = d.get("e") else {
            panic!("expected inner list");
        };
        assert_eq!(inner.items.len(), 2);
        assert!(inner.params.contains_key("q"));
        assert!(dict_integer(&d, "e").is_none());
        assert!(matches!(
            d.get("f"),
            Some(ListEntry::Item(item)) if item.bare_item.as_date().is_some()
        ));
    }

    #[test]
    fn parses_lists_and_items() {
        let l = parse_list(b"sugar, tea;x=1, (a b);y").unwrap();
        assert_eq!(l.len(), 3);
        let item = parse_item(b"12.445;foo=bar").unwrap();
        assert_eq!(
            item.bare_item
                .as_decimal()
                .map(|d| d.as_integer_scaled_1000()),
            Some(sfv::integer(12_445))
        );
    }

    #[test]
    fn rejects_malformed_fields() {
        let bad: &[&[u8]] = &[
            b"a=1,",
            b"a=1 b=2",
            b"a=",
            b"A=1",
            b"a=1.2345",
            b"a=1234567890123456",
            b"a=?2",
            b"a=(1 2",
            b"a=\"unterminated",
            b"a=@1.5",
            b":aGVsbG8:",
        ];
        for input in bad {
            assert!(
                parse_dictionary(input).is_err(),
                "should have rejected {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn enforces_the_size_bound() {
        let long = vec![b'a'; MAX_INPUT + 1];
        assert!(matches!(
            parse_dictionary(&long),
            Err(SfvError::TooLong { .. })
        ));
    }

    #[test]
    fn typed_priority_header() {
        let p = Priority::parse_field(b"u=5, i").unwrap();
        assert_eq!(p.urgency(), 5);
        assert!(p.incremental);

        let d = Priority::parse_field(b"").unwrap();
        assert_eq!(d, Priority::default());
        assert_eq!(d.urgency(), 3);

        // Unknown keys are ignored; out-of-range urgency falls back to default.
        let ext = Priority::parse_field(b"u=9, ext=(1 2), i=?0").unwrap();
        assert_eq!(ext.urgency(), 3);
        assert!(!ext.incremental);

        // Wrong type and syntax errors are both rejections.
        assert!(matches!(
            Priority::parse_field(b"u=\"high\""),
            Err(SfvError::WrongType { key: "u", .. })
        ));
        assert!(matches!(
            Priority::parse_field(b"u=(1 2)"),
            Err(SfvError::UnexpectedInnerList { key: "u" })
        ));
        assert!(matches!(
            Priority::parse_field(b"u=1,"),
            Err(SfvError::Parse(_))
        ));
    }

    sfv_dictionary! {
        /// Test-only header exercising required, defaulted and optional fields.
        struct TestHeader for "x-test" {
            "id" => id: String,
            "n" => n: i64 = 7,
            "tag" => tag: Option<String>,
            "raw" => raw: Option<Vec<u8>>,
            "ratio" => ratio: Option<f64>,
        }
    }

    #[test]
    fn macro_handles_required_default_and_optional() {
        let h = TestHeader::parse_field(b"id=\"a\", tag=tok, raw=:aGk=:, ratio=1.5").unwrap();
        assert_eq!(h.id, "a");
        assert_eq!(h.n, 7);
        assert_eq!(h.tag.as_deref(), Some("tok"));
        assert_eq!(h.raw.as_deref(), Some(&b"hi"[..]));
        assert_eq!(h.ratio, Some(1.5));

        assert!(matches!(
            TestHeader::parse_field(b"n=1"),
            Err(SfvError::MissingKey { key: "id" })
        ));
    }

    #[test]
    fn duplicate_keys_take_the_last_value() {
        let h = TestHeader::parse_field(b"id=\"a\", n=1, id=\"b\", n=2").unwrap();
        assert_eq!((h.id.as_str(), h.n), ("b", 2));
    }

    fn parts_with(values: &[&str]) -> hyper::http::request::Parts {
        let mut req = hyper::Request::new(());
        for v in values {
            req.headers_mut()
                .append("priority", v.parse().expect("header value"));
        }
        req.into_parts().0
    }

    #[test]
    fn extractor_parses_rejects_and_joins() {
        let mut parts = parts_with(&["u=1, i"]);
        let StructuredHeader(p) =
            StructuredHeader::<Priority>::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(p.urgency(), 1);
        assert!(p.incremental);

        // Repeated lines are joined into one field.
        let mut parts = parts_with(&["u=2", "i"]);
        let StructuredHeader(p) =
            StructuredHeader::<Priority>::from_request_parts(&mut parts, &()).unwrap();
        assert_eq!(p.urgency(), 2);
        assert!(p.incremental);

        // Missing header and malformed field both reject with 400.
        for parts in [&mut parts_with(&[]), &mut parts_with(&["u=$$$"])] {
            let err = StructuredHeader::<Priority>::from_request_parts(parts, &()).unwrap_err();
            assert!(matches!(
                err,
                crate::http::error::Error::Rejection { status, .. }
                    if status == hyper::StatusCode::BAD_REQUEST
            ));
        }
    }

    #[test]
    fn extractor_rejects_oversized_joined_headers() {
        let chunk = "u=1".to_string() + &";p=1".repeat(1000);
        let values = vec![chunk.as_str(); 64];
        let mut parts = parts_with(&values);
        assert!(StructuredHeader::<Priority>::from_request_parts(&mut parts, &()).is_err());
    }
}
