use nom::{
    error::{ErrorKind, ParseError},
    Err, IResult, InputLength, InputTake, Needed, ToUsize,
};

/// This is a copy from the nom library but adapted to be able to parse data where the size
/// varaible is included in length value. The current implementation only supports be_u32.

/// Gets a number from the first parser,
/// takes a subslice of the input of that size,
/// BUT!!
/// the number is considered to be included
/// in that subslice, thus the actual subslice needs
/// to be shortened by the byte size of the number.
/// BUT!!
/// then applies the second parser on that subslice.
/// If the second parser returns Incomplete,
/// length_value will return an error.
/// # Arguments
/// * `f` The parser to apply.
/// ```rust
/// # #[macro_use] extern crate nom;
/// # use nom::{Err, error::ErrorKind, Needed, IResult};
/// # use nom::Needed::Size;
/// use nom::number::complete::be_u16;
/// use nom::multi::length_value;
/// use nom::bytes::complete::tag;
///
/// fn parser(s: &[u8]) -> IResult<&[u8], &[u8]> {
///   length_value_tuya(be_u32, tag("abcdefgh"))(s)
/// }
///
/// assert_eq!(parser(b"\x00\x00\x00\x0cabcdefghijk"), Ok((&b"ijk"[..], &b"abcdefgh"[..])));
/// assert_eq!(parser(b"\x00\x00\x00\x0c12345678123"), Err(Err::Error((&b"123"[..], ErrorKind::Tag))));
/// assert_eq!(parser(b"\x00\x00\x00\x0c"), Err(Err::Incomplete(Size(12))));
/// ```
pub fn length_value_tuya<I, O, N, E, F, G>(f: F, g: G) -> impl Fn(I) -> IResult<I, O, E>
where
    I: Clone + InputLength + InputTake,
    N: Copy + ToUsize,
    F: Fn(I) -> IResult<I, N, E>,
    G: Fn(I) -> IResult<I, O, E>,
    E: ParseError<I>,
{
    move |i: I| {
        let (i, length) = f(i)?;

        let length: usize = length.to_usize();
        let length = length - 4;

        if i.input_len() < length {
            Err(Err::Incomplete(Needed::Size(length)))
        } else {
            let (rest, i) = i.take_split(length);
            match g(i.clone()) {
                Err(Err::Incomplete(_)) => {
                    Err(Err::Error(E::from_error_kind(i, ErrorKind::Complete)))
                }
                Err(e) => Err(e),
                Ok((_, o)) => Ok((rest, o)),
            }
        }
    }
}
