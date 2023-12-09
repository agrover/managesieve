#![allow(dead_code)]

use either::Either;
use nom::{
    branch::alt,
    bytes::streaming::{escaped_transform, tag, tag_no_case, take},
    character::streaming::{crlf, digit1, none_of, space1},
    combinator::{map, map_res, opt, value},
    error::{make_error, ErrorKind},
    multi::{length_data, many0},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};

use crate::types::{
    MSResult, MSResultList, OkNoBye, QuotaVariant, Response, ResponseCode, SieveUrl,
};

pub(crate) fn ok(input: &str) -> IResult<&str, OkNoBye> {
    value(OkNoBye::Ok, tag_no_case("OK"))(input)
}

pub(crate) fn no(input: &str) -> IResult<&str, OkNoBye> {
    value(OkNoBye::No, tag_no_case("NO"))(input)
}

pub(crate) fn bye(input: &str) -> IResult<&str, OkNoBye> {
    value(OkNoBye::Bye, tag_no_case("BYE"))(input)
}

pub(crate) fn nobye(input: &str) -> IResult<&str, OkNoBye> {
    alt((no, bye))(input)
}

fn atom(input: &str) -> IResult<&str, ResponseCode> {
    map(
        alt((
            tag("AUTH-TOO-WEAK"),
            tag("ENCRYPT-NEEDED"),
            tag("QUOTA/MAXSCRIPTS"),
            tag("QUOTA/MAXSIZE"),
            tag("QUOTA"),
            tag("REFERRAL"),
            tag("SASL"),
            tag("TRANSITION-NEEDED"),
            tag("TRYLATER"),
            tag("ACTIVE"),
            tag("NONEXISTENT"),
            tag("ALREADYEXISTS"),
            tag("TAG"),
            tag("WARNINGS"),
        )),
        |s| match s {
            "AUTH-TOO-WEAK" => ResponseCode::AuthTooWeak,
            "ENCRYPT-NEEDED" => ResponseCode::EncryptNeeded,
            "QUOTA" => ResponseCode::Quota(QuotaVariant::None),
            "QUOTA/MAXSCRIPTS" => ResponseCode::Quota(QuotaVariant::MaxScripts),
            "QUOTA/MAXSIZE" => ResponseCode::Quota(QuotaVariant::MaxSize),
            "REFERRAL" => ResponseCode::Referral(SieveUrl::new()),
            "SASL" => ResponseCode::Sasl,
            "TRANSITION-NEEDED" => ResponseCode::TransitionNeeded,
            "TRYLATER" => ResponseCode::TryLater,
            "ACTIVE" => ResponseCode::Active,
            "NONEXISTENT" => ResponseCode::Nonexistent,
            "ALREADYEXISTS" => ResponseCode::AlreadyExists,
            "TAG" => ResponseCode::Tag,
            "WARNINGS" => ResponseCode::Warnings,
            _ => unreachable!(),
        },
    )(input)
}

#[test]
fn test_atom() {
    assert!(matches!(atom("SASL"), Ok(("", ResponseCode::Sasl))));
    assert!(atom("ABCDE").is_err());
}

fn literal_s2c_len(input: &str) -> IResult<&str, usize> {
    terminated(
        delimited(
            tag("{"),
            map_res(digit1, |s: &str| s.parse::<usize>()),
            tag("}"),
        ),
        crlf,
    )(input)
}

#[test]
fn test_literal_s2c_len() {
    assert!(matches!(literal_s2c_len("{3}\r\n"), Ok(("", 3))));
    assert!(matches!(literal_s2c_len("{0}\r\n"), Ok(("", 0))));
    assert!(literal_s2c_len("{3}").is_err());
    assert!(matches!(literal_s2c_len("{3}\r\nab"), Ok(("ab", 3))));
}

// Needs to return String because quoted_string does too.
fn literal_s2c(input: &str) -> IResult<&str, String> {
    map(length_data(literal_s2c_len), |s| s.to_owned())(input)
}

#[test]
fn test_literal_s2c() {
    assert_eq!(literal_s2c("{3}\r\nabc").unwrap().1, "abc");
    assert!(literal_s2c("{4}\r\nabc").is_err());
    assert!(literal_s2c("{0}\r\n").is_ok());
}

fn sievestring_s2c(input: &str) -> IResult<&str, String> {
    alt((literal_s2c, quoted_string))(input)
}

#[test]
fn test_sievestring_s2c() {
    assert_eq!(sievestring_s2c("{3}\r\nabc").unwrap().1, "abc");
    assert_eq!(sievestring_s2c("\"hello\"").unwrap().1, "hello");
}

fn literal_c2s_len(input: &str) -> IResult<&str, usize> {
    terminated(
        delimited(
            tag("{"),
            map_res(digit1, |s: &str| s.parse::<usize>()),
            alt((tag("+}"), tag("}"))),
        ),
        crlf,
    )(input)
}

#[test]
fn test_literal_c2s_len() {
    test_literal_s2c_len();
    assert!(matches!(literal_c2s_len("{3+}\r\n"), Ok(("", 3))));
}

fn literal_c2s(input: &str) -> IResult<&str, String> {
    map(length_data(literal_c2s_len), |s| s.to_owned())(input)
}

#[test]
fn test_literal_c2s() {
    test_literal_s2c();
    assert_eq!(literal_c2s("{3+}\r\nabc").unwrap().1, "abc");
    assert!(literal_c2s("{4+}\r\nabc").is_err());
}

fn sievestring_c2s(input: &str) -> IResult<&str, String> {
    alt((literal_c2s, quoted_string))(input)
}

#[test]
fn test_sievestring_c2s() {
    assert_eq!(sievestring_c2s("{3+}\r\nabc").unwrap().1, "abc");
    assert_eq!(sievestring_c2s("\"hello\"").unwrap().1, "hello");
}

fn code(input: &str) -> IResult<&str, (ResponseCode, Option<String>)> {
    delimited(
        tag("("),
        pair(atom, opt(preceded(space1, sievestring_s2c))),
        tag(")"),
    )(input)
}

#[test]
fn test_code() {
    assert!(matches!(
        code("(QUOTA)"),
        Ok(("", (ResponseCode::Quota(QuotaVariant::None), None)))
    ));
    assert_eq!(
        code("(TAG {16}\r\nSTARTTLS-SYNC-42)"),
        Ok((
            "",
            (ResponseCode::Tag, Some("STARTTLS-SYNC-42".to_string()))
        ))
    );
    assert_eq!(
        code("(TAG \"STARTTLS-SYNC-42\")"),
        Ok((
            "",
            (ResponseCode::Tag, Some("STARTTLS-SYNC-42".to_string()))
        ))
    );
}

fn quoted_string(input: &str) -> IResult<&str, String> {
    let one: usize = 1;
    delimited(
        tag("\""),
        escaped_transform(none_of(r#"\""#), '\\', take(one)),
        tag("\""),
    )(input)
}

#[test]
fn test_quoted_string() {
    quoted_string("\"hello\"").unwrap();
    quoted_string("\"\"").unwrap();
    assert!(quoted_string("hello").is_err());
}

// see section 1.6 of rfc 5804
pub fn is_bad_sieve_name_char(c: char) -> bool {
    match c {
        c if (c <= 0x1f as char) => true,
        c if (c >= 0x7f as char && c <= 0x9f as char) => true,
        c if (c == '\u{2028}' || c == '\u{2029}') => true,
        _ => false,
    }
}

pub fn sieve_name_c2s(input: &str) -> IResult<&str, String> {
    match sievestring_c2s(input) {
        Err(e) => Err(e),
        Ok((rest, s)) => match s.chars().find(|c| is_bad_sieve_name_char(*c)) {
            Some(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Char))),
            None => Ok((rest, s)),
        },
    }
}

#[test]
fn test_sieve_name_c2s() {
    sieve_name_c2s("\"hello\"").unwrap();
    sieve_name_c2s("\"hello\u{1337}\"").unwrap();
    sieve_name_c2s("{3}\r\nabc").unwrap();
    assert!(matches!(
        sieve_name_c2s("\"he\x1f\""),
        Err(nom::Err::Failure(_))
    ));
    assert!(matches!(sieve_name_c2s("\"he\" \x1f"), Ok((" \x1f", _))));
}

pub fn active_sieve_name(input: &str) -> IResult<&str, Option<String>> {
    opt(sieve_name_c2s)(input)
}

#[test]
fn test_active_sieve_name() {
    assert!(active_sieve_name("hello  ").unwrap().1.is_none());
    assert!(active_sieve_name("\"hello \" ").unwrap().1.is_some());
    assert!(active_sieve_name("\"hello\x7f \" ").is_err());
    assert!(active_sieve_name("\"\"").is_ok());
    assert!(matches!(
        active_sieve_name("hello   "),
        Ok(("hello   ", None))
    ));
    assert!(matches!(active_sieve_name("   "), Ok((_, None))));
}

pub fn response_ok(input: &str) -> IResult<&str, Response> {
    terminated(
        map(
            tuple((
                ok,
                opt(preceded(space1, code)),
                opt(preceded(space1, quoted_string)),
            )),
            |(_, code, human)| Response {
                tag: OkNoBye::Ok,
                code,
                human,
            },
        ),
        crlf,
    )(input)
}

pub fn response_nobye(input: &str) -> IResult<&str, Response> {
    terminated(
        map(
            tuple((
                nobye,
                opt(preceded(space1, code)),
                opt(preceded(space1, quoted_string)),
            )),
            |(oknobye, code, human)| Response {
                tag: oknobye,
                code,
                human,
            },
        ),
        crlf,
    )(input)
}

pub fn response(input: &str) -> IResult<&str, Response> {
    alt((response_ok, response_nobye))(input)
}

#[test]
fn test_response() {
    response("ok\r\n").unwrap();
    response("nO\r\n").unwrap();
    response("BYE\r\n").unwrap();
    response("ok (QUOTA)\r\n").unwrap();
    response("ok (QUOTA) \"hello\"\r\n").unwrap();
    assert!(response("ok").is_err());
    assert!(response(" ok\r\n").is_err());
    assert!(response("ok (\r\n").is_err());
    assert!(response("ok (QUOTA\r\n").is_err());
    assert!(response("ok (QUOTA/)\r\n").is_err());
}

pub fn response_getscript(input: &str) -> IResult<&str, (Option<String>, Response)> {
    alt((
        map(
            separated_pair(sievestring_s2c, crlf, response_ok),
            |(s, r)| (Some(s), r),
        ),
        map(response_nobye, |r| (None, r)),
    ))(input)
}

#[test]
fn test_response_getscript() {
    response_getscript("\"hello\"\r\nOK\r\n").unwrap();
    response_getscript("NO\r\n").unwrap();
    assert!(response_getscript("\"hello\"\r\nBYE\r\n").is_err());
}

pub fn response_listscripts(input: &str) -> MSResultList<(String, bool)> {
    pair(
        many0(terminated(
            pair(
                sievestring_s2c,
                map(opt(pair(space1, tag_no_case("ACTIVE"))), |o| o.is_some()),
            ),
            crlf,
        )),
        response,
    )(input)
}

#[test]
fn test_response_listscripts() {
    response_listscripts("\"script1\"\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("\"script1\" ACTIVE\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("\"script1\" active\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("OK\r\n").unwrap();
    response_listscripts("BYE\r\n").unwrap();
}

fn single_capability(input: &str) -> IResult<&str, (String, Option<String>)> {
    terminated(
        pair(sievestring_s2c, opt(preceded(space1, sievestring_s2c))),
        crlf,
    )(input)
}

#[test]
fn test_single_capability() {
    single_capability("\"CAPABILITY1\"\r\n").unwrap();
    single_capability("\"CAPABILITY2\" \"a b c d e\"\r\n").unwrap();
    assert!(single_capability("\"CAPABILITY2\" \r\n").is_err());
}

pub fn response_capability(
    input: &str,
    //) -> IResult<&str, (Vec<(String, Option<String>)>, Response)> {
) -> MSResultList<(String, Option<String>)> {
    pair(many0(single_capability), response)(input)
}

#[test]
fn test_response_capability() {
    response_capability("\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n").unwrap();
}

#[test]
fn test_response_capability_2() {
    let inc1 = include_str!("test_input/response_capability-1.txt");
    response_capability(inc1).unwrap();
}

pub fn response_starttls(input: &str) -> MSResultList<(String, Option<String>)> {
    alt((
        preceded(response_ok, response_capability),
        map(response_nobye, |r| (Vec::new(), r)),
    ))(input)
}

#[test]
fn test_response_starttls() {
    response_starttls("OK\r\n\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n").unwrap();
    response_starttls("BYE\r\n").unwrap();
}

/// Server responds to authenticate with either a challenge or a oknobye
/// response.
pub fn response_authenticate_initial(input: &str) -> IResult<&str, Either<String, Response>> {
    alt((
        map(terminated(sievestring_s2c, crlf), Either::Left),
        map(response_nobye, Either::Right),
    ))(input)
}

#[test]
fn test_response_authenticate_initial() {
    response_authenticate_initial("{4}\r\nabcd\r\n").unwrap();
    response_authenticate_initial("BYE\r\n").unwrap();
}

/// Server responds to client response with oknobye and can also include new
/// capabilities if OK.
pub fn response_authenticate_complete(
    input: &str,
) -> MSResult<Option<Vec<(String, Option<String>)>>> {
    alt((
        map(
            pair(response_ok, opt(response_capability)),
            |(a, b)| match b {
                None => (None, a),
                Some((s, r)) => (Some(s), r),
            },
        ),
        map(response_nobye, |r| (None, r)),
    ))(input)
}

#[test]
fn test_response_authenticate_complete() {
    response_authenticate_complete("OK\r\n\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n").unwrap();
    response_authenticate_complete("BYE\r\n").unwrap();
}
