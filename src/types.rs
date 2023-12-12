use std::convert::TryFrom;
use std::fmt::Display;
use std::io::{self, ErrorKind};
use std::string::ToString;

use nom::IResult;

use crate::parser as p;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("incomplete response")]
    IncompleteResponse,
    #[error("invalid response")]
    InvalidResponse,
    #[error("invalid input")]
    InvalidInput,
}

impl<T> From<nom::Err<T>> for Error {
    fn from(value: nom::Err<T>) -> Self {
        match value {
            nom::Err::Incomplete(_) => Self::IncompleteResponse,
            nom::Err::Error(_) => Self::InvalidInput,
            nom::Err::Failure(_) => Self::InvalidInput,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Capability {
    Implementation(String),
    Sasl(Vec<String>),
    Sieve(Vec<String>),
    StartTls,
    MaxRedirects(usize),
    Notify(Vec<String>),
    Language(String),
    Owner(String),
    Version(String),
    Unknown(String, Option<String>),
}

impl TryFrom<(&str, Option<&str>)> for Capability {
    type Error = io::Error;

    fn try_from(s: (&str, Option<&str>)) -> Result<Self, Self::Error> {
        let (cap, rest) = s;

        let err = || io::Error::new(ErrorKind::InvalidInput, "Invalid Capability");
        let unwrap_rest = || rest.map(|o| o.to_owned()).ok_or_else(err);
        let unwrap_rest_vec = || {
            rest.map(|r| r.split(' ').map(|x| x.to_string()).collect())
                .ok_or_else(err)
        };

        Ok(match cap {
            "IMPLEMENTATION" => Capability::Implementation(unwrap_rest()?),
            "SASL" => Capability::Sasl(unwrap_rest_vec()?),
            "SIEVE" => Capability::Sieve(unwrap_rest_vec()?),
            "STARTTLS" => Capability::StartTls,
            "MAXREDIRECTS" => {
                Capability::MaxRedirects(unwrap_rest()?.parse::<usize>().map_err(|_| err())?)
            }
            "NOTIFY" => Capability::Notify(unwrap_rest_vec()?),
            "LANGUAGE" => Capability::Owner(unwrap_rest()?),
            "OWNER" => Capability::Owner(unwrap_rest()?),
            "VERSION" => Capability::Version(unwrap_rest()?),
            cap => Capability::Unknown(cap.to_owned(), rest.map(|s| s.to_owned())),
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum Command {
    Authenticate,
    StartTls,
    Logout,
    Capability,
    HaveSpace(String, usize),
    PutScript(String, String),
    ListScripts,
    SetActive(String),
    DeleteScript(String),
    RenameScript(String),
    CheckScript(String),
    Noop,
    UnAuthenticate,
}

impl Command {
    pub fn authenticate() -> Command {
        Command::Authenticate
    }

    pub fn start_tls() -> Command {
        Command::StartTls
    }

    pub fn logout() -> Command {
        Command::Logout
    }

    pub fn capability() -> Command {
        Command::Capability
    }

    pub fn have_space(name: &str, size: usize) -> Result<Command, Error> {
        Ok(Command::HaveSpace(to_sieve_name(name)?, size))
    }

    pub fn put_script(name: &str, script: &str) -> Result<Command, Error> {
        Ok(Command::PutScript(to_sieve_name(name)?, script.to_owned()))
    }

    pub fn list_scripts() -> Command {
        Command::ListScripts
    }

    pub fn set_active(name: &str) -> Result<Command, Error> {
        Ok(Command::SetActive(to_sieve_name(name)?))
    }

    pub fn deletescript(name: &str) -> Result<Command, Error> {
        Ok(Command::DeleteScript(to_sieve_name(name)?))
    }

    pub fn renamescript(name: &str) -> Result<Command, Error> {
        Ok(Command::RenameScript(to_sieve_name(name)?))
    }

    pub fn checkscript(name: &str) -> Result<Command, Error> {
        Ok(Command::CheckScript(to_sieve_name(name)?))
    }

    pub fn noop() -> Command {
        Command::Noop
    }

    pub fn unauthenticate() -> Command {
        Command::UnAuthenticate
    }
}

fn to_sieve_name(s: &str) -> Result<String, Error> {
    if s.chars().any(p::is_bad_sieve_name_char) {
        return Err(Error::InvalidInput);
    }

    Ok(s.to_owned())
}

// to quotedstring
fn to_qs(s: &str) -> String {
    // TODO: escape some things in s?
    format!("\"{}\"", s)
}

fn to_lit_c2s(s: &str) -> String {
    format!("{{{}+}}\r\n{}", s.len(), s)
}

impl ToString for Command {
    fn to_string(&self) -> String {
        match self {
            Command::Authenticate => "AUTHENTICATE\r\n".into(),
            Command::StartTls => "STARTTLS\r\n".into(),
            Command::Logout => "LOGOUT\r\n".into(),
            Command::Capability => "CAPABILITY\r\n".into(),
            Command::HaveSpace(name, size) => format!("HAVESPACE {} {}\r\n", to_qs(name), size),
            Command::PutScript(name, script) => {
                format!("PUTSCRIPT {} {}\r\n", to_qs(name), to_lit_c2s(script))
            }
            Command::ListScripts => "LISTSCRIPTS\r\n".into(),
            Command::SetActive(name) => format!("SETACTIVE {}\r\n", to_qs(name)),
            Command::DeleteScript(name) => format!("DELETESCRIPT {}\r\n", to_qs(name)),
            Command::RenameScript(name) => format!("RENAMESCRIPT {}\r\n", to_qs(name)),
            Command::CheckScript(name) => format!("CHECKSCRIPT {}\r\n", to_qs(name)),
            Command::Noop => "NOOP\r\n".into(),
            Command::UnAuthenticate => "UNAUTHENTICATE\r\n".into(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Response {
    pub tag: OkNoBye,
    pub code: Option<(ResponseCode, Option<String>)>,
    pub human: Option<HumanReadableString>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OkNoBye {
    Ok,
    No,
    Bye,
}

impl std::fmt::Display for OkNoBye {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                OkNoBye::Ok => "OK",
                OkNoBye::No => "NO",
                OkNoBye::Bye => "BYE",
            }
        )
    }
}

pub type SieveUrl = String;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum QuotaVariant {
    None,
    MaxScripts,
    MaxSize,
}

type SieveString = String;
type HumanReadableString = SieveString;

#[derive(Debug, PartialEq, Clone)]
pub enum ResponseCode {
    AuthTooWeak,
    EncryptNeeded,
    Quota(QuotaVariant),
    Referral(SieveUrl),
    Sasl,
    TransitionNeeded,
    TryLater,
    Active,
    Nonexistent,
    AlreadyExists,
    Tag,
    Warnings,
}

fn response_oknobye(input: &str) -> Result<(&str, Response), Error> {
    p::response(input).map_err(Error::from)
}

pub fn response_authenticate(_input: &str) -> Result<OkNoBye, Error> {
    unimplemented!()
}

/// Parses text returned from the server in response to the LOGOUT command.
pub fn response_logout(input: &str) -> Result<(&str, Response), Error> {
    response_oknobye(input)
}

/// Parses text returned from the server in response to the GETSCRIPT command.
pub fn response_getscript(input: &str) -> Result<(&str, String, Response), Error> {
    match p::response_getscript(input) {
        Ok((left, (Some(s), resp))) => Ok((left, s, resp)),
        Err(nom::Err::Incomplete(_)) => Err(Error::IncompleteResponse),
        _ => Err(Error::InvalidResponse),
    }
}

/// Parses text returned from the server in response to the GETSCRIPT command.
pub fn response_setactive(input: &str) -> Result<(&str, Response), Error> {
    response_oknobye(input)
}

pub type ScriptList = Vec<(String, bool)>;

/// Parses text returned from the server in response to the LISTSCRIPTS command.
/// Returns list of scripts and a bool indicating if that script is the active
/// script.
pub fn response_listscripts(input: &str) -> Result<(&str, ScriptList, Response), Error> {
    match p::response_listscripts(input) {
        Ok((left, (s, resp))) => {
            if s.iter().filter(|(_, is_active)| *is_active).count() > 1 {
                Err(Error::InvalidResponse)
            } else {
                Ok((left, s, resp))
            }
        }
        Err(nom::Err::Incomplete(_)) => Err(Error::IncompleteResponse),
        _ => Err(Error::InvalidResponse),
    }
}

/// Parses text returned from the server in response to the DELETESCRIPT command.
pub fn response_deletescript(input: &str) -> Result<(&str, Response), Error> {
    response_oknobye(input)
}

/// Parses text returned from the server in response to the PUTSCRIPT command.
pub fn response_putscript(input: &str) -> Result<(&str, Response), Error> {
    response_oknobye(input)
}

/// Parses text returned from the server in response to the CHECKSCRIPT command.
pub fn response_checkscript(input: &str) -> Result<(&str, Response), Error> {
    response_oknobye(input)
}

/// Parses text returned from the server in response to the CAPABILITY command.
/// Returns list of capabilities and optional additional strings.
pub fn response_capability(input: &str) -> Result<(&str, Vec<Capability>, Response), Error> {
    match p::response_capability(input) {
        Ok((left, (s, resp))) => {
            let caps = s
                .iter()
                .map(|(cap, rest)| Capability::try_from((&**cap, rest.as_deref())).unwrap())
                .collect();
            Ok((left, caps, resp))
        }
        Err(nom::Err::Incomplete(_)) => Err(Error::IncompleteResponse),
        _ => Err(Error::InvalidResponse),
    }
}

/// Parses text returned from the server in response to the HAVESPACE command.
pub fn response_havespace(input: &str) -> Result<(&str, Response), Error> {
    response_oknobye(input)
}

/// Parses text returned from the server in response to the STARTTLS command.
/// Returns list of capabilities and optional additional strings.
pub fn response_starttls(input: &str) -> Result<(&str, Vec<Capability>, Response), Error> {
    match p::response_starttls(input) {
        Ok((left, (s, resp))) => {
            let caps = s
                .iter()
                .map(|(cap, rest)| Capability::try_from((&**cap, rest.as_deref())).unwrap())
                .collect();
            Ok((left, caps, resp))
        }
        Err(nom::Err::Incomplete(_)) => Err(Error::IncompleteResponse),
        _ => Err(Error::InvalidResponse),
    }
}

/// Parses text returned from the server in response to the RENAMESCRIPT command.
pub fn response_renamescript(input: &str) -> Result<(&str, Response), Error> {
    response_oknobye(input)
}

/// Parses text returned from the server in response to the NOOP command.
pub fn response_noop(input: &str) -> Result<(&str, Response), Error> {
    match response_oknobye(input) {
        Ok((
            left,
            r @ Response {
                tag: OkNoBye::Ok, ..
            },
        )) => Ok((left, r)),
        Ok(_) => Err(Error::InvalidResponse),
        Err(e) => Err(e),
    }
}

/// Parses text returned from the server in response to the UNAUTHENTICATE command.
pub fn response_unauthenticate(input: &str) -> Result<(&str, Response), Error> {
    response_oknobye(input)
}

pub type MSResult<'a, T> = IResult<&'a str, (T, Response)>;
pub type MSResultList<'a, T> = IResult<&'a str, (Vec<T>, Response)>;
