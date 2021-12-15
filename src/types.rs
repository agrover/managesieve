#![allow(unused_variables)]

use std::convert::TryFrom;
use std::io::{self, ErrorKind};

use nom;

use crate::parser as p;

#[derive(Debug, PartialEq)]
pub enum Error {
    IncompleteResponse,
    InvalidResponse,
}

#[derive(Debug, PartialEq)]
pub enum Capability {
    Implementation(String),
    Notify(String),
    Sasl(Vec<String>),
    Sieve(Vec<String>),
    StartTls,
    Version(String),
}

impl TryFrom<&str> for Capability {
    type Error = io::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let spl = s.split_once(' ');
        let mut cmd = spl.unwrap().0;
        if cmd.starts_with('"') {
            cmd = &cmd[1..cmd.len() - 1];
        }
        let rest = spl.map(|(_, pre)| &pre[1..pre.len() - 1]);

        match cmd {
            "IMPLEMENTATION" => Ok(Capability::Implementation(rest.unwrap().to_owned())),
            "NOTIFY" => Ok(Capability::Notify(rest.unwrap().to_owned())),
            "SASL" => Ok(Capability::Sasl(Vec::new())),
            "SIEVE" => Ok(Capability::Sieve(
                rest.map(|r| r.split(' ').map(|x| x.to_string()).collect())
                    .unwrap(),
            )),
            "STARTTLS" => Ok(Capability::StartTls),
            "VERSION" => Ok(Capability::Version(rest.unwrap().to_owned())),
            _ => Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Invalid Capability",
            )),
        }
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

    pub fn have_space(name: &str, size: usize) -> Command {
        Command::HaveSpace(name.to_owned(), size)
    }

    pub fn put_script(name: &str, script: &str) -> Command {
        Command::PutScript(name.to_owned(), script.to_owned())
    }

    pub fn list_scripts() -> Command {
        Command::ListScripts
    }

    pub fn set_active(name: &str) -> Command {
        Command::SetActive(name.to_owned())
    }

    pub fn deletescript(name: &str) -> Command {
        Command::DeleteScript(name.to_owned())
    }

    pub fn renamescript(name: &str) -> Command {
        Command::RenameScript(name.to_owned())
    }

    pub fn checkscript(name: &str) -> Command {
        Command::CheckScript(name.to_owned())
    }

    pub fn noop() -> Command {
        Command::Noop
    }

    pub fn unauthenticate() -> Command {
        Command::UnAuthenticate
    }
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub struct SieveUrl;

#[derive(Debug, PartialEq)]
pub enum QuotaVariant {
    None,
    MaxScripts,
    MaxSize,
}

type SieveString = String;
type HumanReadableString = SieveString;

#[derive(Debug, PartialEq)]
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

pub fn response_oknobye(input: &str) -> Result<Response, Error> {
    match p::response(input) {
        Ok((_, response)) => Ok(response),
        Err(e) => match e {
            nom::Err::Incomplete(_) => Err(Error::IncompleteResponse),
            nom::Err::Error(_) => Err(Error::InvalidResponse),
            nom::Err::Failure(_) => Err(Error::InvalidResponse),
        },
    }
}

pub fn response_authenticate(input: &str) -> Result<OkNoBye, Error> {
    unimplemented!()
}

pub fn response_logout(input: &str) -> Result<Response, Error> {
    response_oknobye(input)
}

pub fn response_getscript(input: &str) -> Result<String, Error> {
    match p::response_getscript(input) {
        Ok((_, (Some(s), resp))) => Ok(s),
        Err(nom::Err::Incomplete(_)) => Err(Error::IncompleteResponse),
        _ => Err(Error::InvalidResponse),
    }
}

pub fn response_setactive(input: &str) -> Result<Response, Error> {
    response_oknobye(input)
}

/// Returns list of scripts and a bool for the maximum of one script that is
/// active.
pub fn response_listscripts(input: &str) -> Result<Vec<(String, bool)>, Error> {
    match p::response_listscripts(input) {
        Ok((_, (s, resp))) => {
            if s.iter().filter(|(s, is_active)| *is_active).count() > 1 {
                Err(Error::InvalidResponse)
            } else {
                Ok(s)
            }
        }
        Err(nom::Err::Incomplete(_)) => Err(Error::IncompleteResponse),
        _ => Err(Error::InvalidResponse),
    }
}

pub fn response_deletescript(input: &str) -> Result<Response, Error> {
    response_oknobye(input)
}

pub fn response_putscript(input: &str) -> Result<Response, Error> {
    response_oknobye(input)
}

pub fn response_checkscript(input: &str) -> Result<Response, Error> {
    response_oknobye(input)
}

pub fn response_capability(
    input: &str,
) -> Result<(Vec<(String, Option<String>)>, Response), Error> {
    match p::response_capability(input) {
        Ok((_, (s, resp))) => Ok((s, resp)),
        Err(nom::Err::Incomplete(_)) => Err(Error::IncompleteResponse),
        _ => Err(Error::InvalidResponse),
    }
}

pub fn response_havespace(input: &str) -> Result<Response, Error> {
    response_oknobye(input)
}

pub fn response_starttls(input: &str) -> Result<(Vec<(String, Option<String>)>, Response), Error> {
    match p::response_starttls(input) {
        Ok((_, (s, resp))) => Ok((s, resp)),
        Err(nom::Err::Incomplete(_)) => Err(Error::IncompleteResponse),
        _ => Err(Error::InvalidResponse),
    }
}

pub fn response_renamescript(input: &str) -> Result<Response, Error> {
    response_oknobye(input)
}

pub fn response_noop(input: &str) -> Result<(), Error> {
    match response_oknobye(input) {
        Ok(Response {
            tag: OkNoBye::Ok, ..
        }) => Ok(()),
        Ok(_) => Err(Error::InvalidResponse),
        Err(e) => Err(e),
    }
}

pub fn response_unauthenticate(input: &str) -> Result<Response, Error> {
    response_oknobye(input)
}
