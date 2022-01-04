//! managesieve - parsing and generation of 'managesieve' communications
//! protocol (RFC 5804) commands and responses.
//!
//! # Usage
//!
//! Commands can be generated in the correct form by constructing a [`Command`]
//! of the desired type, which can then be converted into a string and sent.
//!
//! Response parsing is achieved by passing bytes received from the managesieve
//! server to the expected `response_` function. It will either return data and
//! a [`Response`], `Error::IncompleteResponse` if more bytes are expected to form a
//! complete response, or `Error::InvalidResponse` if the server has responded
//! in a nonconforming manner.
//!
//! It is possible to pipeline multiple managesieve commands, and receive a
//! stream of bytes comprising multiple responses. In this case, `response_`
//! functions return the remaining bytes after successfully parsing the first
//! response.

mod parser;
mod types;

pub use types::*;
