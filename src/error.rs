use chrono;
use std::error::Error;
use std::fmt;
use std::string::FromUtf8Error;

#[derive(Debug)]
/// Authentication Error Types
pub enum AWSAuthError {
    /// Error thrown converting from UTF-8.
    FromUtf8Error(FromUtf8Error),
    /// Error thrown when running methods not valid for the current mode.
    ModeError,
    /// General error thrown during operation.
    Other(&'static str),
    /// Error thrown parsing a datetime.
    ParseError(chrono::ParseError),
}

impl Error for AWSAuthError {
    fn description(&self) -> &str {
        match *self {
            AWSAuthError::FromUtf8Error(ref e) => e.description(),
            AWSAuthError::ModeError => "ModeError",
            AWSAuthError::Other(e) => e,
            AWSAuthError::ParseError(ref e) => e.description(),
        }
    }
}

impl fmt::Display for AWSAuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let display = match *self {
            AWSAuthError::FromUtf8Error(_) => "FromUtf8Error",
            AWSAuthError::ModeError => "ModeError",
            AWSAuthError::Other(e) => e,
            AWSAuthError::ParseError(_) => "ParseError",
        };
        write!(f, "{}", display)
    }
}

impl From<FromUtf8Error> for AWSAuthError {
    fn from(e: FromUtf8Error) -> AWSAuthError {
        AWSAuthError::FromUtf8Error(e)
    }
}

impl From<chrono::format::ParseError> for AWSAuthError {
    fn from(e: chrono::format::ParseError) -> AWSAuthError {
        AWSAuthError::ParseError(e)
    }
}

#[derive(Debug,PartialEq)]
/// Thrown when a given region cannot be parsed.
pub struct ParseRegionError;

impl Error for ParseRegionError {
    fn description(&self) -> &str {
        "Unable to parse the given region"
    }
}

impl fmt::Display for ParseRegionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ParseRegionError")
    }
}

#[derive(Debug,PartialEq)]
/// Thrown when a given service cannot be parsed.
pub struct ParseServiceError;

impl Error for ParseServiceError {
    fn description(&self) -> &str {
        "Unable to parse the given region"
    }
}

impl fmt::Display for ParseServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ParseServiceError")
    }
}
