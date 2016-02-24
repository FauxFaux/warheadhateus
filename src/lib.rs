// Copyright (c) 2016 warheadhateus developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! AWS Authorization Header Generation (AWS Signature Version 4)
//!
//! Currently this is implemented for S3 and passes all tests (See [Header Based Auth][1]).
//! [1]: http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
//!
//!     // ##      ##    ###    ########  ##     ## ########    ###    ########
//!     // ##  ##  ##   ## ##   ##     ## ##     ## ##         ## ##   ##     ##
//!     // ##  ##  ##  ##   ##  ##     ## ##     ## ##        ##   ##  ##     ##
//!     // ##  ##  ## ##     ## ########  ######### ######   ##     ## ##     ##
//!     // ##  ##  ## ######### ##   ##   ##     ## ##       ######### ##     ##
//!     // ##  ##  ## ##     ## ##    ##  ##     ## ##       ##     ## ##     ##
//!     //  ###  ###  ##     ## ##     ## ##     ## ######## ##     ## ########
//!
//!     // ##     ##    ###    ######## ########
//!     // ##     ##   ## ##      ##    ##
//!     // ##     ##  ##   ##     ##    ##
//!     // ######### ##     ##    ##    ######
//!     // ##     ## #########    ##    ##
//!     // ##     ## ##     ##    ##    ##
//!     // ##     ## ##     ##    ##    ########
//!
//!     // ##     ##  ######
//!     // ##     ## ##    ##
//!     // ##     ## ##
//!     // ##     ##  ######
//!     // ##     ##       ##
//!     // ##     ## ##    ##
//!     //  #######   ######
//!
//! # Examples
//!
//! ```
//! # #[macro_use] extern crate log;
//! # extern crate chrono;
//! # extern crate warheadhateus;
//!
//! # fn main() {
//! use chrono::UTC;
//! use chrono::offset::TimeZone;
//! use std::io::{self, Write};
//! use warheadhateus::{AWSAuth, hashed_data, HttpRequestMethod, Region, Service};
//!
//! const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
//! const SCOPE_DATE: &'static str = "20130524T000000Z";
//! const ACCESS_KEY_ID: &'static str = "AKIAIOSFODNN7EXAMPLE";
//! const SECRET_ACCESS_KEY: &'static str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
//! const HOST: &'static str = "examplebucket.s3.amazonaws.com";
//! const AWS_TEST_1: &'static str = "AWS4-HMAC-SHA256 \
//! Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,\
//! SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,\
//! Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
//!
//! match AWSAuth::new("https://examplebucket.s3.amazonaws.com/test.txt") {
//!     Ok(mut auth) => {
//!         let payload_hash = match hashed_data(None) {
//!             Ok(ph) => ph,
//!             Err(e) => {
//!                 writeln!(io::stderr(), "{}", e).expect("Unable to write to stderr!");
//!                 "".to_owned()
//!             }
//!         };
//!         let scope_date = UTC.datetime_from_str(SCOPE_DATE, DATE_TIME_FMT)
//!                             .expect("Unable to parse date!");
//!         auth.set_request_type(HttpRequestMethod::GET);
//!         auth.set_payload_hash(&payload_hash);
//!         auth.set_date(scope_date);
//!         auth.set_service(Service::S3);
//!         auth.set_access_key_id(ACCESS_KEY_ID);
//!         auth.set_secret_access_key(SECRET_ACCESS_KEY);
//!         auth.set_region(Region::UsEast1);
//!         auth.add_header("HOST", HOST);
//!         auth.add_header("x-amz-content-sha256", &payload_hash);
//!         auth.add_header("x-amz-date", SCOPE_DATE);
//!         auth.add_header("Range", "bytes=0-9");
//!
//!         match auth.auth_header() {
//!             Ok(ah) => {
//!                 writeln!(io::stdout(), "{}", ah).expect("Unable to write to stdout!");
//!                 writeln!(io::stdout(), "{}", AWS_TEST_1)
//!                     .expect("Unable to write to stdout!");
//!                 assert!(ah == AWS_TEST_1)
//!             }
//!             Err(e) => {
//!                 writeln!(io::stderr(), "{}", e).expect("Unable to write to stderr!");
//!                 assert!(false);
//!             }
//!         }
//!     }
//!     Err(e) => {
//!         writeln!(io::stderr(), "{}", e).expect("Unable to write to stderr!");
//!         assert!(false);
//!     }
//! }
//! # }
//! ```
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", deny(clippy, clippy_pedantic))]
#![deny(missing_docs)]
extern crate chrono;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
extern crate sodium_sys;
extern crate urlparse;

mod error;
mod mode;
mod region;
mod service;
mod utils;

use chrono::{DateTime, UTC};
pub use error::AWSAuthError;
pub use mode::Mode;
pub use region::Region;
use rustc_serialize::hex::ToHex;
pub use service::Service;
use sodium_sys::crypto::utils::init;
use std::collections::HashMap;
use std::fmt;
use std::sync::{ONCE_INIT, Once};
use urlparse::{quote, urlparse};
pub use utils::hashed_data;

const AWS4_REQUEST: &'static str = "aws4_request";
const DATE_FMT: &'static str = "%Y%m%d";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";

static START: Once = ONCE_INIT;

fn init() {
    START.call_once(|| {
        debug!("sodium_sys initialized");
        init::init();
    });
}

/// Amazon Web Service Authorization Header struct
pub struct AWSAuth {
    mode: Mode,
    req_type: HttpRequestMethod,
    path: String,
    query: String,
    sam: SAM,
    access_key_id: String,
    secret_access_key: String,
    region: Region,
    date: DateTime<UTC>,
    service: Service,
    headers: HashMap<String, String>,
    payload_hash: String,
    chunk_size: u32,
}

impl Default for AWSAuth {
    fn default() -> AWSAuth {
        AWSAuth {
            mode: Mode::Normal,
            req_type: HttpRequestMethod::GET,
            path: String::new(),
            query: String::new(),
            sam: SAM::AWS4HMACSHA256,
            access_key_id: String::new(),
            secret_access_key: String::new(),
            region: Region::UsEast1,
            date: UTC::now(),
            service: Service::S3,
            headers: HashMap::new(),
            payload_hash: String::new(),
            chunk_size: 0,
        }
    }
}

/// AWS Authentication Header Generation Result.
pub type AWSAuthResult = Result<String, AWSAuthError>;

impl AWSAuth {
    /// Create a new AWSAuth struct.
    pub fn new(url: &str) -> Result<AWSAuth, AWSAuthError> {
        let parsed = urlparse(url);
        let mut auth = AWSAuth { path: parsed.path, ..Default::default() };

        if let Some(q) = parsed.query {
            auth.query = q;
        }

        Ok(auth)
    }

    /// Add a header field to the AWSAuth struct.
    pub fn add_header(&mut self, key: &str, val: &str) -> &mut AWSAuth {
        self.headers.insert(key.to_owned(), val.to_owned());
        self
    }

    /// Set the AWS Access Key ID (this is supplied by Amazon).
    pub fn set_access_key_id(&mut self, access_key_id: &str) -> &mut AWSAuth {
        self.access_key_id = access_key_id.to_owned();
        self
    }

    /// Set the chunk size.
    /// * Note this is only used when Mode::Chunk is selected.
    /// * Chunk size must be at least 8 KB. We recommend a chunk size of a least 64 KB for better
    /// performance. This chunk size applies to all chunk except the last one. The last chunk you
    /// send can be smaller than 8 KB. If your payload is small and can fit in one chunk, then it
    /// can be smaller than the 8 KB.
    pub fn set_chunk_size(&mut self, chunk_size: u32) -> &mut AWSAuth {
        self.chunk_size = chunk_size;
        self
    }

    /// Set the scope date for the auth request.  Request are valid for 7 days from the given date.
    /// * Note that this date doesn't have to match the *x-amz-date* or *date* header values.
    pub fn set_date(&mut self, date: DateTime<UTC>) -> &mut AWSAuth {
        self.date = date;
        self
    }

    /// Set the mode of operation.
    pub fn set_mode(&mut self, mode: Mode) -> &mut AWSAuth {
        self.mode = mode;
        self
    }

    /// Set the payload hash.  This should be the hash of any request payload, or the hash of the
    /// empty string ("") if there is no payload.
    pub fn set_payload_hash(&mut self, payload_hash: &str) -> &mut AWSAuth {
        self.payload_hash = payload_hash.to_owned();
        self
    }

    /// Set the region the request is scoped for.
    pub fn set_region(&mut self, region: Region) -> &mut AWSAuth {
        self.region = region;
        self
    }

    /// Set the request verb (i.e. GET, PUT, POST, DELETE)
    pub fn set_request_type(&mut self, verb: HttpRequestMethod) -> &mut AWSAuth {
        self.req_type = verb;
        self
    }

    /// Set the AWS Secret Access Key (this is supplied by Amazon).
    pub fn set_secret_access_key(&mut self, secret_access_key: &str) -> &mut AWSAuth {
        self.secret_access_key = secret_access_key.to_owned();
        self
    }

    /// Set the Signing Algorithm Moniker used for this auth.
    pub fn set_sam(&mut self, sam: SAM) -> &mut AWSAuth {
        self.sam = sam;
        self
    }

    /// Set the AWS services this request should be constructed for (i.e. s3)
    pub fn set_service(&mut self, service: Service) -> &mut AWSAuth {
        self.service = service;
        self
    }

    fn scope(&self) -> String {
        let date_fmt = self.date.format(DATE_FMT).to_string();
        format!("{}/{}/{}/{}",
                date_fmt,
                self.region,
                self.service,
                AWS4_REQUEST)
    }

    fn credential(&self) -> String {
        format!("{}/{}", self.access_key_id, self.scope())
    }

    fn signed_headers(&self) -> String {
        let mut keys: Vec<String> = self.headers.keys().map(|x| x.to_lowercase()).collect();
        keys.sort();

        let mut buf = String::new();

        for key in &keys {
            buf.push_str(key);
            buf.push(';');
        }

        let trimmed = buf.trim_right_matches(';');
        trimmed.to_owned()
    }

    fn canonical_uri(&self) -> AWSAuthResult {
        if self.path.is_empty() {
            Ok("/".to_owned())
        } else {
            Ok(try!(quote(&self.path, b"/")))
        }
    }

    fn canonical_query_string(&self) -> AWSAuthResult {
        let cqs = if self.query.is_empty() {
            "".to_owned()
        } else {
            let qstrs: Vec<&str> = self.query.split('&').collect();
            let mut params = HashMap::new();
            for qstr in &qstrs {
                let kvs: Vec<&str> = qstr.split('=').collect();
                let key = try!(quote(kvs[0], b""));
                if kvs.len() == 1 {
                    params.insert(key, "".to_owned());
                } else {
                    let value = try!(quote(kvs[1], b""));
                    params.insert(key, value);
                }
            }

            let mut keys: Vec<&str> = params.keys().map(|x| &x[..]).collect();
            keys.sort();
            let mut cqs = String::new();
            let mut first = true;

            for key in keys {
                if let Some(val) = params.get(key) {
                    if !first {
                        cqs.push('&');
                    }
                    let kvp = format!("{}={}", key, val);
                    cqs.push_str(&kvp);
                }
                first = false;
            }
            cqs
        };

        Ok(cqs)
    }

    fn canonical_headers(&self) -> String {
        let mut keys: Vec<&String> = self.headers.keys().collect();
        keys.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));

        let mut buf = String::new();

        for key in &keys {
            if let Some(val) = self.headers.get(*key) {
                buf.push_str(&format!("{}:{}\n", key.to_lowercase(), val.trim())[..]);
            }
        }

        buf
    }

    fn sign_string(&self, string_to_sign: &str) -> AWSAuthResult {
        let mut key = String::from("AWS4");
        key.push_str(&self.secret_access_key);

        let date = self.date.format(DATE_FMT).to_string();
        let region = self.region.to_string();
        let service = self.service.to_string();
        let aws4 = AWS4_REQUEST.as_bytes();
        let date_key = try!(utils::signed_data(date.as_bytes(), key.as_bytes()));
        let date_region_key = try!(utils::signed_data(region.as_bytes(), &date_key));
        let date_region_service_key = try!(utils::signed_data(service.as_bytes(),
                                                              &date_region_key));
        let signing_key = try!(utils::signed_data(aws4, &date_region_service_key));
        let signature = try!(utils::signed_data(string_to_sign.as_bytes(), &signing_key));
        debug!("Signature\n{}", signature.to_hex());
        Ok(signature.to_hex())
    }

    fn signature(&self, seed: bool) -> AWSAuthResult {
        let hash = if seed {
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        } else {
            &self.payload_hash[..]
        };
        let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
                                        self.req_type,
                                        try!(self.canonical_uri()),
                                        try!(self.canonical_query_string()),
                                        self.canonical_headers(),
                                        self.signed_headers(),
                                        hash);
        debug!("CanonicalRequest\n{}", canonical_request);
        let string_to_sign = format!("{}\n{}\n{}\n{}",
                                     self.sam,
                                     self.date.format(DATE_TIME_FMT),
                                     self.scope(),
                                     try!(utils::hashed_data(Some(canonical_request.as_bytes()))));
        debug!("StringToSign\n{}", string_to_sign);

        self.sign_string(&string_to_sign)
    }

    /// Create the AWS S3 Authorization HTTP header.
    pub fn auth_header(&self) -> AWSAuthResult {
        init();
        let signature = match self.mode {
            Mode::Normal => try!(self.signature(false)),
            Mode::Chunked => try!(self.signature(true)),
        };
        Ok(format!("{} Credential={},SignedHeaders={},Signature={}",
                   self.sam,
                   self.credential(),
                   self.signed_headers(),
                   signature))
    }

    /// Generate the seed signature for chunked mode.
    pub fn seed_signature(&self) -> AWSAuthResult {
        match self.mode {
            Mode::Chunked => Ok(try!(self.signature(true))),
            _ => Err(AWSAuthError::ModeError),
        }
    }

    /// Generate the chunk signature for a given chunk.
    pub fn chunk_signature(&self, previous_signature: &str, chunk: &[u8]) -> AWSAuthResult {
        match self.mode {
            Mode::Chunked => {
                let hashed_chunk = if chunk.len() == 0 {
                    try!(utils::hashed_data(None))
                } else {
                    try!(utils::hashed_data(Some(chunk)))
                };
                let string_to_sign = format!("{}\n{}\n{}\n{}\n{}\n{}",
                                             self.sam,
                                             self.date.format(DATE_TIME_FMT),
                                             self.scope(),
                                             previous_signature,
                                             try!(utils::hashed_data(None)),
                                             hashed_chunk);
                debug!("StringToSign\n{}", string_to_sign);
                Ok(try!(self.sign_string(&string_to_sign)))
            }
            _ => Err(AWSAuthError::ModeError),
        }
    }

    /// Generate the chunk body for a given chunk.
    pub fn chunk_body(&self, chunk_signature: &str, chunk: &[u8]) -> Result<Vec<u8>, AWSAuthError> {
        let hex = format!("{:x}", chunk.len());
        let capacity = hex.len() + 85 + chunk.len();
        let mut buf = Vec::with_capacity(capacity);
        buf.extend(hex.as_bytes());
        buf.extend_from_slice(b";chunk-signature=");
        buf.extend(chunk_signature.as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(chunk);
        buf.extend_from_slice(b"\r\n");
        Ok(buf)
    }

    /// Generate the value for the 'Content-Length' header when using chunked mode.
    pub fn content_length(&self, payload_size: u32) -> Result<usize, AWSAuthError> {
        let mut remaining = payload_size;
        let mut length = 0;

        loop {
            if remaining < self.chunk_size {
                length += remaining as usize;
                length += format!("{:x}", remaining).len();
            } else {
                length += self.chunk_size as usize;
                length += format!("{:x}", self.chunk_size).len();
            }
            // Len(";chunk-signature=") (17) + Signature Length (64) + 2*/r/n (4)
            length += 85;

            if remaining == 0 {
                break;
            }
            remaining = match remaining.checked_sub(self.chunk_size) {
                Some(r) => r,
                None => 0,
            };
        }

        Ok(length)
    }
}

/// Singing Algorithm Moniker
pub enum SAM {
    /// AWS Signature Version 4, HMAC-SHA256
    AWS4HMACSHA256,
    /// AWS Signature Version 4, HMAC-SHA256 Payload (used for chunked mode).
    AWS4HMACSHA256PAYLOAD,
}

impl Default for SAM {
    fn default() -> SAM {
        SAM::AWS4HMACSHA256
    }
}

impl<'a> Into<String> for &'a SAM {
    fn into(self) -> String {
        match *self {
            SAM::AWS4HMACSHA256 => "AWS4-HMAC-SHA256".to_owned(),
            SAM::AWS4HMACSHA256PAYLOAD => "AWS4-HMAC-SHA256-PAYLOAD".to_owned(),
        }
    }
}

impl fmt::Display for SAM {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let display: String = self.into();
        write!(f, "{}", display)
    }
}

#[derive(Clone,Copy,Debug)]
/// See [RFC7231](https://tools.ietf.org/html/rfc7231#section-4)
pub enum HttpRequestMethod {
    /// [GET] (https://tools.ietf.org/html/rfc7231#section-4.3.1)
    GET,
    /// [HEAD] (https://tools.ietf.org/html/rfc7231#section-4.3.2)
    HEAD,
    /// [POST] (https://tools.ietf.org/html/rfc7231#section-4.3.3)
    POST,
    /// [PUT] (https://tools.ietf.org/html/rfc7231#section-4.3.4)
    PUT,
    /// [DELETE] (https://tools.ietf.org/html/rfc7231#section-4.3.5)
    DELETE,
    /// [CONNECT] (https://tools.ietf.org/html/rfc7231#section-4.3.6)
    CONNECT,
    /// [OPTIONS] (https://tools.ietf.org/html/rfc7231#section-4.3.7)
    OPTIONS,
    /// [TRACE] (https://tools.ietf.org/html/rfc7231#section-4.3.8)
    TRACE,
}

#[cfg_attr(feature = "clippy", allow(use_debug))]
impl fmt::Display for HttpRequestMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
