// Copyright (c) 2016 warheadhateus developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! AWS Signature Generation (AWS Signature Version 4 & Version 2)
//!
//! ## AWS Signature Version 4
//! The [Signature Version 4][1] signing process describes how to add authentication information to
//! AWS requests.  This library provides the ability to generate the `auth_header` version or the
//! `query_string` version of v4 signatures.
//!
//! ## AWS Signature Version 2
//! Some AWS Query APIs don't support v4 signatures yet.  You should use [Signature Version 2][2] in
//! these cases.  When configured to use version 2, the library provides the ability to generate the
//! `signature` for v2.
//!
//! ## Examples
//! ### v4 Authorization Header
//! The String generated here would be sent with the actual request in the `Authorization` header.
//!
//! ```
//! # extern crate chrono;
//! # extern crate env_logger;
//! # extern crate warheadhateus;
//!
//! # fn main() {
//! use chrono::Utc;
//! use chrono::offset::TimeZone;
//! use std::io::{self, Write};
//! use warheadhateus::{AWSAuth, AWSAuthError, hashed_data, HttpRequestMethod, Region, Service};
//!
//! const EX_STDOUT: &'static str = "Unable to write to stdout!";
//! const ACCESS_KEY_ID: &'static str = "AKIAIOSFODNN7EXAMPLE";
//! const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
//! const HOST: &'static str = "examplebucket.s3.amazonaws.com";
//! const SCOPE_DATE: &'static str = "20130524T000000Z";
//! const SECRET_ACCESS_KEY: &'static str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
//! const URL_1: &'static str = "https://examplebucket.s3.amazonaws.com/test.txt";
//! const AWS_TEST_1: &'static str = "AWS4-HMAC-SHA256 \
//!             Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,\
//!             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,\
//!             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
//!
//! fn run() -> Result<(), AWSAuthError> {
//!     let mut auth = AWSAuth::new(URL_1)?;
//!     let payload_hash = hashed_data(None)?;
//!     let scope_date = Utc.datetime_from_str(SCOPE_DATE, DATE_TIME_FMT)?;
//!     auth.set_request_type(HttpRequestMethod::GET);
//!     auth.set_payload_hash(&payload_hash);
//!     auth.set_date(scope_date);
//!     auth.set_service(Service::S3);
//!     auth.set_access_key_id(ACCESS_KEY_ID);
//!     auth.set_secret_access_key(SECRET_ACCESS_KEY);
//!     auth.set_region(Region::UsEast1);
//!     auth.add_header("HOST", HOST);
//!     auth.add_header("x-amz-content-sha256", &payload_hash);
//!     auth.add_header("x-amz-date", SCOPE_DATE);
//!     auth.add_header("Range", "bytes=0-9");
//!
//!     let ah = auth.auth_header()?;
//!     assert_eq!(ah, AWS_TEST_1);
//!     writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "Authorization: ", ah).expect(EX_STDOUT);
//!
//!     Ok(())
//! }
//!
//! env_logger::init().expect("Failed to initialize logging!");
//! run().expect("Failed to generate Authorization header!");
//! # }
//! ```
//!
//! ### v4 Query String
//!
//! ### v2 Signature
//!
//! ## Special Modes
//! AWS S3 Chunked (or Streaming) mode is handled a bit differently than a normal signing request.
//! See [Streaming SIG4][3] for Amazon docs or `s3_multi.rs` in the examples directory, but the gist
//! is:
//!
//! 1. Calculate the total content length based on the payload size. Use the `content_length`
//! function to get this value.
//! 2. Create a seed signature from the headers.  Use the `seed_signature` function after setting
//! the `seed` flag to true.
//! 3. For each chunk, generate a chunk signature.  Use the `chunk_signature` function to do this.
//! In the case of the first chunk, use the `seed_signature` as the `previous_signature` value.
//! 4. Generate the chunk body after the signature. This is what will be streamed.  Use the
//! `chunk_body` function to do this.
//! 5. After the last chunk with data is created, generate a chunk signature and chunk body for a
//! 0-byte payload.  This will be the last chunk streamed, and signals the end of your payload.
//!
//! [1]: http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
//! [2]: http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
//! [3]: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
//!
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", deny(clippy, clippy_pedantic))]
#![deny(missing_docs)]
#[macro_use]
extern crate log;

mod error;
mod types;
mod utils;

// Re-exports
pub use crate::error::{AWSAuthError, ParseRegionError, ParseServiceError};
pub use crate::types::{Mode, Region, Service, SigningVersion};
pub use crate::utils::{hashed_data, signed_data};

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::fmt;
use std::sync::Once;
use urlparse::{quote, urlparse};

const AWS4_REQUEST: &'static str = "aws4_request";
const DATE_FMT: &'static str = "%Y%m%d";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";

static START: Once = Once::new();

fn init() {}

/// Amazon Web Service Authorization Header struct
pub struct AWSAuth {
    access_key_id: String,
    chunk_size: usize,
    date: DateTime<Utc>,
    headers: HashMap<String, String>,
    host: String,
    mode: Mode,
    path: String,
    payload_hash: String,
    query: String,
    region: Region,
    req_type: HttpRequestMethod,
    sam: SAM,
    secret_access_key: String,
    seed: bool,
    service: Service,
    version: SigningVersion,
}

impl Default for AWSAuth {
    fn default() -> AWSAuth {
        AWSAuth {
            access_key_id: String::new(),
            chunk_size: 0,
            date: Utc::now(),
            headers: HashMap::new(),
            host: String::new(),
            mode: Mode::Normal,
            path: String::new(),
            payload_hash: String::new(),
            query: String::new(),
            region: Region::UsEast1,
            req_type: HttpRequestMethod::GET,
            sam: SAM::AWS4HMACSHA256,
            secret_access_key: String::new(),
            seed: false,
            service: Service::S3,
            version: SigningVersion::Four,
        }
    }
}

/// AWS Authentication Header Generation Result.
pub type AWSAuthResult = Result<String, AWSAuthError>;

impl AWSAuth {
    /// Create a new AWSAuth struct.
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(auth) => {
    ///         // Do fun stuff with the auth struct
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn new(url: &str) -> Result<AWSAuth, AWSAuthError> {
        let parsed = urlparse(url);
        let mut auth = AWSAuth {
            path: parsed.path,
            ..Default::default()
        };

        if let Some(h) = parsed.hostname {
            auth.host = h;
        }

        if let Some(q) = parsed.query {
            auth.query = q;
        }

        Ok(auth)
    }

    /// Add a header key/value pair.
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.add_header("Host", "s3.amazonaws.com");
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn add_header(&mut self, key: &str, val: &str) -> &mut AWSAuth {
        self.headers.insert(key.to_owned(), val.to_owned());
        self
    }

    /// Set the AWS Access Key ID (this is supplied by Amazon).
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_access_key_id("AKIAIOSFODNN7EXAMPLE");
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_access_key_id(&mut self, access_key_id: &str) -> &mut AWSAuth {
        self.access_key_id = access_key_id.to_owned();
        self
    }

    /// Set the chunk size.
    ///
    /// * Note this is only used when ```Mode::Chunked``` is selected.
    /// * Chunk size must be at least 8 KB. We recommend a chunk size of a least 64 KB for better
    /// performance. This chunk size applies to all CHUNK_SIG_3 except the last one. The last chunk
    /// you send can be smaller than 8 KB. If your payload is small and can fit in one chunk, then
    /// it can be smaller than the 8 KB.
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::{AWSAuth, Mode};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_mode(Mode::Chunked);
    ///         auth.set_chunk_size(65536);
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_chunk_size(&mut self, chunk_size: usize) -> &mut AWSAuth {
        self.chunk_size = chunk_size;
        self
    }

    /// Set the scope date for the auth request.
    ///
    /// * Note that this date doesn't have to match the *x-amz-date* or *date* header values.
    /// * Requests are valid for 7 days from the given scope date.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate chrono;
    /// # extern crate warheadhateus;
    /// #
    /// # fn main() {
    /// use chrono::Utc;
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_date(Utc::now());
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// # }
    /// ```
    pub fn set_date(&mut self, date: DateTime<Utc>) -> &mut AWSAuth {
        self.date = date;
        self
    }

    /// Set the mode of operation.
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::{AWSAuth, Mode};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_mode(Mode::Chunked);
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_mode(&mut self, mode: Mode) -> &mut AWSAuth {
        self.mode = mode;
        self
    }

    /// Set the payload hash.
    ///
    /// This should be the SHA-256 hash of any request payload, or the hash
    /// of the empty string ("") if there is no payload.  There is a ```hashed_data``` function in
    /// this library that will do this for you, but you are free to use any SHA-256 implementation.
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::{AWSAuth, hashed_data};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         if let Ok(hd) = hashed_data(Some(b"This is a test")) {
    ///             auth.set_payload_hash(&hd);
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_payload_hash(&mut self, payload_hash: &str) -> &mut AWSAuth {
        self.payload_hash = payload_hash.to_owned();
        self
    }

    /// Set the region the request is scoped for.
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::{AWSAuth, Region};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_region(Region::UsWest1);
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_region(&mut self, region: Region) -> &mut AWSAuth {
        self.region = region;
        self
    }

    /// Set the request verb (i.e. GET, PUT, POST, DELETE)
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::{AWSAuth, HttpRequestMethod};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_request_type(HttpRequestMethod::PUT);
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_request_type(&mut self, verb: HttpRequestMethod) -> &mut AWSAuth {
        self.req_type = verb;
        self
    }

    /// Set the AWS Secret Access Key (this is supplied by Amazon).
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_secret_access_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_secret_access_key(&mut self, secret_access_key: &str) -> &mut AWSAuth {
        self.secret_access_key = secret_access_key.to_owned();
        self
    }

    /// Set the Signing Algorithm Moniker (SAM).
    ///
    /// * Note that the default is usually acceptable here, only chunked requests need to change it.
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::{AWSAuth, SAM};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_sam(SAM::AWS4HMACSHA256PAYLOAD);
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_sam(&mut self, sam: SAM) -> &mut AWSAuth {
        self.sam = sam;
        self
    }

    /// Set the seed flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_seed(true);
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_seed(&mut self, seed: bool) -> &mut AWSAuth {
        self.seed = seed;
        self
    }

    /// Set the AWS services this request should be constructed for (i.e. S3)
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::{AWSAuth, Service};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_service(Service::S3);
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_service(&mut self, service: Service) -> &mut AWSAuth {
        self.service = service;
        self
    }

    /// Set the Signing Version (2 or 4)
    ///
    /// # Examples
    ///
    /// ```
    /// use warheadhateus::{AWSAuth, SigningVersion};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_version(SigningVersion::Two);
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn set_version(&mut self, version: SigningVersion) -> &mut AWSAuth {
        self.version = version;
        self
    }

    fn scope(&self) -> String {
        let date_fmt = self.date.format(DATE_FMT).to_string();
        format!(
            "{}/{}/{}/{}",
            date_fmt, self.region, self.service, AWS4_REQUEST
        )
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

        let trimmed = buf.trim_end_matches(';');
        trimmed.to_owned()
    }

    fn canonical_uri(&self) -> AWSAuthResult {
        if self.path.is_empty() {
            Ok("/".to_owned())
        } else {
            Ok(r#try!(quote(&self.path, b"/")))
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
                let key = r#try!(quote(kvs[0], b""));
                if kvs.len() == 1 {
                    params.insert(key, "".to_owned());
                } else {
                    let value = r#try!(quote(kvs[1], b""));
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
        let date_key = r#try!(utils::signed_data(date.as_bytes(), key.as_bytes()));
        let date_region_key = r#try!(utils::signed_data(region.as_bytes(), &date_key));
        let date_region_service_key =
            r#try!(utils::signed_data(service.as_bytes(), &date_region_key));
        let signing_key = r#try!(utils::signed_data(aws4, &date_region_service_key));
        let signature = r#try!(utils::signed_data(string_to_sign.as_bytes(), &signing_key));
        debug!("Signature\n{}", hex::encode(&signature));
        Ok(hex::encode(signature))
    }

    fn v2(&self) -> AWSAuthResult {
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            self.req_type,
            self.host,
            r#try!(self.canonical_uri()),
            r#try!(self.canonical_query_string())
        );
        debug!("V2: StringToSign\n{}", string_to_sign);
        let key = &self.secret_access_key;
        let signature = r#try!(utils::signed_data(
            string_to_sign.as_bytes(),
            key.as_bytes()
        ));

        let encoded_sig = quote(base64::encode(&signature), b"")?;
        debug!("V2: Signature\n{}", encoded_sig);

        Ok(encoded_sig)
    }

    fn v4(&self) -> AWSAuthResult {
        let hash = if self.seed {
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        } else {
            &self.payload_hash[..]
        };
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.req_type,
            r#try!(self.canonical_uri()),
            r#try!(self.canonical_query_string()),
            self.canonical_headers(),
            self.signed_headers(),
            hash
        );
        debug!("V4: CanonicalRequest\n{}", canonical_request);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            self.sam,
            self.date.format(DATE_TIME_FMT),
            self.scope(),
            r#try!(utils::hashed_data(Some(canonical_request.as_bytes())))
        );
        debug!("V4: StringToSign\n{}", string_to_sign);

        self.sign_string(&string_to_sign)
    }

    /// Generate the signature.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Write};
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         if let Ok(sig) = auth.signature() {
    ///             writeln!(io::stdout(), "{}", sig).expect("Unable to write to stdout!");
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn signature(&self) -> AWSAuthResult {
        match self.version {
            SigningVersion::Two => self.v2(),
            SigningVersion::Four => self.v4(),
        }
    }

    /// Create the AWS Authorization HTTP header.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Write};
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         if let Ok(ah) = auth.auth_header() {
    ///             writeln!(io::stdout(), "{}", ah).expect("Unable to write to stdout!");
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn auth_header(&self) -> AWSAuthResult {
        init();
        let signature = match self.mode {
            Mode::Normal => r#try!(self.signature()),
            Mode::Chunked => r#try!(self.seed_signature()),
        };
        Ok(format!(
            "{} Credential={},SignedHeaders={},Signature={}",
            self.sam,
            self.credential(),
            self.signed_headers(),
            signature
        ))
    }

    /// Create the AWS Authorization Query String.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Write};
    /// use warheadhateus::AWSAuth;
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         if let Ok(qs) = auth.query_string() {
    ///             writeln!(io::stdout(), "{}", qs).expect("Unable to write to stdout!");
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn query_string(&self) -> AWSAuthResult {
        init();
        match (&self.version, &self.mode) {
            (&SigningVersion::Four, &Mode::Normal) => {
                let fmtdate = self.date.format(DATE_TIME_FMT).to_string();
                Ok(format!(
                    "X-Amz-Algorithm={}\
                           &X-Amz-Credential={}\
                           &X-Amz-Date={}\
                           &X-Amz-SignedHeaders={}\
                           &X-Amz-Signature={}",
                    self.sam,
                    r#try!(quote(self.credential(), b"")),
                    fmtdate,
                    r#try!(quote(self.signed_headers(), b"")),
                    r#try!(self.signature())
                ))
            }
            _ => Err(AWSAuthError::ModeError),
        }
    }

    /// Generate the seed signature for chunked mode.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Write};
    /// use warheadhateus::{AWSAuth, Mode};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_mode(Mode::Chunked);
    ///         auth.set_seed(true);
    ///         auth.set_chunk_size(65536);
    ///         if let Ok(ss) = auth.seed_signature() {
    ///             writeln!(io::stdout(), "{}", ss).expect("Unable to write to stdout!");
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn seed_signature(&self) -> AWSAuthResult {
        match (self.seed, &self.mode) {
            (true, &Mode::Chunked) => Ok(r#try!(self.signature())),
            _ => Err(AWSAuthError::ModeError),
        }
    }

    /// Generate the chunk signature for a given chunk.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Write};
    /// use warheadhateus::{AWSAuth, Mode};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_mode(Mode::Chunked);
    ///         auth.set_chunk_size(65536);
    ///         if let Ok(ss) = auth.seed_signature() {
    ///             if let Ok(cs) = auth.chunk_signature(&ss, &[0; 100]) {
    ///                 writeln!(io::stdout(), "{}", cs).expect("Unable to write to stdout!");
    ///             }
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn chunk_signature(&self, previous_signature: &str, chunk: &[u8]) -> AWSAuthResult {
        match self.mode {
            Mode::Chunked => {
                let hashed_chunk = if chunk.len() == 0 {
                    r#try!(utils::hashed_data(None))
                } else {
                    r#try!(utils::hashed_data(Some(chunk)))
                };
                let string_to_sign = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}",
                    self.sam,
                    self.date.format(DATE_TIME_FMT),
                    self.scope(),
                    previous_signature,
                    r#try!(utils::hashed_data(None)),
                    hashed_chunk
                );
                debug!("StringToSign\n{}", string_to_sign);
                Ok(r#try!(self.sign_string(&string_to_sign)))
            }
            _ => Err(AWSAuthError::ModeError),
        }
    }

    /// Generate the chunk body for a given chunk.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Write};
    /// use warheadhateus::{AWSAuth, Mode};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_mode(Mode::Chunked);
    ///         auth.set_chunk_size(65536);
    ///         if let Ok(ss) = auth.seed_signature() {
    ///             let chunk = [0; 100];
    ///             if let Ok(cs) = auth.chunk_signature(&ss, &chunk) {
    ///                 if let Ok(cb) = auth.chunk_body(&cs, &chunk) {
    ///                     let l = cb.len();
    ///                     writeln!(io::stdout(), "{}", l).expect("Unable to write to stdout!");
    ///                 }
    ///             }
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn chunk_body(&self, chunk_signature: &str, chunk: &[u8]) -> Result<Vec<u8>, AWSAuthError> {
        match self.mode {
            Mode::Chunked => {
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
            _ => Err(AWSAuthError::ModeError),
        }
    }

    /// Generate the value for the 'Content-Length' header when using chunked mode.
    ///
    /// This function can be used for the following requirement from Amazon for pre-computing the
    /// `Content-Length` header.
    ///
    /// * When transferring data in a series of chunks, you must use the `Content-Length` HTTP
    /// header to explicitly specify the total content length (object length in bytes plus metadata
    /// in each chunk). This will require you to pre-compute the total length of the payload
    /// including the metadata you will send in each chunk before starting your request. The
    /// `x-amz-decoded-content-length` header will contain the size of the object length in bytes.
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Write};
    /// use warheadhateus::{AWSAuth, Mode};
    ///
    /// match AWSAuth::new("https://s3.amazonaws.com/examplebucket/test.txt") {
    ///     Ok(mut auth) => {
    ///         auth.set_mode(Mode::Chunked);
    ///         auth.set_chunk_size(65536);
    ///         if let Ok(cl) = auth.content_length(100000) {
    ///             writeln!(io::stdout(), "{}", cl).expect("Unable to write to stdout!");
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // Failure
    ///     }
    /// }
    /// ```
    pub fn content_length(&self, payload_size: usize) -> Result<usize, AWSAuthError> {
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

#[derive(Clone, Copy, Debug)]
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
