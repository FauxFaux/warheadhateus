extern crate env_logger;
extern crate warheadhateus;

use std::io::{self, Write};
use warheadhateus::{AWSAuth, AWSAuthError, HttpRequestMethod, SigningVersion};

const ACCESS_KEY_ID: &'static str = "AKIAIOSFODNN7EXAMPLE";
const EX_STDOUT: &'static str = "Unable to write to stdout!";
const SECRET_ACCESS_KEY: &'static str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn run() -> Result<(), AWSAuthError> {
    let url = format!(
        "https://elasticmapreduce.amazonaws.com\
                      ?Action=DescribeJobFlows\
                      &Version=2009-03-31\
                      &AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE\
                      &SignatureVersion=2\
                      &SignatureMethod=HmacSHA256\
                      &Timestamp=2011-10-03T15:19:30"
    );
    let mut auth = try!(AWSAuth::new(&url));
    auth.set_version(SigningVersion::Two);
    auth.set_request_type(HttpRequestMethod::GET);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);

    let sig = try!(auth.signature());
    writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "Signature: ", sig).expect(EX_STDOUT);

    Ok(())
}

fn main() {
    env_logger::init().expect("Failed to initialize logging!");
    run().expect("Failed to chunk request!");
}
