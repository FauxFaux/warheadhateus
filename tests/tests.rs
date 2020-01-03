extern crate chrono;
extern crate warheadhateus;

mod s3;
mod v2;

use std::error::Error;
use std::io::{self, Write};

const ACCESS_KEY_ID: &'static str = "AKIAIOSFODNN7EXAMPLE";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
const HOST: &'static str = "examplebucket.s3.amazonaws.com";
const SCOPE_DATE: &'static str = "20130524T000000Z";
const SECRET_ACCESS_KEY: &'static str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn fail<T>(e: T) -> !
where
    T: Error,
{
    writeln!(io::stderr(), "{}", e).expect("Unable to write to stderr!");
    panic!();
}
