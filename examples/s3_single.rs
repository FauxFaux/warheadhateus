use chrono::offset::TimeZone;
use chrono::Utc;
use std::io::{self, Write};
use warheadhateus::{hashed_data, AWSAuth, AWSAuthError, HttpRequestMethod, Region, Service};

const EX_STDOUT: &'static str = "Unable to write to stdout!";
const ACCESS_KEY_ID: &'static str = "AKIAIOSFODNN7EXAMPLE";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
const HOST: &'static str = "examplebucket.s3.amazonaws.com";
const SCOPE_DATE: &'static str = "20130524T000000Z";
const SECRET_ACCESS_KEY: &'static str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const URL_1: &'static str = "https://examplebucket.s3.amazonaws.com/test.txt";
const AWS_TEST_1: &'static str = "AWS4-HMAC-SHA256 \
                                  Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_r\
                                  equest,SignedHeaders=host;range;x-amz-content-sha256;\
                                  x-amz-date,\
                                  Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd9\
                                  1039c6036bdb41";
const AWS_TEST_2: &'static str = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                                  &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2F\
                                  s3%2Faws4_request\
                                  &X-Amz-Date=20130524T000000Z\
                                  &X-Amz-SignedHeaders=host%3Brange%3Bx-amz-content-sha256%3B\
                                  x-amz-date\
                                  &X-Amz-Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48d\
                                  d91039c6036bdb41";

fn run() -> Result<(), AWSAuthError> {
    let mut auth = r#try!(AWSAuth::new(URL_1));
    let payload_hash = r#try!(hashed_data(None));
    let scope_date = r#try!(Utc.datetime_from_str(SCOPE_DATE, DATE_TIME_FMT));
    auth.set_request_type(HttpRequestMethod::GET)
        .set_payload_hash(&payload_hash)
        .set_date(scope_date)
        .set_service(Service::S3)
        .set_access_key_id(ACCESS_KEY_ID)
        .set_secret_access_key(SECRET_ACCESS_KEY)
        .set_region(Region::UsEast1)
        .add_header("HOST", HOST)
        .add_header("x-amz-content-sha256", &payload_hash)
        .add_header("x-amz-date", SCOPE_DATE)
        .add_header("Range", "bytes=0-9");

    let ah = r#try!(auth.auth_header());
    writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "Authorization: ", ah).expect(EX_STDOUT);
    assert!(ah == AWS_TEST_1);

    let qs = r#try!(auth.query_string());
    writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "Query String: ", qs).expect(EX_STDOUT);
    assert!(qs == AWS_TEST_2);

    Ok(())
}

fn main() {
    env_logger::init().expect("Failed to initialize logging!");
    run().expect("Failed to chunk request!");
}
