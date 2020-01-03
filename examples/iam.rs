use chrono::UTC;
use std::io::{self, Write};
use warheadhateus::{hashed_data, AWSAuth, AWSAuthError, HttpRequestMethod, Region, Service};

const EX_STDOUT: &'static str = "Unable to write to stdout!";
const ACCESS_KEY_ID: &'static str = "AKIAJLXUEQWQQ2DGABQA";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
const HOST: &'static str = "iam.amazonaws.com";
const SECRET_ACCESS_KEY: &'static str = "94lsPupTRZa9nTbDnoTYg4BO6+BF19jVZYbrepry";
const URL_1: &'static str = "https://iam.amazonaws.com/?Version=2010-05-08&Action=ListUsers";

fn run() -> Result<(), AWSAuthError> {
    let mut auth = r#try!(AWSAuth::new(URL_1));
    let payload_hash = r#try!(hashed_data(None));
    let date = UTC::now();
    let fmtdate = &date.format(DATE_TIME_FMT).to_string();
    auth.set_request_type(HttpRequestMethod::GET);
    auth.set_payload_hash(&payload_hash);
    auth.set_date(UTC::now());
    auth.set_service(Service::IAM);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.add_header("Host", HOST);
    auth.add_header("X-Amz-Date", &fmtdate);

    let ah = r#try!(auth.auth_header());
    writeln!(
        io::stdout(),
        "\x1b[32;1m{}\x1b[0m{}",
        "X-Amz-Date: ",
        fmtdate
    )
    .expect(EX_STDOUT);
    writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "Authorization: ", ah).expect(EX_STDOUT);

    Ok(())
}

fn main() {
    env_logger::init().expect("Failed to initialize logging!");
    run().expect("Failed to chunk request!");
}
