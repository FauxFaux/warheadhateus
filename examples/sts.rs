use chrono::UTC;
use clap::{App, Arg};
use regex::Regex;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use warheadhateus::{AWSAuth, AWSAuthError, HttpRequestMethod, SigningVersion};

const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
const EX_STDOUT: &'static str = "Unable to write to stdout!";

fn credentials() -> Result<(String, String), io::Error> {
    let mut ak = String::new();
    let mut sk = String::new();

    if let Some(hd) = env::home_dir() {
        let akre = Regex::new(r"^aws_access_key_id = (.*)").expect("Failed to compile regex!");
        let skre = Regex::new(r"^aws_secret_access_key = (.*)").expect("Failed to compile regex!");
        let creds = r#try!(File::open(hd.join(".aws").join("credentials")));
        let f = BufReader::new(creds);

        for line in f.lines() {
            if let Ok(l) = line {
                if let Some(caps) = akre.captures(&l) {
                    ak.push_str(caps.at(1).expect("Unable to capture!"));
                }

                if let Some(scaps) = skre.captures(&l) {
                    sk.push_str(scaps.at(1).expect("Unable to capture!"));
                }
            }
        }
    }

    Ok((ak, sk))
}

fn run(token: &str) -> Result<(), AWSAuthError> {
    let date = UTC::now();
    let fmtdate = date.format(DATE_TIME_FMT).to_string();
    if let Ok((access_key, secret_key)) = credentials() {
        let mut url = format!(
            "https://sts.amazonaws.com\
                          ?Action=GetSessionToken\
                          &Version=2011-06-15\
                          &DurationSeconds=3600\
                          &SerialNumber=arn:aws:iam::184438746295:mfa/jozias\
                          &TokenCode={}\
                          &AWSAccessKeyId={}\
                          &SignatureVersion=2\
                          &SignatureMethod=HmacSHA256\
                          &Timestamp={}",
            token, access_key, fmtdate
        );
        let mut auth = r#try!(AWSAuth::new(&url));
        auth.set_version(SigningVersion::Two);
        auth.set_request_type(HttpRequestMethod::GET);
        auth.set_access_key_id(&access_key);
        auth.set_secret_access_key(&secret_key);

        let sig = r#try!(auth.signature());
        url.push_str(&format!("&Signature={}", sig));
        writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "URL: ", url).expect(EX_STDOUT);
        Ok(())
    } else {
        Err(AWSAuthError::Other("Unable to open credentials!"))
    }
}

fn main() {
    env_logger::init().expect("Failed to initialize logging!");
    let matches = App::new("sts")
        .version("1.0")
        .author("Jason Ozias <jason.g.ozias@gmail.com>")
        .about("Run an AWS STS Request")
        .arg(
            Arg::with_name("token")
                .short("t")
                .long("token")
                .value_name("TOKEN")
                .help("Sets a token code from an authenticator")
                .takes_value(true),
        )
        .get_matches();
    let token = matches.value_of("token").unwrap_or("123456");
    run(token).expect("Failed to chunk request!");
}
