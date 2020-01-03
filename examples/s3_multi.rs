use chrono::offset::TimeZone;
use chrono::Utc;
use std::fmt;
use std::io::{self, Write};
use warheadhateus::{AWSAuth, AWSAuthError, HttpRequestMethod, Mode, Region, Service, SAM};

const EX_STDOUT: &'static str = "Unable to write to stdout!";
const ACCESS_KEY_ID: &'static str = "AKIAIOSFODNN7EXAMPLE";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
const HOST: &'static str = "s3.amazonaws.com";
const SCOPE_DATE: &'static str = "20130524T000000Z";
const SECRET_ACCESS_KEY: &'static str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

#[derive(Debug, Default)]
struct Line {
    heading: String,
    val: String,
}

#[derive(Default)]
struct OutCache {
    lines: Vec<Line>,
}

impl OutCache {
    pub fn hl<T>(&mut self, heading: &str, val: T) -> &mut OutCache
    where
        T: fmt::Display,
    {
        let mut h = String::from(heading);
        h.push(':');
        self.lines.push(Line {
            heading: h,
            val: format!("{}", val),
        });
        self
    }

    pub fn flush(self) {
        // Calculate max here
        let tmp = &self.lines;
        let mut max = 0;
        if let Some(x) = tmp.iter().max_by_key(|x| x.heading.len()) {
            max = x.heading.len() + 1;
        };

        for line in &self.lines {
            // Bump up the heading string to max.
            let mut h = String::from(&line.heading[..]);
            let mut len = h.len();

            loop {
                if len == max {
                    break;
                }
                h.push(' ');
                len = h.len();
            }

            writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", h, line.val).expect(EX_STDOUT);
        }
    }
}

fn run() -> Result<(), AWSAuthError> {
    let chunk_size = 65536;
    let mut auth = AWSAuth::new("https://s3.amazonaws.com/examplebucket/chunkObject.txt")?;
    let scope_date = Utc.datetime_from_str(SCOPE_DATE, DATE_TIME_FMT)?;
    auth.set_mode(Mode::Chunked);
    auth.set_request_type(HttpRequestMethod::PUT);
    auth.set_date(scope_date);
    auth.set_service(Service::S3);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.set_chunk_size(chunk_size);
    auth.set_seed(true);
    auth.add_header("Host", HOST);
    auth.add_header("Content-Encoding", "aws-chunked");
    auth.add_header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
    auth.add_header("x-amz-storage-class", "REDUCED_REDUNDANCY");
    auth.add_header("x-amz-date", SCOPE_DATE);
    auth.add_header("x-amz-decoded-content-length", "66560");
    auth.add_header("Content-Length", "66824");

    let payload = vec![97; 66560];
    let ah = auth.auth_header()?;
    let mut oc: OutCache = Default::default();
    oc.hl("Authorization", ah);
    let cl = auth.content_length(payload.len())?;
    oc.hl("Content-Length", cl);
    let ss = auth.seed_signature()?;
    oc.hl("Seed Signature", &ss);
    auth.set_sam(SAM::AWS4HMACSHA256PAYLOAD);
    auth.set_seed(false);

    // Previous Signature, initialized to seed signature.
    let mut ps = ss;
    // Total Length
    let mut tl = 0;
    let mut count = 1;

    for (i, chunk) in payload.chunks(chunk_size).enumerate() {
        let cs = auth.chunk_signature(&ps, &chunk)?;
        oc.hl(&format!("Chunk {} Signature", i + 1), &cs);
        let cb = auth.chunk_body(&cs, &chunk)?;
        tl += cb.len();
        oc.hl(&format!("Chunk {} Body Length", i + 1), &cb.len());
        if let Some(p) = cb.len().checked_sub(chunk.len()) {
            // Account for 2 \r\n's
            let np = p - 4;
            oc.hl(
                &format!("Chunk {} Prefix", count),
                String::from_utf8_lossy(&cb[..np]),
            );
        }
        count += 1;
        ps = cs;
    }

    // Final 0-byte payload chunk
    let cs = auth.chunk_signature(&ps, &[])?;
    oc.hl(&format!("Chunk {} Signature", count), &cs);
    let cb = auth.chunk_body(&cs, &[])?;
    tl += cb.len();
    oc.hl(&format!("Chunk {} Body Length", count), &cb.len());
    if let Some(p) = cb.len().checked_sub(0) {
        // Account for 2 \r\n's
        let np = p - 4;
        oc.hl(
            &format!("Chunk {} Prefix", count),
            String::from_utf8_lossy(&cb[..np]),
        );
    }
    oc.hl("Total Payload Length", tl);
    oc.hl("CL = TPL", cl == tl);

    oc.flush();
    Ok(())
}

fn main() {
    env_logger::init().expect("Failed to initialize logging!");
    run().expect("Failed to chunk request!");
}
