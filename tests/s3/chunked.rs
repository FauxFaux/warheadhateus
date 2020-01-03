use crate::{fail, ACCESS_KEY_ID, DATE_TIME_FMT, SCOPE_DATE, SECRET_ACCESS_KEY};
use chrono::offset::TimeZone;
use chrono::UTC;
use warheadhateus::{AWSAuth, AWSAuthError, HttpRequestMethod, Mode, Region, Service, SAM};

const HOST: &'static str = "s3.amazonaws.com";
const SEED_SIG: &'static str = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0\
                                a9";
const CHUNK_SIG_1: &'static str = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a2\
                                   88648";
const CHUNK_SIG_2: &'static str = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503e\
                                   f5497";
const CHUNK_SIG_3: &'static str = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d4\
                                   49df9";
const AWS_TEST_5: &'static str = "AWS4-HMAC-SHA256 \
                                 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_r\
                                 equest,SignedHeaders=content-encoding;content-length;host;\
                                 x-amz-content-sha256;x-amz-date;\
                                 x-amz-decoded-content-length;x-amz-storage-class,\
                                 Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea15\
                                 3f7db9fa80a0a9";

fn test_cl(
    auth: &mut AWSAuth,
    chunk_size: usize,
    payload_size: usize,
) -> Result<usize, AWSAuthError> {
    auth.set_chunk_size(chunk_size);
    Ok(r#try!(auth.content_length(payload_size)))
}

fn get_auth() -> Result<AWSAuth, AWSAuthError> {
    let mut auth = r#try!(AWSAuth::new(
        "https://s3.amazonaws.com/examplebucket/chunkObject.txt"
    ));
    let scope_date = r#try!(UTC.datetime_from_str(SCOPE_DATE, DATE_TIME_FMT));
    auth.set_mode(Mode::Chunked);
    auth.set_request_type(HttpRequestMethod::PUT);
    auth.set_date(scope_date);
    auth.set_service(Service::S3);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.set_chunk_size(65536);
    auth.add_header("HOST", HOST);
    auth.add_header("Content-Encoding", "aws-chunked");
    auth.add_header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
    auth.add_header("x-amz-storage-class", "REDUCED_REDUNDANCY");
    auth.add_header("x-amz-date", SCOPE_DATE);
    auth.add_header("x-amz-decoded-content-length", "66560");
    auth.add_header("Content-Length", "66824");
    Ok(auth)
}

#[test]
fn test_content_length() {
    let mut auth = AWSAuth::new("").unwrap_or_else(|e| fail(e));
    assert!(test_cl(&mut auth, 65536, 66560).expect("") == 66824);
    assert!(test_cl(&mut auth, 1024, 1024).expect("") == 1198);
    assert!(test_cl(&mut auth, 1024, 2048).expect("") == 2310);
}

#[test]
fn test_auth_header() {
    let mut auth = get_auth().unwrap_or_else(|e| fail(e));
    auth.set_seed(true);
    let ah = auth.auth_header().unwrap_or_else(|e| fail(e));
    assert!(ah == AWS_TEST_5);
}

#[test]
fn test_seed_signature() {
    let mut auth = get_auth().unwrap_or_else(|e| fail(e));
    auth.set_seed(true);
    let ss = auth.seed_signature().unwrap_or_else(|e| fail(e));
    assert!(ss == SEED_SIG);
}

#[test]
fn test_chunk_1() {
    let mut auth = get_auth().unwrap_or_else(|e| fail(e));
    auth.set_sam(SAM::AWS4HMACSHA256PAYLOAD);
    let many_a: Vec<u8> = vec![97; 65536];
    let sig = auth
        .chunk_signature(SEED_SIG, &many_a)
        .unwrap_or_else(|e| fail(e));
    assert!(sig == CHUNK_SIG_1);
    let b = auth.chunk_body(&sig, &many_a).unwrap_or_else(|e| fail(e));
    assert_eq!(b.len(), 65626);
}

#[test]
fn test_chunk_2() {
    let mut auth = get_auth().unwrap_or_else(|e| fail(e));
    auth.set_sam(SAM::AWS4HMACSHA256PAYLOAD);
    let less_a = vec![97; 1024];
    let sig = auth
        .chunk_signature(CHUNK_SIG_1, &less_a)
        .unwrap_or_else(|e| fail(e));
    assert!(sig == CHUNK_SIG_2);
    let b = auth.chunk_body(&sig, &less_a).unwrap_or_else(|e| fail(e));
    assert!(b.len() == 1112);
}

#[test]
fn test_chunk_3() {
    let mut auth = get_auth().unwrap_or_else(|e| fail(e));
    auth.set_sam(SAM::AWS4HMACSHA256PAYLOAD);
    let sig = auth
        .chunk_signature(CHUNK_SIG_2, &[])
        .unwrap_or_else(|e| fail(e));
    assert!(sig == CHUNK_SIG_3);
    let b = auth.chunk_body(&sig, &[]).unwrap_or_else(|e| fail(e));
    assert!(b.len() == 86);
}
