use chrono::offset::TimeZone;
use chrono::UTC;
use warheadhateus::{hashed_data, AWSAuth, HttpRequestMethod, Region, Service};
use {fail, ACCESS_KEY_ID, DATE_TIME_FMT, HOST, SCOPE_DATE, SECRET_ACCESS_KEY};

const URL_1: &'static str = "https://examplebucket.s3.amazonaws.com/test.txt";
const URL_2: &'static str = "https://examplebucket.s3.amazonaws.com/test$file.text";
const URL_3: &'static str = "https://examplebucket.s3.amazonaws.com/?lifecycle";
const URL_4: &'static str = "https://examplebucket.s3.amazonaws.com?max-keys=2&prefix=J";
const AWS_TEST_1: &'static str = "AWS4-HMAC-SHA256 \
                                  Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_r\
                                  equest,SignedHeaders=host;range;x-amz-content-sha256;\
                                  x-amz-date,\
                                  Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd9\
                                  1039c6036bdb41";
const AWS_TEST_2: &'static str = "AWS4-HMAC-SHA256 \
                                  Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_r\
                                  equest,SignedHeaders=date;host;x-amz-content-sha256;\
                                  x-amz-date;x-amz-storage-class,\
                                  Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5\
                                  971af0ece108bd";
const AWS_TEST_3: &'static str = "AWS4-HMAC-SHA256 \
                                  Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_r\
                                  equest,SignedHeaders=host;x-amz-content-sha256;x-amz-date,\
                                  Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a\
                                  200a0136783543";
const AWS_TEST_4: &'static str = "AWS4-HMAC-SHA256 \
                                  Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_r\
                                  equest,SignedHeaders=host;x-amz-content-sha256;x-amz-date,\
                                  Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670e\
                                  d5711ef69dc6f7";

#[test]
fn test_get_object() {
    let mut auth = AWSAuth::new(URL_1).unwrap_or_else(|e| fail(e));
    let payload_hash = hashed_data(None).unwrap_or_else(|e| fail(e));
    let scope_date = UTC
        .datetime_from_str(SCOPE_DATE, DATE_TIME_FMT)
        .unwrap_or_else(|e| fail(e));
    auth.set_request_type(HttpRequestMethod::GET);
    auth.set_payload_hash(&payload_hash);
    auth.set_date(scope_date);
    auth.set_service(Service::S3);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.add_header("HOST", HOST);
    auth.add_header("x-amz-content-sha256", &payload_hash);
    auth.add_header("x-amz-date", SCOPE_DATE);
    auth.add_header("Range", "bytes=0-9");

    let ah = auth.auth_header().unwrap_or_else(|e| fail(e));
    assert!(ah == AWS_TEST_1);
}

#[test]
fn test_put_object() {
    let mut auth = AWSAuth::new(URL_2).unwrap_or_else(|e| fail(e));
    let payload_hash = hashed_data(Some(b"Welcome to Amazon S3.")).unwrap_or_else(|e| fail(e));
    let scope_date = UTC
        .datetime_from_str(SCOPE_DATE, DATE_TIME_FMT)
        .unwrap_or_else(|e| fail(e));
    auth.set_request_type(HttpRequestMethod::PUT);
    auth.set_payload_hash(&payload_hash);
    auth.set_date(scope_date);
    auth.set_service(Service::S3);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.add_header("HOST", HOST);
    auth.add_header("date", "Fri, 24 May 2013 00:00:00 GMT");
    auth.add_header("x-amz-content-sha256", &payload_hash);
    auth.add_header("x-amz-storage-class", "REDUCED_REDUNDANCY");
    auth.add_header("x-amz-date", SCOPE_DATE);

    let ah = auth.auth_header().unwrap_or_else(|e| fail(e));
    assert!(ah == AWS_TEST_2);
}

#[test]
fn test_get_bucket_lifecycle() {
    let mut auth = AWSAuth::new(URL_3).unwrap_or_else(|e| fail(e));
    let payload_hash = hashed_data(None).unwrap_or_else(|e| fail(e));
    let scope_date = UTC
        .datetime_from_str(SCOPE_DATE, DATE_TIME_FMT)
        .unwrap_or_else(|e| fail(e));
    auth.set_request_type(HttpRequestMethod::GET);
    auth.set_payload_hash(&payload_hash);
    auth.set_date(scope_date);
    auth.set_service(Service::S3);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.add_header("HOST", HOST);
    auth.add_header("x-amz-content-sha256", &payload_hash);
    auth.add_header("x-amz-date", SCOPE_DATE);

    let ah = auth.auth_header().unwrap_or_else(|e| fail(e));
    assert!(ah == AWS_TEST_3);
}

#[test]
fn test_get_bucket_list_objects() {
    let mut auth = AWSAuth::new(URL_4).unwrap_or_else(|e| fail(e));
    let payload_hash = hashed_data(None).unwrap_or_else(|e| fail(e));
    let scope_date = UTC
        .datetime_from_str(SCOPE_DATE, DATE_TIME_FMT)
        .unwrap_or_else(|e| fail(e));
    auth.set_request_type(HttpRequestMethod::GET);
    auth.set_payload_hash(&payload_hash);
    auth.set_date(scope_date);
    auth.set_service(Service::S3);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.add_header("HOST", HOST);
    auth.add_header("x-amz-content-sha256", &payload_hash);
    auth.add_header("x-amz-date", SCOPE_DATE);

    let ah = auth.auth_header().unwrap_or_else(|e| fail(e));
    assert!(ah == AWS_TEST_4);
}
