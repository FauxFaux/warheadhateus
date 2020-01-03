use crate::{fail, ACCESS_KEY_ID, SECRET_ACCESS_KEY};
use warheadhateus::{AWSAuth, HttpRequestMethod, SigningVersion};

const SIG_1: &'static str = "i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf%2FMj6vPxyYIs%3D";

#[test]
fn test_v2_signature() {
    let url = format!(
        "https://elasticmapreduce.amazonaws.com\
                      ?Action=DescribeJobFlows\
                      &Version=2009-03-31\
                      &AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE\
                      &SignatureVersion=2\
                      &SignatureMethod=HmacSHA256\
                      &Timestamp=2011-10-03T15:19:30"
    );
    let mut auth = AWSAuth::new(&url).unwrap_or_else(|e| fail(e));
    auth.set_version(SigningVersion::Two);
    auth.set_request_type(HttpRequestMethod::GET);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);

    let sig = auth.signature().unwrap_or_else(|e| fail(e));
    assert!(sig == SIG_1);
}
