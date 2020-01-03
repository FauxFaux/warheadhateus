use crate::error::{ParseRegionError, ParseServiceError};
use std::fmt;
use std::str::FromStr;

/// Amazon S3 Mode of Operation
pub enum Mode {
    /// Use this mode when transferring a payload in one chunk.
    Normal,
    /// Use this mode when transferring a payload in multiple chunks.
    Chunked,
}

/// AWS Services
#[derive(Debug, PartialEq)]
pub enum Service {
    /// AWS DynamoDB (Managed NoSQL Database)
    DynamoDB,
    /// AWS EC2 (Virtual Servers in the Cloud)
    EC2,
    /// AWS Identity and Account Management
    IAM,
    /// AWS S3 (Scalable Storage in the Cloud)
    S3,
    /// AWS STS (Security Token Service)
    STS,
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let display: String = self.into();
        write!(f, "{}", display)
    }
}

impl FromStr for Service {
    type Err = ParseServiceError;

    fn from_str(s: &str) -> Result<Service, ParseServiceError> {
        match s {
            "dynamodb" => Ok(Service::DynamoDB),
            "ec2" => Ok(Service::EC2),
            "iam" => Ok(Service::IAM),
            "s3" => Ok(Service::S3),
            "sts" => Ok(Service::STS),
            _ => Err(ParseServiceError),
        }
    }
}

/// Translates region enum into AWS format.  EG: us-east-1
impl<'a> Into<String> for &'a Service {
    fn into(self) -> String {
        match *self {
            Service::DynamoDB => "dynamodb".to_owned(),
            Service::EC2 => "ec2".to_owned(),
            Service::IAM => "iam".to_owned(),
            Service::S3 => "s3".to_owned(),
            Service::STS => "sts".to_owned(),
        }
    }
}

/// Amazon AWS Signing Version
pub enum SigningVersion {
    /// Version 2 (Only use this is the API doesn't support 4 yet)
    Two,
    /// Version 4
    Four,
}

/// AWS Region
#[derive(Debug, PartialEq)]
pub enum Region {
    /// us-east-1
    UsEast1,
    ///
    UsWest1,
    ///
    UsWest2,
    ///
    EuWest1,
    ///
    EuCentral1,
    ///
    ApSoutheast1,
    ///
    ApNortheast1,
    ///
    ApSoutheast2,
    ///
    SaEast1,
}

impl Default for Region {
    fn default() -> Region {
        Region::UsEast1
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let display: String = self.into();
        write!(f, "{}", display)
    }
}

impl FromStr for Region {
    type Err = ParseRegionError;

    fn from_str(s: &str) -> Result<Region, ParseRegionError> {
        match s {
            "us-east-1" => Ok(Region::UsEast1),
            "us-west-1" => Ok(Region::UsWest1),
            "us-west-2" => Ok(Region::UsWest2),
            "eu-west-1" => Ok(Region::EuWest1),
            "eu-central-1" => Ok(Region::EuCentral1),
            "ap-southeast-1" => Ok(Region::ApSoutheast1),
            "ap-northeast-1" => Ok(Region::ApNortheast1),
            "ap-southeast-2" => Ok(Region::ApSoutheast2),
            "sa-east-1" => Ok(Region::SaEast1),
            _ => Err(ParseRegionError),
        }
    }
}

/// Translates region enum into AWS format.  EG: us-east-1
impl<'a> Into<String> for &'a Region {
    fn into(self) -> String {
        match *self {
            Region::UsEast1 => "us-east-1".to_owned(),
            Region::UsWest1 => "us-west-1".to_owned(),
            Region::UsWest2 => "us-west-2".to_owned(),
            Region::EuWest1 => "eu-west-1".to_owned(),
            Region::EuCentral1 => "eu-central-1".to_owned(),
            Region::ApSoutheast1 => "ap-southeast-1".to_owned(),
            Region::ApNortheast1 => "ap-northeast-1".to_owned(),
            Region::ApSoutheast2 => "ap-southeast-2".to_owned(),
            Region::SaEast1 => "sa-east-1".to_owned(),
        }
    }
}
