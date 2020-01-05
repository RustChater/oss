use std::{
    fs::{
        self,
        File,
    },
    env,
    path::PathBuf,
    io::{
        Error,
        ErrorKind,
    },
};
use crypto::{
    mac::{
        Mac,
        MacResult,
    },
    hmac::Hmac,
    sha1::Sha1,
};
use reqwest::{
    Response,
};
use rust_util::{
    iff,
    XResult,
    new_box_ioerror,
    util_time::get_current_secs,
};

pub const OSS_VERB_GET: &str = "GET";
pub const OSS_VERB_PUT: &str = "PUT";
pub const OSS_VERB_DELETE: &str = "DELETE";

/// OSSClient - Alibaba Cloud OSS Client
/// 
/// Reference URL: https://help.aliyun.com/document_detail/31952.html
/// 
/// ```rust
/// let oss_client = OSSClient::new("AK", "SK");
/// ```
pub struct OSSClient<'a> {
    pub endpoint: &'a str,
    pub access_key_id: &'a str,
    pub access_key_secret: &'a str,
}

/// OSS Client implemention
impl<'a> OSSClient<'a> {

    /// New OSSClient
    /// 
    /// Use access_key_id and access_key_secret to create a OSSClient
    /// Consider support STS!
    pub fn new(endpoint: &'a str, access_key_id: &'a str, access_key_secret: &'a str) -> OSSClient<'a> {
        OSSClient {
            endpoint,
            access_key_id,
            access_key_secret,
        }
    }

    /// New OSSClient from JSON file
    pub fn from_file(f: &str) -> XResult<Self> {
        let f_path_buf = if f.starts_with("~/") {
            let home = PathBuf::from(env::var("HOME")?);
            home.join(f.chars().skip(2).collect::<String>())
        } else {
            PathBuf::from(f)
        };
        let f_content = fs::read_to_string(f_path_buf)?;
        Self::from_json(&f_content)
    }

    /// New OSSClient from JSON
    /// 
    /// JSON sample:
    /// ```json
    /// {
    ///     "endpoint": "",
    ///     "accessKeyId": "",
    ///     "accessKeySecret": ""
    /// }
    /// ```
    pub fn from_json(json: &str) -> XResult<Self> {
        let json_value = json::parse(json)?;
        if !json_value.is_object() {
            return Err(Box::new(Error::new(ErrorKind::Other, format!("JSON format erorr: {}", json))));
        }

        let endpoint = Self::string_to_a_str(json_value["endpoint"].as_str().unwrap_or_default());
        let access_key_id = Self::string_to_a_str(json_value["accessKeyId"].as_str().unwrap_or_default());
        let access_key_secret = Self::string_to_a_str(json_value["accessKeySecret"].as_str().unwrap_or_default());

        if endpoint.is_empty() || access_key_id.is_empty() || access_key_secret.is_empty() {
            return Err(Box::new(Error::new(ErrorKind::Other,"Endpoint, access_key_id or access_key_secret cannot be empty")));
        }
        
        Ok(Self::new(endpoint, access_key_id, access_key_secret))
    }

    pub fn put_file(&self, bucket_name: &str, key: &str, expire_in_seconds: u64, file: File) -> XResult<Response> {
        let client = reqwest::Client::new();
        Ok(client.put(&self.generate_signed_put_url(bucket_name, key, expire_in_seconds)).body(file).send()?)
    }

    pub fn delete_file(&self, bucket_name: &str, key: &str) -> XResult<Response> {
        let delete_url = self.generate_signed_delete_url(bucket_name, key, 30_u64);
        let client = reqwest::Client::new();
        Ok(client.delete(&delete_url).send()?)
    }

    pub fn get_file_content(&self, bucket_name: &str, key: &str) -> XResult<Option<String>> {
        let get_url = self.generate_signed_get_url(bucket_name, key, 30_u64);
        let mut response = reqwest::get(&get_url)?;
        match response.status().as_u16() {
            404_u16 => Ok(None),
            200_u16 => Ok(Some(response.text()?)),
            _ => Err(new_box_ioerror(&format!("Error in read: {}/{}, returns: {:?}", bucket_name, key, response))),
        }
    }

    pub fn get_file_content_bytes(&self, bucket_name: &str, key: &str) -> XResult<Option<Vec<u8>>> {
        let get_url = self.generate_signed_get_url(bucket_name, key, 30_u64);
        let mut response = reqwest::get(&get_url)?;
        match response.status().as_u16() {
            404_u16 => Ok(None),
            200_u16 => {
                let mut buf: Vec<u8> = vec![];
                response.copy_to(&mut buf)?;
                Ok(Some(buf))
            },
            _ => Err(new_box_ioerror(&format!("Error in read: {}/{}, returns: {:?}", bucket_name, key, response))),
        }
    }

    pub fn put_file_content(&self, bucket_name: &str, key: &str, content: &str) -> XResult<Response> {
        self.put_file_content_bytes(bucket_name, key, content.as_bytes().to_vec())
    }

    pub fn put_file_content_bytes(&self, bucket_name: &str, key: &str, content_bytes: Vec<u8>) -> XResult<Response> {
        let put_url = self.generate_signed_put_url(bucket_name, key, 30_u64);
        let client = reqwest::Client::new();
        Ok(client.put(&put_url).body(content_bytes).send()?)
    }

    pub fn generate_signed_put_url(&self, bucket_name: &str, key: &str, expire_in_seconds: u64) -> String {
        self.generate_signed_url(OSS_VERB_PUT, bucket_name, key, expire_in_seconds, true)
    }

    pub fn generate_signed_get_url(&self, bucket_name: &str, key: &str, expire_in_seconds: u64) -> String {
        self.generate_signed_url(OSS_VERB_GET, bucket_name, key, expire_in_seconds, true)
    }

    pub fn generate_signed_delete_url(&self, bucket_name: &str, key: &str, expire_in_seconds: u64) -> String {
        self.generate_signed_url(OSS_VERB_DELETE, bucket_name, key, expire_in_seconds, true)
    }

    pub fn generate_signed_url(&self, verb: &str, bucket_name: &str, key: &str, expire_in_seconds: u64, is_https: bool) -> String {
        let mut signed_url = String::with_capacity(1024);
        signed_url.push_str(iff!(is_https, "https://", "http://"));
        signed_url.push_str(&format!("{}.{}/{}", bucket_name, self.endpoint, key));
    
        let current_secs = get_current_secs();
        let expire_secs = current_secs + expire_in_seconds;
    
        signed_url.push_str("?Expires=");
        signed_url.push_str(expire_secs.to_string().as_str());
        signed_url.push_str("&OSSAccessKeyId=");
        signed_url.push_str(&urlencoding::encode(self.access_key_id));
        signed_url.push_str("&Signature=");
    
        let to_be_signed = get_to_be_signed(verb, expire_secs, bucket_name, key);
        let signature = to_base64(calc_hmac_sha1(self.access_key_secret.as_bytes(), to_be_signed.as_bytes()));
        signed_url.push_str(&urlencoding::encode(signature.as_str()));
    
        signed_url
    }

    // SAFE? may these codes cause memory leak?
    fn string_to_a_str(s: &str) -> &'a str {
        Box::leak(s.to_owned().into_boxed_str())
    }
}

fn get_to_be_signed(verb: &str, expire_secs: u64, bucket_name: &str, key: &str) -> String {
    let mut to_be_signed = String::with_capacity(512);
    to_be_signed.push_str(verb);
    to_be_signed.push_str("\n");
    to_be_signed.push_str("\n");
    to_be_signed.push_str("\n");
    to_be_signed.push_str(expire_secs.to_string().as_str());
    to_be_signed.push_str("\n");
    to_be_signed.push_str("/");
    to_be_signed.push_str(bucket_name);
    to_be_signed.push_str("/");
    to_be_signed.push_str(key);
    to_be_signed
}

fn to_base64(mac_result: MacResult) -> String {
    base64::encode(mac_result.code())
}

fn calc_hmac_sha1(key: &[u8], message: &[u8]) -> MacResult {
    let mut hmac = Hmac::new(Sha1::new(), key);
    hmac.input(message);
    hmac.result()
}
