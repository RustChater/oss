# simple-oss

Simple Alibaba Cloud OSS Client in Rust


```rust
let oss_client = OSSClient::new("<endpoint>", "<access_key_id>", "<access_key_secret>");
oss_cleint.put_file_content("<bucket>", "helloworld.txt", "hello world!")?;
```