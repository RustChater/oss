# simple-oss

Simple Alibaba Cloud OSS Client in Rust


```rust
let oss_client = OSSClient::new("<endpoint>", "<access_key_id>", "<access_key_secret>");
oss_cleint.put_file_content("<bucket>", "helloworld.txt", "hello world!").await?;
```


#### Changelog

* v0.3.0
    * Do not use `'a` lifecycle
* v0.2.0
    * Use `async/await` by `reqwest v0.10.0`

