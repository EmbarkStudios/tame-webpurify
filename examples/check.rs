use std::env;
use std::error::Error;

use tame_webpurify::client;
use tame_webpurify::client::Region;

mod common;

/// Run as `cargo run --example check -- --apikey <the-api-key>`
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let api_key = args.get(2).expect("No API key provided").as_str();

    let region = Region::Es;
    // sorry for the bad language :p
    // webpurify should filter out profanities as well as phone numbers and other contact info
    let text = "fuck you man! call me at +46123123123 or email me at some.name@example.com";

    let request = client::profanity_check_request(api_key, region, text)?;
    println!("{:?}", &request.uri());

    let http_client = reqwest::Client::new();
    let response = common::http_send(&http_client, request).await?;

    let result = client::profanity_check_result(response)?;

    println!("Found bad words: {result}");

    Ok(())
}
