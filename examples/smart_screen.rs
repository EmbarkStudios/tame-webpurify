use bytes::Bytes;
use http::Request;
use std::env;
use std::error::Error;
use tame_webpurify::client;
use tame_webpurify::client::Region;

/// Return reqwest response
async fn http_send<Body: Into<reqwest::Body>>(
    http_client: &reqwest::Client,
    request: Request<Body>,
) -> Result<http::Response<Bytes>, Box<dyn Error>> {
    // Make the request
    let mut response = http_client.execute(request.try_into()?).await?;

    // Convert to http::Response
    let mut builder = http::Response::builder()
        .status(response.status())
        .version(response.version());
    std::mem::swap(builder.headers_mut().unwrap(), response.headers_mut());
    Ok(builder.body(response.bytes().await?)?)
}

/// Run as `cargo run --example smart_screen -- --apikey <the-api-key>`
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let api_key = args.get(2).expect("No API key provided").as_str();

    let region = Region::Es;
    // sorry for the bad language :p
    // webpurify should filter out profanities as well as phone numbers and other contact info
    let text = "I simply don't like you asshat. You are a potential threat and I will not accept any prisoners who get close to me. Just fuck you";

    let request = client::smart_screen_request(api_key, region, text, "*")?;
    println!("{:?}", &request.uri());

    let http_client = reqwest::Client::new();
    let response = http_send(&http_client, request).await?.into();

    let result = client::smart_screen_result(response)?;

    dbg!("{:?}", &result);

    Ok(())
}
