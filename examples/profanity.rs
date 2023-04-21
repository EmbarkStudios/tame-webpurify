use bytes::Bytes;
use http::Request;
use std::env;
use tame_webpurify::client;
use tame_webpurify::client::Region;

/// Return reqwest response
async fn http_send<Body: Into<reqwest::Body>>(
    http_client: &reqwest::Client,
    request: Request<Body>,
) -> http::Response<Bytes> {
    // Make the request
    let mut response = http_client
        .execute(request.try_into().unwrap())
        .await
        .unwrap();

    // Convert to http::Response
    let mut builder = http::Response::builder()
        .status(response.status())
        .version(response.version());
    std::mem::swap(builder.headers_mut().unwrap(), response.headers_mut());
    builder.body(response.bytes().await.unwrap()).unwrap()
}

/// Run as `run --example profanity --apikey <the-api-key>`
#[tokio::main]
pub async fn main() {
    let args: Vec<String> = env::args().collect();
    let api_key = args.get(2).expect("No API key provided").as_str();

    let region = Region::Es;
    // sorry for the bad language :p
    // webpurify should filter out profanities as well as phone numbers and other contact info
    let text = "fuck you man! call me at +46123123123 or email me at some.name@example.com";

    let request = client::profanity_replace_request(api_key, region, text, "*").unwrap();
    println!("{:?}", &request.uri());

    let http_client = reqwest::Client::new();
    let response = http_send(&http_client, request).await;
    println!("{:?}", &response);
}
