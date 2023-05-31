use bytes::Bytes;
use http::Request;
use std::error::Error;

/// Return reqwest response
pub async fn http_send<Body: Into<reqwest::Body>>(
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
