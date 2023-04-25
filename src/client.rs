use http::header::CONTENT_TYPE;
use http::{Request, Response, Uri};
use url::form_urlencoded;

#[derive(thiserror::Error, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum RequestError {
    #[error("The provided Uri was invalid")]
    InvalidUri,

    #[error(transparent)]
    HTTP(#[from] http::Error),
}

#[derive(thiserror::Error, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum ResponseError {
    #[error("The response status was invalid: {0}")]
    HttpStatus(http::StatusCode),
    #[error(transparent)]
    Deserialize(#[from] serde_json::Error),
    #[error("Missing field {0} in response")]
    MissingField(String),
    #[error("Invalid field {0} in response")]
    InvalidField(String),
}

#[derive(Clone, Copy)]
pub enum Region {
    Europe,
    Us,
    Asia,
    Es,
}

pub enum Method {
    /// webpurify.live.check
    Check,
    /// webpurify.live.check
    Replace(String),
}

fn api_url_by_region(region: Region) -> String {
    match region {
        Region::Us => "https://api1.webpurify.com/services/rest/",
        Region::Europe => "https://api1-eu.webpurify.com/services/rest/",
        Region::Asia => "https://api1-ap.webpurify.com/services/rest/",
        Region::Es => "https://es-api.webpurify.net/services/rest/",
    }
    .to_string()
}

/// method: Which method should we use on matched strings?
///     Check - returns 1 if profanity is found, otherwise 0
///     Replace - returns 1 if profanity if found and replaces
pub fn query_string(api_key: &str, text: &str, method: Method) -> String {
    let method_str = match method {
        Method::Check => "webpurify.live.check".to_string(),
        Method::Replace(_) => "webpurify.live.replace".to_string(),
    };

    let mut serializer = form_urlencoded::Serializer::new(String::new());
    let qs = serializer
        .append_pair("format", "json")
        .append_pair("api_key", api_key)
        .append_pair("text", text)
        .append_pair("method", &method_str)
        .append_pair("semail", "1")
        .append_pair("slink", "1")
        .append_pair("rsp", "1")
        .append_pair("sphone", "1");

    if let Method::Replace(replace_with) = method {
        qs.append_pair("replacesymbol", &replace_with);
    }

    qs.finish()
}

pub(crate) fn into_uri<U: TryInto<Uri>>(uri: U) -> Result<Uri, RequestError> {
    uri.try_into().map_err(|_err| RequestError::InvalidUri)
}

fn request_builder(api_uri: String) -> Result<Request<Vec<u8>>, RequestError> {
    let request_builder = Request::builder()
        .method("POST")
        .uri(into_uri(api_uri)?)
        .header(CONTENT_TYPE, "application/json");

    let req = request_builder.body(vec![])?;
    Ok(req)
}

/// Create and return a request object for profanity filtering against webpurify.
/// Extend the function when more languages are required
/// Documentation: <https://www.webpurify.com/documentation/additional/language/>
pub fn profanity_check_request(
    api_key: &str,
    region: Region,
    text: &str,
) -> Result<Request<Vec<u8>>, RequestError> {
    let qs = query_string(api_key, text, Method::Check);
    let api_uri = format!("{}?{}", api_url_by_region(region), qs);

    let req = request_builder(api_uri)?;
    Ok(req)
}

/// Replace profanities with a given symbol
pub fn profanity_replace_request(
    api_key: &str,
    region: Region,
    text: &str,
    replace_text: &str,
) -> Result<Request<Vec<u8>>, RequestError> {
    let qs = query_string(api_key, text, Method::Replace(replace_text.to_string()));
    let api_uri = format!("{}?{}", api_url_by_region(region), qs);

    let req = request_builder(api_uri)?;
    Ok(req)
}

#[derive(serde::Deserialize)]
struct ApiResponse {
    rsp: ApiResponseRsp,
}

#[derive(serde::Deserialize)]
struct ApiResponseRsp {
    found: String,
    text: Option<String>,
}

fn parse_response<T>(response: Response<T>) -> Result<ApiResponse, ResponseError>
where
    T: AsRef<[u8]>,
{
    if !response.status().is_success() {
        return Err(ResponseError::HttpStatus(response.status()));
    }

    let body = response.body();
    Ok(serde_json::from_slice(body.as_ref())?)
}

/// Check for profanities result based on response
pub fn profanity_check_result(response: http::Response<Vec<u8>>) -> Result<bool, ResponseError> {
    let response = parse_response(response)?;

    let check = response
        .rsp
        .found
        .parse::<u32>()
        .map_err(|_err| ResponseError::InvalidField("found".to_owned()))?;

    Ok(check > 0)
}

/// Replace profanities with a given symbol result based on response
pub fn profanity_replace_result<T>(response: http::Response<T>) -> Result<String, ResponseError>
where
    T: AsRef<[u8]>,
{
    let response = parse_response(response)?;

    let Some(text) = response.rsp.text else {
        return Err(ResponseError::MissingField("text".to_owned()))
    };

    Ok(text)
}

#[cfg(test)]
mod test {
    use std::error::Error;

    use crate::client;
    use http::Request;
    use http::Response;
    use http::StatusCode;

    fn uri_contains(req: &Request<Vec<u8>>, needle: &str) -> bool {
        req.uri().to_string().contains(needle)
    }

    #[test]
    fn qs_encoding() {
        assert_eq!(
            client::query_string("abcd", "hi there", client::Method::Check),
            "format=json&api_key=abcd&text=hi+there&method=webpurify.live.check&semail=1&slink=1&rsp=1&sphone=1"
        );
    }

    #[test]
    fn check_request() {
        let region = client::Region::Europe;
        let req = client::profanity_check_request("abcd", region, "hi there");
        assert_eq!(
            req.unwrap().uri(),
            "https://api1-eu.webpurify.com/services/rest/?format=json&api_key=abcd&text=hi+there&method=webpurify.live.check&semail=1&slink=1&rsp=1&sphone=1"
        );
    }

    #[test]
    fn check_result() -> Result<(), Box<dyn Error>> {
        let response_found = |found: u32| {
            let body = format!("{{\"rsp\":{{\"@attributes\":{{\"stat\":\"ok\",\"rsp\":\"0.0072040557861328\"}},\"method\":\"webpurify.live.check\",\"format\":\"rest\",\"found\":\"{found}\",\"api_key\":\"123\"}}}}");
            Response::builder()
                .status(StatusCode::OK)
                .body(body.as_bytes().to_vec())
        };
        let result = client::profanity_check_result(response_found(3)?)?;
        assert!(result);
        let result = client::profanity_check_result(response_found(0)?)?;
        assert!(!result);
        Ok(())
    }

    #[test]
    fn replace_request() {
        let region = client::Region::Europe;
        let res_req = client::profanity_replace_request("abcd", region, "hi there", "*");
        let req = res_req.unwrap();
        assert!(uri_contains(&req, "method=webpurify.live.replace"));
        assert!(uri_contains(&req, "replacesymbol=*"));
        assert!(uri_contains(&req, "text=hi+there"));
    }

    #[test]
    fn replace_result() -> Result<(), Box<dyn Error>> {
        let body = b"{\"rsp\":{\"@attributes\":{\"stat\":\"ok\",\"rsp\":\"0.018898963928223\"},\"method\":\"webpurify.live.replace\",\"format\":\"rest\",\"found\":\"3\",\"text\":\"foo\",\"api_key\":\"123\"}}";
        let response = Response::builder()
            .status(StatusCode::OK)
            .body((*body).into_iter().collect::<Vec<_>>())?;
        let result = client::profanity_replace_result(response)?;

        assert_eq!(result, "foo".to_owned());
        Ok(())
    }
}
