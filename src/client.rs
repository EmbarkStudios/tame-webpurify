use http::header::CONTENT_TYPE;
use http::{Request, Response, Uri};
use serde_json::Value;
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

#[derive(Clone)]
pub enum Method {
    /// webpurify.live.check
    Check,
    /// webpurify.live.check
    Replace(String),
    /// webpurify.live.smartscreen
    SmartScreen(String, bool, bool),
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
    let method_str = match method.clone() {
        Method::Check => "webpurify.live.check".to_string(),
        Method::Replace(_) => "webpurify.live.replace".to_string(),
        // TODO(mathias): Change to actually convey meaning about the args (text, sentiment, topics)
        Method::SmartScreen(_, _, _) => "webpurify.live.smartscreen".to_string(),
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

    if let Method::Replace(replace_with) = method.clone() {
        qs.append_pair("replacesymbol", &replace_with);
    }

    if let Method::SmartScreen(replace_with, _sentiment, _topics) = method.clone() {
        qs.append_pair("replacesymbol", &replace_with);
        qs.append_pair("sentiment", "true");
        qs.append_pair("topics", "true");
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

/// `WebPurify` returns the number of matched profanities, PII etc.
/// This function only returns a request object, you need to do the actual HTTP request yourself.
///
/// Extend the function when more languages are required.
/// Documentation: <https://www.webpurify.com/documentation/additional/language/>
///
/// # Arguments
///
/// * `api_key` - a string slice that holds your `WebPurify` API Key
///
/// * `region` - the regional `WebPurify` API to use
///
/// * `text` - a string slice to be checked by `WebPurify`
///
/// # Examples
/// ```
/// use tame_webpurify::client;
/// let res = client::profanity_check_request("some-api-key", client::Region::Europe, "my filthy user-input string");
/// ```
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

/// `WebPurify` replaces matched profanities, PII etc with a given symbol.
/// This function only returns a request object, you need to do the actual HTTP request yourself.
///
/// Extend the function when more languages are required.
/// Documentation: <https://www.webpurify.com/documentation/additional/language/>
///
/// # Arguments
///
/// * `api_key` - a string slice that holds your `WebPurify` API Key
///
/// * `region` - the regional `WebPurify` API to use
///
/// * `text` - a string slice you want to be moderated by `WebPurify`
///
/// * `replace_text` - a string slice to replace profanities in `text` with
///
/// # Examples
/// ```
/// use tame_webpurify::client;
/// let res = client::profanity_replace_request("some-api-key", client::Region::Europe, "my filthy user-input string", "*");
/// ```
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

pub fn smart_screen_request(
    api_key: &str,
    region: Region,
    text: &str,
    replace_text: &str,
) -> Result<Request<Vec<u8>>, RequestError> {
    let qs = query_string(api_key, text, Method::SmartScreen(replace_text.to_string(), true, true));
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

#[derive(Debug, serde::Deserialize)]
pub struct ApiSmartScreenResponseSentiment {
    text: String,
    polarity: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct ApiSmartScreenResponse {
    #[serde(deserialize_with="de_bool")]
    pub bigotry: bool,
    #[serde(deserialize_with="de_bool")]
    pub personal_attack: bool,
    #[serde(deserialize_with="de_bool")]
    pub sexual_advances: bool,
    #[serde(deserialize_with="de_bool")]
    pub criminal_activity: bool,
    #[serde(deserialize_with="de_bool")]
    pub external_contact: bool,
    #[serde(deserialize_with="de_bool")]
    pub profanity: bool,
    pub profanity_found: Option<Vec<String>>,
    pub replace_text: Option<String>,

    /// Only active if "topics=true" is passed to WebPurify in the query string
    pub topics: Option<Vec<String>>,

    /// Only active if "sentiment=true" is passed to WebPurify in the query string
    pub overall_sentiment: Option<String>,
    /// Only active if "sentiment=true" is passed to WebPurify in the query string
    pub sentiment: Option<Vec<ApiSmartScreenResponseSentiment>>,
}

fn de_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: serde::de::Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(deserializer)?;

    match s.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(serde::de::Error::unknown_variant(&s, &["true", "false"])),
    }
}

fn parse_smart_screen_response<T>(response: Response<T>) -> Result<ApiSmartScreenResponse, ResponseError>
where T: AsRef<[u8]>, {
    if !response.status().is_success() {
        return Err(ResponseError::HttpStatus(response.status()));
    }

    let body = response.body();
    Ok(serde_json::from_slice(body.as_ref())?)
}

/// Returns true if `WebPurify` flagged a request to contain profanities, PII, etc
///
/// # Arguments
///
/// * `response` - a response object from the `WebPurify` `check` API call
///
pub fn profanity_check_result(response: Response<Vec<u8>>) -> Result<bool, ResponseError> {
    let response = parse_response(response)?;

    let check = response
        .rsp
        .found
        .parse::<u32>()
        .map_err(|_err| ResponseError::InvalidField("found".to_owned()))?;

    Ok(check > 0)
}

/// Returns the sanitized string from a response object.
///
/// # Arguments
///
/// * `response` - a response object from the `WebPurify` `replace` API call
///
pub fn profanity_replace_result<T>(response: Response<T>) -> Result<String, ResponseError>
where
    T: AsRef<[u8]>,
{
    let response = parse_response(response)?;

    match response.rsp.text {
        Some(text) => Ok(text),
        None => Err(ResponseError::MissingField("text".to_owned())),
    }
}

pub fn smart_screen_result<T>(response: Response<T>) -> Result<ApiSmartScreenResponse, ResponseError>
where
    T: AsRef<[u8]>,
{
    let res = parse_smart_screen_response(response)?;
    Ok(res)
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
