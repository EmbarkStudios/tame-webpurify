use crate::RequestError;
use crate::ResponseError;
use http::header::CONTENT_TYPE;
use http::{Request, Response, Uri};
use url::form_urlencoded;

pub use crate::smart_screen::smart_screen_request;
pub use crate::smart_screen::smart_screen_result;
pub use crate::smart_screen::ApiSmartScreenResponse;
pub use crate::smart_screen::ApiSmartScreenResponseSentiment;

fn bool_to_str(value: bool) -> &'static str {
    match value {
        true => "true",
        false => "false",
    }
}

#[derive(Clone, Copy)]
pub enum Region {
    Europe,
    Us,
    Asia,
    Es,
}

#[derive(Clone, Eq, PartialEq)]
pub enum Method {
    /// webpurify.live.check
    Check,
    /// webpurify.live.replace
    Replace(String),
    /// webpurify.live.smartscreen
    SmartScreen(String, bool, bool),
}

impl Method {
    fn method_str(&self) -> &'static str {
        match self {
            Method::Check => "webpurify.live.check",
            Method::Replace(_) => "webpurify.live.replace",
            Method::SmartScreen(_, _, _) => "webpurify.live.smartscreen",
        }
    }
}

pub(crate) fn api_url_by_region(region: Region) -> String {
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
    let method_str = method.method_str();

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

    if let Method::SmartScreen(replace_with, sentiment, topics) = method {
        let sentiment_str = bool_to_str(sentiment);
        let topics_str = bool_to_str(topics);
        qs.append_pair("replacesymbol", &replace_with);
        qs.append_pair("sentiment", sentiment_str);
        qs.append_pair("topics", topics_str);
    }

    qs.finish()
}

pub fn into_uri<U: TryInto<Uri>>(uri: U) -> Result<Uri, RequestError> {
    uri.try_into().map_err(|_err| RequestError::InvalidUri)
}

pub(crate) fn request_builder(api_uri: String) -> Result<Request<Vec<u8>>, RequestError> {
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

#[derive(serde::Deserialize)]
struct ApiResponse {
    rsp: ApiResponseRsp,
}

#[derive(serde::Deserialize)]
struct ApiResponseRsp {
    #[serde(rename = "@attributes")]
    attributes: ApiResponseRspAttributes,
    err: Option<ApiResponseErr>,
    method: Option<String>,
    found: Option<String>,
    text: Option<String>,
}

#[derive(serde::Deserialize)]
struct ApiResponseRspAttributes {
    stat: String,
}

#[derive(serde::Deserialize)]
struct ApiResponseErr {
    #[serde(rename = "@attributes")]
    attributes: ApiResponseErrAttributes,
}

#[derive(serde::Deserialize)]
struct ApiResponseErrAttributes {
    code: String,
    msg: String,
}

fn parse_response<T>(response: Response<T>, method: Method) -> Result<ApiResponse, ResponseError>
where
    T: AsRef<[u8]>,
{
    if !response.status().is_success() {
        return Err(ResponseError::HttpStatus(response.status()));
    }

    let body = response.body();
    let api_response: ApiResponse = serde_json::from_slice(body.as_ref())?;

    if let Some(ApiResponseErr {
        attributes: ApiResponseErrAttributes { code, msg },
    }) = api_response.rsp.err
    {
        let err = match code.as_str() {
            "100" => ResponseError::InvalidApiKey(msg),
            "101" => ResponseError::InactiveApiKey(msg),
            "102" => ResponseError::MissingApiKey(msg),
            "103" => ResponseError::ServiceUnavailable(msg),
            _ => ResponseError::UnknownErr(code, msg),
        };
        return Err(err);
    }

    if !api_response.rsp.attributes.stat.eq("ok") {
        return Err(ResponseError::NonOkStat(api_response.rsp.attributes.stat));
    }

    if !api_response
        .rsp
        .method
        .as_ref()
        .map(|s| s.as_str())
        .eq(&Some(method.method_str()))
    {
        return Err(ResponseError::MisMatchedMethod(
            api_response.rsp.method.unwrap_or_default(),
            method.method_str().to_owned(),
        ));
    }

    Ok(api_response)
}

/// Returns true if `WebPurify` flagged a request to contain profanities, PII, etc
///
/// # Arguments
///
/// * `response` - a response object from the `WebPurify` `check` API call
///
pub fn profanity_check_result<T>(response: Response<T>) -> Result<bool, ResponseError>
where
    T: AsRef<[u8]>,
{
    let response = parse_response(response, Method::Check)?;

    // Note, `found` is a boolean in the form of an integer, see: https://www.webpurify.com/documentation/methods/check/
    let found: u32 = response
        .rsp
        .found
        .ok_or_else(|| ResponseError::MissingField("found".to_owned()))
        .and_then(|found| {
            found
                .parse()
                .map_err(|_err| ResponseError::InvalidField("found".to_owned()))
        })?;

    Ok(found > 0)
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
    let response = parse_response(response, Method::Replace("".to_owned()))?; // TODO It is inconvenient to pass in the replace char here

    match response.rsp.text {
        Some(text) => Ok(text),
        None => Err(ResponseError::MissingField("text".to_owned())),
    }
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
    fn check_result_missing_found() -> Result<(), Box<dyn Error>> {
        let body = format!("{{\"rsp\":{{\"@attributes\":{{\"stat\":\"ok\",\"rsp\":\"0.0072040557861328\"}},\"method\":\"webpurify.live.check\",\"format\":\"rest\",\"api_key\":\"123\"}}}}");
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(body.as_bytes().to_vec());
        let result = client::profanity_check_result(response?);
        assert!(result.is_err());
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

    #[test]
    fn replace_result_missing_found() -> Result<(), Box<dyn Error>> {
        let body = b"{\"rsp\":{\"@attributes\":{\"stat\":\"ok\",\"rsp\":\"0.018898963928223\"},\"method\":\"webpurify.live.replace\",\"format\":\"rest\",\"text\":\"foo\",\"api_key\":\"123\"}}";
        let response = Response::builder()
            .status(StatusCode::OK)
            .body((*body).into_iter().collect::<Vec<_>>())?;
        let result = client::profanity_replace_result(response)?;

        assert_eq!(result, "foo".to_owned());
        Ok(())
    }

    #[test]
    fn response_errors() -> Result<(), Box<dyn Error>> {
        let response = |code: u32| {
            let body = format!("{{\"rsp\":{{\"@attributes\":{{\"stat\":\"fail\"}},\"err\":{{\"@attributes\":{{\"code\":\"{code}\",\"msg\":\"Msg\"}}}},\"text\":\"text\"}}}}");
            Response::builder()
                .status(StatusCode::OK)
                .body(body.as_bytes().to_vec())
        };

        for (code, err) in [
            (100, client::ResponseError::InvalidApiKey("Msg".to_owned())),
            (101, client::ResponseError::InactiveApiKey("Msg".to_owned())),
            (102, client::ResponseError::MissingApiKey("Msg".to_owned())),
            (
                103,
                client::ResponseError::ServiceUnavailable("Msg".to_owned()),
            ),
            (
                999,
                client::ResponseError::UnknownErr("999".to_owned(), "Msg".to_owned()),
            ),
        ] {
            let result = client::profanity_replace_result(response(code)?);
            let result_err = result.err().expect("Expected error");
            assert!(
                std::mem::discriminant(&result_err) == std::mem::discriminant(&err),
                "Expected error: {:?} but got: {:?}",
                err,
                result_err
            );
        }

        Ok(())
    }

    #[test]
    fn mismatched_response_methods() -> Result<(), Box<dyn Error>> {
        // Check treated as replace result
        let body = format!("{{\"rsp\":{{\"@attributes\":{{\"stat\":\"ok\",\"rsp\":\"0.0072040557861328\"}},\"method\":\"webpurify.live.check\",\"format\":\"rest\",\"found\":\"1\",\"api_key\":\"123\"}}}}");
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(body.as_bytes().to_vec());
        let result = client::profanity_replace_result(response?);
        assert!(result.is_err());

        // Replace treated as check result
        let body = b"{\"rsp\":{\"@attributes\":{\"stat\":\"ok\",\"rsp\":\"0.018898963928223\"},\"method\":\"webpurify.live.replace\",\"format\":\"rest\",\"found\":\"3\",\"text\":\"foo\",\"api_key\":\"123\"}}";
        let response = Response::builder()
            .status(StatusCode::OK)
            .body((*body).into_iter().collect::<Vec<_>>())?;
        let result = client::profanity_check_result(response);
        assert!(result.is_err());

        Ok(())
    }
}
