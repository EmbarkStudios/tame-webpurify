use crate::client::api_url_by_region;
use crate::client::query_string;
use crate::client::request_builder;
use crate::client::Method;
use crate::client::Region;
use http::{Request, Response};

use crate::{RequestError, ResponseError};

#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ApiSmartScreenResponseSentiment {
    pub text: String,
    pub polarity: String,
}

#[derive(Debug, serde::Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ApiSmartScreenResponse {
    #[serde(deserialize_with = "de_bool")]
    pub bigotry: bool,
    #[serde(deserialize_with = "de_bool")]
    pub personal_attack: bool,
    #[serde(deserialize_with = "de_bool")]
    pub sexual_advances: bool,
    #[serde(deserialize_with = "de_bool")]
    pub criminal_activity: bool,
    #[serde(deserialize_with = "de_bool")]
    pub external_contact: bool,
    #[serde(deserialize_with = "de_bool")]
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

pub fn smart_screen_request(
    api_key: &str,
    region: Region,
    text: &str,
    replace_text: &str,
    sentiment: bool,
    topics: bool,
) -> Result<Request<Vec<u8>>, RequestError> {
    let qs = query_string(
        api_key,
        text,
        Method::SmartScreen(replace_text.to_string(), sentiment, topics),
    );
    let api_uri = format!("{}?{}", api_url_by_region(region), qs);

    let req = request_builder(api_uri)?;
    Ok(req)
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

fn parse_smart_screen_response<T>(
    response: Response<T>,
) -> Result<ApiSmartScreenResponse, ResponseError>
where
    T: AsRef<[u8]>,
{
    if !response.status().is_success() {
        return Err(ResponseError::HttpStatus(response.status()));
    }

    let body = response.body();
    Ok(serde_json::from_slice(body.as_ref())?)
}

pub fn smart_screen_result<T>(
    response: Response<T>,
) -> Result<ApiSmartScreenResponse, ResponseError>
where
    T: AsRef<[u8]>,
{
    let res = parse_smart_screen_response(response)?;
    Ok(res)
}

#[cfg(test)]
mod test {
    use crate::client;
    use http::Request;
    use http::Response;
    use http::StatusCode;
    use std::error::Error;

    fn uri_contains(req: &Request<Vec<u8>>, needle: &str) -> bool {
        req.uri().to_string().contains(needle)
    }

    #[test]
    fn smart_screen_request() -> Result<(), Box<dyn Error>> {
        let region = crate::client::Region::Europe;
        let req = client::smart_screen_request("abcd", region, "hi there", "*", true, true)?;
        assert!(uri_contains(&req, "method=webpurify.live.smartscreen"));
        assert!(uri_contains(&req, "replacesymbol=*"));
        assert!(uri_contains(&req, "text=hi+there"));

        Ok(())
    }

    #[test]
    fn smart_screen_result() -> Result<(), Box<dyn Error>> {
        let body = b"{\"language\":\"en\",\"bigotry\":\"false\",\"personal_attack\":\"false\",\"sexual_advances\":\"false\",\
                                  \"criminal_activity\":\"false\",\"external_contact\":\"false\",\"mental_health\":\"false\",\"profanity\":\"true\",\
                                  \"profanity_found\":[\"hell\"],\"replace_text\":\"To **** and back\",\"overall_sentmient\":\"negative\",\
                                  \"sentiment\":[{\"text\":\"to hell and back\",\"polarity\":\"negative\"}]}";
        let response = Response::builder()
            .status(StatusCode::OK)
            .body((*body).into_iter().collect::<Vec<_>>())?;
        let result = client::smart_screen_result(response)?;

        assert_eq!(
            result,
            client::ApiSmartScreenResponse {
                bigotry: false,
                personal_attack: false,
                sexual_advances: false,
                criminal_activity: false,
                external_contact: false,
                profanity: true,
                profanity_found: Some(vec!["hell".to_owned()]),
                replace_text: Some("To **** and back".to_owned()),
                topics: None,
                overall_sentiment: None,
                sentiment: Some(vec![client::ApiSmartScreenResponseSentiment {
                    text: "to hell and back".to_owned(),
                    polarity: "negative".to_owned()
                }])
            }
        );
        Ok(())
    }
}
