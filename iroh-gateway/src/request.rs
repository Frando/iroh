use axum::http::header::HeaderMap;

pub const ERR_UNSUPPORTED_FORMAT: &str = "unsuported format";
pub const MIME_TYPE_IPLD_RAW: &str = "application/vnd.ipld.raw";
pub const MIME_TYPE_IPLD_CAR: &str = "application/vnd.ipld.car";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestFormat {
    Raw,
    Car,
}

impl ToString for RequestFormat {
    fn to_string(&self) -> String {
        match self {
            RequestFormat::Raw => MIME_TYPE_IPLD_RAW.to_string(),
            RequestFormat::Car => MIME_TYPE_IPLD_CAR.to_string(),
        }
    }
}

impl std::convert::TryFrom<&str> for RequestFormat {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            MIME_TYPE_IPLD_RAW | "raw" => Ok(RequestFormat::Raw),
            MIME_TYPE_IPLD_CAR | "car" => Ok(RequestFormat::Car),
            _ => Err(format!("{}: {}", ERR_UNSUPPORTED_FORMAT, s)),
        }
    }
}

impl RequestFormat {
    pub fn try_from_headers(headers: &HeaderMap) -> Result<Self, String> {
        if let Some(h_values) = headers.get("Content-Type") {
            let h_values = h_values.to_str().unwrap().split(',');
            for h_value in h_values {
                let h_value = h_value.trim();
                let format = RequestFormat::try_from(h_value);
                if format.is_ok() {
                    return format;
                }
            }
        }
        Err(format!("{}: {}", ERR_UNSUPPORTED_FORMAT, "none"))
    }
}

#[tracing::instrument()]
pub fn get_request_format(
    request_headers: &HeaderMap,
    query_format: Option<String>,
) -> Result<RequestFormat, String> {
    match query_format {
        Some(format) if !format.is_empty() => RequestFormat::try_from(format.as_str()),
        _ => RequestFormat::try_from_headers(request_headers),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_format_try_from() {
        let rf = RequestFormat::try_from("raw");
        assert_eq!(rf, Ok(RequestFormat::Raw));
        let rf = RequestFormat::try_from("car");
        assert_eq!(rf, Ok(RequestFormat::Car));

        let rf = RequestFormat::try_from("RaW");
        assert_eq!(rf, Ok(RequestFormat::Raw));

        let rf = RequestFormat::try_from("UNKNOWN");
        assert!(rf.is_err());
    }
}
