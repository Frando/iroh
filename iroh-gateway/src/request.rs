use axum::http::header::*;

pub const ERR_UNSUPPORTED_FORMAT: &str = "unsuported format";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestFormat {
    Raw,
    Car,
    // Fs(Cid, String),
}

impl std::convert::TryFrom<&str> for RequestFormat {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "application/vnd.ipld.raw" | "raw" => Ok(RequestFormat::Raw),
            "application/vnd.ipld.car" | "car" => Ok(RequestFormat::Car),
            _ => Err(format!("{}: {}", ERR_UNSUPPORTED_FORMAT, s)),
        }
    }
}

impl RequestFormat {
    pub fn try_from_headers(headers: &HeaderMap) -> Result<Self, String> {
        if headers.contains_key("Content-Type") {
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
        }
        Err(format!("{}: {}", ERR_UNSUPPORTED_FORMAT, "none"))
    }
}

#[tracing::instrument()]
pub fn get_request_format(
    request_headers: &HeaderMap,
    query_format: Option<String>,
) -> Result<RequestFormat, String> {
    let format = if let Some(format) = query_format {
        if format.is_empty() {
            match RequestFormat::try_from_headers(request_headers) {
                Ok(format) => format,
                Err(_) => {
                    return Err("invalid format".to_string());
                }
            }
        } else {
            match RequestFormat::try_from(format.as_str()) {
                Ok(format) => format,
                Err(_) => {
                    match RequestFormat::try_from_headers(request_headers) {
                        Ok(format) => format,
                        Err(_) => {
                            return Err("invalid format".to_string());
                        }
                    };
                    return Err("invalid format".to_string());
                }
            }
        }
    } else {
        match RequestFormat::try_from_headers(request_headers) {
            Ok(format) => format,
            Err(_) => {
                return Err("invalid format".to_string());
            }
        }
    };
    Ok(format)
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
