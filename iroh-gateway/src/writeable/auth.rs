use axum::{
    async_trait,
    extract::{FromRequest, RequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension,
};
use iroh_metrics::get_current_trace_id;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::GatewayError;
use crate::writeable::WriteableConfig;

pub struct JwtConfig {
    alg: Algorithm,
    key: DecodingKey,
}

impl JwtConfig {
    pub fn from_secret_hs256(secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        let key = DecodingKey::from_secret(secret.as_bytes());
        let alg = Algorithm::HS256;
        Ok(Self { alg, key })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    // The only claim being required and validated is expiration date.
    // More claims can be added as needed.
    exp: usize,
}

#[derive(Debug)]
pub struct WriteCapability;

#[async_trait]
impl<B> FromRequest<B> for WriteCapability
where
    B: Send,
{
    type Rejection = AuthError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(writeable_config) = Extension::<WriteableConfig>::from_request(req)
            .await
            .map_err(|_| AuthError::WritingDisabled)?;

        match writeable_config {
            WriteableConfig::Disabled => Err(AuthError::WritingDisabled),
            WriteableConfig::Unprotected => Ok(WriteCapability),
            WriteableConfig::Jwt(jwt_config) => {
                // Extract the token from the authorization header
                let TypedHeader(Authorization(bearer)) =
                    TypedHeader::<Authorization<Bearer>>::from_request(req)
                        .await
                        .map_err(|_| AuthError::MissingToken)?;

                // Validate the token and decode the user data
                let validation = Validation::new(jwt_config.alg);
                let _token_data = decode::<Claims>(bearer.token(), &jwt_config.key, &validation)
                    .map_err(AuthError::InvalidToken)?;

                // TODO: Optionally validate required claims if configured.

                Ok(WriteCapability)
            }
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    WritingDisabled,
    MissingToken,
    InvalidToken(jsonwebtoken::errors::Error),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::WritingDisabled => write!(f, "This gateway is not writable"),
            AuthError::MissingToken => write!(f, "Authentication token is required"),
            AuthError::InvalidToken(_err) => write!(f, "Authentication token is invalid"),
        }
    }
}

impl From<AuthError> for StatusCode {
    fn from(err: AuthError) -> StatusCode {
        match err {
            AuthError::WritingDisabled => StatusCode::NOT_IMPLEMENTED,
            AuthError::MissingToken => StatusCode::UNAUTHORIZED,
            AuthError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
        }
    }
}

impl From<AuthError> for GatewayError {
    fn from(err: AuthError) -> GatewayError {
        GatewayError {
            message: format!("{}", err),
            status_code: StatusCode::from(err),
            trace_id: get_current_trace_id().to_string(),
            method: None,
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        GatewayError::from(self).into_response()
    }
}
