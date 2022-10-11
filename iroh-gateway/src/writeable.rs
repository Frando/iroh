use axum::{
    async_trait,
    extract::{FromRequest, RequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub enum WriteableConfig {
    Disabled,
    Unprotected,
    Jwt(Arc<JwtConfig>),
}

pub struct JwtConfig {
    // aud: String,
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

                let validation = Validation::new(jwt_config.alg);
                // Validate the token and decode the user data
                let _token_data = decode::<Claims>(bearer.token(), &jwt_config.key, &validation)
                    .map_err(AuthError::InvalidToken)?;

                // TODO: Check for required claims.

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

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WritingDisabled => (
                StatusCode::NOT_IMPLEMENTED,
                "Write support not available.".to_string(),
            ),
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing auth token".to_string()),
            AuthError::InvalidToken(err) => (
                StatusCode::UNAUTHORIZED,
                format!("Invalid auth token: {}", err),
            ),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
