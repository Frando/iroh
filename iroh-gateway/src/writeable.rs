use std::sync::Arc;

pub mod auth;
pub mod client;
pub mod handlers;
pub mod writer;

#[derive(Clone)]
pub enum WriteableConfig {
    Disabled,
    Unprotected,
    Jwt(Arc<auth::JwtConfig>),
}
