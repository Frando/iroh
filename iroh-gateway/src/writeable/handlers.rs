use axum::{
    body::{self},
    extract::{BodyStream, Extension, Query},
    http::{header::*, StatusCode},
    routing::post,
    Router,
};

use futures::TryStreamExt;
use iroh_metrics::{core::MRecorder, gateway::GatewayMetrics, get_current_trace_id, inc};
use iroh_resolver::resolver::ContentLoader;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time};
use tokio::io::AsyncRead;
use tracing::debug;

use crate::{
    core::State,
    error::GatewayError,
    headers::*,
    request::{get_request_format, RequestFormat},
    response::GatewayResponse,
};

use super::auth::WriteCapability;
use super::client::WritingClient;
use super::writer::ContentWriter;

pub fn add_write_route<
    T: ContentLoader + std::marker::Unpin,
    U: ContentWriter + std::marker::Unpin,
>(
    router: Router,
    state: &Arc<State<T>>,
    writer: &Arc<WritingClient<U>>,
) -> Router {
    let writeable_config = state.config.writeable_config();
    router
        .route("/_experimental/write", post(write_handler::<T, U>))
        .layer(Extension(Arc::clone(writer)))
        .layer(Extension(writeable_config))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GetParams {
    format: Option<String>,
}

#[tracing::instrument(skip(state, writer))]
pub async fn write_handler<T: ContentLoader, U: ContentWriter + std::marker::Unpin>(
    _cap: WriteCapability,
    Extension(state): Extension<Arc<State<T>>>,
    Extension(writer): Extension<Arc<WritingClient<U>>>,
    Query(query_params): Query<GetParams>,
    body: BodyStream,
    request_headers: HeaderMap,
) -> Result<GatewayResponse, GatewayError> {
    let start_time = time::Instant::now();
    let mut headers = HeaderMap::new();
    add_user_headers(&mut headers, state.config.user_headers().clone());
    let format = get_request_format(&request_headers, query_params.format)
        .map_err(|err| error(StatusCode::BAD_REQUEST, &err, &state))?;
    let body_reader = body_to_reader(body);
    debug!("write request, format {:?}", format);
    match format {
        RequestFormat::Car => {
            let out = writer
                .put_car(body_reader, start_time)
                .await
                .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string(), &state))?;
            response_json(StatusCode::OK, &out, headers)
        }
        _ => Err(error(
            StatusCode::BAD_REQUEST,
            &format!("unsupported content type: {}", format.to_string()),
            &state,
        )),
    }
}

fn body_to_reader(body: BodyStream) -> impl AsyncRead + Send + Unpin + 'static {
    tokio_util::io::StreamReader::new(
        body.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string())),
    )
}

#[tracing::instrument()]
fn error<T: ContentLoader>(
    status_code: StatusCode,
    message: &str,
    state: &State<T>,
) -> GatewayError {
    inc!(GatewayMetrics::ErrorCount);
    GatewayError {
        status_code,
        message: message.to_string(),
        trace_id: get_current_trace_id().to_string(),
        method: None,
    }
}

#[tracing::instrument(skip(data))]
fn response_json<T: Serialize>(
    status_code: StatusCode,
    data: T,
    mut headers: HeaderMap,
) -> Result<GatewayResponse, GatewayError> {
    let body = serde_json::to_string(&data).map_err(|err| GatewayError {
        status_code: http::status::StatusCode::INTERNAL_SERVER_ERROR,
        message: err.to_string(),
        trace_id: get_current_trace_id().to_string(),
        method: None,
    })?;
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(mime::APPLICATION_JSON.as_ref()),
    );
    Ok(GatewayResponse {
        status_code,
        body: body::boxed(body),
        headers,
        trace_id: get_current_trace_id().to_string(),
    })
}
