//! UI API errors: `{"error": {"code", "message"}}` with the matching status (api.md §2, §7). A
//! refused save adds `issues`, the problems it would introduce. The UI API's handlers read their
//! body, query string and path through [`ApiJson`], [`ApiQuery`] and [`ApiPath`], so what they
//! can't read gets this shape too (README §2: JSON everywhere).

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::validate::Issue;
use crate::error::CoreError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub issues: Vec<Issue>,
}

#[derive(Serialize)]
struct Body<'a> {
    error: Detail<'a>,
}

#[derive(Serialize)]
struct Detail<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "<[Issue]>::is_empty")]
    issues: &'a [Issue],
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            issues: vec![],
        }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", m)
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", m)
    }
    pub fn unprocessable(m: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid", m)
    }
    pub fn not_implemented(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            format!("not implemented yet: {what}"),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Body {
            error: Detail {
                code: self.code,
                message: &self.message,
                issues: &self.issues,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::NotFound(m) => Self::not_found(m),
            CoreError::Conflict(m) => Self::new(StatusCode::CONFLICT, "conflict", m),
            CoreError::ConflictCode(code, m) => Self::new(StatusCode::CONFLICT, code, m),
            CoreError::Invalid(m) => Self::unprocessable(m),
            CoreError::Forbidden(m) => Self::forbidden(m),
            CoreError::Unavailable(m) => Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", m),
            CoreError::NotImplemented(w) => Self::not_implemented(w),
            CoreError::Validation(issues) => {
                let message = CoreError::Validation(issues.clone()).to_string();
                Self {
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                    code: "validation",
                    message,
                    issues,
                }
            }
            CoreError::Db(err) => {
                tracing::error!(error = %err, "database error in the UI API");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
            }
            CoreError::Other(err) => {
                // A CoreError wrapped in anyhow (from the writer task) keeps its meaning.
                match err.downcast::<CoreError>() {
                    Ok(inner) => Self::from(inner),
                    Err(err) => {
                        tracing::error!(error = %format!("{err:#}"), "error in the UI API");
                        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
                    }
                }
            }
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::from(CoreError::Other(e))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// A JSON body whose rejections use the API's error shape. The whole body must arrive within the
/// server's body deadline (`web::BodyTimeout`, README §2 Bounded): `408` (`timeout`) past it.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let deadline = req
            .extensions()
            .get::<super::BodyTimeout>()
            .map_or(super::BODY_TIMEOUT, |t| t.0);
        let Ok(read) = tokio::time::timeout(deadline, Json::<T>::from_request(req, state)).await else {
            return Err(ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                format!(
                    "the request body didn't arrive within {} s",
                    deadline.as_secs_f32()
                ),
            ));
        };
        match read {
            Ok(Json(v)) => Ok(Self(v)),
            Err(rej) => Err(match rej {
                JsonRejection::JsonDataError(e) => ApiError::unprocessable(e.body_text()),
                JsonRejection::JsonSyntaxError(e) => ApiError::bad_request(e.body_text()),
                JsonRejection::MissingJsonContentType(_) => {
                    ApiError::forbidden("mutating requests need a JSON body (Content-Type: application/json)")
                }
                JsonRejection::BytesRejection(e) => ApiError::new(e.status(), "bad_body", e.body_text()),
                other => ApiError::bad_request(other.body_text()),
            }),
        }
    }
}

/// A query string or path parameter the API couldn't read: `400` (`bad_request`) with axum's
/// explanation in the API's error shape; a route that can't supply its parameters is ours
/// (`500`).
fn unreadable(status: StatusCode, message: String) -> ApiError {
    if status.is_client_error() {
        ApiError::new(status, "bad_request", message)
    } else {
        tracing::error!(%status, error = %message, "a UI API route's parameters");
        ApiError::new(status, "internal", message)
    }
}

/// A query string whose rejections use the API's error shape (README §2: JSON everywhere;
/// api.md §7 errors): a value it can't read, such as `redirects=maybe`, is a `400` with
/// `{"error": {"code": "bad_request", …}}`, never axum's plain-text reply.
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(v)| Self(v))
            .map_err(|e| unreadable(e.status(), e.body_text()))
    }
}

/// Path parameters whose rejections use the API's error shape, as [`ApiQuery`]'s (an alert id
/// that isn't a number: `400`).
pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(v)| Self(v))
            .map_err(|e| unreadable(e.status(), e.body_text()))
    }
}
