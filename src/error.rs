#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("UserError: {0}")]
    UserError(String),

    #[error("ConfigError: {0}")]
    ConfigError(String),

    #[error("AuthError: {0}")]
    AuthError(String),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),

    #[error(transparent)]
    OAuth2RequestTokenError(
        #[from]
        oauth2::RequestTokenError<
            oauth2::reqwest::Error<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),

    #[error(transparent)]
    HyperError(#[from] hyper::Error),

    #[error(transparent)]
    TonicTransportError(#[from] tonic::transport::Error),

    #[error(transparent)]
    TonicStatusError(#[from] tonic::Status),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error("ApiError({0}): {1}; {2:}")]
    ApiError(String, String, reqwest::StatusCode),
}

pub type Result<T> = std::result::Result<T, Error>;
