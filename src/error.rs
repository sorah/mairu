#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("UserError: {0}")]
    UserError(String),

    #[error("ConfigError: {0}")]
    ConfigError(String),

    #[error("AuthError: {0}")]
    AuthError(String),

    #[error("UnknownError: {0}")]
    UnknownError(String),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    NixErrnoError(#[from] nix::errno::Errno),

    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),

    #[error("AuthNotReadyError: flow not yet ready")]
    AuthNotReadyError { slow_down: bool },

    #[error(transparent)]
    OAuth2RequestTokenError(
        #[from]
        oauth2::RequestTokenError<
            oauth2::HttpClientError<reqwest::Error>,
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

    #[error(transparent)]
    AwsSsooidcError(#[from] Box<aws_sdk_ssooidc::Error>),

    #[error(transparent)]
    RemoteError(#[from] crate::client::Error),

    #[error("{0}")]
    SidecarError(String),

    /// Failure, but we don't want to emit error to stderr/out anymore. Used in cmd
    #[error("")]
    FailureButSilentlyExit,

    /// Failure, but we don't want to emit error to stderr/out anymore. Used in cmd
    #[error("")]
    SilentlyExitWithCode(std::process::ExitCode),
}

pub type Result<T> = std::result::Result<T, Error>;
