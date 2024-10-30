#[derive(clap::Args, Debug)]
pub struct CredentialProcessArgs {
    /// Credential server ID or URL to use.
    server: String,

    /// 'role' parameter to query your credential server.
    /// For AWS SSO servers, this is formatted like "${account_id}/${permission_set_name}"
    role: String,

    /// Disable credential cache on mairu agent.
    #[arg(long, default_value_t = false)]
    no_cache: bool,
}

#[tokio::main]
pub async fn run(args: &CredentialProcessArgs) -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;

    let resp = agent
        .assume_role(crate::proto::AssumeRoleRequest {
            server_id: args.server.clone(),
            role: args.role.clone(),
            cached: !args.no_cache,
        })
        .await;

    match resp {
        Ok(r) => match r.into_inner().credentials {
            None => {
                anyhow::bail!("Server returned invalid assume-role response, credentials was None")
            }
            Some(c) => {
                serde_json::to_writer(std::io::stdout(), &CredentialProcessResponse::from(&c))?;
                Ok(())
            }
        },
        Err(e) => {
            tracing::debug!(err = ?e, args = ?args, "Failed to obtain AWS credentials");
            let product = env!("CARGO_PKG_NAME");
            let server_id = &args.server;
            let role = &args.role;
            if e.code() == tonic::Code::Unauthenticated {
                crate::terminal::send(&indoc::formatdoc! {"
                    :: {product} :: Authentication Needed to obtain AWS credentials from {server_id} ({role}) :::::::
                    :: {product} :: Run the following command to continue
                    :: {product} ::   $ {product} login {server_id}
                "})
                .await;
            } else {
                let code = e.code();
                let message = e.message();
                crate::terminal::send(&format!(":: {product} :: ERROR when obtaining AWS credentials [{server_id},{role}]: {code:?}; {message}")).await;
            }
            Err(crate::Error::FailureButSilentlyExit.into())
        }
    }
}

/// https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html
#[derive(Clone, Debug, serde::Serialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "PascalCase")]
pub struct CredentialProcessResponse {
    pub version: i64,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    #[zeroize(skip)]
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<&crate::proto::Credentials> for CredentialProcessResponse {
    fn from(cred: &crate::proto::Credentials) -> CredentialProcessResponse {
        CredentialProcessResponse {
            version: cred.version,
            access_key_id: cred.access_key_id.clone(),
            secret_access_key: cred.secret_access_key.clone(),
            session_token: if cred.session_token.is_empty() {
                None
            } else {
                Some(cred.session_token.clone())
            },
            expiration: cred.expiration().ok().flatten(),
        }
    }
}
