#[derive(clap::Parser)]
#[clap(author, version, long_about = None)]
#[clap(about = "Mairu: on-memory AWS credentials agent")]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Execute command with AWS credentials
    Exec(mairu::cmd::exec::ExecArgs),

    /// Login to your credential server
    Login(mairu::cmd::login::LoginArgs),
    /// Use Mairu as a credenital process provider
    CredentialProcess(mairu::cmd::credential_process::CredentialProcessArgs),
    /// List active sessions
    ListSessions(mairu::cmd::list_sessions::ListSessionsArgs),

    /// Manually start agent process; it is automatically spawned when not present
    Agent(mairu::cmd::agent::AgentArgs),

    /// Setup Mairu for your AWS SSO (AWS IAM Identity Center) instance
    SetupSso(mairu::cmd::setup_sso::SetupSsoArgs),
}

fn main() -> Result<std::process::ExitCode, anyhow::Error> {
    use clap::Parser;
    let cli = Cli::parse();

    match &cli.command {
        Commands::Agent(a) => {
            if let Ok(l) = std::env::var("MAIRU_AGENT_LOG") {
                std::env::set_var("MAIRU_LOG", l);
            }
            if a.log_to_file {
                enable_log(LogType::File)
            } else {
                enable_log(LogType::Custom);
            }
        }
        Commands::Exec(_) => enable_log(LogType::Custom),
        Commands::CredentialProcess(_) => enable_log(LogType::Custom),
        _ => enable_log(LogType::Default),
    }
    let retval = match &cli.command {
        Commands::Agent(args) => mairu::cmd::agent::run(args),
        Commands::Login(args) => mairu::cmd::login::run(args),
        Commands::CredentialProcess(args) => mairu::cmd::credential_process::run(args),
        Commands::ListSessions(args) => mairu::cmd::list_sessions::run(args),
        Commands::Exec(args) => mairu::cmd::exec::run(args),
        Commands::SetupSso(args) => mairu::cmd::setup_sso::run(args),
    };
    match retval {
        Ok(_) => Ok(std::process::ExitCode::SUCCESS),
        Err(e) => match e.downcast_ref::<mairu::Error>() {
            Some(mairu::Error::FailureButSilentlyExit) => Ok(std::process::ExitCode::FAILURE),
            Some(mairu::Error::SilentlyExitWithCode(c)) => Ok(*c),
            _ => Err(e),
        },
    }
}

enum LogType {
    Default,
    Custom,
    File,
}

fn enable_log(kind: LogType) {
    let rust_log = std::env::var_os("RUST_LOG");

    #[cfg(not(debug_assertions))]
    std::env::remove_var("RUST_LOG");

    if let Ok(l) = std::env::var("MAIRU_LOG") {
        std::env::set_var("RUST_LOG", l);
    }
    match kind {
        LogType::Default => {
            if std::env::var_os("RUST_LOG").is_none() {
                std::env::set_var("RUST_LOG", "mairu=info");
            }
            tracing_subscriber::fmt::init();
        }
        LogType::Custom => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
        }
        LogType::File => {
            if std::env::var_os("RUST_LOG").is_none() {
                std::env::set_var("RUST_LOG", "mairu=info");
            }
            let log_dir = mairu::config::log_dir_mkpath().expect("can't create log directory");
            nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o077).unwrap());
            let w = tracing_appender::rolling::daily(log_dir, "mairu.log");
            tracing_subscriber::fmt()
                .with_writer(w)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
        }
    }

    if let Some(v) = rust_log {
        std::env::set_var("RUST_LOG", v);
    } else {
        std::env::remove_var("RUST_LOG");
    }
}
