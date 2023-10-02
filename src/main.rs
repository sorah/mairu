#[derive(clap::Parser)]
#[clap(author, version, long_about = None)]
#[clap(about = "Mairu TODO")]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Agent(mairu::cmd::agent::AgentArgs),
    Login(mairu::cmd::login::LoginArgs),
    CredentialProcess(mairu::cmd::credential_process::CredentialProcessArgs),
    ListSessions,
    Exec(mairu::cmd::exec::ExecArgs),
}

fn main() -> Result<std::process::ExitCode, anyhow::Error> {
    use clap::Parser;
    let cli = Cli::parse();

    enable_tracing(true); // TODO: move to cmd::*
    let retval = match &cli.command {
        Commands::Agent(args) => mairu::cmd::agent::run(args),
        Commands::Login(args) => mairu::cmd::login::run(args),
        Commands::CredentialProcess(args) => mairu::cmd::credential_process::run(args),
        Commands::ListSessions => mairu::cmd::list_sessions::run(),
        Commands::Exec(args) => mairu::cmd::exec::run(args),
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

fn enable_tracing(stderr: bool) {
    if let Ok(l) = std::env::var("MAIRU_LOG") {
        std::env::set_var("RUST_LOG", l);
    }
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "mairu=info");
    }

    if stderr {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }
}
