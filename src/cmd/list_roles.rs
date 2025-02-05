#[derive(clap::Args)]
pub struct ListRolesArgs {
    /// List only roles from specified credential server (ID or URL)
    #[arg(long)]
    server: Option<String>,

    #[arg(long, short = 'o', default_value = "text")]
    output: ListRolesFormat,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ListRolesFormat {
    Text,
    Oneline,
    Json,
}
impl std::str::FromStr for ListRolesFormat {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<ListRolesFormat, crate::Error> {
        match s {
            "text" => Ok(ListRolesFormat::Text),
            "oneline" => Ok(ListRolesFormat::Oneline),
            "json" => Ok(ListRolesFormat::Json),
            _ => Err(crate::Error::UserError("unknown --output".to_owned())),
        }
    }
}

#[tokio::main]
pub async fn run(args: &ListRolesArgs) -> Result<(), anyhow::Error> {
    use tokio::io::AsyncWriteExt;

    let mut agent = crate::cmd::agent::connect_or_start().await?;
    let list = agent
        .list_roles(tonic::Request::new(crate::proto::ListRolesRequest {
            server_id: args.server.clone().unwrap_or_default(),
        }))
        .await?
        .into_inner();

    let mut stdout = tokio::io::stdout();

    match args.output {
        ListRolesFormat::Text => {
            let mut role_id_width = 0;
            for server in list.servers.iter() {
                for role in server.roles.iter() {
                    role_id_width = role_id_width.max(role.name.len());
                }
            }

            for server in list.servers.iter() {
                stdout
                    .write_all(format!("{id}\n", id = server.server_id).as_bytes())
                    .await
                    .unwrap();

                if server.logged_in {
                    for role in server.roles.iter() {
                        stdout
                            .write_all(
                                format!(
                                    "    {role:<role_id_width$}  {description}\n",
                                    role = role.name,
                                    description = role.description,
                                )
                                .as_bytes(),
                            )
                            .await
                            .unwrap();
                    }
                } else {
                    stdout
                        .write_all(format!("    not logged in\n").as_bytes())
                        .await
                        .unwrap();
                }
                stdout.write_all(format!("\n").as_bytes()).await.unwrap();
            }
        }
        ListRolesFormat::Oneline => {
            let mut server_id_width = 0;
            let mut role_id_width = 0;
            for server in list.servers.iter() {
                server_id_width = server_id_width.max(server.server_id.len());
                for role in server.roles.iter() {
                    role_id_width = role_id_width.max(role.name.len());
                }
            }

            for server in list.servers.iter() {
                for role in server.roles.iter() {
                    stdout
                        .write_all(
                            format!(
                                "{id:<server_id_width$}  {role:<role_id_width$}  {description}\n",
                                id = server.server_id,
                                role = role.name,
                                description = role.description,
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            }
        }
        ListRolesFormat::Json => {
            let json = serde_json::to_string_pretty(&list)?;
            stdout.write_all(json.as_bytes()).await.unwrap();
            stdout.write_all(b"\n").await.unwrap();
        }
    }
    stdout.flush().await.unwrap();

    Ok(())
}
