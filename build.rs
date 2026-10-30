fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .message_attribute("mairu.Credentials", "#[derive(zeroize::ZeroizeOnDrop)]")
        .field_attribute("mairu.Credentials.expiration", "#[zeroize(skip)]")
        .message_attribute("mairu.ExecEnvVar", "#[derive(zeroize::ZeroizeOnDrop)]")
        .message_attribute("mairu.ListRolesResponse", "#[derive(serde::Serialize)]")
        .message_attribute(
            "mairu.ListRolesResponse.Item",
            "#[derive(serde::Serialize)]",
        )
        .message_attribute(
            "mairu.ListRolesResponse.Item.Role",
            "#[derive(serde::Serialize)]",
        )
        .compile_protos(
            &["proto/mairu.proto", "proto/mairu_platform.proto"],
            &["proto"],
        )?;

    minimum_versions()?;

    shadow_rs::ShadowBuilder::builder().build()?;
    Ok(())
}

/// Exports `[package.metadata.mairu]` minimum versions as `MAIRU_MINIMUM_{CLIENT,AGENT}_VERSION`.
fn minimum_versions() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=Cargo.toml");
    let manifest = std::fs::read_to_string("Cargo.toml")?;
    let mut in_section = false;
    let mut found = std::collections::HashMap::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == "[package.metadata.mairu]";
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            found.insert(
                key.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            );
        }
    }
    for (key, env) in [
        ("minimum-client-version", "MAIRU_MINIMUM_CLIENT_VERSION"),
        ("minimum-agent-version", "MAIRU_MINIMUM_AGENT_VERSION"),
    ] {
        let value = found
            .get(key)
            .ok_or_else(|| format!("Cargo.toml lacks package.metadata.mairu.{key}"))?;
        println!("cargo:rustc-env={env}={value}");
    }
    Ok(())
}
