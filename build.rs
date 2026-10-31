fn main() -> Result<(), Box<dyn std::error::Error>> {
    // minimum_versions() names its own input, which turns off Cargo's default of rerunning on any change.
    println!("cargo:rerun-if-changed=proto");
    windows_hello_helper_sha256()?;
    // On Windows only mairu-windows-hello builds, and the library is empty.
    if std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref() != Ok("unix") {
        return Ok(());
    }
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

/// Re-exports `MAIRU_WINDOWS_HELLO_HELPER_SHA256`, the SHA-256 of the helper a release ships, after checking its form.
fn windows_hello_helper_sha256() -> Result<(), Box<dyn std::error::Error>> {
    const NAME: &str = "MAIRU_WINDOWS_HELLO_HELPER_SHA256";
    println!("cargo:rerun-if-env-changed={NAME}");
    let Ok(value) = std::env::var(NAME) else {
        return Ok(());
    };
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{NAME} is not a hex SHA-256: {value:?}").into());
    }
    println!("cargo:rustc-env={NAME}={value}");
    Ok(())
}
