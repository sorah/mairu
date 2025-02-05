fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
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
        .compile_protos(&["proto/mairu.proto"], &["proto"])?;
    Ok(())
}
