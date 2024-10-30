fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .message_attribute("mairu.Credentials", "#[derive(zeroize::ZeroizeOnDrop)]")
        .field_attribute("mairu.Credentials.expiration", "#[zeroize(skip)]")
        .message_attribute("mairu.ExecEnvVar", "#[derive(zeroize::ZeroizeOnDrop)]")
        .compile_protos(&["proto/mairu.proto"], &["proto"])?;
    Ok(())
}
