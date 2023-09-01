pub(crate) fn generate_flow_handle() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE.encode(buf)
}
