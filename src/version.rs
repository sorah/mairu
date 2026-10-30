//! This build's version and the minimum versions a hardened peer must have.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// From `[package.metadata.mairu]` in Cargo.toml.
pub const MINIMUM_CLIENT_VERSION: &str = env!("MAIRU_MINIMUM_CLIENT_VERSION");
/// From `[package.metadata.mairu]` in Cargo.toml.
pub const MINIMUM_AGENT_VERSION: &str = env!("MAIRU_MINIMUM_AGENT_VERSION");

/// Whether `version` is at least `minimum`, comparing `major.minor.patch` and ignoring any pre-release or build
/// suffix. An unparsable `version` is older than any minimum.
pub fn at_least(version: &str, minimum: &str) -> bool {
    match (parse(version), parse(minimum)) {
        (Some(v), Some(m)) => v >= m,
        _ => false,
    }
}

fn parse(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.split(['-', '+', ' ']).next()?;
    let mut parts = core.split('.');
    let parsed = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    if parts.next().is_some() {
        return None;
    }
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimums_parse() {
        assert!(parse(MINIMUM_CLIENT_VERSION).is_some());
        assert!(parse(MINIMUM_AGENT_VERSION).is_some());
        assert!(at_least(VERSION, MINIMUM_CLIENT_VERSION));
        assert!(at_least(VERSION, MINIMUM_AGENT_VERSION));
    }

    #[test]
    fn test_at_least() {
        assert!(at_least("0.12.0", "0.12.0"));
        assert!(at_least("0.12.1", "0.12.0"));
        assert!(at_least("0.13.0", "0.12.9"));
        assert!(at_least("1.0.0", "0.99.99"));
        assert!(at_least("0.12.0-rc1", "0.12.0"));
        assert!(!at_least("0.11.9", "0.12.0"));
        assert!(!at_least("0.9.0", "0.10.0"));
        assert!(!at_least("", "0.12.0"));
        assert!(!at_least("0.12", "0.12.0"));
        assert!(!at_least("garbage", "0.12.0"));
    }
}
