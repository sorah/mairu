// async_trait and async_recursion expansions trip this lint on code we do not write.
#![allow(clippy::double_must_use)]

mod error;
pub use error::{Error, Result};

pub mod hardening;
pub mod os;
pub mod platform;
pub mod ppid;
pub mod proto;
pub mod version;

pub mod helpers;

#[cfg(feature = "cli")]
pub mod ext_awssso;
#[cfg(feature = "cli")]
pub mod ext_axum;
#[cfg(feature = "cli")]
pub mod ext_oauth2;
#[cfg(feature = "cli")]
pub mod git;
#[cfg(feature = "cli")]
pub mod singleflight;
#[cfg(feature = "cli")]
pub mod terminal;

#[cfg(feature = "cli")]
pub mod auto;
#[cfg(feature = "cli")]
pub mod config;
#[cfg(feature = "cli")]
pub mod token;
#[cfg(feature = "cli")]
pub mod utils;

#[cfg(feature = "cli")]
pub mod oauth_awssso_code;
#[cfg(feature = "cli")]
pub mod oauth_awssso_device_code;
#[cfg(feature = "cli")]
pub mod oauth_code;
#[cfg(feature = "cli")]
pub mod oauth_device_code;
#[cfg(feature = "cli")]
pub mod oauth_refresh_token;

#[cfg(all(feature = "cli", target_os = "linux"))]
pub mod attestation;

#[cfg(feature = "cli")]
pub mod api_client;
#[cfg(feature = "cli")]
pub mod awssso_client;
#[cfg(feature = "cli")]
pub mod client;

#[cfg(feature = "cli")]
pub mod auth_flow_manager;
#[cfg(feature = "cli")]
pub mod credential_cache;
#[cfg(feature = "cli")]
pub mod session_manager;

#[cfg(feature = "cli")]
pub mod agent;
#[cfg(feature = "cli")]
pub mod authorization;
#[cfg(feature = "cli")]
pub mod caller_identity;
#[cfg(feature = "cli")]
pub mod ecs_server;
#[cfg(feature = "cli")]
pub mod network;
#[cfg(feature = "cli")]
pub mod policy;
#[cfg(feature = "cli")]
pub mod polkit_tty_agent;
#[cfg(feature = "cli")]
pub mod tool_detection;

#[cfg(any(feature = "cli", feature = "platform-services"))]
pub mod cmd;
