mod error;
pub use error::{Error, Result};

pub mod ext_awssso;
pub mod ext_axum;
pub mod ext_oauth2;
pub mod os;
pub mod ppid;
pub mod singleflight;
pub mod terminal;

pub mod auto;
pub mod config;
pub mod proto;
pub mod token;
pub mod utils;

pub mod oauth_awssso_code;
pub mod oauth_awssso_device_code;
pub mod oauth_code;
pub mod oauth_device_code;
pub mod oauth_refresh_token;

pub mod api_client;
pub mod awssso_client;
pub mod client;

pub mod auth_flow_manager;
pub mod credential_cache;
pub mod session_manager;

pub mod agent;
pub mod ecs_server;

pub mod cmd;
