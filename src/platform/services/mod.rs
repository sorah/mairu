//! Platform service backends. They run only inside the platform helper, never in the agent.

pub mod fallback;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod system_bus;
