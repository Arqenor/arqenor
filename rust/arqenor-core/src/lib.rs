pub mod config;
pub mod correlation;
pub mod error;
pub mod ioc;
pub mod models;
pub mod pipeline;
pub mod rules;
pub mod traits;

pub mod ebpf_bridge;

// Re-export for downstream crates: `use arqenor_core::sanitize_metadata_value;`
pub use crate::models::alert::sanitize_metadata_value;
