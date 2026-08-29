//! Goal: provide adapters that connect the kernel process to external systems
//! without placing infrastructure concerns inside capability modules.

pub mod database;
pub mod postgres_identity_repository;
