//! Goal: provide adapters that connect the kernel process to external systems
//! without placing infrastructure concerns inside capability modules.

pub mod database;
pub mod kubernetes_token_reviewer;
pub mod postgres_enrollment_binding_repository;
pub mod postgres_identity_repository;
pub mod postgres_instance_registry;
pub mod postgres_subscription_repository;
