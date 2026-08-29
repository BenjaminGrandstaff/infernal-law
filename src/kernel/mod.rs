//! Goal: define the minimum kernel's capability boundaries and provide one
//! traceable registry for requirements ILK-001 through ILK-013.

pub mod artifacts;
pub mod audit;
pub mod authority;
pub mod decisions;
pub mod events;
pub mod idempotency;
pub mod identity;
pub mod instance_keys;
pub mod mediation;
pub mod relationships;
mod requirement;
pub mod resources;
pub mod subscriptions;
pub mod versions;
pub mod work_claims;

pub use requirement::Requirement;

pub const REQUIREMENTS: [Requirement; 13] = [
    identity::REQUIREMENT,
    authority::REQUIREMENT,
    resources::REQUIREMENT,
    versions::REQUIREMENT,
    relationships::REQUIREMENT,
    artifacts::REQUIREMENT,
    decisions::REQUIREMENT,
    audit::REQUIREMENT,
    events::REQUIREMENT,
    subscriptions::REQUIREMENT,
    work_claims::REQUIREMENT,
    idempotency::REQUIREMENT,
    mediation::REQUIREMENT,
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::REQUIREMENTS;

    #[test]
    fn registry_contains_every_minimum_kernel_requirement_once() {
        let unique_ids: HashSet<_> = REQUIREMENTS.iter().map(|item| item.id).collect();

        assert_eq!(REQUIREMENTS.len(), 13);
        assert_eq!(unique_ids.len(), REQUIREMENTS.len());
        assert_eq!(REQUIREMENTS.first().unwrap().id, "ILK-001");
        assert_eq!(REQUIREMENTS.last().unwrap().id, "ILK-013");
    }
}
