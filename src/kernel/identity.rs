//! Goal: implement ILK-001 so every actor and worker operation is attributable
//! to a stable identity.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-001",
    "Identity",
    "Every actor and worker has a stable identity.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_identity_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-001");
        assert_eq!(REQUIREMENT.capability, "Identity");
    }
}
