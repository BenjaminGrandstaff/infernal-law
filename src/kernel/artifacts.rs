//! Goal: implement ILK-006 by accepting immutable worker evidence and results
//! with durable provenance.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-006",
    "Artifacts",
    "Workers can submit immutable evidence and results.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_artifacts_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-006");
        assert_eq!(REQUIREMENT.capability, "Artifacts");
    }
}
