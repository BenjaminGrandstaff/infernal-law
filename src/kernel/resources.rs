//! Goal: implement ILK-003 by representing governed, durable objects with
//! stable and non-reusable identifiers.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-003",
    "Resources",
    "Governed objects are durable and have stable, non-reusable IDs.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_resources_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-003");
        assert_eq!(REQUIREMENT.capability, "Resources");
    }
}
