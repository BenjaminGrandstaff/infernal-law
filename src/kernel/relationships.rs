//! Goal: implement ILK-005 by connecting resources through validated, typed,
//! and historically preserved links.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-005",
    "Relationships",
    "Resources can be connected by typed links.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_relationships_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-005");
        assert_eq!(REQUIREMENT.capability, "Relationships");
    }
}
