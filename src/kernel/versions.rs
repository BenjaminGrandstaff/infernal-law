//! Goal: implement ILK-004 by preserving accepted resource history as explicit
//! versions and detecting conflicting updates.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-004",
    "Versions",
    "Accepted resource history is versioned and never silently overwritten.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_versions_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-004");
        assert_eq!(REQUIREMENT.capability, "Versions");
    }
}
