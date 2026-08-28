//! Goal: implement ILK-011 by ensuring only one worker holds an active claim
//! for a work item while allowing abandoned work to be recovered.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-011",
    "Work claims",
    "At most one worker can hold the active claim for a piece of work.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_work_claims_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-011");
        assert_eq!(REQUIREMENT.capability, "Work claims");
    }
}
