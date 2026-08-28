//! Goal: implement ILK-007 by storing governed decisions as explicit,
//! traceable, and durable records.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-007",
    "Decisions",
    "Governed decisions are explicit durable records.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_decisions_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-007");
        assert_eq!(REQUIREMENT.capability, "Decisions");
    }
}
