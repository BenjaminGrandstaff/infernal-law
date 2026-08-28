//! Goal: implement ILK-008 by recording security and governance activity in an
//! append-only audit history.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-008",
    "Audit",
    "Security and governance actions produce append-only audit records.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_audit_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-008");
        assert_eq!(REQUIREMENT.capability, "Audit");
    }
}
