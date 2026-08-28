//! Goal: implement ILK-013 by requiring workers to use kernel contracts rather
//! than directly mutate kernel-owned state.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-013",
    "Mediation",
    "Workers use kernel contracts and cannot directly mutate kernel state.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_mediation_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-013");
        assert_eq!(REQUIREMENT.capability, "Mediation");
    }
}
