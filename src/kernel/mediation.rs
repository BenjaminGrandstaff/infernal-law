//! Goal: implement ILK-013 by requiring workers to use typed kernel contracts
//! without direct state mutation or caller-supplied SQL.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-013",
    "Mediation",
    "Workers use typed kernel contracts and cannot submit SQL or directly mutate kernel state.",
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
