//! Goal: implement ILK-012 by making retries converge on one committed result
//! without repeating side effects.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-012",
    "Idempotency",
    "Retrying a request cannot accidentally perform it twice.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_idempotency_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-012");
        assert_eq!(REQUIREMENT.capability, "Idempotency");
    }
}
