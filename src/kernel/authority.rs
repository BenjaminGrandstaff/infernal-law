//! Goal: implement ILK-002 so the kernel authorizes every governed operation
//! and denies operations that are not explicitly permitted.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-002",
    "Authority",
    "The kernel decides whether an identity may perform an operation.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_authority_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-002");
        assert_eq!(REQUIREMENT.capability, "Authority");
    }
}
