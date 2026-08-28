//! Goal: provide immutable metadata that connects a Rust capability module to
//! its documented `ILK-*` requirement.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requirement {
    pub id: &'static str,
    pub capability: &'static str,
    pub summary: &'static str,
}

impl Requirement {
    pub const fn new(id: &'static str, capability: &'static str, summary: &'static str) -> Self {
        Self {
            id,
            capability,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Requirement;

    #[test]
    fn requirement_preserves_traceability_metadata() {
        let requirement = Requirement::new("ILK-000", "Example", "Example requirement");

        assert_eq!(requirement.id, "ILK-000");
        assert_eq!(requirement.capability, "Example");
        assert_eq!(requirement.summary, "Example requirement");
    }
}
