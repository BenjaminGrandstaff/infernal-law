//! Goal: implement ILK-009 by representing committed changes as typed,
//! versioned, and durable events.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-009",
    "Events",
    "Committed changes can produce typed events.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_events_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-009");
        assert_eq!(REQUIREMENT.capability, "Events");
    }
}
