//! Goal: implement ILK-010 by allowing workers to declare and manage interest
//! in authorized event types.

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-010",
    "Subscriptions",
    "Workers can declare the event types in which they are interested.",
);

#[cfg(test)]
mod tests {
    use super::REQUIREMENT;

    #[test]
    fn traces_to_subscriptions_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-010");
        assert_eq!(REQUIREMENT.capability, "Subscriptions");
    }
}
