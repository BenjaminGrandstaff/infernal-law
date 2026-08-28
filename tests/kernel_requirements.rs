//! Goal: verify that the library publicly exposes every minimum-kernel
//! requirement exactly once through a stable registry.

use std::collections::HashSet;

use infernal_law::kernel::REQUIREMENTS;

#[test]
fn public_registry_has_unique_requirement_ids() {
    let ids: HashSet<_> = REQUIREMENTS
        .iter()
        .map(|requirement| requirement.id)
        .collect();

    assert_eq!(ids.len(), 13);
    assert!(ids.contains("ILK-001"));
    assert!(ids.contains("ILK-013"));
}
