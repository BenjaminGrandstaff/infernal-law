//! Goal: verify the HTTP module's public health contract independently of its
//! internal implementation.

use infernal_law::http::{readiness_response, route};

#[test]
fn health_contract_is_publicly_available() {
    let response = route("/health/live");

    assert_eq!(response.status, "200 OK");
    assert_eq!(response.body, "ok\n");
}

#[test]
fn readiness_contract_reflects_database_state() {
    assert_eq!(readiness_response(true).status, "200 OK");
    assert_eq!(readiness_response(false).status, "503 Service Unavailable");
}
