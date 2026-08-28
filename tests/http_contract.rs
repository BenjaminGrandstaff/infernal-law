//! Goal: verify the HTTP module's public health contract independently of its
//! internal implementation.

use infernal_law::http::route;

#[test]
fn health_contract_is_publicly_available() {
    let response = route("/health/ready");

    assert_eq!(response.status, "200 OK");
    assert_eq!(response.body, "ok\n");
}
