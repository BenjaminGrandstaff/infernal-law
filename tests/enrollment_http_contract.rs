//! Goal: prove the POST enrollment handler enforces its JSON boundary and
//! returns only typed, sanitized responses.

use infernal_law::http::enrollment_dto::EnrollmentSubmissionRequest;
use infernal_law::http::{
    EnrollmentAuthenticator, MAX_ENROLLMENT_BODY_BYTES, enrollment_response, route,
};
use infernal_law::kernel::enrollment::{EnrollmentChallenge, EnrollmentError, EnrollmentRequest};
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::InstanceCredential;
use infernal_law::kernel::instance_registry::RegisteredInstance;

struct AcceptEnrollment;

impl EnrollmentAuthenticator for AcceptEnrollment {
    fn authenticate(
        &self,
        request: EnrollmentRequest,
        now: i64,
    ) -> Result<RegisteredInstance, EnrollmentError> {
        RegisteredInstance::create(
            request.public_key().clone(),
            request.endpoint(),
            now,
            now + 60,
        )
        .map_err(EnrollmentError::Registry)
    }
}

struct RejectEnrollment;

impl EnrollmentAuthenticator for RejectEnrollment {
    fn authenticate(
        &self,
        _: EnrollmentRequest,
        _: i64,
    ) -> Result<RegisteredInstance, EnrollmentError> {
        Err(EnrollmentError::Repository(
            "database password=secret".to_owned(),
        ))
    }
}

struct RejectAuthentication;

impl EnrollmentAuthenticator for RejectAuthentication {
    fn authenticate(
        &self,
        _: EnrollmentRequest,
        _: i64,
    ) -> Result<RegisteredInstance, EnrollmentError> {
        Err(EnrollmentError::InvalidProof)
    }
}

fn valid_json() -> Vec<u8> {
    let credential = InstanceCredential::generate(ActorId::new());
    let dto = EnrollmentSubmissionRequest::sign(
        &credential,
        EnrollmentChallenge::from_bytes([5; 32]),
        "https://worker.example.test",
        "pod-uid",
        "projected-secret-token".to_owned(),
    )
    .unwrap();
    serde_json::to_vec(&dto).unwrap()
}

#[test]
fn valid_json_returns_the_typed_registration_response() {
    let response = enrollment_response(
        Some("application/json; charset=utf-8"),
        &valid_json(),
        &AcceptEnrollment,
        1_000,
    );
    let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();

    assert_eq!(response.status, "201 Created");
    assert_eq!(response.content_type, "application/json");
    assert_eq!(body["lease_expires_at"], 1_060);
    assert_eq!(body["algorithm"], "ed25519");
}

#[test]
fn content_type_and_body_limit_are_enforced_before_authentication() {
    assert_eq!(
        enrollment_response(None, &valid_json(), &AcceptEnrollment, 1_000).status,
        "415 Unsupported Media Type"
    );
    assert_eq!(
        enrollment_response(Some("text/plain"), &valid_json(), &AcceptEnrollment, 1_000,).status,
        "415 Unsupported Media Type"
    );
    assert_eq!(
        enrollment_response(
            Some("application/json"),
            &vec![b'x'; MAX_ENROLLMENT_BODY_BYTES + 1],
            &AcceptEnrollment,
            1_000,
        )
        .status,
        "413 Payload Too Large"
    );
}

#[test]
fn malformed_and_internal_failures_return_safe_json() {
    let malformed = enrollment_response(
        Some("application/json"),
        br#"{"workload_token":"do-not-leak"}"#,
        &AcceptEnrollment,
        1_000,
    );
    let internal = enrollment_response(
        Some("application/json"),
        &valid_json(),
        &RejectEnrollment,
        1_000,
    );
    let rejected = enrollment_response(
        Some("application/json"),
        &valid_json(),
        &RejectAuthentication,
        1_000,
    );

    assert_eq!(malformed.status, "400 Bad Request");
    assert_eq!(internal.status, "503 Service Unavailable");
    assert_eq!(rejected.status, "401 Unauthorized");
    assert!(!malformed.body.contains("do-not-leak"));
    assert!(!internal.body.contains("password"));
    assert!(!internal.body.contains("secret"));
    assert!(!rejected.body.contains("proof"));
    assert!(!rejected.body.contains("projected-secret-token"));
}

#[test]
fn challenge_issuance_has_no_public_http_route() {
    assert_eq!(route("/v1/enrollment-challenges").status, "404 Not Found");
    assert_eq!(route("/v1/enrollments/challenges").status, "404 Not Found");
}
