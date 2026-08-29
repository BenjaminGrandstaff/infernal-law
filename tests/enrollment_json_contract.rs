//! Goal: prove initial-enrollment JSON has one strict, independently testable
//! wire format that converts to the kernel domain contract.

use infernal_law::http::enrollment_dto::{
    EnrollmentChallengeRequest, EnrollmentChallengeResponse, EnrollmentErrorResponse,
    EnrollmentSubmissionRequest, EnrollmentSuccessResponse,
};
use infernal_law::kernel::enrollment::{EnrollmentChallenge, EnrollmentError};
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::InstanceCredential;
use infernal_law::kernel::instance_registry::RegisteredInstance;

#[test]
fn challenge_request_and_response_use_typed_json() {
    let service_id = ActorId::new();
    let request_json = serde_json::to_string(&EnrollmentChallengeRequest {
        service_id: service_id.to_string(),
    })
    .unwrap();
    let request: EnrollmentChallengeRequest = serde_json::from_str(&request_json).unwrap();
    assert_eq!(request.service_id().unwrap(), service_id);

    let response = EnrollmentChallengeResponse::new(
        service_id,
        EnrollmentChallenge::from_bytes([3; 32]),
        1_000,
    )
    .unwrap();
    let response_json = serde_json::to_string(&response).unwrap();
    let restored: EnrollmentChallengeResponse = serde_json::from_str(&response_json).unwrap();
    assert_eq!(restored, response);
    assert_eq!(restored.expires_at, 1_030);
    assert!(!restored.challenge.contains('='));
}

#[test]
fn signed_submission_round_trips_to_the_domain_and_success_response() {
    let credential = InstanceCredential::generate(ActorId::new());
    let submission = EnrollmentSubmissionRequest::sign(
        &credential,
        EnrollmentChallenge::from_bytes([4; 32]),
        "https://worker.example.test",
        "pod-uid",
        "projected-service-account-token".to_owned(),
    )
    .unwrap();
    let json = serde_json::to_string(&submission).unwrap();
    let restored: EnrollmentSubmissionRequest = serde_json::from_str(&json).unwrap();
    let domain = restored.into_domain().unwrap();
    assert_eq!(domain.public_key(), credential.public_key());

    let registered = RegisteredInstance::create(
        credential.public_key().clone(),
        "https://worker.example.test",
        1_000,
        1_060,
    )
    .unwrap();
    let success = EnrollmentSuccessResponse::from(&registered);
    let success_json = serde_json::to_string(&success).unwrap();
    let restored: EnrollmentSuccessResponse = serde_json::from_str(&success_json).unwrap();
    assert_eq!(restored, success);
}

#[test]
fn safe_error_json_hides_authentication_and_repository_details() {
    let rejected =
        EnrollmentErrorResponse::from_enrollment_error(&EnrollmentError::BindingNotFound);
    let internal = EnrollmentErrorResponse::from_enrollment_error(&EnrollmentError::Repository(
        "database password was secret".to_owned(),
    ));
    let json = serde_json::to_string(&(rejected, internal)).unwrap();

    assert!(!json.contains("BindingNotFound"));
    assert!(!json.contains("password"));
    assert!(!json.contains("secret"));
}
