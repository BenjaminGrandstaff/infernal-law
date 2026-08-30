//! Goal: define the ILK-003 request-submission JSON wire format, kept
//! separate from HTTP status/error-code mapping (`src/http.rs`) the same
//! way `subscription_dto` and `schema_dto` separate their wire shapes from
//! dispatch.

use serde::{Deserialize, Serialize};

use crate::kernel::authority::{SchemaVersionRefs, Scope};
use crate::kernel::identity::ActorId;
use crate::kernel::requests::{AcceptedRequest, Request, RequestId};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitRequestRequest {
    action: String,
    scope: String,
    artifact_schema_version_id: String,
    permission_policy_schema_version_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitRequestRequestError {
    InvalidScope,
    InvalidSchemaVersionId,
    InvalidAction,
}

impl SubmitRequestRequest {
    /// Builds the domain `Request` this submission describes, owned by
    /// `source_service` -- the caller's own verified identity, never a
    /// field this DTO itself carries, so a request body can never claim
    /// another service as its source.
    ///
    /// `request_id` comes from the signed envelope's own
    /// `infernal-request-id` (`VerifiedServiceRequest::request_id`), not a
    /// body field: the caller already controls that value and retries a
    /// lost response with it unchanged, so reusing it as ILK-003's stable
    /// request ID is what makes `POST /v1/requests` idempotent under retry
    /// without a second, redundant identifier.
    pub fn into_request(
        self,
        source_service: ActorId,
        request_id: RequestId,
    ) -> Result<Request, SubmitRequestRequestError> {
        let scope = Scope::new(&self.scope).map_err(|_| SubmitRequestRequestError::InvalidScope)?;
        let artifact = self
            .artifact_schema_version_id
            .parse()
            .map_err(|_| SubmitRequestRequestError::InvalidSchemaVersionId)?;
        let permission_policy = self
            .permission_policy_schema_version_id
            .parse()
            .map_err(|_| SubmitRequestRequestError::InvalidSchemaVersionId)?;
        let schema_versions = SchemaVersionRefs::new(artifact, permission_policy);
        Request::restore(
            request_id,
            source_service,
            &self.action,
            scope,
            schema_versions,
        )
        .map_err(|_| SubmitRequestRequestError::InvalidAction)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptedRequestResponse {
    pub request_id: String,
    pub source_service_id: String,
    pub action: String,
    pub scope: String,
    pub artifact_schema_version_id: String,
    pub permission_policy_schema_version_id: String,
    pub accepted_at: i64,
}

impl From<&AcceptedRequest> for AcceptedRequestResponse {
    fn from(record: &AcceptedRequest) -> Self {
        let request = record.request();
        Self {
            request_id: request.id().to_string(),
            source_service_id: request.source_service().to_string(),
            action: request.action().as_str().to_owned(),
            scope: request.scope().as_str().to_owned(),
            artifact_schema_version_id: request.schema_versions().artifact().to_string(),
            permission_policy_schema_version_id: request
                .schema_versions()
                .permission_policy()
                .to_string(),
            accepted_at: record.accepted_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::authority::SchemaVersionId;

    fn well_formed_body() -> String {
        format!(
            r#"{{"action":"billing.invoice.submit","scope":"invoice-4471","artifact_schema_version_id":"{}","permission_policy_schema_version_id":"{}"}}"#,
            SchemaVersionId::new(),
            SchemaVersionId::new(),
        )
    }

    #[test]
    fn rejects_unknown_fields() {
        let body = well_formed_body().replace('}', r#","extra":true}"#);
        let result: Result<SubmitRequestRequest, _> = serde_json::from_str(&body);
        assert!(result.is_err());
    }

    #[test]
    fn builds_a_request_owned_by_the_verified_caller_under_the_envelope_request_id() {
        let dto: SubmitRequestRequest = serde_json::from_str(&well_formed_body()).unwrap();
        let source = ActorId::new();
        let request_id = RequestId::new();

        let request = dto.into_request(source, request_id).unwrap();

        assert_eq!(request.id(), request_id);
        assert_eq!(request.source_service(), source);
        assert_eq!(request.action().as_str(), "billing.invoice.submit");
        assert_eq!(request.scope().as_str(), "invoice-4471");
    }

    #[test]
    fn rejects_an_invalid_schema_version_id() {
        let body = r#"{"action":"billing.invoice.submit","scope":"invoice-4471","artifact_schema_version_id":"not-a-uuid","permission_policy_schema_version_id":"also-not-a-uuid"}"#;
        let dto: SubmitRequestRequest = serde_json::from_str(body).unwrap();

        assert_eq!(
            dto.into_request(ActorId::new(), RequestId::new()),
            Err(SubmitRequestRequestError::InvalidSchemaVersionId)
        );
    }

    #[test]
    fn rejects_an_invalid_action() {
        let body = format!(
            r#"{{"action":"submit","scope":"invoice-4471","artifact_schema_version_id":"{}","permission_policy_schema_version_id":"{}"}}"#,
            SchemaVersionId::new(),
            SchemaVersionId::new(),
        );
        let dto: SubmitRequestRequest = serde_json::from_str(&body).unwrap();

        assert_eq!(
            dto.into_request(ActorId::new(), RequestId::new()),
            Err(SubmitRequestRequestError::InvalidAction)
        );
    }
}
