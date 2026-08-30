//! Goal: define the ILK-002 schema-publication JSON wire format, kept
//! separate from HTTP status/error-code mapping (`src/http.rs`) the same
//! way `subscription_dto` and `enrollment_dto` separate their wire shapes
//! from dispatch.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::kernel::authority::{ContentDigest, SchemaKind, SchemaName, SchemaRecord, SchemaStatus};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishSchemaRequest {
    kind: String,
    name: String,
    content_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishSchemaRequestError {
    InvalidKind,
    InvalidName,
    InvalidContentDigest,
}

impl PublishSchemaRequest {
    pub fn kind(&self) -> Result<SchemaKind, PublishSchemaRequestError> {
        match self.kind.as_str() {
            "artifact" => Ok(SchemaKind::Artifact),
            "permission_policy" => Ok(SchemaKind::PermissionPolicy),
            _ => Err(PublishSchemaRequestError::InvalidKind),
        }
    }

    pub fn name(&self) -> Result<SchemaName, PublishSchemaRequestError> {
        SchemaName::new(&self.name).map_err(|_| PublishSchemaRequestError::InvalidName)
    }

    /// Decodes `content_digest` from URL-safe, unpadded base64 -- the same
    /// encoding `GET /v1/kernel-identity` uses for key material -- into the
    /// exact 32 bytes `ContentDigest` requires.
    pub fn content_digest(&self) -> Result<ContentDigest, PublishSchemaRequestError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.content_digest)
            .map_err(|_| PublishSchemaRequestError::InvalidContentDigest)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| PublishSchemaRequestError::InvalidContentDigest)?;
        Ok(ContentDigest::from_bytes(bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SchemaVersionResponse {
    pub schema_version_id: String,
    pub kind: String,
    pub name: String,
    pub version: i64,
    pub owner_service_id: String,
    pub content_digest: String,
    pub predecessor_id: Option<String>,
    pub published_at: i64,
    pub status: String,
}

impl From<&SchemaRecord> for SchemaVersionResponse {
    fn from(record: &SchemaRecord) -> Self {
        let version = record.version();
        Self {
            schema_version_id: version.id().to_string(),
            kind: schema_kind_str(version.kind()).to_owned(),
            name: version.name().as_str().to_owned(),
            version: version.version(),
            owner_service_id: version.owner().to_string(),
            content_digest: URL_SAFE_NO_PAD.encode(version.content_digest().as_bytes()),
            predecessor_id: version.predecessor().map(|id| id.to_string()),
            published_at: version.published_at(),
            status: schema_status_str(record.status()).to_owned(),
        }
    }
}

fn schema_kind_str(kind: SchemaKind) -> &'static str {
    match kind {
        SchemaKind::Artifact => "artifact",
        SchemaKind::PermissionPolicy => "permission_policy",
    }
}

fn schema_status_str(status: SchemaStatus) -> &'static str {
    match status {
        SchemaStatus::Published => "published",
        SchemaStatus::Active => "active",
        SchemaStatus::Suspended => "suspended",
        SchemaStatus::Superseded => "superseded",
        SchemaStatus::Retired => "retired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::authority::SchemaVersion;
    use crate::kernel::identity::ActorId;

    #[test]
    fn rejects_unknown_fields() {
        let result: Result<PublishSchemaRequest, _> = serde_json::from_str(
            r#"{"kind":"artifact","name":"billing.invoice","content_digest":"AA","extra":true}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_an_unknown_kind() {
        let dto: PublishSchemaRequest = serde_json::from_str(
            r#"{"kind":"weird","name":"billing.invoice","content_digest":"AA"}"#,
        )
        .unwrap();
        assert_eq!(dto.kind(), Err(PublishSchemaRequestError::InvalidKind));
    }

    #[test]
    fn rejects_a_content_digest_of_the_wrong_length() {
        let dto: PublishSchemaRequest = serde_json::from_str(
            r#"{"kind":"artifact","name":"billing.invoice","content_digest":"AA"}"#,
        )
        .unwrap();
        assert_eq!(
            dto.content_digest(),
            Err(PublishSchemaRequestError::InvalidContentDigest)
        );
    }

    #[test]
    fn accepts_a_well_formed_request() {
        let digest = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let dto: PublishSchemaRequest = serde_json::from_str(&format!(
            r#"{{"kind":"permission_policy","name":"billing.invoice","content_digest":"{digest}"}}"#
        ))
        .unwrap();

        assert_eq!(dto.kind(), Ok(SchemaKind::PermissionPolicy));
        assert_eq!(dto.name().unwrap().as_str(), "billing.invoice");
        assert_eq!(dto.content_digest().unwrap().as_bytes(), &[7_u8; 32]);
    }

    #[test]
    fn response_reflects_the_published_record() {
        let owner = ActorId::new();
        let version = SchemaVersion::restore(
            crate::kernel::authority::SchemaVersionId::new(),
            SchemaKind::Artifact,
            SchemaName::new("billing.invoice").unwrap(),
            1,
            owner,
            ContentDigest::from_bytes([1; 32]),
            None,
            10,
        )
        .unwrap();
        let record = SchemaRecord::restore(version, SchemaStatus::Published);

        let response = SchemaVersionResponse::from(&record);

        assert_eq!(response.kind, "artifact");
        assert_eq!(response.status, "published");
        assert_eq!(response.owner_service_id, owner.to_string());
        assert_eq!(response.predecessor_id, None);
    }
}
