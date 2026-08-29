//! Goal: prove communication admission is a default-deny read boundary that
//! remains independent from identity lifecycle and health state.

use std::collections::HashMap;
use std::sync::Mutex;

use infernal_law::kernel::admission::{
    AdmissionError, AdmissionRepository, AdmissionService, CommunicationAdmission,
};
use infernal_law::kernel::identity::ActorId;

#[derive(Default)]
struct MemoryAdmissionRepository {
    records: Mutex<HashMap<ActorId, CommunicationAdmission>>,
}

impl MemoryAdmissionRepository {
    fn with(record: CommunicationAdmission) -> Self {
        Self {
            records: Mutex::new(HashMap::from([(record.service_id(), record)])),
        }
    }
}

impl AdmissionRepository for MemoryAdmissionRepository {
    fn find(&self, service_id: ActorId) -> Result<Option<CommunicationAdmission>, AdmissionError> {
        Ok(self.records.lock().unwrap().get(&service_id).cloned())
    }
}

#[test]
fn disabled_admission_fails_closed_even_for_a_known_service() {
    let service_id = ActorId::new();
    let admission = CommunicationAdmission::restore(service_id, false, 0, 1_000).unwrap();
    let service = AdmissionService::new(MemoryAdmissionRepository::with(admission));

    assert_eq!(
        service.require_enabled(service_id),
        Err(AdmissionError::Disabled(service_id))
    );
}

#[test]
fn enabled_admission_returns_its_independent_revisioned_state() {
    let service_id = ActorId::new();
    let admission = CommunicationAdmission::restore(service_id, true, 3, 1_000).unwrap();
    let service = AdmissionService::new(MemoryAdmissionRepository::with(admission.clone()));

    assert_eq!(service.require_enabled(service_id), Ok(admission));
}

#[test]
fn a_missing_admission_record_is_denied_instead_of_assumed_enabled() {
    let service_id = ActorId::new();
    let service = AdmissionService::new(MemoryAdmissionRepository::default());

    assert_eq!(
        service.require_enabled(service_id),
        Err(AdmissionError::UnknownService(service_id))
    );
}

#[test]
fn invalid_persisted_metadata_cannot_be_restored() {
    assert_eq!(
        CommunicationAdmission::restore(ActorId::new(), true, -1, 1_000),
        Err(AdmissionError::InvalidStoredRecord)
    );
    assert_eq!(
        CommunicationAdmission::restore(ActorId::new(), true, 1, -1),
        Err(AdmissionError::InvalidStoredRecord)
    );
}
