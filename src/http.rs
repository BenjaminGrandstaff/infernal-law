//! Goal: translate bounded HTTP requests into typed service operations without
//! containing governance-domain behavior or exposing authentication secrets.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::infrastructure::http_policy_evaluator::HttpPolicyEvaluator;
use crate::infrastructure::kubernetes_token_reviewer::KubernetesTokenReviewer;
use crate::infrastructure::postgres_authority_repository::PostgresAuthorityRepository;
use crate::kernel::authority::{
    AuthorityDecision, AuthorityDecisionRecorder, AuthorityError, AuthorityRepository,
    AuthorityService, PolicyEvaluator, PolicyFacts, SchemaRepository, SchemaService, Scope,
    no_artifact_schema_versions,
};
use crate::kernel::enrollment::{
    EnrollmentBindingRepository, EnrollmentError, EnrollmentRequest, EnrollmentService,
    WorkloadTokenReviewer,
};
use crate::kernel::identity::ActorId;
use crate::kernel::instance_keys::InstancePublicKey;
use crate::kernel::instance_registry::{InstanceRegistryRepository, RegisteredInstance};
use crate::kernel::request_gate::{
    AdmittedServiceRequest, ServiceRequestGate, ServiceRequestGateError,
};
use crate::kernel::requests::{
    ActionName, RequestAcceptance, RequestError, RequestId, RequestRepository, RequestService,
};
use crate::kernel::service_requests::{
    ServiceRequestAuthenticationError, ServiceRequestParts, SignedServiceRequest,
};
use crate::kernel::subscriptions::{
    SubscriptionError, SubscriptionId, SubscriptionRepository, SubscriptionService,
};
use crate::kernel::{admission::AdmissionError, replay_protection::ReplayProtectionError};
use crate::wiring::Application;

use self::enrollment_dto::{
    EnrollmentErrorResponse, EnrollmentSubmissionRequest, EnrollmentSuccessResponse,
};
use self::request_dto::{AcceptedRequestResponse, SubmitRequestRequest};
use self::schema_dto::{PublishSchemaRequest, SchemaVersionResponse};
use self::subscription_dto::{
    CreateSubscriptionRequest, SubscriptionListResponse, SubscriptionResponse,
};

pub mod enrollment_dto;
pub mod request_dto;
pub mod schema_dto;
pub mod subscription_dto;

const DEFAULT_ADDRESS: &str = "0.0.0.0";
const DEFAULT_PORT: &str = "8080";
const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_ENROLLMENT_BODY_BYTES: usize = 40 * 1024;
const POLICY_EVALUATOR_AUTHORITY_ENV: &str = "POLICY_EVALUATOR_AUTHORITY";
const POLICY_EVALUATOR_ID_ENV: &str = "POLICY_EVALUATOR_ID";

#[derive(Debug, Eq, PartialEq)]
pub struct Response {
    pub status: &'static str,
    pub content_type: &'static str,
    pub body: String,
}

pub struct GovernedHttpRequest<'a> {
    pub method: &'a str,
    pub authority: &'a str,
    pub path_and_query: &'a str,
    pub content_type: &'a str,
    pub body: &'a [u8],
    pub service_id: &'a str,
    pub instance_id: &'a str,
    pub request_id: &'a str,
    pub content_digest: &'a str,
    pub signature_input: &'a str,
    pub signature: &'a str,
}

impl GovernedHttpRequest<'_> {
    fn into_signed(self) -> Result<SignedServiceRequest, ServiceRequestAuthenticationError> {
        let request_id = self
            .request_id
            .parse()
            .map_err(|_| ServiceRequestAuthenticationError::Malformed)?;
        let parts = ServiceRequestParts::new(
            self.method,
            self.authority,
            self.path_and_query,
            self.content_type,
            self.body,
            request_id,
        )?;
        SignedServiceRequest::from_wire(
            parts,
            self.service_id,
            self.instance_id,
            self.content_digest,
            self.signature_input,
            self.signature,
        )
    }
}

pub trait GovernedRequestAuthenticator {
    fn authenticate_governed(
        &self,
        request: &SignedServiceRequest,
        now: i64,
    ) -> Result<AdmittedServiceRequest, ServiceRequestGateError>;
}

impl<V, P, A> GovernedRequestAuthenticator for ServiceRequestGate<V, P, A>
where
    V: crate::kernel::request_gate::SignatureVerification,
    P: crate::kernel::request_gate::ReplayReservation,
    A: crate::kernel::request_gate::CommunicationAdmissionCheck,
{
    fn authenticate_governed(
        &self,
        request: &SignedServiceRequest,
        now: i64,
    ) -> Result<AdmittedServiceRequest, ServiceRequestGateError> {
        self.admit(request, now)
    }
}

pub fn authenticate_governed_request<A>(
    request: GovernedHttpRequest<'_>,
    authenticator: &A,
    now: i64,
) -> Result<AdmittedServiceRequest, Response>
where
    A: GovernedRequestAuthenticator,
{
    let signed = request
        .into_signed()
        .map_err(|_| authentication_rejected())?;
    authenticator
        .authenticate_governed(&signed, now)
        .map_err(gate_error_response)
}

pub trait EnrollmentAuthenticator {
    fn authenticate(
        &self,
        request: EnrollmentRequest,
        now: i64,
    ) -> Result<RegisteredInstance, EnrollmentError>;
}

impl<A, B, R> EnrollmentAuthenticator for EnrollmentService<A, B, R>
where
    A: WorkloadTokenReviewer,
    B: EnrollmentBindingRepository,
    R: InstanceRegistryRepository,
{
    fn authenticate(
        &self,
        request: EnrollmentRequest,
        now: i64,
    ) -> Result<RegisteredInstance, EnrollmentError> {
        self.authenticate_and_register(request, now)
    }
}

/// Gates a governed administrative action (one that changes state, not a
/// read of the caller's own data) behind ILK-002 Authority. Subscription
/// management has no artifact content to pin a real schema version to, so
/// every call here uses [`no_artifact_schema_versions`] -- see that
/// constant's documentation for why, and for the still-open gaps that keep
/// this fail-closed against a real Postgres backend today.
pub trait SubscriptionAuthorizer {
    fn authorize_subscription_action(
        &self,
        service_id: ActorId,
        action: &str,
        now: i64,
    ) -> Result<AuthorityDecision, AuthorityError>;
}

impl<R, E, D> SubscriptionAuthorizer for AuthorityService<R, E, D>
where
    R: AuthorityRepository,
    E: PolicyEvaluator,
    D: AuthorityDecisionRecorder,
{
    fn authorize_subscription_action(
        &self,
        service_id: ActorId,
        action: &str,
        now: i64,
    ) -> Result<AuthorityDecision, AuthorityError> {
        let action = ActionName::new(action)
            .unwrap_or_else(|_| panic!("subscription action {action:?} must be a valid literal"));
        let facts = PolicyFacts::for_request_acceptance(
            service_id,
            action,
            Scope::wildcard(),
            no_artifact_schema_versions(),
        );
        self.authorize(facts, now)
    }
}

/// Gates ILK-003 request submission behind a real ILK-002 authority
/// decision, built by the caller from the request's own action, scope, and
/// schema versions. Unlike [`SubscriptionAuthorizer`], this is exactly the
/// artifact-bearing case ILK-002's schema-version machinery exists for, so
/// no `no_artifact_schema_versions` sentinel is involved.
pub trait RequestAuthorizer {
    fn authorize_request(
        &self,
        facts: PolicyFacts,
        now: i64,
    ) -> Result<AuthorityDecision, AuthorityError>;
}

impl<R, E, D> RequestAuthorizer for AuthorityService<R, E, D>
where
    R: AuthorityRepository,
    E: PolicyEvaluator,
    D: AuthorityDecisionRecorder,
{
    fn authorize_request(
        &self,
        facts: PolicyFacts,
        now: i64,
    ) -> Result<AuthorityDecision, AuthorityError> {
        self.authorize(facts, now)
    }
}

pub fn serve(application: Application) -> std::io::Result<()> {
    let address = env::var("BIND_ADDRESS").unwrap_or_else(|_| DEFAULT_ADDRESS.to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| DEFAULT_PORT.to_owned());
    let listener = TcpListener::bind(format!("{address}:{port}"))?;

    println!("infernal-law listening on {address}:{port}");

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let application = application.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &application) {
                        eprintln!("request failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("connection failed: {error}"),
        }
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream, application: &Application) -> std::io::Result<()> {
    let response = match read_request(&mut stream) {
        Ok(request) => dispatch(request, application),
        Err(RequestReadError::PayloadTooLarge) => json_error(
            "413 Payload Too Large",
            EnrollmentErrorResponse::malformed_request(),
        ),
        Err(RequestReadError::Malformed) => json_error(
            "400 Bad Request",
            EnrollmentErrorResponse::malformed_request(),
        ),
    };
    write_response(&mut stream, &response)
}

fn dispatch(request: ParsedRequest, application: &Application) -> Response {
    if request.path == "/v1/enrollments" {
        if request.method != "POST" {
            return text_response("405 Method Not Allowed", "method not allowed\n");
        }
        let enrollment_request =
            match parse_enrollment_request(request.content_type.as_deref(), &request.body) {
                Ok(request) => request,
                Err(response) => return response,
            };
        let reviewer = match KubernetesTokenReviewer::from_env() {
            Ok(reviewer) => reviewer,
            Err(error) => {
                return json_error(
                    "503 Service Unavailable",
                    EnrollmentErrorResponse::from_enrollment_error(&error),
                );
            }
        };
        let service = application.enrollment_service(reviewer);
        return authenticate_enrollment(enrollment_request, &service, unix_time());
    }

    if is_governed_route(&request.path) {
        if !is_supported_governed_method(&request.method, &request.path) {
            return text_response("405 Method Not Allowed", "method not allowed\n");
        }
        let governed = match request.as_governed() {
            Some(request) => request,
            None => return authentication_rejected(),
        };
        let gate = application.service_request_gate();
        let admitted = match authenticate_governed_request(governed, &gate, unix_time()) {
            Ok(admitted) => admitted,
            Err(response) => return response,
        };
        let verified = admitted.verified();
        let service_id = verified.service_id();
        let path = request.path.split('?').next().unwrap_or(&request.path);
        if path == "/v1/authority/schemas" {
            return publish_schema(&request, service_id, application.schemas());
        }
        let authority = match policy_evaluator_from_env(application) {
            Ok(authority) => authority,
            Err(response) => return response,
        };
        if path == "/v1/requests" || path.starts_with("/v1/requests/") {
            let envelope_request_id = RequestId::from_uuid(verified.request_id());
            return request_route(
                &request,
                service_id,
                envelope_request_id,
                application.requests(),
                &authority,
            );
        }
        return subscription_route(
            &request,
            service_id,
            application.subscriptions(),
            &authority,
        );
    }

    if request.path == "/health/ready" {
        return readiness_response(application.database().check_connection().is_ok());
    }

    if request.path == "/v1/kernel-identity" {
        if request.method != "GET" {
            return text_response("405 Method Not Allowed", "method not allowed\n");
        }
        return json_response(
            "200 OK",
            &KernelIdentityResponse::from(application.instance_public_key()),
        );
    }

    route(&request.path)
}

/// Deliberately unauthenticated (ADR-0014): a public key is not confidential,
/// and a caller cannot authenticate to the kernel via a mechanism that
/// itself depends on already knowing the kernel's key. Publishes only this
/// process's own signing material — never another service's keys or any
/// administrative state.
#[derive(serde::Serialize)]
struct KernelIdentityResponse {
    algorithm: &'static str,
    instance_id: String,
    key_id: String,
    public_key: String,
    fingerprint: String,
}

impl From<&InstancePublicKey> for KernelIdentityResponse {
    fn from(key: &InstancePublicKey) -> Self {
        Self {
            algorithm: key.algorithm(),
            instance_id: key.instance_id().to_string(),
            key_id: key.key_id().to_string(),
            public_key: URL_SAFE_NO_PAD.encode(key.public_key_bytes()),
            fingerprint: URL_SAFE_NO_PAD.encode(key.fingerprint()),
        }
    }
}

#[derive(serde::Serialize)]
struct GovernedErrorResponse {
    code: &'static str,
    message: &'static str,
}

impl GovernedErrorResponse {
    const fn authentication_rejected() -> Self {
        Self {
            code: "request_rejected",
            message: "request authentication failed",
        }
    }

    const fn communication_disabled() -> Self {
        Self {
            code: "communication_disabled",
            message: "service communication is disabled",
        }
    }

    const fn unavailable() -> Self {
        Self {
            code: "security_boundary_unavailable",
            message: "request security checks are unavailable",
        }
    }

    const fn invalid_subscription_request() -> Self {
        Self {
            code: "invalid_subscription_request",
            message: "subscription request is invalid",
        }
    }

    const fn subscription_not_found() -> Self {
        Self {
            code: "subscription_not_found",
            message: "subscription was not found",
        }
    }

    const fn subscription_conflict() -> Self {
        Self {
            code: "subscription_conflict",
            message: "subscription already exists in that state",
        }
    }

    const fn internal_error() -> Self {
        Self {
            code: "internal_error",
            message: "request could not be completed",
        }
    }

    const fn subscription_not_authorized() -> Self {
        Self {
            code: "subscription_not_authorized",
            message: "subscription action is not authorized",
        }
    }

    const fn invalid_schema_request() -> Self {
        Self {
            code: "invalid_schema_request",
            message: "schema request is invalid",
        }
    }

    const fn schema_namespace_conflict() -> Self {
        Self {
            code: "schema_namespace_conflict",
            message: "schema name is owned by a different service",
        }
    }

    const fn invalid_request() -> Self {
        Self {
            code: "invalid_request",
            message: "request submission is invalid",
        }
    }

    const fn request_conflict() -> Self {
        Self {
            code: "request_conflict",
            message: "request ID is bound to different content",
        }
    }

    const fn request_not_found() -> Self {
        Self {
            code: "request_not_found",
            message: "request was not found",
        }
    }

    const fn request_not_authorized() -> Self {
        Self {
            code: "request_not_authorized",
            message: "request is not authorized",
        }
    }
}

fn authentication_rejected() -> Response {
    json_response(
        "401 Unauthorized",
        &GovernedErrorResponse::authentication_rejected(),
    )
}

fn gate_error_response(error: ServiceRequestGateError) -> Response {
    match error {
        ServiceRequestGateError::Admission(AdmissionError::Disabled(_)) => json_response(
            "403 Forbidden",
            &GovernedErrorResponse::communication_disabled(),
        ),
        ServiceRequestGateError::Signature(ServiceRequestAuthenticationError::Registry(
            crate::kernel::instance_registry::InstanceRegistryError::Repository(_),
        ))
        | ServiceRequestGateError::Replay(ReplayProtectionError::Repository(_))
        | ServiceRequestGateError::Admission(
            AdmissionError::Repository(_) | AdmissionError::InvalidStoredRecord,
        ) => json_response(
            "503 Service Unavailable",
            &GovernedErrorResponse::unavailable(),
        ),
        ServiceRequestGateError::Admission(AdmissionError::UnknownService(_))
        | ServiceRequestGateError::Replay(
            ReplayProtectionError::ReplayDetected
            | ReplayProtectionError::RequestIdConflict
            | ReplayProtectionError::InvalidTimestamp,
        )
        | ServiceRequestGateError::Signature(_) => authentication_rejected(),
    }
}

fn is_governed_route(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path == "/v1/subscriptions"
        || path.starts_with("/v1/subscriptions/")
        || path == "/v1/authority/schemas"
        || path == "/v1/requests"
        || path.starts_with("/v1/requests/")
}

fn is_supported_governed_method(method: &str, path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    (path == "/v1/subscriptions" && matches!(method, "GET" | "POST"))
        || (path.starts_with("/v1/subscriptions/") && method == "DELETE")
        || (path == "/v1/authority/schemas" && method == "POST")
        || (path == "/v1/requests" && method == "POST")
        || (path.starts_with("/v1/requests/") && method == "GET")
}

/// Builds the configured `HttpPolicyEvaluator`-backed authority service, or
/// a sanitized 503 if the evaluator is unconfigured or unreachable --
/// fail-closed, never an implicit allow, matching every other unreachable
/// dependency in this module.
fn policy_evaluator_from_env(
    application: &Application,
) -> Result<
    AuthorityService<
        PostgresAuthorityRepository,
        HttpPolicyEvaluator<'_>,
        PostgresAuthorityRepository,
    >,
    Response,
> {
    let unavailable = || {
        json_response(
            "503 Service Unavailable",
            &GovernedErrorResponse::internal_error(),
        )
    };
    let evaluator_authority =
        env::var(POLICY_EVALUATOR_AUTHORITY_ENV).map_err(|_| unavailable())?;
    let evaluator_id: ActorId = env::var(POLICY_EVALUATOR_ID_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(unavailable)?;
    application
        .authority_service(evaluator_authority, evaluator_id)
        .map_err(|_| unavailable())
}

/// Dispatches an already-authenticated governed request to ILK-010's
/// subscription operations. `service_id` is the caller's own verified
/// identity (`VerifiedServiceRequest::service_id`), never taken from the
/// request body, so a caller can only ever act as itself. Create and
/// disable additionally require an ILK-002 authority decision, since both
/// change governed administrative state; list is a read of the caller's own
/// data and is gated by ownership alone, matching ILK-002's own wording
/// ("before... changing governed administrative state").
fn subscription_route<R: SubscriptionRepository, A: SubscriptionAuthorizer>(
    request: &ParsedRequest,
    service_id: ActorId,
    subscriptions: &SubscriptionService<R>,
    authority: &A,
) -> Response {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    if path == "/v1/subscriptions" {
        return match request.method.as_str() {
            "POST" => create_subscription(request, service_id, subscriptions, authority),
            "GET" => list_subscriptions(&request.path, service_id, subscriptions),
            _ => text_response("405 Method Not Allowed", "method not allowed\n"),
        };
    }
    match path.strip_prefix("/v1/subscriptions/") {
        Some(id) => disable_subscription(id, service_id, subscriptions, authority),
        None => text_response("404 Not Found", "not found\n"),
    }
}

fn create_subscription<R: SubscriptionRepository, A: SubscriptionAuthorizer>(
    request: &ParsedRequest,
    service_id: ActorId,
    subscriptions: &SubscriptionService<R>,
    authority: &A,
) -> Response {
    if !request
        .content_type
        .as_deref()
        .is_some_and(is_json_content_type)
    {
        return json_response(
            "415 Unsupported Media Type",
            &GovernedErrorResponse::invalid_subscription_request(),
        );
    }
    let dto: CreateSubscriptionRequest = match serde_json::from_slice(&request.body) {
        Ok(dto) => dto,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_subscription_request(),
            );
        }
    };
    let event_type = match dto.event_type() {
        Ok(event_type) => event_type,
        Err(error) => return subscription_error_response(&error),
    };
    if let Some(response) = check_authorized(authority, service_id, "subscription.create") {
        return response;
    }
    match subscriptions.create(service_id, event_type, unix_time()) {
        Ok(subscription) => {
            json_response("201 Created", &SubscriptionResponse::from(&subscription))
        }
        Err(error) => subscription_error_response(&error),
    }
}

fn list_subscriptions<R: SubscriptionRepository>(
    path_and_query: &str,
    service_id: ActorId,
    subscriptions: &SubscriptionService<R>,
) -> Response {
    let active_only = path_and_query
        .split_once('?')
        .is_some_and(|(_, query)| query.split('&').any(|pair| pair == "active=true"));
    let result = if active_only {
        subscriptions.list_active(service_id)
    } else {
        subscriptions.list(service_id)
    };
    match result {
        Ok(values) => json_response(
            "200 OK",
            &values
                .iter()
                .map(SubscriptionResponse::from)
                .collect::<SubscriptionListResponse>(),
        ),
        Err(error) => subscription_error_response(&error),
    }
}

fn disable_subscription<R: SubscriptionRepository, A: SubscriptionAuthorizer>(
    id: &str,
    service_id: ActorId,
    subscriptions: &SubscriptionService<R>,
    authority: &A,
) -> Response {
    let subscription_id: SubscriptionId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_subscription_request(),
            );
        }
    };
    if let Some(response) = check_authorized(authority, service_id, "subscription.disable") {
        return response;
    }
    match subscriptions.disable(service_id, subscription_id, unix_time()) {
        Ok(subscription) => json_response("200 OK", &SubscriptionResponse::from(&subscription)),
        Err(error) => subscription_error_response(&error),
    }
}

/// Runs an ILK-002 authority decision for `action` and returns `Some`
/// response to short-circuit with if the caller should not proceed --
/// `None` means the caller is authorized. An unreachable or erroring
/// evaluator/repository fails closed as `503`, never as an implicit allow.
fn check_authorized<A: SubscriptionAuthorizer>(
    authority: &A,
    service_id: ActorId,
    action: &str,
) -> Option<Response> {
    match authority.authorize_subscription_action(service_id, action, unix_time()) {
        Ok(decision) if decision.is_allowed() => None,
        Ok(_) => Some(json_response(
            "403 Forbidden",
            &GovernedErrorResponse::subscription_not_authorized(),
        )),
        Err(_) => Some(json_response(
            "503 Service Unavailable",
            &GovernedErrorResponse::internal_error(),
        )),
    }
}

fn subscription_error_response(error: &SubscriptionError) -> Response {
    match error {
        SubscriptionError::InvalidEventType
        | SubscriptionError::InvalidSubscriptionId
        | SubscriptionError::InvalidTimestamp => json_response(
            "400 Bad Request",
            &GovernedErrorResponse::invalid_subscription_request(),
        ),
        SubscriptionError::NotFound(_) => json_response(
            "404 Not Found",
            &GovernedErrorResponse::subscription_not_found(),
        ),
        SubscriptionError::AlreadyDisabled(_) | SubscriptionError::DuplicateActive(_, _) => {
            json_response(
                "409 Conflict",
                &GovernedErrorResponse::subscription_conflict(),
            )
        }
        SubscriptionError::UnknownService(_) => authentication_rejected(),
        SubscriptionError::AlreadyExists(_) | SubscriptionError::Repository(_) => json_response(
            "503 Service Unavailable",
            &GovernedErrorResponse::internal_error(),
        ),
    }
}

/// Dispatches an already-authenticated governed request to ILK-003's
/// request-submission operations. `service_id` is the caller's own
/// verified identity, never a request-body field. Unlike ILK-010
/// subscription management, submission is authorized against the
/// request's own real action, scope, and schema versions -- the
/// artifact-bearing case ILK-002 was designed for.
fn request_route<R: RequestRepository, A: RequestAuthorizer>(
    request: &ParsedRequest,
    service_id: ActorId,
    envelope_request_id: RequestId,
    requests: &RequestService<R>,
    authority: &A,
) -> Response {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    if path == "/v1/requests" {
        return match request.method.as_str() {
            "POST" => submit_request(
                request,
                service_id,
                envelope_request_id,
                requests,
                authority,
            ),
            _ => text_response("405 Method Not Allowed", "method not allowed\n"),
        };
    }
    match path.strip_prefix("/v1/requests/") {
        Some(id) => find_request(id, service_id, requests),
        None => text_response("404 Not Found", "not found\n"),
    }
}

fn submit_request<R: RequestRepository, A: RequestAuthorizer>(
    request: &ParsedRequest,
    service_id: ActorId,
    envelope_request_id: RequestId,
    requests: &RequestService<R>,
    authority: &A,
) -> Response {
    if !request
        .content_type
        .as_deref()
        .is_some_and(is_json_content_type)
    {
        return json_response(
            "415 Unsupported Media Type",
            &GovernedErrorResponse::invalid_request(),
        );
    }
    let dto: SubmitRequestRequest = match serde_json::from_slice(&request.body) {
        Ok(dto) => dto,
        Err(_) => {
            return json_response("400 Bad Request", &GovernedErrorResponse::invalid_request());
        }
    };
    let submitted = match dto.into_request(service_id, envelope_request_id) {
        Ok(request) => request,
        Err(_) => {
            return json_response("400 Bad Request", &GovernedErrorResponse::invalid_request());
        }
    };
    let now = unix_time();
    let facts = PolicyFacts::for_request_acceptance(
        service_id,
        submitted.action().clone(),
        submitted.scope().clone(),
        submitted.schema_versions(),
    );
    match authority.authorize_request(facts, now) {
        Ok(decision) if decision.is_allowed() => {}
        Ok(_) => {
            return json_response(
                "403 Forbidden",
                &GovernedErrorResponse::request_not_authorized(),
            );
        }
        Err(_) => {
            return json_response(
                "503 Service Unavailable",
                &GovernedErrorResponse::internal_error(),
            );
        }
    }
    let fingerprint = submitted.fingerprint();
    match requests.accept(submitted, fingerprint) {
        Ok(RequestAcceptance::Accepted(record)) => {
            json_response("201 Created", &AcceptedRequestResponse::from(&record))
        }
        Ok(RequestAcceptance::SafeRetry(record)) => {
            json_response("200 OK", &AcceptedRequestResponse::from(&record))
        }
        Err(error) => request_error_response(&error),
    }
}

fn find_request<R: RequestRepository>(
    id: &str,
    service_id: ActorId,
    requests: &RequestService<R>,
) -> Response {
    let request_id: RequestId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return json_response("400 Bad Request", &GovernedErrorResponse::invalid_request());
        }
    };
    match requests.find(service_id, request_id) {
        Ok(Some(record)) => json_response("200 OK", &AcceptedRequestResponse::from(&record)),
        Ok(None) => json_response("404 Not Found", &GovernedErrorResponse::request_not_found()),
        Err(error) => request_error_response(&error),
    }
}

fn request_error_response(error: &RequestError) -> Response {
    match error {
        RequestError::InvalidRequestId
        | RequestError::InvalidActionName
        | RequestError::InvalidAcceptedAt => {
            json_response("400 Bad Request", &GovernedErrorResponse::invalid_request())
        }
        RequestError::RequestIdConflict(_) => {
            json_response("409 Conflict", &GovernedErrorResponse::request_conflict())
        }
        RequestError::UnknownSource(_) => authentication_rejected(),
        RequestError::UnknownSchemaVersion | RequestError::Repository(_) => json_response(
            "503 Service Unavailable",
            &GovernedErrorResponse::internal_error(),
        ),
    }
}

/// Publishes a schema version for the caller's own verified identity
/// (`VerifiedServiceRequest::service_id`), never a request-body field, so a
/// caller can only ever publish under its own ownership -- the repository
/// still enforces that a name already owned by a different service is
/// rejected (`AuthorityError::SchemaNamespaceConflict`). Publication alone
/// never activates a schema or grants its publisher permission (ILK-002).
fn publish_schema<R: SchemaRepository>(
    request: &ParsedRequest,
    service_id: ActorId,
    schemas: &SchemaService<R>,
) -> Response {
    if !request
        .content_type
        .as_deref()
        .is_some_and(is_json_content_type)
    {
        return json_response(
            "415 Unsupported Media Type",
            &GovernedErrorResponse::invalid_schema_request(),
        );
    }
    let dto: PublishSchemaRequest = match serde_json::from_slice(&request.body) {
        Ok(dto) => dto,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_schema_request(),
            );
        }
    };
    let kind = match dto.kind() {
        Ok(kind) => kind,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_schema_request(),
            );
        }
    };
    let name = match dto.name() {
        Ok(name) => name,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_schema_request(),
            );
        }
    };
    let content_digest = match dto.content_digest() {
        Ok(digest) => digest,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_schema_request(),
            );
        }
    };
    match schemas.publish(kind, name, service_id, content_digest, unix_time()) {
        Ok(record) => json_response("201 Created", &SchemaVersionResponse::from(&record)),
        Err(error) => schema_error_response(&error),
    }
}

fn schema_error_response(error: &AuthorityError) -> Response {
    match error {
        AuthorityError::InvalidSchemaName | AuthorityError::InvalidSchemaVersion => json_response(
            "400 Bad Request",
            &GovernedErrorResponse::invalid_schema_request(),
        ),
        AuthorityError::SchemaNamespaceConflict(_) => json_response(
            "409 Conflict",
            &GovernedErrorResponse::schema_namespace_conflict(),
        ),
        _ => json_response(
            "503 Service Unavailable",
            &GovernedErrorResponse::internal_error(),
        ),
    }
}

pub fn enrollment_response<A>(
    content_type: Option<&str>,
    body: &[u8],
    authenticator: &A,
    now: i64,
) -> Response
where
    A: EnrollmentAuthenticator,
{
    let request = match parse_enrollment_request(content_type, body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    authenticate_enrollment(request, authenticator, now)
}

fn parse_enrollment_request(
    content_type: Option<&str>,
    body: &[u8],
) -> Result<EnrollmentRequest, Response> {
    if body.len() > MAX_ENROLLMENT_BODY_BYTES {
        return Err(json_error(
            "413 Payload Too Large",
            EnrollmentErrorResponse::malformed_request(),
        ));
    }
    if !content_type.is_some_and(is_json_content_type) {
        return Err(json_error(
            "415 Unsupported Media Type",
            EnrollmentErrorResponse::malformed_request(),
        ));
    }
    let dto = match serde_json::from_slice::<EnrollmentSubmissionRequest>(body) {
        Ok(dto) => dto,
        Err(_) => {
            return Err(json_error(
                "400 Bad Request",
                EnrollmentErrorResponse::malformed_request(),
            ));
        }
    };
    dto.into_domain().map_err(|_| {
        json_error(
            "400 Bad Request",
            EnrollmentErrorResponse::malformed_request(),
        )
    })
}

fn authenticate_enrollment<A>(request: EnrollmentRequest, authenticator: &A, now: i64) -> Response
where
    A: EnrollmentAuthenticator,
{
    match authenticator.authenticate(request, now) {
        Ok(registered) => {
            json_response("201 Created", &EnrollmentSuccessResponse::from(&registered))
        }
        Err(error) => {
            let response = EnrollmentErrorResponse::from_enrollment_error(&error);
            let status = match response.code.as_str() {
                "enrollment_rejected" => "401 Unauthorized",
                "invalid_enrollment_request" => "400 Bad Request",
                _ => "503 Service Unavailable",
            };
            json_error(status, response)
        }
    }
}

pub fn route(path: &str) -> Response {
    match path {
        "/" => Response {
            status: "200 OK",
            content_type: "application/json",
            body: "{\"service\":\"infernal-law\"}\n".to_owned(),
        },
        "/health/live" => text_response("200 OK", "ok\n"),
        _ => text_response("404 Not Found", "not found\n"),
    }
}

pub fn readiness_response(database_ready: bool) -> Response {
    if database_ready {
        text_response("200 OK", "ok\n")
    } else {
        text_response("503 Service Unavailable", "database unavailable\n")
    }
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn json_error(status: &'static str, error: EnrollmentErrorResponse) -> Response {
    json_response(status, &error)
}

fn json_response(status: &'static str, value: &impl serde::Serialize) -> Response {
    match serde_json::to_string(value) {
        Ok(mut body) => {
            body.push('\n');
            Response {
                status,
                content_type: "application/json",
                body,
            }
        }
        Err(_) => Response {
            status: "500 Internal Server Error",
            content_type: "application/json",
            body: "{\"code\":\"internal_error\",\"message\":\"response serialization failed\"}\n"
                .to_owned(),
        },
    }
}

fn text_response(status: &'static str, body: &str) -> Response {
    Response {
        status,
        content_type: "text/plain",
        body: body.to_owned(),
    }
}

fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let serialized = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.status,
        response.content_type,
        response.body.len(),
        response.body
    );
    stream.write_all(serialized.as_bytes())
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedRequest {
    method: String,
    path: String,
    authority: Option<String>,
    content_type: Option<String>,
    content_digest: Option<String>,
    service_id: Option<String>,
    instance_id: Option<String>,
    request_id: Option<String>,
    signature_input: Option<String>,
    signature: Option<String>,
    body: Vec<u8>,
}

impl ParsedRequest {
    fn as_governed(&self) -> Option<GovernedHttpRequest<'_>> {
        Some(GovernedHttpRequest {
            method: &self.method,
            authority: self.authority.as_deref()?,
            path_and_query: &self.path,
            content_type: self.content_type.as_deref()?,
            body: &self.body,
            service_id: self.service_id.as_deref()?,
            instance_id: self.instance_id.as_deref()?,
            request_id: self.request_id.as_deref()?,
            content_digest: self.content_digest.as_deref()?,
            signature_input: self.signature_input.as_deref()?,
            signature: self.signature.as_deref()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestReadError {
    Malformed,
    PayloadTooLarge,
}

fn read_request(stream: &mut impl Read) -> Result<ParsedRequest, RequestReadError> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(position) = find_header_end(&bytes) {
            if position > MAX_HEADER_BYTES {
                return Err(RequestReadError::Malformed);
            }
            break position;
        }
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(RequestReadError::Malformed);
        }
        let mut buffer = [0_u8; 4096];
        let read = stream
            .read(&mut buffer)
            .map_err(|_| RequestReadError::Malformed)?;
        if read == 0 {
            return Err(RequestReadError::Malformed);
        }
        bytes.extend_from_slice(&buffer[..read]);
    };

    let header =
        std::str::from_utf8(&bytes[..header_end]).map_err(|_| RequestReadError::Malformed)?;
    let mut lines = header.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or(RequestReadError::Malformed)?
        .split_whitespace();
    let method = request_line
        .next()
        .ok_or(RequestReadError::Malformed)?
        .to_owned();
    let path = request_line
        .next()
        .ok_or(RequestReadError::Malformed)?
        .to_owned();
    let version = request_line.next().ok_or(RequestReadError::Malformed)?;
    if request_line.next().is_some() || version != "HTTP/1.1" || !path.starts_with('/') {
        return Err(RequestReadError::Malformed);
    }

    let mut content_length = None;
    let mut authority = None;
    let mut content_type = None;
    let mut content_digest = None;
    let mut service_id = None;
    let mut instance_id = None;
    let mut request_id = None;
    let mut signature_input = None;
    let mut signature = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(RequestReadError::Malformed)?;
        if !valid_header_name(name) {
            return Err(RequestReadError::Malformed);
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(RequestReadError::Malformed);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| RequestReadError::Malformed)?,
            );
        } else if name.eq_ignore_ascii_case("content-type") {
            set_header(&mut content_type, value)?;
        } else if name.eq_ignore_ascii_case("host") {
            set_header(&mut authority, value)?;
        } else if name.eq_ignore_ascii_case("content-digest") {
            set_header(&mut content_digest, value)?;
        } else if name.eq_ignore_ascii_case("infernal-service-id") {
            set_header(&mut service_id, value)?;
        } else if name.eq_ignore_ascii_case("infernal-instance-id") {
            set_header(&mut instance_id, value)?;
        } else if name.eq_ignore_ascii_case("infernal-request-id") {
            set_header(&mut request_id, value)?;
        } else if name.eq_ignore_ascii_case("signature-input") {
            set_header(&mut signature_input, value)?;
        } else if name.eq_ignore_ascii_case("signature") {
            set_header(&mut signature, value)?;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(RequestReadError::Malformed);
        }
    }

    let content_length = content_length.unwrap_or(0);
    if method == "POST" && path == "/v1/enrollments" && content_length == 0 {
        return Err(RequestReadError::Malformed);
    }
    if content_length > MAX_ENROLLMENT_BODY_BYTES {
        return Err(RequestReadError::PayloadTooLarge);
    }
    let body_start = header_end + 4;
    while bytes.len().saturating_sub(body_start) < content_length {
        let remaining = content_length - bytes.len().saturating_sub(body_start);
        let mut buffer = [0_u8; 4096];
        let read = stream
            .read(&mut buffer[..remaining.min(4096)])
            .map_err(|_| RequestReadError::Malformed)?;
        if read == 0 {
            return Err(RequestReadError::Malformed);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }

    Ok(ParsedRequest {
        method,
        path,
        authority,
        content_type,
        content_digest,
        service_id,
        instance_id,
        request_id,
        signature_input,
        signature,
        body: bytes[body_start..body_start + content_length].to_vec(),
    })
}

fn set_header(target: &mut Option<String>, value: &str) -> Result<(), RequestReadError> {
    if target.is_some() || value.is_empty() {
        return Err(RequestReadError::Malformed);
    }
    *target = Some(value.to_owned());
    Ok(())
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn unix_time() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::{
        KernelIdentityResponse, MAX_ENROLLMENT_BODY_BYTES, RequestReadError, read_request,
        readiness_response, route,
    };
    use crate::kernel::identity::ActorId;
    use crate::kernel::instance_keys::InstanceCredential;

    #[test]
    fn health_endpoints_are_available() {
        assert_eq!(route("/health/live").status, "200 OK");
        assert_eq!(readiness_response(true).status, "200 OK");
    }

    #[test]
    fn kernel_identity_response_publishes_only_this_processs_public_signing_material() {
        let credential = InstanceCredential::generate(ActorId::new());
        let public_key = credential.public_key();

        let response = KernelIdentityResponse::from(public_key);

        assert_eq!(response.algorithm, "ed25519");
        assert_eq!(response.instance_id, public_key.instance_id().to_string());
        assert_eq!(response.key_id, public_key.key_id().to_string());
        assert_eq!(
            response.public_key,
            URL_SAFE_NO_PAD.encode(public_key.public_key_bytes())
        );
        assert_eq!(
            response.fingerprint,
            URL_SAFE_NO_PAD.encode(public_key.fingerprint())
        );
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains("signing_key"));
    }

    #[test]
    fn readiness_fails_when_the_database_is_unavailable() {
        assert_eq!(readiness_response(false).status, "503 Service Unavailable");
    }

    #[test]
    fn unknown_routes_are_not_found() {
        assert_eq!(route("/missing").status, "404 Not Found");
    }

    #[test]
    fn parser_accepts_a_bounded_post_enrollment_request() {
        let request = b"POST /v1/enrollments HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let parsed = read_request(&mut Cursor::new(request)).unwrap();

        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/v1/enrollments");
        assert_eq!(parsed.content_type.as_deref(), Some("application/json"));
        assert_eq!(parsed.body, b"{}");
    }

    #[test]
    fn parser_rejects_an_oversized_body_before_reading_it() {
        let request = format!(
            "POST /v1/enrollments HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_ENROLLMENT_BODY_BYTES + 1
        );
        assert_eq!(
            read_request(&mut Cursor::new(request)),
            Err(RequestReadError::PayloadTooLarge)
        );
    }

    #[test]
    fn parser_collects_each_governed_security_header_once() {
        let request = b"GET /v1/subscriptions HTTP/1.1\r\nHost: kernel.example.test\r\nContent-Type: application/json\r\nContent-Digest: sha-256=:digest:\r\nInfernal-Service-Id: service\r\nInfernal-Instance-Id: instance\r\nInfernal-Request-Id: request\r\nSignature-Input: sig1=(components)\r\nSignature: sig1=:signature:\r\n\r\n";
        let parsed = read_request(&mut Cursor::new(request)).unwrap();

        assert_eq!(parsed.authority.as_deref(), Some("kernel.example.test"));
        assert_eq!(parsed.content_digest.as_deref(), Some("sha-256=:digest:"));
        assert_eq!(parsed.service_id.as_deref(), Some("service"));
        assert_eq!(parsed.instance_id.as_deref(), Some("instance"));
        assert_eq!(parsed.request_id.as_deref(), Some("request"));
        assert_eq!(parsed.signature_input.as_deref(), Some("sig1=(components)"));
        assert_eq!(parsed.signature.as_deref(), Some("sig1=:signature:"));
    }

    #[test]
    fn parser_rejects_duplicate_security_headers() {
        let request = b"GET /v1/subscriptions HTTP/1.1\r\nHost: kernel.example.test\r\nSignature: sig1=:first:\r\nSignature: sig1=:second:\r\n\r\n";

        assert_eq!(
            read_request(&mut Cursor::new(request)),
            Err(RequestReadError::Malformed)
        );
    }

    mod subscription_routes {
        use std::sync::{Arc, Mutex};

        use super::super::*;
        use crate::kernel::authority::{DecisionId, PolicyBundleVersion, Verdict};
        use crate::kernel::subscriptions::{EventType, Subscription};

        /// A `SubscriptionAuthorizer` fixture that always returns a fixed
        /// verdict, or a fixed evaluator/repository error, so the HTTP
        /// gating logic can be tested without a real `AuthorityService`.
        struct FixedAuthority(Result<bool, ()>);

        impl FixedAuthority {
            fn allow() -> Self {
                Self(Ok(true))
            }

            fn deny() -> Self {
                Self(Ok(false))
            }

            fn unavailable() -> Self {
                Self(Err(()))
            }
        }

        impl SubscriptionAuthorizer for FixedAuthority {
            fn authorize_subscription_action(
                &self,
                service_id: ActorId,
                action: &str,
                now: i64,
            ) -> Result<AuthorityDecision, AuthorityError> {
                let allowed = self
                    .0
                    .map_err(|()| AuthorityError::Evaluator("fixed authority error".to_owned()))?;
                let facts = PolicyFacts::for_request_acceptance(
                    service_id,
                    ActionName::new(action).unwrap(),
                    Scope::wildcard(),
                    no_artifact_schema_versions(),
                );
                let verdict = if allowed {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                };
                Ok(AuthorityDecision::restore(
                    DecisionId::new(),
                    facts,
                    verdict,
                    ActorId::new(),
                    Some(PolicyBundleVersion::new("test").unwrap()),
                    now,
                ))
            }
        }

        #[derive(Clone, Default)]
        struct MemorySubscriptions(Arc<Mutex<Vec<Subscription>>>);

        impl SubscriptionRepository for MemorySubscriptions {
            fn insert(&self, subscription: Subscription) -> Result<(), SubscriptionError> {
                let mut values = self.0.lock().unwrap();
                if values.iter().any(|value| {
                    value.service_id() == subscription.service_id()
                        && value.event_type() == subscription.event_type()
                        && value.is_active()
                }) {
                    return Err(SubscriptionError::DuplicateActive(
                        subscription.service_id(),
                        subscription.event_type().clone(),
                    ));
                }
                values.push(subscription);
                Ok(())
            }

            fn list_for_service(
                &self,
                service_id: ActorId,
            ) -> Result<Vec<Subscription>, SubscriptionError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|value| value.service_id() == service_id)
                    .cloned()
                    .collect())
            }

            fn list_active_for_service(
                &self,
                service_id: ActorId,
            ) -> Result<Vec<Subscription>, SubscriptionError> {
                Ok(self
                    .list_for_service(service_id)?
                    .into_iter()
                    .filter(Subscription::is_active)
                    .collect())
            }

            fn disable(
                &self,
                service_id: ActorId,
                subscription_id: SubscriptionId,
                disabled_at: i64,
            ) -> Result<Subscription, SubscriptionError> {
                let mut values = self.0.lock().unwrap();
                let value = values
                    .iter_mut()
                    .find(|value| value.id() == subscription_id && value.service_id() == service_id)
                    .ok_or(SubscriptionError::NotFound(subscription_id))?;
                if !value.is_active() {
                    return Err(SubscriptionError::AlreadyDisabled(subscription_id));
                }
                let disabled = Subscription::restore(
                    value.id(),
                    value.service_id(),
                    value.event_type().clone(),
                    value.created_at(),
                    Some(disabled_at),
                )?;
                *value = disabled.clone();
                Ok(disabled)
            }
        }

        fn parsed_request(method: &str, path: &str, body: &[u8]) -> ParsedRequest {
            ParsedRequest {
                method: method.to_owned(),
                path: path.to_owned(),
                authority: Some("kernel.example.test".to_owned()),
                content_type: Some("application/json".to_owned()),
                content_digest: None,
                service_id: None,
                instance_id: None,
                request_id: None,
                signature_input: None,
                signature: None,
                body: body.to_vec(),
            }
        }

        #[test]
        fn create_returns_201_with_the_created_subscription() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let service_id = ActorId::new();
            let request = parsed_request(
                "POST",
                "/v1/subscriptions",
                br#"{"event_type":"resource.created.v1"}"#,
            );

            let response = create_subscription(
                &request,
                service_id,
                &subscriptions,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "201 Created");
            assert!(response.body.contains("resource.created.v1"));
            assert!(response.body.contains(&service_id.to_string()));
        }

        #[test]
        fn create_rejects_a_non_json_content_type() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let mut request = parsed_request("POST", "/v1/subscriptions", b"{}");
            request.content_type = Some("text/plain".to_owned());

            let response = create_subscription(
                &request,
                ActorId::new(),
                &subscriptions,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "415 Unsupported Media Type");
        }

        #[test]
        fn create_rejects_malformed_json() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let request = parsed_request("POST", "/v1/subscriptions", b"not json");

            let response = create_subscription(
                &request,
                ActorId::new(),
                &subscriptions,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "400 Bad Request");
        }

        #[test]
        fn create_maps_an_invalid_event_type_to_400() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let request = parsed_request(
                "POST",
                "/v1/subscriptions",
                br#"{"event_type":"Not Valid"}"#,
            );

            let response = create_subscription(
                &request,
                ActorId::new(),
                &subscriptions,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "400 Bad Request");
        }

        #[test]
        fn create_maps_a_duplicate_active_subscription_to_409() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let service_id = ActorId::new();
            subscriptions
                .create(
                    service_id,
                    EventType::new("resource.created.v1").unwrap(),
                    1,
                )
                .unwrap();
            let request = parsed_request(
                "POST",
                "/v1/subscriptions",
                br#"{"event_type":"resource.created.v1"}"#,
            );

            let response = create_subscription(
                &request,
                service_id,
                &subscriptions,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "409 Conflict");
        }

        #[test]
        fn list_returns_only_the_callers_own_subscriptions() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let owner = ActorId::new();
            let other = ActorId::new();
            subscriptions
                .create(owner, EventType::new("resource.created.v1").unwrap(), 1)
                .unwrap();
            subscriptions
                .create(other, EventType::new("resource.deleted.v1").unwrap(), 1)
                .unwrap();

            let response = list_subscriptions("/v1/subscriptions", owner, &subscriptions);

            assert_eq!(response.status, "200 OK");
            assert!(response.body.contains("resource.created.v1"));
            assert!(!response.body.contains("resource.deleted.v1"));
        }

        #[test]
        fn list_with_active_query_parameter_excludes_disabled_subscriptions() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let owner = ActorId::new();
            let created = subscriptions
                .create(owner, EventType::new("resource.created.v1").unwrap(), 1)
                .unwrap();
            subscriptions.disable(owner, created.id(), 2).unwrap();

            let all = list_subscriptions("/v1/subscriptions", owner, &subscriptions);
            let active_only =
                list_subscriptions("/v1/subscriptions?active=true", owner, &subscriptions);

            assert!(all.body.contains("resource.created.v1"));
            assert_eq!(
                active_only.body,
                r#"{"subscriptions":[]}"#.to_owned() + "\n"
            );
        }

        #[test]
        fn disable_returns_the_disabled_subscription() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let owner = ActorId::new();
            let created = subscriptions
                .create(owner, EventType::new("resource.created.v1").unwrap(), 1)
                .unwrap();

            let response = disable_subscription(
                &created.id().to_string(),
                owner,
                &subscriptions,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "200 OK");
            assert!(response.body.contains("\"active\":false"));
        }

        #[test]
        fn disable_rejects_a_malformed_subscription_id() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());

            let response = disable_subscription(
                "not-a-uuid",
                ActorId::new(),
                &subscriptions,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "400 Bad Request");
        }

        #[test]
        fn disable_hides_another_services_subscription_as_not_found() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let owner = ActorId::new();
            let stranger = ActorId::new();
            let created = subscriptions
                .create(owner, EventType::new("resource.created.v1").unwrap(), 1)
                .unwrap();

            let response = disable_subscription(
                &created.id().to_string(),
                stranger,
                &subscriptions,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "404 Not Found");
        }

        #[test]
        fn route_dispatches_by_method_and_path() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let owner = ActorId::new();
            let create_request = parsed_request(
                "POST",
                "/v1/subscriptions",
                br#"{"event_type":"resource.created.v1"}"#,
            );

            let created = subscription_route(
                &create_request,
                owner,
                &subscriptions,
                &FixedAuthority::allow(),
            );
            assert_eq!(created.status, "201 Created");

            let list_request = parsed_request("GET", "/v1/subscriptions", b"");
            let listed = subscription_route(
                &list_request,
                owner,
                &subscriptions,
                &FixedAuthority::allow(),
            );
            assert_eq!(listed.status, "200 OK");

            let subscription_id = subscriptions.list(owner).unwrap()[0].id();
            let delete_request = parsed_request(
                "DELETE",
                &format!("/v1/subscriptions/{subscription_id}"),
                b"",
            );
            let disabled = subscription_route(
                &delete_request,
                owner,
                &subscriptions,
                &FixedAuthority::allow(),
            );
            assert_eq!(disabled.status, "200 OK");
        }

        #[test]
        fn create_is_forbidden_when_authority_denies() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let request = parsed_request(
                "POST",
                "/v1/subscriptions",
                br#"{"event_type":"resource.created.v1"}"#,
            );

            let response = create_subscription(
                &request,
                ActorId::new(),
                &subscriptions,
                &FixedAuthority::deny(),
            );

            assert_eq!(response.status, "403 Forbidden");
        }

        #[test]
        fn create_fails_closed_when_the_evaluator_is_unreachable() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let request = parsed_request(
                "POST",
                "/v1/subscriptions",
                br#"{"event_type":"resource.created.v1"}"#,
            );

            let response = create_subscription(
                &request,
                ActorId::new(),
                &subscriptions,
                &FixedAuthority::unavailable(),
            );

            assert_eq!(response.status, "503 Service Unavailable");
        }

        #[test]
        fn disable_is_forbidden_when_authority_denies() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let owner = ActorId::new();
            let created = subscriptions
                .create(owner, EventType::new("resource.created.v1").unwrap(), 1)
                .unwrap();

            let response = disable_subscription(
                &created.id().to_string(),
                owner,
                &subscriptions,
                &FixedAuthority::deny(),
            );

            assert_eq!(response.status, "403 Forbidden");
        }

        #[test]
        fn disable_fails_closed_when_the_evaluator_is_unreachable() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let owner = ActorId::new();
            let created = subscriptions
                .create(owner, EventType::new("resource.created.v1").unwrap(), 1)
                .unwrap();

            let response = disable_subscription(
                &created.id().to_string(),
                owner,
                &subscriptions,
                &FixedAuthority::unavailable(),
            );

            assert_eq!(response.status, "503 Service Unavailable");
        }

        #[test]
        fn a_denied_disable_does_not_mutate_the_subscription() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let owner = ActorId::new();
            let created = subscriptions
                .create(owner, EventType::new("resource.created.v1").unwrap(), 1)
                .unwrap();

            disable_subscription(
                &created.id().to_string(),
                owner,
                &subscriptions,
                &FixedAuthority::deny(),
            );

            assert!(subscriptions.list_active(owner).unwrap()[0].is_active());
        }
    }

    mod schema_routes {
        use std::sync::{Arc, Mutex};

        use super::super::*;
        use crate::kernel::authority::{SchemaName, SchemaRecord, SchemaVersion, SchemaVersionId};

        #[derive(Clone, Default)]
        struct MemorySchemas(Arc<Mutex<Vec<SchemaRecord>>>);

        impl SchemaRepository for MemorySchemas {
            fn publish(
                &self,
                kind: crate::kernel::authority::SchemaKind,
                name: SchemaName,
                owner: ActorId,
                content_digest: crate::kernel::authority::ContentDigest,
                published_at: i64,
            ) -> Result<SchemaRecord, AuthorityError> {
                let mut records = self.0.lock().unwrap();
                let latest = records
                    .iter()
                    .filter(|record| {
                        record.version().kind() == kind && record.version().name() == &name
                    })
                    .max_by_key(|record| record.version().version());
                if let Some(latest) = latest {
                    if latest.version().owner() != owner {
                        return Err(AuthorityError::SchemaNamespaceConflict(name));
                    }
                }
                let next_version = latest.map_or(1, |record| record.version().version() + 1);
                let predecessor = latest.map(|record| record.version().id());
                let version = SchemaVersion::restore(
                    SchemaVersionId::new(),
                    kind,
                    name,
                    next_version,
                    owner,
                    content_digest,
                    predecessor,
                    published_at,
                )?;
                let record = SchemaRecord::restore(
                    version,
                    crate::kernel::authority::SchemaStatus::Published,
                );
                records.push(record.clone());
                Ok(record)
            }

            fn find(
                &self,
                kind: crate::kernel::authority::SchemaKind,
                name: &SchemaName,
                version: i64,
            ) -> Result<Option<SchemaRecord>, AuthorityError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|record| {
                        record.version().kind() == kind
                            && record.version().name() == name
                            && record.version().version() == version
                    })
                    .cloned())
            }
        }

        fn parsed_request(body: &[u8]) -> ParsedRequest {
            ParsedRequest {
                method: "POST".to_owned(),
                path: "/v1/authority/schemas".to_owned(),
                authority: Some("kernel.example.test".to_owned()),
                content_type: Some("application/json".to_owned()),
                content_digest: None,
                service_id: None,
                instance_id: None,
                request_id: None,
                signature_input: None,
                signature: None,
                body: body.to_vec(),
            }
        }

        #[test]
        fn publish_returns_201_with_the_published_record() {
            let schemas = SchemaService::new(MemorySchemas::default());
            let owner = ActorId::new();
            let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1_u8; 32]);
            let request = parsed_request(
                format!(
                    r#"{{"kind":"artifact","name":"billing.invoice","content_digest":"{digest}"}}"#
                )
                .as_bytes(),
            );

            let response = publish_schema(&request, owner, &schemas);

            assert_eq!(response.status, "201 Created");
            assert!(response.body.contains("billing.invoice"));
            assert!(response.body.contains(&owner.to_string()));
            assert!(response.body.contains("\"version\":1"));
        }

        #[test]
        fn publish_rejects_a_non_json_content_type() {
            let schemas = SchemaService::new(MemorySchemas::default());
            let mut request = parsed_request(b"{}");
            request.content_type = Some("text/plain".to_owned());

            let response = publish_schema(&request, ActorId::new(), &schemas);

            assert_eq!(response.status, "415 Unsupported Media Type");
        }

        #[test]
        fn publish_rejects_an_invalid_content_digest() {
            let schemas = SchemaService::new(MemorySchemas::default());
            let request = parsed_request(
                br#"{"kind":"artifact","name":"billing.invoice","content_digest":"AA"}"#,
            );

            let response = publish_schema(&request, ActorId::new(), &schemas);

            assert_eq!(response.status, "400 Bad Request");
        }

        #[test]
        fn publish_second_version_uses_the_callers_ownership() {
            let schemas = SchemaService::new(MemorySchemas::default());
            let owner = ActorId::new();
            let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2_u8; 32]);
            let request = parsed_request(
                format!(
                    r#"{{"kind":"artifact","name":"billing.invoice","content_digest":"{digest}"}}"#
                )
                .as_bytes(),
            );
            publish_schema(&request, owner, &schemas);

            let response = publish_schema(&request, owner, &schemas);

            assert_eq!(response.status, "201 Created");
            assert!(response.body.contains("\"version\":2"));
        }

        #[test]
        fn publish_rejects_a_different_owner_for_an_existing_name() {
            let schemas = SchemaService::new(MemorySchemas::default());
            let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3_u8; 32]);
            let request = parsed_request(
                format!(
                    r#"{{"kind":"artifact","name":"billing.invoice","content_digest":"{digest}"}}"#
                )
                .as_bytes(),
            );
            publish_schema(&request, ActorId::new(), &schemas);

            let response = publish_schema(&request, ActorId::new(), &schemas);

            assert_eq!(response.status, "409 Conflict");
        }
    }

    mod request_routes {
        use std::sync::{Arc, Mutex};

        use super::super::*;
        use crate::kernel::authority::{
            DecisionId, PolicyBundleVersion, SchemaVersionId, SchemaVersionRefs, Verdict,
        };
        use crate::kernel::requests::{AcceptedRequest, Request};

        #[derive(Clone, Default)]
        struct MemoryRequests(Arc<Mutex<Vec<AcceptedRequest>>>);

        impl RequestRepository for MemoryRequests {
            fn accept(
                &self,
                request: Request,
                fingerprint: crate::kernel::requests::RequestFingerprint,
            ) -> Result<RequestAcceptance, RequestError> {
                let mut records = self.0.lock().unwrap();
                if let Some(stored) = records
                    .iter()
                    .find(|record| record.request().id() == request.id())
                {
                    return if stored.request() == &request && stored.fingerprint() == fingerprint {
                        Ok(RequestAcceptance::SafeRetry(stored.clone()))
                    } else {
                        Err(RequestError::RequestIdConflict(request.id()))
                    };
                }
                let record = AcceptedRequest::restore(request, fingerprint, records.len() as i64)?;
                records.push(record.clone());
                Ok(RequestAcceptance::Accepted(record))
            }

            fn find(
                &self,
                source_service: ActorId,
                request_id: RequestId,
            ) -> Result<Option<AcceptedRequest>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|record| {
                        record.request().source_service() == source_service
                            && record.request().id() == request_id
                    })
                    .cloned())
            }
        }

        struct FixedAuthority(Result<bool, ()>);

        impl FixedAuthority {
            fn allow() -> Self {
                Self(Ok(true))
            }

            fn deny() -> Self {
                Self(Ok(false))
            }

            fn unavailable() -> Self {
                Self(Err(()))
            }
        }

        impl RequestAuthorizer for FixedAuthority {
            fn authorize_request(
                &self,
                facts: PolicyFacts,
                now: i64,
            ) -> Result<AuthorityDecision, AuthorityError> {
                let allowed = self
                    .0
                    .map_err(|()| AuthorityError::Evaluator("fixed authority error".to_owned()))?;
                let verdict = if allowed {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                };
                Ok(AuthorityDecision::restore(
                    DecisionId::new(),
                    facts,
                    verdict,
                    ActorId::new(),
                    Some(PolicyBundleVersion::new("test").unwrap()),
                    now,
                ))
            }
        }

        fn submission_body() -> String {
            format!(
                r#"{{"action":"billing.invoice.submit","scope":"invoice-4471","artifact_schema_version_id":"{}","permission_policy_schema_version_id":"{}"}}"#,
                SchemaVersionId::new(),
                SchemaVersionId::new(),
            )
        }

        fn parsed_request(method: &str, path: &str, body: &[u8]) -> ParsedRequest {
            ParsedRequest {
                method: method.to_owned(),
                path: path.to_owned(),
                authority: Some("kernel.example.test".to_owned()),
                content_type: Some("application/json".to_owned()),
                content_digest: None,
                service_id: None,
                instance_id: None,
                request_id: None,
                signature_input: None,
                signature: None,
                body: body.to_vec(),
            }
        }

        #[test]
        fn submit_returns_201_with_the_accepted_request() {
            let requests = RequestService::new(MemoryRequests::default());
            let service_id = ActorId::new();
            let request = parsed_request("POST", "/v1/requests", submission_body().as_bytes());

            let response = submit_request(
                &request,
                service_id,
                RequestId::new(),
                &requests,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "201 Created");
            assert!(response.body.contains("billing.invoice.submit"));
            assert!(response.body.contains(&service_id.to_string()));
        }

        #[test]
        fn submit_retrying_under_the_same_envelope_request_id_returns_200() {
            let requests = RequestService::new(MemoryRequests::default());
            let service_id = ActorId::new();
            let body = submission_body();
            let request = parsed_request("POST", "/v1/requests", body.as_bytes());
            let envelope_request_id = RequestId::new();
            let first = submit_request(
                &request,
                service_id,
                envelope_request_id,
                &requests,
                &FixedAuthority::allow(),
            );
            assert_eq!(first.status, "201 Created");

            let retry = submit_request(
                &request,
                service_id,
                envelope_request_id,
                &requests,
                &FixedAuthority::allow(),
            );

            assert_eq!(retry.status, "200 OK");
        }

        #[test]
        fn submit_is_forbidden_when_authority_denies() {
            let requests = RequestService::new(MemoryRequests::default());
            let request = parsed_request("POST", "/v1/requests", submission_body().as_bytes());

            let response = submit_request(
                &request,
                ActorId::new(),
                RequestId::new(),
                &requests,
                &FixedAuthority::deny(),
            );

            assert_eq!(response.status, "403 Forbidden");
        }

        #[test]
        fn submit_fails_closed_when_the_evaluator_is_unreachable() {
            let requests = RequestService::new(MemoryRequests::default());
            let request = parsed_request("POST", "/v1/requests", submission_body().as_bytes());

            let response = submit_request(
                &request,
                ActorId::new(),
                RequestId::new(),
                &requests,
                &FixedAuthority::unavailable(),
            );

            assert_eq!(response.status, "503 Service Unavailable");
        }

        #[test]
        fn submit_rejects_a_non_json_content_type() {
            let requests = RequestService::new(MemoryRequests::default());
            let mut request = parsed_request("POST", "/v1/requests", b"{}");
            request.content_type = Some("text/plain".to_owned());

            let response = submit_request(
                &request,
                ActorId::new(),
                RequestId::new(),
                &requests,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "415 Unsupported Media Type");
        }

        #[test]
        fn submit_rejects_malformed_json() {
            let requests = RequestService::new(MemoryRequests::default());
            let request = parsed_request("POST", "/v1/requests", b"not json");

            let response = submit_request(
                &request,
                ActorId::new(),
                RequestId::new(),
                &requests,
                &FixedAuthority::allow(),
            );

            assert_eq!(response.status, "400 Bad Request");
        }

        #[test]
        fn find_returns_the_callers_own_accepted_request() {
            let requests = RequestService::new(MemoryRequests::default());
            let service_id = ActorId::new();
            let submitted = Request::create(
                service_id,
                "billing.invoice.submit",
                Scope::new("invoice-4471").unwrap(),
                SchemaVersionRefs::new(SchemaVersionId::new(), SchemaVersionId::new()),
            )
            .unwrap();
            let fingerprint = submitted.fingerprint();
            let accepted = requests.accept(submitted, fingerprint).unwrap();
            let request_id = accepted.record().request().id();

            let response = find_request(&request_id.to_string(), service_id, &requests);

            assert_eq!(response.status, "200 OK");
            assert!(response.body.contains("billing.invoice.submit"));
        }

        #[test]
        fn find_hides_another_services_request_as_not_found() {
            let requests = RequestService::new(MemoryRequests::default());
            let owner = ActorId::new();
            let stranger = ActorId::new();
            let accepted = requests
                .accept(
                    Request::create(
                        owner,
                        "billing.invoice.submit",
                        Scope::new("invoice-4471").unwrap(),
                        SchemaVersionRefs::new(SchemaVersionId::new(), SchemaVersionId::new()),
                    )
                    .unwrap(),
                    Request::create(
                        owner,
                        "billing.invoice.submit",
                        Scope::new("invoice-4471").unwrap(),
                        SchemaVersionRefs::new(SchemaVersionId::new(), SchemaVersionId::new()),
                    )
                    .unwrap()
                    .fingerprint(),
                )
                .unwrap();

            let response = find_request(
                &accepted.record().request().id().to_string(),
                stranger,
                &requests,
            );

            assert_eq!(response.status, "404 Not Found");
        }

        #[test]
        fn find_rejects_a_malformed_request_id() {
            let requests = RequestService::new(MemoryRequests::default());

            let response = find_request("not-a-uuid", ActorId::new(), &requests);

            assert_eq!(response.status, "400 Bad Request");
        }

        #[test]
        fn route_dispatches_by_method_and_path() {
            let requests = RequestService::new(MemoryRequests::default());
            let service_id = ActorId::new();
            let submit_req = parsed_request("POST", "/v1/requests", submission_body().as_bytes());

            let submitted = request_route(
                &submit_req,
                service_id,
                RequestId::new(),
                &requests,
                &FixedAuthority::allow(),
            );
            assert_eq!(submitted.status, "201 Created");

            let probe = Request::create(
                service_id,
                "noop.probe",
                Scope::wildcard(),
                no_artifact_schema_versions(),
            )
            .unwrap();
            let probe_fingerprint = probe.fingerprint();
            let request_id = requests
                .accept(probe, probe_fingerprint)
                .unwrap()
                .record()
                .request()
                .id();

            let find_req = parsed_request("GET", &format!("/v1/requests/{request_id}"), b"");
            let found = request_route(
                &find_req,
                service_id,
                RequestId::new(),
                &requests,
                &FixedAuthority::allow(),
            );
            assert_eq!(found.status, "200 OK");
        }
    }
}
