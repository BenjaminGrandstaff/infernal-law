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
use crate::kernel::instance_keys::{InstanceId, InstancePublicKey};
use crate::kernel::instance_registry::{InstanceRegistryRepository, RegisteredInstance};
use crate::kernel::request_gate::{
    AdmittedServiceRequest, ServiceRequestGate, ServiceRequestGateError,
};
use crate::kernel::requests::{
    AcceptedRequest, ActionName, RequestAcceptance, RequestError, RequestId, RequestRepository,
    RequestService, Route, RouteId, RouteRepository, RouteService,
};
use crate::kernel::service_requests::{
    ServiceRequestAuthenticationError, ServiceRequestParts, SignedServiceRequest,
};
use crate::kernel::subscriptions::{
    DeliveryMode, EventType, SubscriptionError, SubscriptionId, SubscriptionRepository,
    SubscriptionService,
};
use crate::kernel::work_claims::{ClaimId, WorkClaimError, WorkClaimRepository, WorkClaimService};
use crate::kernel::{admission::AdmissionError, replay_protection::ReplayProtectionError};
use crate::wiring::Application;

use self::enrollment_dto::{
    EnrollmentErrorResponse, EnrollmentSubmissionRequest, EnrollmentSuccessResponse,
};
use self::request_dto::{AcceptedRequestResponse, SubmitRequestRequest};
use self::route_dto::{EligibleRouteListResponse, RouteResponse};
use self::schema_dto::{PublishSchemaRequest, SchemaVersionResponse};
use self::subscription_dto::{
    CreateSubscriptionRequest, SubscriptionListResponse, SubscriptionResponse,
};
use self::work_claim_dto::{ClaimRequest, FencedActionRequest, RenewRequest, WorkClaimResponse};

pub mod enrollment_dto;
pub mod request_dto;
pub mod route_dto;
pub mod schema_dto;
pub mod subscription_dto;
pub mod work_claim_dto;

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

/// Materializes ILK-010 routes for an accepted request -- the bridge
/// between ILK-003 (owns the request and its routes) and ILK-010 (owns
/// subscription matching), composed here rather than having either kernel
/// module depend on the other's repository. This is deliberately the
/// minimum slice: only currently-active inclusive subscriptions are
/// considered (matched directly against the subscription's own
/// `EventType`, reused as-is for the request's action rather than a
/// separate typed field); a subscription committed *after* this call
/// will not retroactively see this request until a later backlog-matching
/// slice exists.
pub trait RequestRouter {
    fn materialize_routes(
        &self,
        source_service: ActorId,
        request_id: RequestId,
        action: &ActionName,
        now: i64,
    ) -> Result<Vec<Route>, RequestError>;
}

pub struct SubscriptionRouter<'a, S, RR> {
    subscriptions: &'a SubscriptionService<S>,
    routes: &'a RouteService<RR>,
}

impl<'a, S, RR> SubscriptionRouter<'a, S, RR> {
    pub const fn new(
        subscriptions: &'a SubscriptionService<S>,
        routes: &'a RouteService<RR>,
    ) -> Self {
        Self {
            subscriptions,
            routes,
        }
    }
}

impl<S, RR> RequestRouter for SubscriptionRouter<'_, S, RR>
where
    S: SubscriptionRepository,
    RR: RouteRepository,
{
    fn materialize_routes(
        &self,
        source_service: ActorId,
        request_id: RequestId,
        action: &ActionName,
        now: i64,
    ) -> Result<Vec<Route>, RequestError> {
        let event_type = EventType::new(action.as_str())
            .map_err(|_| RequestError::Repository("action is not a valid event type".to_owned()))?;
        let matching = self
            .subscriptions
            .find_active_by_event_type(&event_type)
            .map_err(|error| RequestError::Repository(error.to_string()))?;
        matching
            .into_iter()
            .filter(|subscription| matches!(subscription.delivery_mode(), DeliveryMode::Inclusive))
            .map(|subscription| {
                self.routes.materialize(
                    source_service,
                    request_id,
                    subscription.id(),
                    subscription.service_id(),
                    now,
                )
            })
            .collect()
    }
}

/// Answers the one read an external scheduler needs before it can propose
/// a claim (ADR-0011): which of the caller's own routes are still
/// unclaimed. Composes ILK-003's route listing with ILK-011's active-claim
/// check without either kernel module depending on the other's
/// repository, the same way `SubscriptionRouter` composes ILK-010 and
/// ILK-003. The caller's own verified identity is always the destination
/// queried -- never a request parameter -- so this exposes no route
/// belonging to another service.
struct EligibleRouteQuery<'a, RR, WR> {
    routes: &'a RouteService<RR>,
    work_claims: &'a WorkClaimService<WR>,
}

impl<'a, RR, WR> EligibleRouteQuery<'a, RR, WR> {
    const fn new(routes: &'a RouteService<RR>, work_claims: &'a WorkClaimService<WR>) -> Self {
        Self {
            routes,
            work_claims,
        }
    }
}

impl<RR, WR> EligibleRouteQuery<'_, RR, WR>
where
    RR: RouteRepository,
    WR: WorkClaimRepository,
{
    fn eligible_for(
        &self,
        destination_service: ActorId,
        now: i64,
    ) -> Result<Vec<Route>, RequestError> {
        let routes = self.routes.list_for_destination(destination_service)?;
        let route_ids: Vec<RouteId> = routes.iter().map(Route::id).collect();
        let claimed = self
            .work_claims
            .active_route_ids(&route_ids, now)
            .map_err(|error| RequestError::Repository(error.to_string()))?;
        Ok(routes
            .into_iter()
            .filter(|route| !claimed.contains(&route.id()))
            .collect())
    }
}

/// Resolves the Request behind a materialized route, but only for the
/// route's own destination service -- the worker that claimed it, or
/// could claim it. A route alone names a request ID; until this
/// composition existed, nothing let the destination service actually read
/// what that request asked for (`GET /v1/requests/{id}` is intentionally
/// scoped to the request's *source* service only). Composes ILK-003's own
/// route and request lookups without either depending on the other's
/// repository, the same compositional style as `EligibleRouteQuery` and
/// `SubscriptionRouter`. A route that does not exist, or is not assigned
/// to the caller, is indistinguishable from a request that does not
/// exist -- the same ownership-hiding convention used everywhere else in
/// this module.
struct RoutedRequestQuery<'a, RR, RQ> {
    routes: &'a RouteService<RR>,
    requests: &'a RequestService<RQ>,
}

impl<'a, RR, RQ> RoutedRequestQuery<'a, RR, RQ> {
    const fn new(routes: &'a RouteService<RR>, requests: &'a RequestService<RQ>) -> Self {
        Self { routes, requests }
    }
}

impl<RR, RQ> RoutedRequestQuery<'_, RR, RQ>
where
    RR: RouteRepository,
    RQ: RequestRepository,
{
    fn find_for_destination(
        &self,
        caller: ActorId,
        route_id: RouteId,
    ) -> Result<Option<AcceptedRequest>, RequestError> {
        let route = match self.routes.find(route_id)? {
            Some(route) if route.destination_service() == caller => route,
            _ => return Ok(None),
        };
        self.requests
            .find(route.source_service(), route.request_id())
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
        Err(RequestReadError::PayloadTooLarge) => json_response(
            "413 Payload Too Large",
            &MalformedRequestResponse::payload_too_large(),
        ),
        Err(RequestReadError::Malformed) => {
            json_response("400 Bad Request", &MalformedRequestResponse::malformed())
        }
    };
    write_response(&mut stream, &response)
}

/// The raw HTTP request could not even be parsed into a route, so no
/// endpoint-specific error shape (enrollment, governed route, etc.)
/// applies yet — this is the one response shape every caller can hit
/// regardless of what it was trying to reach, for example a
/// TLS-terminating proxy in front of this process forwarding a request
/// over an unsupported HTTP version.
#[derive(serde::Serialize)]
struct MalformedRequestResponse {
    code: &'static str,
    message: &'static str,
}

impl MalformedRequestResponse {
    const fn malformed() -> Self {
        Self {
            code: "malformed_request",
            message: "the HTTP request could not be parsed",
        }
    }

    const fn payload_too_large() -> Self {
        Self {
            code: "payload_too_large",
            message: "the request body exceeds the maximum accepted size",
        }
    }
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
        if path == "/v1/routes/eligible" {
            return list_eligible_routes(
                service_id,
                application.routes(),
                application.work_claims(),
            );
        }
        if let Some(route_id) = path
            .strip_prefix("/v1/routes/")
            .and_then(|rest| rest.strip_suffix("/claims"))
        {
            return claim_route(
                &request,
                service_id,
                verified.instance_id(),
                route_id,
                application.work_claims(),
            );
        }
        if let Some(route_id) = path
            .strip_prefix("/v1/routes/")
            .and_then(|rest| rest.strip_suffix("/request"))
        {
            return find_routed_request(
                route_id,
                service_id,
                application.routes(),
                application.requests(),
            );
        }
        if let Some(rest) = path.strip_prefix("/v1/claims/") {
            if let Some(claim_id) = rest.strip_suffix("/renew") {
                return renew_claim_route(&request, claim_id, application.work_claims());
            }
            if let Some(claim_id) = rest.strip_suffix("/release") {
                return release_claim_route(&request, claim_id, application.work_claims());
            }
            if let Some(claim_id) = rest.strip_suffix("/complete") {
                return complete_claim_route(&request, claim_id, application.work_claims());
            }
        }
        let authority = match policy_evaluator_from_env(application) {
            Ok(authority) => authority,
            Err(response) => return response,
        };
        if path == "/v1/requests" || path.starts_with("/v1/requests/") {
            let envelope_request_id = RequestId::from_uuid(verified.request_id());
            let router = SubscriptionRouter::new(application.subscriptions(), application.routes());
            return request_route(
                &request,
                service_id,
                envelope_request_id,
                application.requests(),
                &authority,
                &router,
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

    const fn invalid_route_id() -> Self {
        Self {
            code: "invalid_route_id",
            message: "route ID must be a UUID",
        }
    }

    const fn request_not_authorized() -> Self {
        Self {
            code: "request_not_authorized",
            message: "request is not authorized",
        }
    }

    const fn invalid_work_claim_request() -> Self {
        Self {
            code: "invalid_work_claim_request",
            message: "work claim request is invalid",
        }
    }

    const fn claim_not_found() -> Self {
        Self {
            code: "claim_not_found",
            message: "claim or route was not found",
        }
    }

    const fn route_already_claimed() -> Self {
        Self {
            code: "route_already_claimed",
            message: "route already has an active claim",
        }
    }

    const fn claim_fenced() -> Self {
        Self {
            code: "claim_fenced",
            message: "fencing token does not match the current active claim",
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
        || path == "/v1/routes/eligible"
        || (path.starts_with("/v1/routes/") && path.ends_with("/claims"))
        || (path.starts_with("/v1/routes/") && path.ends_with("/request"))
        || is_claim_action_path(path)
}

fn is_supported_governed_method(method: &str, path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    (path == "/v1/subscriptions" && matches!(method, "GET" | "POST"))
        || (path.starts_with("/v1/subscriptions/") && method == "DELETE")
        || (path == "/v1/authority/schemas" && method == "POST")
        || (path == "/v1/requests" && method == "POST")
        || (path.starts_with("/v1/requests/") && method == "GET")
        || (path == "/v1/routes/eligible" && method == "GET")
        || (path.starts_with("/v1/routes/") && path.ends_with("/claims") && method == "POST")
        || (path.starts_with("/v1/routes/") && path.ends_with("/request") && method == "GET")
        || (is_claim_action_path(path) && method == "POST")
}

fn is_claim_action_path(path: &str) -> bool {
    path.starts_with("/v1/claims/")
        && (path.ends_with("/renew") || path.ends_with("/release") || path.ends_with("/complete"))
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
    match subscriptions.create(service_id, event_type, DeliveryMode::Inclusive, unix_time()) {
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
fn request_route<R: RequestRepository, A: RequestAuthorizer, RT: RequestRouter>(
    request: &ParsedRequest,
    service_id: ActorId,
    envelope_request_id: RequestId,
    requests: &RequestService<R>,
    authority: &A,
    router: &RT,
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
                router,
            ),
            _ => text_response("405 Method Not Allowed", "method not allowed\n"),
        };
    }
    match path.strip_prefix("/v1/requests/") {
        Some(id) => find_request(id, service_id, requests),
        None => text_response("404 Not Found", "not found\n"),
    }
}

fn submit_request<R: RequestRepository, A: RequestAuthorizer, RT: RequestRouter>(
    request: &ParsedRequest,
    service_id: ActorId,
    envelope_request_id: RequestId,
    requests: &RequestService<R>,
    authority: &A,
    router: &RT,
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
    let (status, record) = match requests.accept(submitted, fingerprint) {
        Ok(RequestAcceptance::Accepted(record)) => ("201 Created", record),
        Ok(RequestAcceptance::SafeRetry(record)) => ("200 OK", record),
        Err(error) => return request_error_response(&error),
    };
    // Route materialization runs on both a fresh acceptance and a safe
    // retry, since a prior attempt may have accepted the request and then
    // crashed before materializing routes -- idempotent materialization
    // makes re-running this safe either way. A failure here does not
    // change the response: the request is already durably accepted
    // (ILK-003 requires acceptance to not depend on subscription state),
    // so routing is retried as a side effect of the client's own retry,
    // not surfaced as this call failing.
    if let Err(error) = router.materialize_routes(
        record.request().source_service(),
        record.request().id(),
        record.request().action(),
        now,
    ) {
        eprintln!(
            "route materialization failed for request {}: {error}",
            record.request().id()
        );
    }
    json_response(status, &AcceptedRequestResponse::from(&record))
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
        RequestError::UnknownSchemaVersion
        | RequestError::UnknownSubscription
        | RequestError::InvalidRouteId
        | RequestError::Repository(_) => json_response(
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

/// Lists the caller's own eligible routes -- materialized, incomplete, and
/// not currently claimed by anyone -- so an external scheduler (Taskmaster,
/// ADR-0011) has something to propose a claim against. The destination
/// queried is always the caller's own verified identity, never a request
/// parameter, so this exposes no other service's routes. A plain read of
/// the caller's own data, like `GET /v1/subscriptions`, so it requires no
/// separate ILK-002 authority decision.
fn list_eligible_routes<RR: RouteRepository, WR: WorkClaimRepository>(
    service_id: ActorId,
    routes: &RouteService<RR>,
    work_claims: &WorkClaimService<WR>,
) -> Response {
    let query = EligibleRouteQuery::new(routes, work_claims);
    match query.eligible_for(service_id, unix_time()) {
        Ok(values) => json_response(
            "200 OK",
            &values
                .iter()
                .map(RouteResponse::from)
                .collect::<EligibleRouteListResponse>(),
        ),
        Err(error) => request_error_response(&error),
    }
}

/// Resolves the Request behind `route_id` for the caller's own verified
/// identity -- the piece a worker needs to actually perform the work it
/// claimed (or is about to claim). Only the route's own destination
/// service may read it; a route belonging to another service, or that
/// does not exist, is indistinguishable to the caller. No separate
/// ILK-002 authority decision gates this, matching every other read
/// gated by route ownership rather than a fresh policy call.
fn find_routed_request<RR: RouteRepository, RQ: RequestRepository>(
    route_id: &str,
    service_id: ActorId,
    routes: &RouteService<RR>,
    requests: &RequestService<RQ>,
) -> Response {
    let route_id: RouteId = match route_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_route_id(),
            );
        }
    };
    let query = RoutedRequestQuery::new(routes, requests);
    match query.find_for_destination(service_id, route_id) {
        Ok(Some(record)) => json_response("200 OK", &AcceptedRequestResponse::from(&record)),
        Ok(None) => json_response("404 Not Found", &GovernedErrorResponse::claim_not_found()),
        Err(error) => request_error_response(&error),
    }
}

/// Claims `route_id` for the caller's own verified identity and instance
/// (`worker_service`/`worker_instance`), never a request-body field --
/// exactly like every other governed handler, a caller can only ever act
/// as itself. Ownership is enforced by the repository against the route's
/// own assigned destination (ILK-010), not by a separate ILK-002 authority
/// call: a route already encodes "this destination is entitled to this
/// work" through the subscription that produced it.
fn claim_route<R: WorkClaimRepository>(
    request: &ParsedRequest,
    worker_service: ActorId,
    worker_instance: InstanceId,
    route_id: &str,
    claims: &WorkClaimService<R>,
) -> Response {
    let route_id: RouteId = match route_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_work_claim_request(),
            );
        }
    };
    if !request
        .content_type
        .as_deref()
        .is_some_and(is_json_content_type)
    {
        return json_response(
            "415 Unsupported Media Type",
            &GovernedErrorResponse::invalid_work_claim_request(),
        );
    }
    let dto: ClaimRequest = match serde_json::from_slice(&request.body) {
        Ok(dto) => dto,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_work_claim_request(),
            );
        }
    };
    let now = unix_time();
    let lease_expires_at = match dto.lease_expires_at(now) {
        Some(value) => value,
        None => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_work_claim_request(),
            );
        }
    };
    match claims.claim(
        route_id,
        worker_service,
        worker_instance,
        lease_expires_at,
        now,
    ) {
        Ok(claim) => json_response("201 Created", &WorkClaimResponse::from(&claim)),
        Err(error) => work_claim_error_response(&error),
    }
}

fn renew_claim_route<R: WorkClaimRepository>(
    request: &ParsedRequest,
    claim_id: &str,
    claims: &WorkClaimService<R>,
) -> Response {
    let claim_id: ClaimId = match claim_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_work_claim_request(),
            );
        }
    };
    if !request
        .content_type
        .as_deref()
        .is_some_and(is_json_content_type)
    {
        return json_response(
            "415 Unsupported Media Type",
            &GovernedErrorResponse::invalid_work_claim_request(),
        );
    }
    let dto: RenewRequest = match serde_json::from_slice(&request.body) {
        Ok(dto) => dto,
        Err(_) => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_work_claim_request(),
            );
        }
    };
    let now = unix_time();
    let lease_expires_at = match dto.lease_expires_at(now) {
        Some(value) => value,
        None => {
            return json_response(
                "400 Bad Request",
                &GovernedErrorResponse::invalid_work_claim_request(),
            );
        }
    };
    match claims.renew(claim_id, dto.fencing_token(), lease_expires_at, now) {
        Ok(claim) => json_response("200 OK", &WorkClaimResponse::from(&claim)),
        Err(error) => work_claim_error_response(&error),
    }
}

fn release_claim_route<R: WorkClaimRepository>(
    request: &ParsedRequest,
    claim_id: &str,
    claims: &WorkClaimService<R>,
) -> Response {
    let (claim_id, dto) = match parse_fenced_action(claim_id, request) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match claims.release(claim_id, dto.fencing_token(), unix_time()) {
        Ok(claim) => json_response("200 OK", &WorkClaimResponse::from(&claim)),
        Err(error) => work_claim_error_response(&error),
    }
}

fn complete_claim_route<R: WorkClaimRepository>(
    request: &ParsedRequest,
    claim_id: &str,
    claims: &WorkClaimService<R>,
) -> Response {
    let (claim_id, dto) = match parse_fenced_action(claim_id, request) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match claims.complete(claim_id, dto.fencing_token(), unix_time()) {
        Ok(claim) => json_response("200 OK", &WorkClaimResponse::from(&claim)),
        Err(error) => work_claim_error_response(&error),
    }
}

fn parse_fenced_action(
    claim_id: &str,
    request: &ParsedRequest,
) -> Result<(ClaimId, FencedActionRequest), Response> {
    let claim_id: ClaimId = claim_id.parse().map_err(|_| {
        json_response(
            "400 Bad Request",
            &GovernedErrorResponse::invalid_work_claim_request(),
        )
    })?;
    if !request
        .content_type
        .as_deref()
        .is_some_and(is_json_content_type)
    {
        return Err(json_response(
            "415 Unsupported Media Type",
            &GovernedErrorResponse::invalid_work_claim_request(),
        ));
    }
    let dto: FencedActionRequest = serde_json::from_slice(&request.body).map_err(|_| {
        json_response(
            "400 Bad Request",
            &GovernedErrorResponse::invalid_work_claim_request(),
        )
    })?;
    Ok((claim_id, dto))
}

fn work_claim_error_response(error: &WorkClaimError) -> Response {
    match error {
        WorkClaimError::InvalidClaimId
        | WorkClaimError::InvalidFencingToken
        | WorkClaimError::InvalidLease
        | WorkClaimError::InvalidTimestamp => json_response(
            "400 Bad Request",
            &GovernedErrorResponse::invalid_work_claim_request(),
        ),
        WorkClaimError::RouteNotFound(_) | WorkClaimError::NotFound(_) => {
            json_response("404 Not Found", &GovernedErrorResponse::claim_not_found())
        }
        WorkClaimError::AlreadyClaimed(_) => json_response(
            "409 Conflict",
            &GovernedErrorResponse::route_already_claimed(),
        ),
        WorkClaimError::Fenced => {
            json_response("409 Conflict", &GovernedErrorResponse::claim_fenced())
        }
        WorkClaimError::Repository(_) => json_response(
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
        KernelIdentityResponse, MAX_ENROLLMENT_BODY_BYTES, MalformedRequestResponse,
        RequestReadError, read_request, readiness_response, route,
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
    fn a_connection_level_parse_failure_is_not_shaped_like_an_enrollment_error() {
        let malformed = serde_json::to_string(&MalformedRequestResponse::malformed()).unwrap();
        let too_large =
            serde_json::to_string(&MalformedRequestResponse::payload_too_large()).unwrap();

        assert!(!malformed.contains("enrollment"));
        assert!(!too_large.contains("enrollment"));
        assert!(malformed.contains("\"code\":\"malformed_request\""));
        assert!(too_large.contains("\"code\":\"payload_too_large\""));
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
                    value.delivery_mode(),
                    value.created_at(),
                    Some(disabled_at),
                )?;
                *value = disabled.clone();
                Ok(disabled)
            }

            fn find_active_by_event_type(
                &self,
                event_type: &EventType,
            ) -> Result<Vec<Subscription>, SubscriptionError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|value| value.event_type() == event_type && value.is_active())
                    .cloned()
                    .collect())
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
                    DeliveryMode::Inclusive,
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
                .create(
                    owner,
                    EventType::new("resource.created.v1").unwrap(),
                    DeliveryMode::Inclusive,
                    1,
                )
                .unwrap();
            subscriptions
                .create(
                    other,
                    EventType::new("resource.deleted.v1").unwrap(),
                    DeliveryMode::Inclusive,
                    1,
                )
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
                .create(
                    owner,
                    EventType::new("resource.created.v1").unwrap(),
                    DeliveryMode::Inclusive,
                    1,
                )
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
                .create(
                    owner,
                    EventType::new("resource.created.v1").unwrap(),
                    DeliveryMode::Inclusive,
                    1,
                )
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
                .create(
                    owner,
                    EventType::new("resource.created.v1").unwrap(),
                    DeliveryMode::Inclusive,
                    1,
                )
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
                .create(
                    owner,
                    EventType::new("resource.created.v1").unwrap(),
                    DeliveryMode::Inclusive,
                    1,
                )
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
                .create(
                    owner,
                    EventType::new("resource.created.v1").unwrap(),
                    DeliveryMode::Inclusive,
                    1,
                )
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
                .create(
                    owner,
                    EventType::new("resource.created.v1").unwrap(),
                    DeliveryMode::Inclusive,
                    1,
                )
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

        /// A `RequestRouter` fixture that materializes nothing and never
        /// fails, so tests of `submit_request`/`find_request` themselves
        /// don't need a real `SubscriptionService`/`RouteService` pair.
        /// Route materialization has its own dedicated tests below.
        struct NoopRouter;

        impl RequestRouter for NoopRouter {
            fn materialize_routes(
                &self,
                _source_service: ActorId,
                _request_id: RequestId,
                _action: &ActionName,
                _now: i64,
            ) -> Result<Vec<Route>, RequestError> {
                Ok(Vec::new())
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
                &NoopRouter,
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
                &NoopRouter,
            );
            assert_eq!(first.status, "201 Created");

            let retry = submit_request(
                &request,
                service_id,
                envelope_request_id,
                &requests,
                &FixedAuthority::allow(),
                &NoopRouter,
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
                &NoopRouter,
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
                &NoopRouter,
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
                &NoopRouter,
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
                &NoopRouter,
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
                &NoopRouter,
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
                &NoopRouter,
            );
            assert_eq!(found.status, "200 OK");
        }
    }

    mod subscription_router {
        use std::sync::{Arc, Mutex};

        use super::super::*;
        use crate::kernel::requests::Route;
        use crate::kernel::subscriptions::{DeliveryMode, EventType, Subscription};

        #[derive(Clone, Default)]
        struct MemorySubscriptions(Arc<Mutex<Vec<Subscription>>>);

        impl MemorySubscriptions {
            fn seed(&self, subscription: Subscription) {
                self.0.lock().unwrap().push(subscription);
            }
        }

        impl SubscriptionRepository for MemorySubscriptions {
            fn insert(&self, subscription: Subscription) -> Result<(), SubscriptionError> {
                self.0.lock().unwrap().push(subscription);
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
                self.list_for_service(service_id)
                    .map(|values| values.into_iter().filter(Subscription::is_active).collect())
            }

            fn disable(
                &self,
                _service_id: ActorId,
                subscription_id: SubscriptionId,
                _disabled_at: i64,
            ) -> Result<Subscription, SubscriptionError> {
                Err(SubscriptionError::NotFound(subscription_id))
            }

            fn find_active_by_event_type(
                &self,
                event_type: &EventType,
            ) -> Result<Vec<Subscription>, SubscriptionError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|value| value.event_type() == event_type && value.is_active())
                    .cloned()
                    .collect())
            }
        }

        #[derive(Clone, Default)]
        struct MemoryRoutes(Arc<Mutex<Vec<Route>>>);

        impl RouteRepository for MemoryRoutes {
            fn materialize(&self, route: Route) -> Result<Route, RequestError> {
                let mut routes = self.0.lock().unwrap();
                if let Some(existing) = routes.iter().find(|value| {
                    value.request_id() == route.request_id()
                        && value.subscription_id() == route.subscription_id()
                }) {
                    return Ok(existing.clone());
                }
                routes.push(route.clone());
                Ok(route)
            }

            fn find(&self, route_id: RouteId) -> Result<Option<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|route| route.id() == route_id)
                    .cloned())
            }

            fn list_for_request(&self, request_id: RequestId) -> Result<Vec<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|route| route.request_id() == request_id)
                    .cloned()
                    .collect())
            }

            fn list_for_destination(
                &self,
                destination_service: ActorId,
            ) -> Result<Vec<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|route| route.destination_service() == destination_service)
                    .cloned()
                    .collect())
            }
        }

        fn active_subscription(owner: ActorId, event_type: &str) -> Subscription {
            Subscription::restore(
                SubscriptionId::new(),
                owner,
                EventType::new(event_type).unwrap(),
                DeliveryMode::Inclusive,
                0,
                None,
            )
            .unwrap()
        }

        #[test]
        fn materializes_a_route_for_each_matching_active_subscription() {
            let owner = ActorId::new();
            let repository = MemorySubscriptions::default();
            repository.seed(active_subscription(owner, "billing.invoice.submit"));
            let subscriptions = SubscriptionService::new(repository);
            let routes = RouteService::new(MemoryRoutes::default());
            let router = SubscriptionRouter::new(&subscriptions, &routes);
            let source = ActorId::new();
            let request_id = RequestId::new();

            let materialized = router
                .materialize_routes(
                    source,
                    request_id,
                    &ActionName::new("billing.invoice.submit").unwrap(),
                    100,
                )
                .unwrap();

            assert_eq!(materialized.len(), 1);
            assert_eq!(materialized[0].destination_service(), owner);
            assert_eq!(routes.list_for_request(request_id).unwrap().len(), 1);
        }

        #[test]
        fn a_request_with_no_matching_subscription_materializes_no_routes_and_does_not_fail() {
            let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
            let routes = RouteService::new(MemoryRoutes::default());
            let router = SubscriptionRouter::new(&subscriptions, &routes);

            let materialized = router
                .materialize_routes(
                    ActorId::new(),
                    RequestId::new(),
                    &ActionName::new("billing.invoice.submit").unwrap(),
                    100,
                )
                .unwrap();

            assert!(materialized.is_empty());
        }

        #[test]
        fn a_disabled_subscription_never_matches() {
            let repository = MemorySubscriptions::default();
            let owner = ActorId::new();
            let disabled = Subscription::restore(
                SubscriptionId::new(),
                owner,
                EventType::new("billing.invoice.submit").unwrap(),
                DeliveryMode::Inclusive,
                0,
                Some(50),
            )
            .unwrap();
            repository.seed(disabled);
            let subscriptions = SubscriptionService::new(repository);
            let routes = RouteService::new(MemoryRoutes::default());
            let router = SubscriptionRouter::new(&subscriptions, &routes);

            let materialized = router
                .materialize_routes(
                    ActorId::new(),
                    RequestId::new(),
                    &ActionName::new("billing.invoice.submit").unwrap(),
                    100,
                )
                .unwrap();

            assert!(materialized.is_empty());
        }

        #[test]
        fn materializing_the_same_request_twice_does_not_duplicate_routes() {
            let repository = MemorySubscriptions::default();
            let owner = ActorId::new();
            repository.seed(active_subscription(owner, "billing.invoice.submit"));
            let subscriptions = SubscriptionService::new(repository);
            let routes = RouteService::new(MemoryRoutes::default());
            let router = SubscriptionRouter::new(&subscriptions, &routes);
            let source = ActorId::new();
            let request_id = RequestId::new();
            let action = ActionName::new("billing.invoice.submit").unwrap();

            router
                .materialize_routes(source, request_id, &action, 100)
                .unwrap();
            router
                .materialize_routes(source, request_id, &action, 200)
                .unwrap();

            assert_eq!(routes.list_for_request(request_id).unwrap().len(), 1);
        }

        #[test]
        fn a_different_event_type_does_not_match() {
            let repository = MemorySubscriptions::default();
            repository.seed(active_subscription(
                ActorId::new(),
                "billing.invoice.cancel",
            ));
            let subscriptions = SubscriptionService::new(repository);
            let routes = RouteService::new(MemoryRoutes::default());
            let router = SubscriptionRouter::new(&subscriptions, &routes);

            let materialized = router
                .materialize_routes(
                    ActorId::new(),
                    RequestId::new(),
                    &ActionName::new("billing.invoice.submit").unwrap(),
                    100,
                )
                .unwrap();

            assert!(materialized.is_empty());
        }
    }

    mod work_claim_routes {
        use std::collections::{HashMap, HashSet};
        use std::sync::{Arc, Mutex};

        use super::super::*;
        use crate::kernel::work_claims::{WorkClaim, WorkClaimStatus};

        #[derive(Clone, Default)]
        struct MemoryWorkClaims {
            route_destinations: Arc<Mutex<HashMap<RouteId, ActorId>>>,
            claims: Arc<Mutex<Vec<WorkClaim>>>,
        }

        impl MemoryWorkClaims {
            fn with_route(route_id: RouteId, destination: ActorId) -> Self {
                let repository = Self::default();
                repository
                    .route_destinations
                    .lock()
                    .unwrap()
                    .insert(route_id, destination);
                repository
            }
        }

        impl WorkClaimRepository for MemoryWorkClaims {
            fn claim(
                &self,
                route_id: RouteId,
                worker_service: ActorId,
                worker_instance: InstanceId,
                lease_expires_at: i64,
                now: i64,
            ) -> Result<WorkClaim, WorkClaimError> {
                let destinations = self.route_destinations.lock().unwrap();
                if destinations.get(&route_id) != Some(&worker_service) {
                    return Err(WorkClaimError::RouteNotFound(route_id));
                }
                let mut claims = self.claims.lock().unwrap();
                let latest = claims
                    .iter_mut()
                    .filter(|claim| claim.route_id() == route_id)
                    .max_by_key(|claim| claim.fencing_token());
                let next_fencing_token = match latest {
                    Some(claim) if claim.is_current(now) => {
                        return Err(WorkClaimError::AlreadyClaimed(route_id));
                    }
                    Some(claim) => claim.fencing_token() + 1,
                    None => 1,
                };
                let claim = WorkClaim::restore(
                    ClaimId::new(),
                    route_id,
                    worker_service,
                    worker_instance,
                    next_fencing_token,
                    WorkClaimStatus::Active,
                    now,
                    lease_expires_at,
                )
                .unwrap();
                claims.push(claim.clone());
                Ok(claim)
            }

            fn renew(
                &self,
                claim_id: ClaimId,
                fencing_token: i64,
                lease_expires_at: i64,
                now: i64,
            ) -> Result<WorkClaim, WorkClaimError> {
                let mut claims = self.claims.lock().unwrap();
                let claim = Self::current(&mut claims, claim_id, fencing_token, now)?;
                *claim = WorkClaim::restore(
                    claim.id(),
                    claim.route_id(),
                    claim.worker_service(),
                    claim.worker_instance(),
                    claim.fencing_token(),
                    WorkClaimStatus::Active,
                    claim.claimed_at(),
                    lease_expires_at,
                )
                .unwrap();
                Ok(claim.clone())
            }

            fn release(
                &self,
                claim_id: ClaimId,
                fencing_token: i64,
                now: i64,
            ) -> Result<WorkClaim, WorkClaimError> {
                self.transition(claim_id, fencing_token, now, WorkClaimStatus::Released)
            }

            fn complete(
                &self,
                claim_id: ClaimId,
                fencing_token: i64,
                now: i64,
            ) -> Result<WorkClaim, WorkClaimError> {
                self.transition(claim_id, fencing_token, now, WorkClaimStatus::Completed)
            }

            fn find(&self, claim_id: ClaimId) -> Result<Option<WorkClaim>, WorkClaimError> {
                Ok(self
                    .claims
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|claim| claim.id() == claim_id)
                    .cloned())
            }

            fn active_route_ids(
                &self,
                route_ids: &[RouteId],
                now: i64,
            ) -> Result<HashSet<RouteId>, WorkClaimError> {
                Ok(self
                    .claims
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|claim| route_ids.contains(&claim.route_id()) && claim.is_current(now))
                    .map(WorkClaim::route_id)
                    .collect())
            }
        }

        impl MemoryWorkClaims {
            fn current(
                claims: &mut [WorkClaim],
                claim_id: ClaimId,
                fencing_token: i64,
                now: i64,
            ) -> Result<&mut WorkClaim, WorkClaimError> {
                let claim = claims
                    .iter_mut()
                    .find(|claim| claim.id() == claim_id)
                    .ok_or(WorkClaimError::NotFound(claim_id))?;
                if claim.fencing_token() != fencing_token || !claim.is_current(now) {
                    return Err(WorkClaimError::Fenced);
                }
                Ok(claim)
            }

            fn transition(
                &self,
                claim_id: ClaimId,
                fencing_token: i64,
                now: i64,
                status: WorkClaimStatus,
            ) -> Result<WorkClaim, WorkClaimError> {
                let mut claims = self.claims.lock().unwrap();
                let claim = Self::current(&mut claims, claim_id, fencing_token, now)?;
                *claim = WorkClaim::restore(
                    claim.id(),
                    claim.route_id(),
                    claim.worker_service(),
                    claim.worker_instance(),
                    claim.fencing_token(),
                    status,
                    claim.claimed_at(),
                    claim.lease_expires_at(),
                )
                .unwrap();
                Ok(claim.clone())
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
        fn claim_returns_201_with_the_created_claim() {
            let destination = ActorId::new();
            let route_id = RouteId::new();
            let claims = WorkClaimService::new(MemoryWorkClaims::with_route(route_id, destination));
            let request = parsed_request(
                "POST",
                &format!("/v1/routes/{route_id}/claims"),
                br#"{"lease_seconds":30}"#,
            );

            let response = claim_route(
                &request,
                destination,
                InstanceId::new(),
                &route_id.to_string(),
                &claims,
            );

            assert_eq!(response.status, "201 Created");
            assert!(response.body.contains("\"fencing_token\":1"));
            assert!(response.body.contains("\"status\":\"active\""));
        }

        #[test]
        fn claim_rejects_a_malformed_route_id() {
            let claims = WorkClaimService::new(MemoryWorkClaims::default());
            let request = parsed_request(
                "POST",
                "/v1/routes/not-a-uuid/claims",
                br#"{"lease_seconds":30}"#,
            );

            let response = claim_route(
                &request,
                ActorId::new(),
                InstanceId::new(),
                "not-a-uuid",
                &claims,
            );

            assert_eq!(response.status, "400 Bad Request");
        }

        #[test]
        fn claim_rejects_a_non_positive_lease() {
            let destination = ActorId::new();
            let route_id = RouteId::new();
            let claims = WorkClaimService::new(MemoryWorkClaims::with_route(route_id, destination));
            let request = parsed_request(
                "POST",
                &format!("/v1/routes/{route_id}/claims"),
                br#"{"lease_seconds":0}"#,
            );

            let response = claim_route(
                &request,
                destination,
                InstanceId::new(),
                &route_id.to_string(),
                &claims,
            );

            assert_eq!(response.status, "400 Bad Request");
        }

        #[test]
        fn claim_conflicts_when_a_current_claim_already_exists() {
            let destination = ActorId::new();
            let route_id = RouteId::new();
            let claims = WorkClaimService::new(MemoryWorkClaims::with_route(route_id, destination));
            let request = parsed_request(
                "POST",
                &format!("/v1/routes/{route_id}/claims"),
                br#"{"lease_seconds":30}"#,
            );
            claim_route(
                &request,
                destination,
                InstanceId::new(),
                &route_id.to_string(),
                &claims,
            );

            let response = claim_route(
                &request,
                destination,
                InstanceId::new(),
                &route_id.to_string(),
                &claims,
            );

            assert_eq!(response.status, "409 Conflict");
        }

        #[test]
        fn claim_hides_a_route_owned_by_another_service_as_not_found() {
            let route_id = RouteId::new();
            let claims =
                WorkClaimService::new(MemoryWorkClaims::with_route(route_id, ActorId::new()));
            let request = parsed_request(
                "POST",
                &format!("/v1/routes/{route_id}/claims"),
                br#"{"lease_seconds":30}"#,
            );

            let response = claim_route(
                &request,
                ActorId::new(),
                InstanceId::new(),
                &route_id.to_string(),
                &claims,
            );

            assert_eq!(response.status, "404 Not Found");
        }

        #[test]
        fn renew_extends_the_lease_without_changing_the_fencing_token() {
            let destination = ActorId::new();
            let route_id = RouteId::new();
            let claims = WorkClaimService::new(MemoryWorkClaims::with_route(route_id, destination));
            let claimed = claims
                .claim(
                    route_id,
                    destination,
                    InstanceId::new(),
                    unix_time() + 30,
                    unix_time(),
                )
                .unwrap();
            let request = parsed_request(
                "POST",
                &format!("/v1/claims/{}/renew", claimed.id()),
                format!(
                    r#"{{"fencing_token":{},"lease_seconds":30}}"#,
                    claimed.fencing_token()
                )
                .as_bytes(),
            );

            let response = renew_claim_route(&request, &claimed.id().to_string(), &claims);

            assert_eq!(response.status, "200 OK");
            assert!(response.body.contains("\"fencing_token\":1"));
        }

        #[test]
        fn renew_is_fenced_when_the_token_is_stale() {
            let destination = ActorId::new();
            let route_id = RouteId::new();
            let claims = WorkClaimService::new(MemoryWorkClaims::with_route(route_id, destination));
            let claimed = claims
                .claim(route_id, destination, InstanceId::new(), 30, 0)
                .unwrap();
            claims
                .claim(route_id, destination, InstanceId::new(), 100, 40)
                .unwrap();
            let request = parsed_request(
                "POST",
                &format!("/v1/claims/{}/renew", claimed.id()),
                br#"{"fencing_token":1,"lease_seconds":30}"#,
            );

            let response = renew_claim_route(&request, &claimed.id().to_string(), &claims);

            assert_eq!(response.status, "409 Conflict");
        }

        #[test]
        fn release_allows_immediate_reclaim() {
            let destination = ActorId::new();
            let route_id = RouteId::new();
            let claims = WorkClaimService::new(MemoryWorkClaims::with_route(route_id, destination));
            let claimed = claims
                .claim(
                    route_id,
                    destination,
                    InstanceId::new(),
                    unix_time() + 1_000,
                    unix_time(),
                )
                .unwrap();
            let release_request = parsed_request(
                "POST",
                &format!("/v1/claims/{}/release", claimed.id()),
                br#"{"fencing_token":1}"#,
            );

            let released =
                release_claim_route(&release_request, &claimed.id().to_string(), &claims);
            assert_eq!(released.status, "200 OK");
            assert!(released.body.contains("\"status\":\"released\""));

            let claim_request = parsed_request(
                "POST",
                &format!("/v1/routes/{route_id}/claims"),
                br#"{"lease_seconds":30}"#,
            );
            let reclaimed = claim_route(
                &claim_request,
                destination,
                InstanceId::new(),
                &route_id.to_string(),
                &claims,
            );
            assert_eq!(reclaimed.status, "201 Created");
        }

        #[test]
        fn complete_is_terminal() {
            let destination = ActorId::new();
            let route_id = RouteId::new();
            let claims = WorkClaimService::new(MemoryWorkClaims::with_route(route_id, destination));
            let claimed = claims
                .claim(
                    route_id,
                    destination,
                    InstanceId::new(),
                    unix_time() + 1_000,
                    unix_time(),
                )
                .unwrap();
            let complete_request = parsed_request(
                "POST",
                &format!("/v1/claims/{}/complete", claimed.id()),
                br#"{"fencing_token":1}"#,
            );

            let response =
                complete_claim_route(&complete_request, &claimed.id().to_string(), &claims);
            assert_eq!(response.status, "200 OK");
            assert!(response.body.contains("\"status\":\"completed\""));

            let second_complete =
                complete_claim_route(&complete_request, &claimed.id().to_string(), &claims);
            assert_eq!(second_complete.status, "409 Conflict");
        }

        #[test]
        fn actions_reject_a_non_json_content_type() {
            let claims = WorkClaimService::new(MemoryWorkClaims::default());
            let claim_id = ClaimId::new().to_string();
            let mut request =
                parsed_request("POST", &format!("/v1/claims/{claim_id}/release"), b"{}");
            request.content_type = Some("text/plain".to_owned());

            let response = release_claim_route(&request, &claim_id, &claims);

            assert_eq!(response.status, "415 Unsupported Media Type");
        }
    }

    mod eligible_route_routes {
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};

        use super::super::*;
        use crate::kernel::work_claims::{WorkClaim, WorkClaimStatus};

        #[derive(Clone, Default)]
        struct MemoryRoutes(Arc<Mutex<Vec<Route>>>);

        impl MemoryRoutes {
            fn seed(&self, route: Route) {
                self.0.lock().unwrap().push(route);
            }
        }

        impl RouteRepository for MemoryRoutes {
            fn materialize(&self, route: Route) -> Result<Route, RequestError> {
                self.0.lock().unwrap().push(route.clone());
                Ok(route)
            }

            fn find(&self, route_id: RouteId) -> Result<Option<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|route| route.id() == route_id)
                    .cloned())
            }

            fn list_for_request(&self, request_id: RequestId) -> Result<Vec<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|route| route.request_id() == request_id)
                    .cloned()
                    .collect())
            }

            fn list_for_destination(
                &self,
                destination_service: ActorId,
            ) -> Result<Vec<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|route| route.destination_service() == destination_service)
                    .cloned()
                    .collect())
            }
        }

        #[derive(Clone, Default)]
        struct MemoryWorkClaims(Arc<Mutex<Vec<WorkClaim>>>);

        impl MemoryWorkClaims {
            fn seed(&self, claim: WorkClaim) {
                self.0.lock().unwrap().push(claim);
            }
        }

        impl WorkClaimRepository for MemoryWorkClaims {
            fn claim(
                &self,
                _route_id: RouteId,
                _worker_service: ActorId,
                _worker_instance: InstanceId,
                _lease_expires_at: i64,
                _now: i64,
            ) -> Result<WorkClaim, WorkClaimError> {
                Err(WorkClaimError::Repository(
                    "not exercised by these tests".to_owned(),
                ))
            }

            fn renew(
                &self,
                _claim_id: ClaimId,
                _fencing_token: i64,
                _lease_expires_at: i64,
                _now: i64,
            ) -> Result<WorkClaim, WorkClaimError> {
                Err(WorkClaimError::Repository(
                    "not exercised by these tests".to_owned(),
                ))
            }

            fn release(
                &self,
                _claim_id: ClaimId,
                _fencing_token: i64,
                _now: i64,
            ) -> Result<WorkClaim, WorkClaimError> {
                Err(WorkClaimError::Repository(
                    "not exercised by these tests".to_owned(),
                ))
            }

            fn complete(
                &self,
                _claim_id: ClaimId,
                _fencing_token: i64,
                _now: i64,
            ) -> Result<WorkClaim, WorkClaimError> {
                Err(WorkClaimError::Repository(
                    "not exercised by these tests".to_owned(),
                ))
            }

            fn find(&self, _claim_id: ClaimId) -> Result<Option<WorkClaim>, WorkClaimError> {
                Err(WorkClaimError::Repository(
                    "not exercised by these tests".to_owned(),
                ))
            }

            fn active_route_ids(
                &self,
                route_ids: &[RouteId],
                now: i64,
            ) -> Result<HashSet<RouteId>, WorkClaimError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|claim| route_ids.contains(&claim.route_id()) && claim.is_current(now))
                    .map(WorkClaim::route_id)
                    .collect())
            }
        }

        fn route(destination: ActorId, created_at: i64) -> Route {
            Route::create(
                ActorId::new(),
                RequestId::new(),
                SubscriptionId::new(),
                destination,
                created_at,
            )
            .unwrap()
        }

        fn claim(route_id: RouteId, lease_expires_at: i64) -> WorkClaim {
            WorkClaim::restore(
                ClaimId::new(),
                route_id,
                ActorId::new(),
                InstanceId::new(),
                1,
                WorkClaimStatus::Active,
                0,
                lease_expires_at,
            )
            .unwrap()
        }

        #[test]
        fn returns_only_unclaimed_routes_for_the_callers_own_destination() {
            let destination = ActorId::new();
            let routes = MemoryRoutes::default();
            let claimed_route = route(destination, 1);
            let unclaimed_route = route(destination, 2);
            routes.seed(claimed_route.clone());
            routes.seed(unclaimed_route.clone());
            let work_claims = MemoryWorkClaims::default();
            work_claims.seed(claim(claimed_route.id(), unix_time() + 1_000));
            let route_service = RouteService::new(routes);
            let claim_service = WorkClaimService::new(work_claims);

            let response = list_eligible_routes(destination, &route_service, &claim_service);

            assert_eq!(response.status, "200 OK");
            assert!(response.body.contains(&unclaimed_route.id().to_string()));
            assert!(!response.body.contains(&claimed_route.id().to_string()));
        }

        #[test]
        fn a_route_becomes_eligible_again_once_its_claim_expires() {
            let destination = ActorId::new();
            let routes = MemoryRoutes::default();
            let expired_route = route(destination, 1);
            routes.seed(expired_route.clone());
            let work_claims = MemoryWorkClaims::default();
            work_claims.seed(claim(expired_route.id(), unix_time() - 50));
            let route_service = RouteService::new(routes);
            let claim_service = WorkClaimService::new(work_claims);

            let response = list_eligible_routes(destination, &route_service, &claim_service);

            assert!(response.body.contains(&expired_route.id().to_string()));
        }

        #[test]
        fn a_caller_never_sees_another_services_routes() {
            let destination = ActorId::new();
            let other_service = ActorId::new();
            let routes = MemoryRoutes::default();
            let other_route = route(other_service, 1);
            routes.seed(other_route.clone());
            let route_service = RouteService::new(routes);
            let claim_service = WorkClaimService::new(MemoryWorkClaims::default());

            let response = list_eligible_routes(destination, &route_service, &claim_service);

            assert_eq!(response.status, "200 OK");
            assert!(!response.body.contains(&other_route.id().to_string()));
        }
    }

    mod routed_request_routes {
        use std::sync::{Arc, Mutex};

        use super::super::*;
        use crate::kernel::authority::{Scope, no_artifact_schema_versions};
        use crate::kernel::requests::{AcceptedRequest, Request, RequestFingerprint};
        use crate::kernel::subscriptions::SubscriptionId;

        #[derive(Clone, Default)]
        struct MemoryRoutes(Arc<Mutex<Vec<Route>>>);

        impl MemoryRoutes {
            fn seed(&self, route: Route) {
                self.0.lock().unwrap().push(route);
            }
        }

        impl RouteRepository for MemoryRoutes {
            fn materialize(&self, route: Route) -> Result<Route, RequestError> {
                self.0.lock().unwrap().push(route.clone());
                Ok(route)
            }

            fn find(&self, route_id: RouteId) -> Result<Option<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|route| route.id() == route_id)
                    .cloned())
            }

            fn list_for_request(&self, request_id: RequestId) -> Result<Vec<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|route| route.request_id() == request_id)
                    .cloned()
                    .collect())
            }

            fn list_for_destination(
                &self,
                destination_service: ActorId,
            ) -> Result<Vec<Route>, RequestError> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|route| route.destination_service() == destination_service)
                    .cloned()
                    .collect())
            }
        }

        #[derive(Clone, Default)]
        struct MemoryRequests(Arc<Mutex<Vec<AcceptedRequest>>>);

        impl MemoryRequests {
            fn seed(&self, record: AcceptedRequest) {
                self.0.lock().unwrap().push(record);
            }
        }

        impl RequestRepository for MemoryRequests {
            fn accept(
                &self,
                request: Request,
                fingerprint: RequestFingerprint,
            ) -> Result<RequestAcceptance, RequestError> {
                let record = AcceptedRequest::restore(request, fingerprint, 0)?;
                self.0.lock().unwrap().push(record.clone());
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

        fn accepted_request(source: ActorId, request_id: RequestId) -> AcceptedRequest {
            let request = Request::restore(
                request_id,
                source,
                "billing.invoice.submit",
                Scope::wildcard(),
                no_artifact_schema_versions(),
            )
            .unwrap();
            let fingerprint = request.fingerprint();
            AcceptedRequest::restore(request, fingerprint, 0).unwrap()
        }

        #[test]
        fn returns_the_request_for_the_routes_own_destination() {
            let source = ActorId::new();
            let destination = ActorId::new();
            let request_id = RequestId::new();
            let route =
                Route::create(source, request_id, SubscriptionId::new(), destination, 1).unwrap();
            let routes = MemoryRoutes::default();
            routes.seed(route.clone());
            let requests = MemoryRequests::default();
            requests.seed(accepted_request(source, request_id));
            let route_service = RouteService::new(routes);
            let request_service = RequestService::new(requests);

            let response = find_routed_request(
                &route.id().to_string(),
                destination,
                &route_service,
                &request_service,
            );

            assert_eq!(response.status, "200 OK");
            assert!(response.body.contains("billing.invoice.submit"));
            assert!(response.body.contains(&request_id.to_string()));
        }

        #[test]
        fn hides_a_route_owned_by_another_service_as_not_found() {
            let source = ActorId::new();
            let destination = ActorId::new();
            let request_id = RequestId::new();
            let route =
                Route::create(source, request_id, SubscriptionId::new(), destination, 1).unwrap();
            let routes = MemoryRoutes::default();
            routes.seed(route.clone());
            let requests = MemoryRequests::default();
            requests.seed(accepted_request(source, request_id));
            let route_service = RouteService::new(routes);
            let request_service = RequestService::new(requests);

            let response = find_routed_request(
                &route.id().to_string(),
                ActorId::new(),
                &route_service,
                &request_service,
            );

            assert_eq!(response.status, "404 Not Found");
        }

        #[test]
        fn hides_a_nonexistent_route_as_not_found() {
            let route_service = RouteService::new(MemoryRoutes::default());
            let request_service = RequestService::new(MemoryRequests::default());

            let response = find_routed_request(
                &RouteId::new().to_string(),
                ActorId::new(),
                &route_service,
                &request_service,
            );

            assert_eq!(response.status, "404 Not Found");
        }

        #[test]
        fn rejects_a_malformed_route_id() {
            let route_service = RouteService::new(MemoryRoutes::default());
            let request_service = RequestService::new(MemoryRequests::default());

            let response = find_routed_request(
                "not-a-uuid",
                ActorId::new(),
                &route_service,
                &request_service,
            );

            assert_eq!(response.status, "400 Bad Request");
        }
    }
}
