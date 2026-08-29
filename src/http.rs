//! Goal: translate bounded HTTP requests into typed service operations without
//! containing governance-domain behavior or exposing authentication secrets.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::infrastructure::kubernetes_token_reviewer::KubernetesTokenReviewer;
use crate::kernel::enrollment::{
    EnrollmentBindingRepository, EnrollmentError, EnrollmentRequest, EnrollmentService,
    WorkloadTokenReviewer,
};
use crate::kernel::instance_keys::InstancePublicKey;
use crate::kernel::instance_registry::{InstanceRegistryRepository, RegisteredInstance};
use crate::kernel::request_gate::{
    AdmittedServiceRequest, ServiceRequestGate, ServiceRequestGateError,
};
use crate::kernel::service_requests::{
    ServiceRequestAuthenticationError, ServiceRequestParts, SignedServiceRequest,
};
use crate::kernel::{admission::AdmissionError, replay_protection::ReplayProtectionError};
use crate::wiring::Application;

use self::enrollment_dto::{
    EnrollmentErrorResponse, EnrollmentSubmissionRequest, EnrollmentSuccessResponse,
};

pub mod enrollment_dto;

const DEFAULT_ADDRESS: &str = "0.0.0.0";
const DEFAULT_PORT: &str = "8080";
const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_ENROLLMENT_BODY_BYTES: usize = 40 * 1024;

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
        return match authenticate_governed_request(governed, &gate, unix_time()) {
            Ok(_) => json_response(
                "501 Not Implemented",
                &GovernedErrorResponse::route_not_implemented(),
            ),
            Err(response) => response,
        };
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

    const fn route_not_implemented() -> Self {
        Self {
            code: "route_not_implemented",
            message: "governed route is not implemented",
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
    path == "/v1/subscriptions" || path.starts_with("/v1/subscriptions/")
}

fn is_supported_governed_method(method: &str, path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    (path == "/v1/subscriptions" && matches!(method, "GET" | "POST"))
        || (path.starts_with("/v1/subscriptions/") && method == "DELETE")
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
}
