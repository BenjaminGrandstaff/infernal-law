//! Goal: validate bootstrap workload tokens with the Kubernetes TokenReview
//! API without logging or retaining the submitted bearer token.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::time::Duration;

use reqwest::Certificate;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use crate::kernel::enrollment::{EnrollmentError, VerifiedWorkload, WorkloadTokenReviewer};

pub const API_URL_ENV: &str = "KUBERNETES_API_URL";
pub const REVIEWER_TOKEN_PATH_ENV: &str = "KUBERNETES_REVIEWER_TOKEN_PATH";
pub const CA_PATH_ENV: &str = "KUBERNETES_CA_PATH";
const DEFAULT_API_URL: &str = "https://kubernetes.default.svc";
const DEFAULT_TOKEN_PATH: &str = "/var/run/secrets/infernal-law-kubernetes/token";
const DEFAULT_CA_PATH: &str = "/var/run/secrets/infernal-law-kubernetes/ca.crt";

pub struct KubernetesTokenReviewer {
    client: Client,
    endpoint: String,
    reviewer_token: String,
}

impl KubernetesTokenReviewer {
    pub fn from_env() -> Result<Self, EnrollmentError> {
        let api_url = env::var(API_URL_ENV).unwrap_or_else(|_| DEFAULT_API_URL.to_owned());
        let token_path =
            env::var(REVIEWER_TOKEN_PATH_ENV).unwrap_or_else(|_| DEFAULT_TOKEN_PATH.to_owned());
        let ca_path = env::var(CA_PATH_ENV).unwrap_or_else(|_| DEFAULT_CA_PATH.to_owned());
        Self::new(&api_url, &token_path, &ca_path)
    }

    pub fn new(api_url: &str, token_path: &str, ca_path: &str) -> Result<Self, EnrollmentError> {
        let reviewer_token = fs::read_to_string(token_path)
            .map_err(|error| configuration_error("reviewer token", error))?;
        let reviewer_token = reviewer_token.trim().to_owned();
        if reviewer_token.is_empty() {
            return Err(configuration_error("reviewer token", "file is empty"));
        }
        let ca = fs::read(ca_path).map_err(|error| configuration_error("cluster CA", error))?;
        let certificate =
            Certificate::from_pem(&ca).map_err(|error| configuration_error("cluster CA", error))?;
        let client = Client::builder()
            .add_root_certificate(certificate)
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|error| configuration_error("HTTP client", error))?;
        Ok(Self {
            client,
            endpoint: format!(
                "{}/apis/authentication.k8s.io/v1/tokenreviews",
                api_url.trim_end_matches('/')
            ),
            reviewer_token,
        })
    }
}

impl WorkloadTokenReviewer for KubernetesTokenReviewer {
    fn review(&self, token: &str, audience: &str) -> Result<VerifiedWorkload, EnrollmentError> {
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.reviewer_token)
            .json(&TokenReviewRequest {
                api_version: "authentication.k8s.io/v1",
                kind: "TokenReview",
                spec: TokenReviewSpec {
                    token,
                    audiences: vec![audience],
                },
            })
            .send()
            .map_err(|_| EnrollmentError::TokenRejected)?;
        if !response.status().is_success() {
            return Err(EnrollmentError::TokenRejected);
        }
        let review: TokenReviewResponse = response
            .json()
            .map_err(|_| EnrollmentError::TokenRejected)?;
        parse_review(review, audience)
    }
}

#[derive(Serialize)]
struct TokenReviewRequest<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    spec: TokenReviewSpec<'a>,
}

#[derive(Serialize)]
struct TokenReviewSpec<'a> {
    token: &'a str,
    audiences: Vec<&'a str>,
}

#[derive(Deserialize)]
struct TokenReviewResponse {
    status: Option<TokenReviewStatus>,
}

#[derive(Deserialize)]
struct TokenReviewStatus {
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    audiences: Vec<String>,
    user: Option<TokenReviewUser>,
}

#[derive(Deserialize)]
struct TokenReviewUser {
    username: String,
    uid: String,
    #[serde(default)]
    extra: HashMap<String, Vec<String>>,
}

fn parse_review(
    review: TokenReviewResponse,
    audience: &str,
) -> Result<VerifiedWorkload, EnrollmentError> {
    let status = review.status.ok_or(EnrollmentError::TokenRejected)?;
    if !status.authenticated {
        return Err(EnrollmentError::TokenRejected);
    }
    if !status.audiences.iter().any(|value| value == audience) {
        return Err(EnrollmentError::AudienceMismatch);
    }
    let user = status.user.ok_or(EnrollmentError::TokenRejected)?;
    let account = user
        .username
        .strip_prefix("system:serviceaccount:")
        .ok_or(EnrollmentError::TokenRejected)?;
    let (namespace, service_account) = account
        .split_once(':')
        .ok_or(EnrollmentError::TokenRejected)?;
    let pod_name = single_extra(&user.extra, "authentication.kubernetes.io/pod-name")?;
    let pod_uid = single_extra(&user.extra, "authentication.kubernetes.io/pod-uid")?;
    VerifiedWorkload::new(
        namespace,
        service_account,
        &user.uid,
        pod_name,
        pod_uid,
        status.audiences,
    )
}

fn single_extra<'a>(
    extra: &'a HashMap<String, Vec<String>>,
    key: &str,
) -> Result<&'a str, EnrollmentError> {
    let values = extra.get(key).ok_or(EnrollmentError::TokenRejected)?;
    if values.len() != 1 {
        return Err(EnrollmentError::TokenRejected);
    }
    Ok(&values[0])
}

fn configuration_error(label: &str, error: impl std::fmt::Display) -> EnrollmentError {
    EnrollmentError::Repository(format!("Kubernetes {label} configuration failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(audience: &str) -> TokenReviewResponse {
        TokenReviewResponse {
            status: Some(TokenReviewStatus {
                authenticated: true,
                audiences: vec![audience.to_owned()],
                user: Some(TokenReviewUser {
                    username: "system:serviceaccount:workers:indexer".to_owned(),
                    uid: "sa-uid".to_owned(),
                    extra: HashMap::from([
                        (
                            "authentication.kubernetes.io/pod-name".to_owned(),
                            vec!["indexer-1".to_owned()],
                        ),
                        (
                            "authentication.kubernetes.io/pod-uid".to_owned(),
                            vec!["pod-uid".to_owned()],
                        ),
                    ]),
                }),
            }),
        }
    }

    #[test]
    fn parses_a_bound_service_account_token_review() {
        let workload = parse_review(
            response("infernal-law-enrollment"),
            "infernal-law-enrollment",
        )
        .unwrap();
        assert_eq!(workload.namespace(), "workers");
        assert_eq!(workload.service_account(), "indexer");
        assert_eq!(workload.pod_uid(), "pod-uid");
    }

    #[test]
    fn rejects_a_review_without_the_requested_audience() {
        assert_eq!(
            parse_review(response("another-audience"), "infernal-law-enrollment"),
            Err(EnrollmentError::AudienceMismatch)
        );
    }
}
