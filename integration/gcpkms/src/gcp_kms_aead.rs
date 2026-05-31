// Copyright 2020 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! AEAD functionality via GCP KMS.

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use percent_encoding::percent_encode;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, rc::Rc};
use tink_core::{utils::wrap_err, TinkError};

use crate::default_sa::DefaultServiceAccountAuthenticator;

const PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

type RequestBody = Full<Bytes>;
type HttpsClient = Client<HttpsConnector<HttpConnector>, RequestBody>;

pub(crate) trait Authenticator {
    fn get_token(
        &self,
        runtime: &mut tokio::runtime::Runtime,
        scopes: &[&str],
    ) -> Result<String, TinkError>;
}

impl Authenticator for yup_oauth2::authenticator::Authenticator<HttpsConnector<HttpConnector>> {
    fn get_token(
        &self,
        runtime: &mut tokio::runtime::Runtime,
        scopes: &[&str],
    ) -> Result<String, TinkError> {
        runtime
            .block_on(self.token(scopes))
            .map_err(|e| wrap_err("failed to get token", e))?
            .token()
            .map(str::to_string)
            .ok_or_else(|| TinkError::new("empty access token"))
    }
}

/// `GcpAead` represents a GCP KMS service to a particular URI.
#[derive(Clone)]
pub struct GcpAead {
    key_uri: String,
    auth: Rc<dyn Authenticator>,
    client: HttpsClient,
    // The Tokio runtime to execute KMS requests on, wrapped in:
    //  - a `RefCell` for interior mutability (the [`tink_core::Aead`] trait's methods take
    //    `&self`)
    //  - an `Rc` to allow `Clone`, as required by the trait bound on [`tink_core::Aead`].
    runtime: Rc<RefCell<tokio::runtime::Runtime>>,
    user_agent: String,
}

impl GcpAead {
    /// Return a new AEAD primitive backed by the GCP KMS service.
    pub fn new(
        key_uri: &str,
        sa_key: &Option<yup_oauth2::ServiceAccountKey>,
    ) -> Result<GcpAead, TinkError> {
        let https = HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls::crypto::ring::default_provider())
            .map_err(|e| wrap_err("failed to load native root certificates", e))?
            .https_only()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| wrap_err("failed to build tokio runtime", e))?;
        let auth: Rc<dyn Authenticator> = match sa_key {
            None => Rc::new(runtime.block_on(DefaultServiceAccountAuthenticator::new())?),
            Some(k) => Rc::new(
                runtime
                    .block_on(yup_oauth2::ServiceAccountAuthenticator::builder(k.clone()).build())
                    .map_err(|e| wrap_err("failed to build authenticator", e))?,
            ),
        };
        Ok(GcpAead {
            key_uri: key_uri.to_string(),
            auth,
            client,
            user_agent: format!(
                "Tink-Rust/{}  Rust/{}",
                tink_core::UPSTREAM_VERSION,
                env!("CARGO_PKG_VERSION")
            ),
            runtime: Rc::new(RefCell::new(runtime)),
        })
    }

    fn token(&self) -> Result<String, TinkError> {
        self.auth
            .get_token(&mut self.runtime.borrow_mut(), &[PLATFORM_SCOPE])
    }

    fn build_http_req<T: serde::Serialize>(
        &self,
        req: T,
        op: &str,
    ) -> Result<http::Request<RequestBody>, TinkError> {
        let pq: http::uri::PathAndQuery = format!(
            "/v1/{}:{}/?alt=json",
            percent_encode(self.key_uri.as_bytes(), crate::DEFAULT_URL_ENCODE_SET),
            op
        )
        .parse()
        .map_err(|e| wrap_err("failed to parse path", e))?;
        let uri = hyper::Uri::builder()
            .scheme("https")
            .authority("cloudkms.googleapis.com")
            .path_and_query(pq)
            .build()
            .map_err(|e| wrap_err("failed to build URI", e))?;
        let req_body =
            serde_json::to_vec(&req).map_err(|e| wrap_err("failed to JSON encode request", e))?;

        hyper::Request::builder()
            .method(http::method::Method::POST)
            .uri(uri)
            .header(http::header::USER_AGENT, &self.user_agent)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::CONTENT_LENGTH, req_body.len() as u64)
            .header(
                hyper::header::AUTHORIZATION,
                format!("Bearer {}", self.token()?),
            )
            .body(Full::new(Bytes::from(req_body)))
            .map_err(|e| wrap_err("failed to build request", e))
    }

    fn parse_http_rsp<T: serde::de::DeserializeOwned>(
        &self,
        http_rsp: http::Response<Incoming>,
    ) -> Result<T, TinkError> {
        let status = http_rsp.status();
        let body = self
            .runtime
            .borrow_mut()
            .block_on(async { http_rsp.into_body().collect().await })
            .map_err(|e| wrap_err("failed to aggregate body", e))?;
        let bytes = body.to_bytes();

        if status.is_success() {
            let rsp: T = serde_json::from_slice(&bytes)
                .map_err(|e| wrap_err("failed to parse JSON response", e))?;
            Ok(rsp)
        } else {
            // Attempt to parse the response body as a GCP ErrorResponse object.
            let err_rsp: ErrorResponse = serde_json::from_slice(&bytes)
                .map_err(|e| wrap_err("failed to parse JSON error response", e))?;
            Err(format!("API failure {err_rsp:?}").into())
        }
    }
}

impl tink_core::Aead for GcpAead {
    fn encrypt(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, tink_core::TinkError> {
        let req = EncryptRequest {
            plaintext: Some(base64::engine::general_purpose::URL_SAFE.encode(plaintext)),
            additional_authenticated_data: Some(
                base64::engine::general_purpose::URL_SAFE.encode(additional_data),
            ),
            ..EncryptRequest::default()
        };
        let http_req = self.build_http_req(req, "encrypt")?;
        let http_rsp = self
            .runtime
            .borrow_mut()
            .block_on(self.client.request(http_req))
            .map_err(|e| wrap_err("HTTP request failed", e))?;
        let rsp = self.parse_http_rsp::<EncryptResponse>(http_rsp)?;
        let ct = rsp
            .ciphertext
            .ok_or_else(|| tink_core::TinkError::new("no ciphertext"))?;
        base64::engine::general_purpose::STANDARD
            .decode(ct)
            .map_err(|e| wrap_err("base64 decode failed", e))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, tink_core::TinkError> {
        let req = DecryptRequest {
            ciphertext: Some(base64::engine::general_purpose::URL_SAFE.encode(ciphertext)),
            additional_authenticated_data: Some(
                base64::engine::general_purpose::URL_SAFE.encode(additional_data),
            ),
            ..DecryptRequest::default()
        };
        let http_req = self.build_http_req(req, "decrypt")?;
        let http_rsp = self
            .runtime
            .borrow_mut()
            .block_on(self.client.request(http_req))
            .map_err(|e| wrap_err("HTTP request failed", e))?;
        let rsp = self.parse_http_rsp::<DecryptResponse>(http_rsp)?;

        let pt = rsp
            .plaintext
            .ok_or_else(|| tink_core::TinkError::new("no plaintext"))?;
        base64::engine::general_purpose::STANDARD
            .decode(pt)
            .map_err(|e| wrap_err("base64 decode failed", e))
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: Option<String>,
    #[serde(rename = "additionalAuthenticatedData")]
    pub additional_authenticated_data: Option<String>,
    #[serde(rename = "additionalAuthenticatedDataCrc32c")]
    pub additional_authenticated_data_crc32c: Option<String>,
    #[serde(rename = "plaintextCrc32c")]
    pub plaintext_crc32c: Option<String>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EncryptResponse {
    #[serde(rename = "verifiedAdditionalAuthenticatedDataCrc32c")]
    pub verified_additional_authenticated_data_crc32c: Option<bool>,
    #[serde(rename = "verifiedPlaintextCrc32c")]
    pub verified_plaintext_crc32c: Option<bool>,
    #[serde(rename = "ciphertextCrc32c")]
    pub ciphertext_crc32c: Option<String>,
    pub ciphertext: Option<String>,
    pub name: Option<String>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: Option<String>,
    #[serde(rename = "additionalAuthenticatedData")]
    pub additional_authenticated_data: Option<String>,
    #[serde(rename = "ciphertextCrc32c")]
    pub ciphertext_crc32c: Option<String>,
    #[serde(rename = "additionalAuthenticatedDataCrc32c")]
    pub additional_authenticated_data_crc32c: Option<String>,
}
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: Option<String>,
    #[serde(rename = "plaintextCrc32c")]
    pub plaintext_crc32c: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ErrorResponse {
    pub error: ServerError,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ServerError {
    #[serde(default)]
    pub errors: Vec<ServerMessage>,
    pub code: u16,
    pub message: String,
    pub status: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ServerMessage {
    pub domain: String,
    pub reason: String,
    pub message: String,
    #[serde(rename = "locationType")]
    pub location_type: Option<String>,
    pub location: Option<String>,
}
