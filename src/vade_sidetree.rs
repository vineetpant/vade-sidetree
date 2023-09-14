/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
extern crate regex;
extern crate vade;

use crate::datatypes::*;
#[cfg(feature = "sdk")]
use crate::in3_request_list::{send_request, ResolveHttpRequest};
use crate::vade_sidetree_client::{
    did::{JsonWebKey, PublicKey, Service},
    multihash,
    operations::{self, DeactivateOperationInput, OperationInput},
    operations::{RecoverOperationInput, UpdateOperationInput},
};
use async_std::task;
use async_trait::async_trait;
use core::time;
use regex::Regex;
#[cfg(not(feature = "sdk"))]
use reqwest::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::error::Error;
#[cfg(feature = "sdk")]
use std::os::raw::c_void;
use vade::{VadePlugin, VadePluginResultValue};

const DEFAULT_URL: &str = "https://sidetree.equs.qa-idm.bc-labs.dev/3.0/";
const EVAN_METHOD: &str = "did:evan";
const METHOD_REGEX: &str = r#"^(.*):0x(.*)$"#;
const DID_SIDETREE: &str = "sidetree";

macro_rules! parse {
    ($data:expr, $type_name:expr) => {{
        serde_json::from_str($data)
            .map_err(|e| format!("{} when parsing {} {}", &e, $type_name, $data))?
    }};
}

macro_rules! ignore_unrelated {
    ($options:expr) => {{
        let type_options: TypeOptions = parse!($options, "options");
        match type_options.r#type.as_deref() {
            Some(DID_SIDETREE) => (),
            _ => return Ok(VadePluginResultValue::Ignored),
        };
    }};
}

/// Options for DID creation. If keys are not provided, they will be generated automatically
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidOptions {
    pub r#type: String,
    pub wait_for_completion: Option<bool>,
}

/// Payload for DID creation. If keys are not provided, they will be generated automatically
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidPayload {
    pub update_key: Option<JsonWebKey>,
    pub recovery_key: Option<JsonWebKey>,
    pub public_keys: Option<Vec<PublicKey>>,
    pub services: Option<Vec<Service>>,
}

/// Options for DID update.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDidOptions {
    pub r#type: String,
    pub wait_for_completion: Option<bool>,
}

/// Sidetree Rest API url
pub struct VadeSidetree {
    pub config: SideTreeConfig,
}

impl VadeSidetree {
    /// Creates new instance of `VadeSidetree`.
    pub fn new(
        #[cfg(feature = "sdk")] request_id: *const c_void,
        #[cfg(feature = "sdk")] resolve_http_request: ResolveHttpRequest,
        sidetree_rest_api_url: Option<String>,
    ) -> VadeSidetree {
        // Setting default value for sidetree api url
        // If environment variable is found and it contains some value, it will replace default value
        let url = sidetree_rest_api_url.unwrap_or_else(|| DEFAULT_URL.to_string());

        let config = SideTreeConfig {
            #[cfg(feature = "sdk")]
            request_id,
            #[cfg(feature = "sdk")]
            resolve_http_request,
            sidetree_rest_api_url: url,
        };
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        VadeSidetree { config }
    }

    async fn resolve_sidetree_did(
        &self,
        base_url: String,
        did: &str,
    ) -> Result<String, Box<dyn Error>> {
        let mut api_url = base_url;
        api_url.push_str("identifiers/");
        api_url.push_str(did);

        let res: String;

        cfg_if::cfg_if! {
            if #[cfg(feature = "sdk")] {
                res = send_request(
                    api_url,
                    "GET".to_string(),
                    None,
                    self.config.request_id,
                    self.config.resolve_http_request,
                )?;
            } else {
                let client = reqwest::Client::new();
                let request = client
                .get(api_url)
                .send()
                .await?;
                let status_code = request.status();
                if status_code.as_u16() > 200 {
                    res = "Not Found".to_string();
                } else {
                    res = request.text()
                    .await
                    .map_err(|err| format!("DID resolve request failed; {}", &err.to_string()))?;
                }
            }
        }
        Ok(res)
    }
}

#[async_trait(?Send)]
impl VadePlugin for VadeSidetree {
    /// Creates a new DID on sidetree.
    ///
    /// # Arguments
    ///
    /// * `did_method` - did method to cater to, usually "did:evan"
    /// * `options` - serialized object of CreateDidOptions
    /// * `payload` - no payload required, so can be left empty
    async fn did_create(
        &mut self,
        did_method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(options);

        if !did_method.starts_with(EVAN_METHOD) {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: CreateDidOptions = serde_json::from_str(options)?;
        let payload: CreateDidPayload = serde_json::from_str(payload)?;
        let config = OperationInput {
            public_keys: payload.public_keys,
            services: payload.services,
            update_key: payload.update_key,
            recovery_key: payload.recovery_key,
        };
        let create_operation = operations::create(Some(config));
        let create_output = match create_operation {
            Ok(value) => value,
            Err(err) => return Err(Box::from(format!("{err}"))),
        };
        let json = serde_json::to_string(&create_output)?;
        let mut api_url = self.config.sidetree_rest_api_url.clone();
        api_url.push_str("operations");
        let create_result: DIDCreateResult = serde_json::from_str(&json)?;

        #[cfg(feature = "sdk")]
        let request_pointer = self.config.request_id.clone();

        #[cfg(feature = "sdk")]
        let resolve_http_request = self.config.resolve_http_request;

        let res: String;

        cfg_if::cfg_if! {
            if #[cfg(feature = "sdk")]{
                res = send_request(
                    api_url,
                    "POST".to_string(),
                    Some(serde_json::to_string(&create_output.operation_request)?),
                    request_pointer, resolve_http_request,
                )?.to_string();
            } else {
                let client = reqwest::Client::new();
                res = client
                    .post(api_url)
                    .json(&create_result.operation_request)
                    .send()
                    .await?
                    .text()
                    .await?;

            }
        }
        let response = DidCreateResponse {
            update_key: create_result.update_key,
            recovery_key: create_result.recovery_key,
            did: serde_json::from_str(&res)?,
        };

        if options.wait_for_completion == Some(true) {
            let mut update_found = false;
            let mut timeout_counter = 0;
            while !update_found {
                let res = self
                    .resolve_sidetree_did(
                        self.config.sidetree_rest_api_url.clone(),
                        &response.did.did_document.id,
                    )
                    .await?;
                if res != "Not Found" {
                    let did_doc: SidetreeDidDocument = serde_json::from_str(&res)?;
                    if did_doc.did_document_metadata.method.published == true {
                        update_found = true;
                        break;
                    }
                }
                task::sleep(time::Duration::from_millis(1_000)).await;
                timeout_counter += 1;
                if timeout_counter == 120 {
                    return Ok(VadePluginResultValue::Success(Some(
                        "Error waiting for DID create".to_string(),
                    )));
                }
            }
        }

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &response,
        )?)))
    }

    /// Updates data related to a DID. Updates are supported as per Sidetree documentation
    /// `https://identity.foundation/sidetree/spec/#update`.
    ///
    /// # Arguments
    ///
    /// * `did` - DID to update data for
    /// * `options` - serialized object of TypeOptions
    /// * `payload` - serialized object of DidUpdatePayload
    async fn did_update(
        &mut self,
        did: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(options);

        if !did.starts_with(EVAN_METHOD) {
            return Ok(VadePluginResultValue::Ignored);
        }

        let options: UpdateDidOptions = serde_json::from_str(options)?;
        let mut operation_type: String = String::new();
        let mut api_url = self.config.sidetree_rest_api_url.clone();
        #[cfg(not(feature = "sdk"))]
        let client = Client::new();

        #[cfg(feature = "sdk")]
        let request_pointer = self.config.request_id.clone();

        #[cfg(feature = "sdk")]
        let resolve_http_request = self.config.resolve_http_request;

        api_url.push_str("operations");

        let update_payload: DidUpdatePayload = serde_json::from_str(payload)?;
        let check_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&update_payload.next_update_key)?;
        let update_operation = match update_payload.update_type {
            UpdateType::Update | UpdateType::Recovery => {
                if update_payload.update_type == UpdateType::Update {
                    let operation = UpdateOperationInput::new()
                        .with_did_suffix(did.split(':').last().ok_or("did not valid")?.to_string())
                        .with_patches(update_payload.patches.ok_or("patches not valid")?)
                        .with_update_key(update_payload.update_key.ok_or("update_key not valid")?)
                        .with_update_commitment(check_commitment.clone());
                    operation_type.push_str("update");
                    operations::update(operation)
                } else {
                    let recovery_commitment = multihash::canonicalize_then_double_hash_then_encode(
                        &update_payload.next_recovery_key,
                    )?;
                    let operation = RecoverOperationInput::new()
                        .with_did_suffix(did.split(':').last().ok_or("did not valid")?.to_string())
                        .with_patches(update_payload.patches.ok_or("patches not valid")?)
                        .with_recover_key(
                            update_payload
                                .recovery_key
                                .ok_or("recovery_key not valid")?,
                        )
                        .with_recovery_commitment(recovery_commitment)
                        .with_update_commitment(check_commitment.clone());
                    operation_type.push_str("recover");
                    operations::recover(operation)
                }
            }
            UpdateType::Deactivate => {
                operation_type.push_str("deactivate");
                let operation = DeactivateOperationInput::new()
                    .with_did_suffix(did.split(':').last().ok_or("did not valid")?.to_string())
                    .with_recover_key(
                        update_payload
                            .recovery_key
                            .ok_or("recovery_key not valid")?,
                    );

                operations::deactivate(operation)
            }
        };
        let update_output = match update_operation {
            Ok(value) => value,
            Err(err) => return Err(Box::from(format!("{err}"))),
        };

        let res;
        cfg_if::cfg_if! {
            if #[cfg(feature = "sdk")]{
                res = send_request(api_url, "POST".to_string(), Some(serde_json::to_string(&update_output.operation_request)?), request_pointer, resolve_http_request)?
            } else {
                res = client.post(api_url).json(&update_output.operation_request).send().await?.text().await?
            }
        }

        if options.wait_for_completion == Some(true) {
            let mut update_found = false;
            let mut timeout_counter = 0;
            while !update_found {
                let res = self
                    .resolve_sidetree_did(self.config.sidetree_rest_api_url.clone(), did)
                    .await?;
                if res != "Not Found" {
                    let did_document: SidetreeDidDocument = serde_json::from_str(&res)?;
                    match update_payload.update_type {
                        UpdateType::Update | UpdateType::Recovery => {
                            if did_document
                                .did_document_metadata
                                .method
                                .update_commitment
                                .eq(&Some(check_commitment.clone()))
                            {
                                update_found = true;
                            }
                        }
                        UpdateType::Deactivate => {
                            if did_document.did_document_metadata.deactivated == Some(true) {
                                update_found = true;
                            }
                        }
                    }
                }
                if !update_found {
                    task::sleep(time::Duration::from_millis(1_000)).await;
                    timeout_counter += 1;
                    if timeout_counter == 120 {
                        return Ok(VadePluginResultValue::Success(Some(
                            "Error waiting for DID update".to_string(),
                        )));
                    }
                }
            }
        }

        Ok(VadePluginResultValue::Success(Some(res)))
    }

    /// Fetch data about a DID, which returns this DID's DID document.
    ///
    /// # Arguments
    ///
    /// * `did` - did to fetch data for
    async fn did_resolve(
        &mut self,
        did: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if !did.starts_with(EVAN_METHOD) {
            return Ok(VadePluginResultValue::Ignored);
        }
        let re = Regex::new(METHOD_REGEX)?;
        let is_ethereum_did = re.is_match(did);

        if is_ethereum_did {
            return Ok(VadePluginResultValue::Ignored);
        }

        let res = self
            .resolve_sidetree_did(self.config.sidetree_rest_api_url.clone(), did)
            .await?;

        Ok(VadePluginResultValue::Success(Some(res)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vade_sidetree_client::{
        did::{Document, JsonWebKey, Purpose, Service},
        secp256k1, Patch,
    };
    use serial_test::serial;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn enable_logging() {
        INIT.call_once(|| {
            env_logger::try_init().ok();
        });
    }

    async fn helper_create_did(
        payload: String,
    ) -> Result<DidCreateResponse, Box<dyn std::error::Error>> {
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        // first create a new DID on sidetree
        let result = did_handler
            .did_create(
                "did:evan",
                "{\"type\":\"sidetree\",\"waitForCompletion\":true}",
                &payload,
            )
            .await?;

        let response = match result {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result for did create".to_string())),
        };

        Ok(parse!(&response, "DID create response"))
    }

    async fn helper_resolve_did(
        did: &str,
    ) -> Result<SidetreeDidDocument, Box<dyn std::error::Error>> {
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        let result = did_handler.did_resolve(did).await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result for did resolve".to_string())),
        };

        Ok(parse!(&did_resolve, "DID resolve response"))
    }

    async fn helper_update_did(
        did: &str,
        update_payload: DidUpdatePayload,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        let result = did_handler
            .did_update(
                did,
                &"{\"type\":\"sidetree\", \"waitForCompletion\":true}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        let _response = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result for did update".to_string())),
        };

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_create_did() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        let result = did_handler
            .did_create(
                "did:evan",
                "{\"type\":\"sidetree\",\"waitForCompletion\":true}",
                "{}",
            )
            .await;

        assert_eq!(result.is_ok(), true);

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_create_did_with_predefined_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());

        let options = r###"{
            "type": "sidetree",
            "waitForCompletion":true
          }"###;

        let payload = r###"{
            "updateKey": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "fjpbUu5Vw9a_N2CLMN0FGDxclkMyYB5KmTY1pLiZUSs",
                "y": "1XhoPXS7o5pnrpQJX3kx6GLePa9ciTcH8Fbmo8Kl9S4",
                "d": "slZ0pCqta5YF60ev1N7SY6ffP6Zh_LmkDS_imHtz_jI"
            },
            "recoveryKey": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "PICqtwQRifxZspzID9073FJSI4AE77kjxQD2_t2cj6U",
                "y": "489btoCSOyvhgQJXU9qo7n25ttJDleOMDVCkpOvB9Uk",
                "d": "gU5iJcTcsSA0q2Ajy5bnBQIzOUthMty7swtGGcWORDw"
            }
          }"###;
        let result = did_handler.did_create("did:evan", options, payload).await;

        assert_eq!(result.is_ok(), true);

        let result_value = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result for did create".to_string())),
        };

        let parsed_payload: CreateDidPayload = serde_json::from_str(payload)?;
        let parsed_result_value: DidCreateResponse = serde_json::from_str(&result_value)?;

        assert_eq!(
            serde_json::to_string(&parsed_result_value.update_key)?,
            serde_json::to_string(&parsed_payload.update_key)?,
        );
        assert_eq!(
            serde_json::to_string(&parsed_result_value.recovery_key)?,
            serde_json::to_string(&parsed_payload.recovery_key)?,
        );

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_resolve_did() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let create_response = helper_create_did("{}".to_string()).await?;

        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        assert_eq!(
            resolve_result.did_document.id,
            create_response.did.did_document.id
        );

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_create_did_with_public_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let payload = r###"{
            "publicKeys": [{
                "id":"#bbs-key-1",
                "controller":"did:evan:EiCg3CsLld3PWhj4Binl7TJwElSWtbjCeeB30DpLC23X-w",
                "type":"Bls12381G2Key2020",
                "purposes": ["assertionMethod"],
                "publicKeyJwk":{
                   "kty":"EC",
                   "crv":"BLS12381_G2",
                   "x":"hl3pWYQyn0Cp3YtbCyij+hbnkEiruK2wQr7cAgnCdIf0ol4WJnWYrEQAIJDYNHvIGRwWuAP1+Fc0Jb8h5dicimgJFWkjEVKLyhjs2lJ0UcAQddq+meNhs5VfzMenSG0l"
                }
             }]
        }"###;

        let create_response = helper_create_did(payload.to_string()).await?;

        assert_eq!(
            create_response
                .did
                .did_document
                .verification_method
                .is_some(),
            true
        );
        assert_eq!(
            create_response
                .did
                .did_document
                .verification_method
                .unwrap()
                .len(),
            1
        );

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_create_did_with_services() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let payload = r###"{
            "services": [{
                "id":"service1",
                "type":"CustomService",
                "serviceEndpoint":"http://google.de"
             }]
        }"###;

        let create_response = helper_create_did(payload.to_string()).await?;

        assert_eq!(create_response.did.did_document.service.is_some(), true);
        assert_eq!(create_response.did.did_document.service.unwrap().len(), 1);

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_add_public_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        // then add a new public key to the DID
        let key_pair = secp256k1::KeyPair::random();
        let update_key =
            key_pair.to_public_key("update_key".into(), Some([Purpose::KeyAgreement].to_vec()));

        let patch: Patch = Patch::AddPublicKeys(crate::vade_sidetree_client::AddPublicKeys {
            public_keys: vec![update_key.clone()],
        });

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key),
            next_update_key: Some((&key_pair).into()),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if there are 2 public keys in the DID document
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        assert_eq!(
            resolve_result.did_document.verification_method.is_some(),
            true
        );
        assert_eq!(
            resolve_result
                .did_document
                .verification_method
                .unwrap()
                .len(),
            1
        );

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_remove_public_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        // then add a new public key to the DID
        let key_pair = secp256k1::KeyPair::random();
        let update_key =
            key_pair.to_public_key("update_key".into(), Some([Purpose::KeyAgreement].to_vec()));

        let patch: Patch = Patch::AddPublicKeys(crate::vade_sidetree_client::AddPublicKeys {
            public_keys: vec![update_key.clone()],
        });

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key),
            next_update_key: Some((&key_pair).into()),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if there are 2 public keys in the DID document
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        assert_eq!(
            resolve_result.did_document.verification_method.is_some(),
            true
        );
        assert_eq!(
            resolve_result
                .did_document
                .verification_method
                .unwrap()
                .len(),
            1
        );

        // then remove the public key from the DID again
        let new_key_pair = secp256k1::KeyPair::random();

        let patch: Patch = Patch::RemovePublicKeys(crate::vade_sidetree_client::RemovePublicKeys {
            ids: vec!["update_key".to_string()],
        });

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(JsonWebKey::from(&key_pair)),
            next_update_key: Some((&new_key_pair).into()),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if there are 2 public keys in the DID document
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        assert_eq!(
            resolve_result.did_document.verification_method.is_some(),
            false
        );
        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_add_service_endpoints() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServices(crate::vade_sidetree_client::AddServices {
            services: vec![service],
        });

        // then add a new public key to the DID
        let key_pair = secp256k1::KeyPair::random();

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key),
            next_update_key: Some((&key_pair).into()),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if there is the new added service
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        let did_document_services = resolve_result
            .did_document
            .service
            .ok_or("No Services defined")?;
        assert_eq!(did_document_services.len(), 1);
        assert_eq!(did_document_services[0].service_endpoint, service_endpoint);

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_remove_services() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServices(crate::vade_sidetree_client::AddServices {
            services: vec![service],
        });

        let update1_key_pair = secp256k1::KeyPair::random();

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key),
            next_update_key: Some((&update1_key_pair).into()),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if there is the new added service
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        let did_document_services = resolve_result
            .did_document
            .service
            .ok_or("No Services defined")?;
        assert_eq!(did_document_services.len(), 1);
        assert_eq!(did_document_services[0].service_endpoint, service_endpoint);

        let patch: Patch = Patch::RemoveServices(crate::vade_sidetree_client::RemoveServices {
            ids: vec!["sds".to_string()],
        });

        let update2_key_pair = secp256k1::KeyPair::random();

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some((&update1_key_pair).into()),
            next_update_key: Some((&update2_key_pair).into()),
            next_recovery_key: None,
            patches: Some(vec![patch]),
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if the service is removed
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        assert_eq!(resolve_result.did_document.service.is_none(), true);

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_remove_services_with_nonce() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let create_response = helper_create_did("{}".to_string()).await?;

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServices(crate::vade_sidetree_client::AddServices {
            services: vec![service],
        });

        let mut update1_key_pair = create_response.update_key.clone();
        update1_key_pair.nonce = Some('1'.to_string());

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key.clone()),
            next_update_key: Some((&update1_key_pair).into()),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if there is the new added service
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        let did_document_services = resolve_result
            .did_document
            .service
            .ok_or("No Services defined")?;
        assert_eq!(did_document_services.len(), 1);
        assert_eq!(did_document_services[0].service_endpoint, service_endpoint);

        let patch: Patch = Patch::RemoveServices(crate::vade_sidetree_client::RemoveServices {
            ids: vec!["sds".to_string()],
        });

        let mut update2_key_pair = create_response.update_key.clone();
        update2_key_pair.nonce = Some('2'.to_string());

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(update1_key_pair),
            next_update_key: Some((&update2_key_pair).into()),
            next_recovery_key: None,
            patches: Some(vec![patch]),
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if the service is removed
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;
        assert_eq!(resolve_result.did_document.service.is_none(), true);

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_three_times_with_nonce() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServices(crate::vade_sidetree_client::AddServices {
            services: vec![service],
        });

        let mut update1_key_pair = create_response.update_key.clone();
        update1_key_pair.nonce = Some('1'.to_string());

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key.clone()),
            next_update_key: Some((&update1_key_pair).into()),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if there is the new added service
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        let did_document_services = resolve_result
            .did_document
            .service
            .ok_or("No Services defined")?;
        assert_eq!(did_document_services.len(), 1);
        assert_eq!(did_document_services[0].service_endpoint, service_endpoint);

        let patch: Patch = Patch::RemoveServices(crate::vade_sidetree_client::RemoveServices {
            ids: vec!["sds".to_string()],
        });

        let mut update2_key_pair = create_response.update_key.clone();
        update2_key_pair.nonce = Some('2'.to_string());

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(update1_key_pair),
            next_update_key: Some((&update2_key_pair).into()),
            next_recovery_key: None,
            patches: Some(vec![patch]),
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if the service is removed
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        assert_eq!(resolve_result.did_document.service.is_none(), true);

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServices(crate::vade_sidetree_client::AddServices {
            services: vec![service],
        });

        let mut update3_key_pair = create_response.update_key.clone();
        update3_key_pair.nonce = Some('3'.to_string());

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(update2_key_pair),
            next_update_key: Some((&update3_key_pair).into()),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if there is the new added service
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        let did_document_services = resolve_result
            .did_document
            .service
            .ok_or("No Services defined")?;
        assert_eq!(did_document_services.len(), 1);
        assert_eq!(did_document_services[0].service_endpoint, service_endpoint);

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_recover() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        // try to recover DID

        let update1_key_pair = secp256k1::KeyPair::random();
        let recover1_key_pair = secp256k1::KeyPair::random();

        let patch: Patch = Patch::Replace(crate::vade_sidetree_client::ReplaceDocument {
            document: Document {
                public_keys: Some(vec![update1_key_pair
                    .to_public_key("doc_key".into(), Some([Purpose::KeyAgreement].to_vec()))]),
                services: None,
            },
        });

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Recovery,
            update_key: Some(create_response.update_key),
            next_update_key: Some((&update1_key_pair).into()),
            patches: Some(vec![patch]),
            recovery_key: Some(create_response.recovery_key),
            next_recovery_key: Some((&recover1_key_pair).into()),
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // try to resolve DID after recovery
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        // check if the replaced key is now in the document
        assert_eq!(
            resolve_result.did_document.verification_method.is_some(),
            true
        );
        assert_eq!(
            resolve_result.did_document.verification_method.unwrap()[0].id,
            "#doc_key"
        );

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_recover_with_nonce() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        // try to recover DID

        let mut update1_key_pair = create_response.update_key.clone();
        update1_key_pair.nonce = Some('1'.to_string());
        let mut recover1_key_pair = create_response.recovery_key.clone();
        recover1_key_pair.nonce = Some('1'.to_string());

        let patch: Patch = Patch::Replace(crate::vade_sidetree_client::ReplaceDocument {
            document: Document {
                public_keys: None,
                services: None,
            },
        });

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Recovery,
            update_key: Some(create_response.update_key),
            next_update_key: Some((&update1_key_pair).into()),
            patches: Some(vec![patch]),
            recovery_key: Some(create_response.recovery_key),
            next_recovery_key: Some((&recover1_key_pair).into()),
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // try to resolve DID after recovery
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        // check if the replaced key is now in the document
        assert_eq!(
            resolve_result.did_document.verification_method.is_some(),
            false
        );

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_deactivate_did_after_recover_with_nonce() -> Result<(), Box<dyn std::error::Error>>
    {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        // try to recover DID

        let mut update1_key_pair = create_response.update_key.clone();
        update1_key_pair.nonce = Some('1'.to_string());
        let mut recover1_key_pair = create_response.recovery_key.clone();
        recover1_key_pair.nonce = Some('2'.to_string());

        let patch: Patch = Patch::Replace(crate::vade_sidetree_client::ReplaceDocument {
            document: Document {
                public_keys: None,
                services: None,
            },
        });

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Recovery,
            update_key: Some(create_response.update_key),
            next_update_key: Some((&update1_key_pair).into()),
            patches: Some(vec![patch]),
            recovery_key: Some(create_response.recovery_key.clone()),
            next_recovery_key: Some((&recover1_key_pair).into()),
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // try to resolve DID after recovery
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        // check if the replaced key is now in the document
        assert_eq!(
            resolve_result.did_document.verification_method.is_some(),
            false
        );

        let mut deactivate_key_pair = create_response.recovery_key.clone();
        deactivate_key_pair.nonce = Some('2'.to_string());

        let deactivate_payload = DidUpdatePayload {
            update_type: UpdateType::Deactivate,
            update_key: None,
            next_update_key: None,
            patches: None,
            recovery_key: Some(deactivate_key_pair),
            next_recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, deactivate_payload).await?;

        // after update, resolve and check if the DID is deactivated
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        // check if the replaced key is now in the document
        assert_eq!(
            resolve_result.did_document_metadata.deactivated.is_some(),
            true
        );
        assert_eq!(
            resolve_result.did_document_metadata.deactivated.unwrap(),
            true
        );

        Ok(())
    }

    #[tokio::main]
    #[test]

    async fn can_update_did_deactivate() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        // first create a new DID on sidetree
        let create_response = helper_create_did("{}".to_string()).await?;

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Deactivate,
            update_key: None,
            next_update_key: None,
            patches: None,
            recovery_key: Some(create_response.recovery_key),
            next_recovery_key: None,
        };

        // update the did document with our patches
        helper_update_did(&create_response.did.did_document.id, update_payload).await?;

        // after update, resolve and check if the DID is deactivated
        let resolve_result = helper_resolve_did(&create_response.did.did_document.id).await?;

        // check if the replaced key is now in the document
        assert_eq!(
            resolve_result.did_document_metadata.deactivated.is_some(),
            true
        );
        assert_eq!(
            resolve_result.did_document_metadata.deactivated.unwrap(),
            true
        );

        Ok(())
    }
}
