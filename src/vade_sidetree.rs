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
use crate::in3_request_list::ResolveHttpRequest;
use async_trait::async_trait;
use base64::encode_config;
use regex::Regex;
#[cfg(not(feature = "sdk"))]
use reqwest::Client;
use std::collections::HashMap;
use std::error::Error;
#[cfg(feature = "sdk")]
use std::ffi::{CStr, CString};
#[cfg(feature = "sdk")]
use std::os::raw::c_char;
#[cfg(feature = "sdk")]
use std::os::raw::c_void;
use vade::{VadePlugin, VadePluginResultValue};
use vade_sidetree_client::{
    operations::{self, DeactivateOperationInput, Operation},
    operations::{RecoverOperationInput, UpdateOperationInput},
};

const DEFAULT_URL: &str = "https://sidetree.evan.network/1.0/";
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
}

#[async_trait(?Send)]
impl VadePlugin for VadeSidetree {
    /// Creates a new DID on sidetree.
    ///
    /// # Arguments
    ///
    /// * `did_method` - did method to cater to, usually "did:evan"
    /// * `options` - serialized object of TypeOptions
    /// * `_payload` - no payload required, so can be left empty
    async fn did_create(
        &mut self,
        did_method: &str,
        options: &str,
        _payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(options);

        if !did_method.starts_with(EVAN_METHOD) {
            return Ok(VadePluginResultValue::Ignored);
        }
        let create_operation = operations::create();
        let create_output = match create_operation {
            Ok(value) => value,
            Err(err) => return Err(Box::from(format!("{}", err))),
        };
        let json = serde_json::to_string(&create_output)?;
        let mut api_url = self.config.sidetree_rest_api_url.clone();
        api_url.push_str("operations");
        let create_result: DIDCreateResult = serde_json::from_str(&json)?;
        let suffix_data_base64 = &encode_config(
            serde_json::to_string(&create_result.operation_request.suffix_data)?,
            base64::STANDARD_NO_PAD,
        );
        let delta_base64 = &encode_config(
            serde_json::to_string(&create_result.operation_request.delta)?,
            base64::STANDARD_NO_PAD,
        );
        let mut map = HashMap::new();
        map.insert("type", "create");
        map.insert("suffix_data", suffix_data_base64);
        map.insert("delta", delta_base64);

        #[cfg(feature = "sdk")]
        let request_pointer = self.config.request_id.clone();

        #[cfg(feature = "sdk")]
        let resolve_http_request = self.config.resolve_http_request;
        
        cfg_if::cfg_if! {
            if #[cfg(feature = "sdk")]{
                    // If compiled for sdk integration, get_http_response function will be called
                    let url = CString::new(api_url.to_string())?;
                    let url = url.as_ptr();
    
                    let method = CString::new("POST")?;
                    let method = method.as_ptr();
    
                    let path = CString::new("")?;
                    let path = path.as_ptr();
    
                    let payload = serde_json::to_string(&map)?;
                    let payload = CString::new(payload)?;
                    let payload = payload.as_ptr();
    
                    let mut res: *mut c_char = std::ptr::null_mut();
    
                    let error_code = (resolve_http_request)(
                        request_pointer,
                        url,
                        method,
                        path,
                        payload,
                        &mut res as *mut *mut c_char);

                    if error_code < 0 {
                        return Err(Box::from(format!("{}", error_code)));
                    }
                    let res = unsafe { CStr::from_ptr(res).to_string_lossy().into_owned() };
                    return Ok(VadePluginResultValue::Success(Some(res.to_string())));
            } else {
                let client = Client::new();
                let res = client.post(api_url).json(&map).send().await?.text().await?;

                let response = DidCreateResponse {
                    update_key: create_result.update_key,
                    recovery_key: create_result.recovery_key,
                    did: serde_json::from_str(&res)?,
                };

                Ok(VadePluginResultValue::Success(Some(serde_json::to_string(&response)?)))
            }
        }
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

        let mut operation_type: String = String::new();
        let mut api_url = self.config.sidetree_rest_api_url.clone();
        let mut map = HashMap::new();
        let client = Client::new();

        #[cfg(feature = "sdk")]
        let request_pointer = self.config.request_id.clone();

        #[cfg(feature = "sdk")]
        let resolve_http_request = self.config.resolve_http_request;

        api_url.push_str("operations");

        let update_payload: DidUpdatePayload = serde_json::from_str(payload)?;
        let update_operation = match update_payload.update_type {
            UpdateType::Update | UpdateType::Recovery => {
                if update_payload.update_type == UpdateType::Update {
                    let operation = UpdateOperationInput::new()
                        .with_did_suffix(did.split(":").last().ok_or("did not valid")?.to_string())
                        .with_patches(update_payload.patches.ok_or("patches not valid")?)
                        .with_update_key(update_payload.update_key.ok_or("update_key not valid")?)
                        .with_update_commitment(
                            update_payload
                                .update_commitment
                                .ok_or("update_commitment not valid")?
                                .to_string(),
                        );
                    operation_type.push_str("update");
                    operations::update(operation)
                } else {
                    let operation = RecoverOperationInput::new()
                        .with_did_suffix(did.split(":").last().ok_or("did not valid")?.to_string())
                        .with_patches(update_payload.patches.ok_or("patches not valid")?)
                        .with_recover_key(
                            update_payload
                                .recovery_key
                                .ok_or("recovery_key not valid")?,
                        )
                        .with_recovery_commitment(
                            update_payload
                                .recovery_commitment
                                .ok_or("recovery_commitment not valid")?
                                .to_string(),
                        )
                        .with_update_commitment(
                            update_payload
                                .update_commitment
                                .ok_or("update_commitment not valid")?
                                .to_string(),
                        );
                    operation_type.push_str("recover");
                    operations::recover(operation)
                }
            }
            UpdateType::Deactivate => {
                operation_type.push_str("deactivate");
                let operation = DeactivateOperationInput::new()
                    .with_did_suffix(did.split(":").last().ok_or("did not valid")?.to_string())
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
            Err(err) => return Err(Box::from(format!("{}", err))),
        };

        let res = match update_output.operation_request {
            Operation::Update(did, delta, signed) | Operation::Recover(did, delta, signed) => {
                let mut delta_base64 = String::new();
                delta_base64.push_str(&encode_config(
                    serde_json::to_string(&delta)?,
                    base64::STANDARD_NO_PAD,
                ));

                map.insert("type", &operation_type);
                map.insert("signed_data", &signed);
                map.insert("did_suffix", &did);
                map.insert("delta", &delta_base64);

                cfg_if::cfg_if! {
                    if #[cfg(feature = "sdk")]{
                            // If compiled for sdk integration, get_http_response function will be called
                            let url = CString::new(api_url.to_string())?;
                            let url = url.as_ptr();
            
                            let method = CString::new("POST")?;
                            let method = method.as_ptr();
            
                            let path = CString::new("")?;
                            let path = path.as_ptr();
            
                            let payload = serde_json::to_string(&map)?;
                            let payload = CString::new(payload)?;
                            let payload = payload.as_ptr();
            
                            let mut res: *mut c_char = std::ptr::null_mut();
            
                            let error_code = (resolve_http_request)(
                                request_pointer,
                                url,
                                method,
                                path,
                                payload,
                                &mut res as *mut *mut c_char);
        
                            if error_code < 0 {
                                return Err(Box::from(format!("{}", error_code)));
                            }
                            let res = unsafe { CStr::from_ptr(res).to_string_lossy().into_owned() };
                            res
                    } else {
                        client.post(api_url).json(&map).send().await?.text().await?
                    }
                }
                
            }

            Operation::Deactivate(did, signed) => {
                map.insert("type", &operation_type);
                map.insert("signed_data", &signed);
                map.insert("did_suffix", &did);

                client.post(api_url).json(&map).send().await?.text().await?
            }
            _ => return Err(Box::from("Invalid operation")),
        };

        Ok(VadePluginResultValue::Success(Some(res)))
    }

    /// Fetch data about a DID, which returns this DID's DID document.
    ///
    /// # Arguments
    ///
    /// * `did` - did to fetch data for
    async fn did_resolve(
        &mut self,
        did_id: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if !did_id.starts_with(EVAN_METHOD) {
            return Ok(VadePluginResultValue::Ignored);
        }
        let re = Regex::new(METHOD_REGEX)?;
        let is_ethereum_did = re.is_match(&did_id);

        if is_ethereum_did {
            return Ok(VadePluginResultValue::Ignored);
        }

        #[cfg(feature = "sdk")]
        let request_pointer = self.config.request_id.clone();

        #[cfg(feature = "sdk")]
        let resolve_http_request = self.config.resolve_http_request;

        let mut api_url = self.config.sidetree_rest_api_url.clone();
        api_url.push_str("identifiers/");
        api_url.push_str(did_id);

        let client = Client::new();
        let res = client.get(api_url).send().await?.text().await?;

        Ok(VadePluginResultValue::Success(Some(res)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::sync::Once;
    use std::{thread, time::Duration};
    use vade_sidetree_client::{
        did::{Document, JsonWebKey, Purpose, Service},
        multihash, secp256k1, Patch,
    };

    static INIT: Once = Once::new();

    fn enable_logging() {
        INIT.call_once(|| {
            env_logger::try_init().ok();
        });
    }

    #[tokio::test]
    #[serial]
    async fn can_create_did() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        let result = did_handler
            .did_create("did:evan", "{\"type\":\"sidetree\"}", "{}")
            .await;

        assert_eq!(result.is_ok(), true);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn can_resolve_did() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());

        // first create a new DID on sidetree
        let result = did_handler
            .did_create("did:evan", "{\"type\":\"sidetree\"}", "{}")
            .await?;

        let response = match result {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        assert_eq!(
            resolve_result.did_document.id,
            create_response.did.did_document.id
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn can_update_did_add_public_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());

        // first create a new DID on sidetree
        let result = did_handler
            .did_create("did:evan", "{\"type\":\"sidetree\"}", "{}")
            .await;
        assert!(result.is_ok());

        let response = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        // then add a new public key to the DID
        let key_pair = secp256k1::KeyPair::random();
        let update_key =
            key_pair.to_public_key("update_key".into(), Some([Purpose::Agreement].to_vec()));

        let patch: Patch = Patch::AddPublicKeys(vade_sidetree_client::AddPublicKeys {
            public_keys: vec![update_key.clone()],
        });

        let update_commitment = multihash::canonicalize_then_double_hash_then_encode(&update_key)?;

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key),
            update_commitment: Some(update_commitment),
            patches: Some(vec![patch]),
            recovery_commitment: None,
            recovery_key: None,
        };

        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                &"{\"type\":\"sidetree\"}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        let _respone = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        // after update, resolve and check if there are 2 public keys in the DID document
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        assert_eq!(resolve_result.did_document.key_agreement.len(), 2);

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    #[serial]
    async fn can_update_did_remove_public_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let create_operation = operations::create();
        let create_output = match create_operation {
            Ok(value) => value,
            Err(err) => return Err(Box::from(format!(" {}", err))),
        };
        let json = serde_json::to_string(&create_output)?;
        let create_response: DIDCreateResult = serde_json::from_str(&json)?;

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        let key_pair = secp256k1::KeyPair::random();
        let update_key =
            key_pair.to_public_key("update_key".into(), Some([Purpose::Agreement].to_vec()));

        let patch: Patch = Patch::RemovePublicKeys(vade_sidetree_client::RemovePublicKeys {
            ids: vec!["update_key".to_string()],
        });

        let update_commitment = multihash::canonicalize_then_double_hash_then_encode(&update_key)?;

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key),
            update_commitment: Some(update_commitment),
            patches: Some(vec![patch]),
            recovery_commitment: None,
            recovery_key: None,
        };

        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        let result = did_handler
            .did_update(
                &format!(
                    "did:evan:{}",
                    "EiC5_bIqTpMDGHBra-XnjoVV1r4mZwBt9pYNx8VaSaEZtQ"
                ),
                &"{\"type\":\"sidetree\"}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);
        let _respone = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn can_update_did_add_service_endpoints() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        // first create a new DID on sidetree
        let result = did_handler
            .did_create("did:evan", "{\"type\":\"sidetree\"}", "{}")
            .await;
        assert!(result.is_ok());

        let response = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServiceEndpoints(vade_sidetree_client::AddServices {
            service_endpoints: vec![service],
        });

        let update_commitment = multihash::canonicalize_then_hash_then_encode(
            &create_response.update_key,
            multihash::HashAlgorithm::Sha256,
        );

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key),
            update_commitment: Some(update_commitment),
            patches: Some(vec![patch]),
            recovery_commitment: None,
            recovery_key: None,
        };

        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                &"{\"type\":\"sidetree\"}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        // after update, resolve and check if there is the new added service
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        let did_document_services = resolve_result
            .did_document
            .service
            .ok_or("No Services defined")?;
        assert_eq!(did_document_services.len(), 1);
        assert_eq!(did_document_services[0].service_endpoint, service_endpoint);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn can_update_did_remove_services() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        // first create a new DID on sidetree
        let result = did_handler
            .did_create("did:evan", "{\"type\":\"sidetree\"}", "{}")
            .await;
        assert!(result.is_ok());

        let response = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServiceEndpoints(vade_sidetree_client::AddServices {
            service_endpoints: vec![service],
        });

        let update1_key_pair = secp256k1::KeyPair::random();
        let mut update1_public_key: JsonWebKey = (&update1_key_pair).into();
        update1_public_key.d = None;

        let update_commitment = multihash::canonicalize_then_hash_then_encode(
            &update1_public_key,
            multihash::HashAlgorithm::Sha256,
        );

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(create_response.update_key),
            update_commitment: Some(update_commitment),
            patches: Some(vec![patch]),
            recovery_commitment: None,
            recovery_key: None,
        };

        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                &"{\"type\":\"sidetree\"}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        // after update, resolve and check if there is the new added service
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        let did_document_services = resolve_result
            .did_document
            .service
            .ok_or("No Services defined")?;
        assert_eq!(did_document_services.len(), 1);
        assert_eq!(did_document_services[0].service_endpoint, service_endpoint);

        let patch: Patch = Patch::RemoveServiceEndpoints(vade_sidetree_client::RemoveServices {
            ids: vec!["sds".to_string()],
        });

        let update_commitment =
            multihash::canonicalize_then_hash_then_encode(&patch, multihash::HashAlgorithm::Sha256);

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some((&update1_key_pair).into()),
            update_commitment: Some(update_commitment),
            patches: Some(vec![patch]),
            recovery_commitment: None,
            recovery_key: None,
        };

        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                &"{\"type\":\"sidetree\"}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        // after update, resolve and check if the service is removed
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        assert!(result.is_ok());

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        assert_eq!(resolve_result.did_document.service.is_none(), true);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn can_update_did_recover() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        // first create a new DID on sidetree
        let result = did_handler
            .did_create("did:evan", "{\"type\":\"sidetree\"}", "{}")
            .await;
        assert!(result.is_ok());

        let response = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        // resolve DID
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        assert_eq!(
            resolve_result.did_document.id,
            create_response.did.did_document.id
        );

        // try to recover DID

        let update1_key_pair = secp256k1::KeyPair::random();
        let mut update1_public_key: JsonWebKey = (&update1_key_pair).into();
        update1_public_key.d = None;

        let recover1_key_pair = secp256k1::KeyPair::random();
        let mut recover1_public_key: JsonWebKey = (&recover1_key_pair).into();
        recover1_public_key.d = None;

        let patch: Patch = Patch::Replace(vade_sidetree_client::ReplaceDocument {
            document: Document {
                public_keys: vec![update1_key_pair
                    .to_public_key("doc_key".into(), Some([Purpose::Agreement].to_vec()))],
                services: None,
            },
        });

        let recovery_commitment = multihash::canonicalize_then_hash_then_encode(
            &recover1_public_key,
            multihash::HashAlgorithm::Sha256,
        );

        let update_commitment = multihash::canonicalize_then_hash_then_encode(
            &update1_public_key,
            multihash::HashAlgorithm::Sha256,
        );

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Recovery,
            update_key: Some(update1_public_key),
            update_commitment: Some(update_commitment),
            patches: Some(vec![patch]),
            recovery_commitment: Some(recovery_commitment),
            recovery_key: Some(create_response.recovery_key),
        };

        let _result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                "{\"type\":\"sidetree\"}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        // try to resolve DID after recovery
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        assert_eq!(result.is_ok(), true);
        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;

        // check if the replaced key is now in the document
        assert_eq!(resolve_result.did_document.key_agreement[0].id, "#doc_key");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn can_update_did_deactivate() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        // first create a new DID on sidetree
        let result = did_handler
            .did_create("did:evan", "{\"type\":\"sidetree\"}", "{}")
            .await;
        assert!(result.is_ok());

        let response = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Deactivate,
            update_key: None,
            update_commitment: None,
            patches: None,
            recovery_commitment: None,
            recovery_key: Some(create_response.recovery_key),
        };

        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                "{\"type\":\"sidetree\"}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(20000));
        // after update, resolve and check if the DID is deactivated
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        assert_eq!(did_resolve, "{\"status\":\"deactivated\"}");

        Ok(())
    }
}
