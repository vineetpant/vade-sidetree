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

extern crate vade;

use crate::datatypes::*;
use async_trait::async_trait;
use base64::encode_config;
use sidetree_client::{
    operations::UpdateOperationInput,
    operations::{self, Operation},
};
use std::collections::HashMap;
use std::error::Error;
use vade::{VadePlugin, VadePluginResultValue};

const DEFAULT_URL: &str = "http://localhost:3000/1.0/";
const EVAN_METHOD: &str = "did:evan";

/// Sidetree Rest API url
pub struct VadeSidetree {
    pub config: SideTreeConfig,
}

impl VadeSidetree {
    /// Creates new instance of `VadeSidetree`.
    pub fn new(sidetree_rest_api_url: Option<String>) -> VadeSidetree {
        // Setting default value for sidetree api url
        // If environment variable is found and it contains some value, it will replace default value
        let url = sidetree_rest_api_url.unwrap_or_else(|| DEFAULT_URL.to_string());

        let config = SideTreeConfig {
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
    /// * `_options` - for sidetree implementation options are not required, so can be left empty
    /// * `_payload` - no payload required, so can be left empty
    async fn did_create(
        &mut self,
        did_method: &str,
        _options: &str,
        _payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
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

        let client = reqwest::Client::new();
        let res = client.post(api_url).json(&map).send().await?.text().await?;

        let response = DidCreateResponse {
            update_key: create_result.update_key,
            recovery_key: create_result.recovery_key,
            did: serde_json::from_str(&res)?,
        };

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
    /// * `_options` - for sidetree implementation options are not required, so can be left empty
    /// * `payload` - serialized object of DidUpdatePayload
    async fn did_update(
        &mut self,
        did: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if !did.starts_with(EVAN_METHOD) {
            return Ok(VadePluginResultValue::Ignored);
        }

        let update_payload: DidUpdatePayload = serde_json::from_str(payload)?;
        let operation = UpdateOperationInput::new()
            .with_did_suffix(did.split(":").last().ok_or("did not valid")?.to_string())
            .with_patches(update_payload.patches)
            .with_update_key(update_payload.update_key)
            .with_update_commitment(update_payload.update_commitment);

        let update_operation = operations::update(operation);
        let update_output = match update_operation {
            Ok(value) => value,
            Err(err) => return Err(Box::from(format!("{}", err))),
        };

        if let Operation::Update(did, delta, signed) = update_output.operation_request {
            let mut api_url = self.config.sidetree_rest_api_url.clone();
            api_url.push_str("operations");
            let delta_base64 =
                &encode_config(serde_json::to_string(&delta)?, base64::STANDARD_NO_PAD);

            let mut map = HashMap::new();
            map.insert("type", "update");
            map.insert("signed_data", &signed);
            map.insert("did_suffix", &did);
            map.insert("delta", delta_base64);
            let client = reqwest::Client::new();
            let res = client.post(api_url).json(&map).send().await?.text().await?;
            return Ok(VadePluginResultValue::Success(Some(res)));
        }
        Ok(VadePluginResultValue::Success(Some("".to_string())))
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

        let mut api_url = self.config.sidetree_rest_api_url.clone();
        api_url.push_str("identifiers/");
        api_url.push_str(did_id);

        let client = reqwest::Client::new();
        let res = client.get(api_url).send().await?.text().await?;

        Ok(VadePluginResultValue::Success(Some(res)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidetree_client::{
        did::{Purpose, Service, JsonWebKey},
        multihash, secp256k1,
        Patch
    };
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn enable_logging() {
        INIT.call_once(|| {
            env_logger::try_init().ok();
        });
    }

    #[tokio::test]
    async fn can_create_did() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        let result = did_handler.did_create("did:evan", "{}", "{}").await;

        assert_eq!(result.is_ok(), true);
        Ok(())
    }

    #[tokio::test]
    async fn can_resolve_did() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());

        // first create a new DID on sidetree
        let result = did_handler.did_create("did:evan", "{}", "{}").await;

        let response = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        assert_eq!(
            resolve_result.did_document.id,
            create_response.did.did_document.id
        );
        Ok(())
    }

    #[tokio::test]
    async fn can_update_did_add_public_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());

        // first create a new DID on sidetree
        let result = did_handler.did_create("did:evan", "{}", "{}").await;

        let response = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        // then add a new public key to the DID
        let key_pair = secp256k1::KeyPair::random();
        let update_key =
            key_pair.to_public_key("update_key".into(), Some([Purpose::Agreement].to_vec()));

        let patch: Patch = Patch::AddPublicKeys(sidetree_client::AddPublicKeys {
            public_keys: vec![update_key.clone()],
        });

        let update_commitment = multihash::canonicalize_then_double_hash_then_encode(&update_key)?;

        let update_payload = DidUpdatePayload {
            update_key: create_response.update_key,
            update_commitment,
            patches: vec![patch],
        };
        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                &"{}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        let _respone = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        // after update, resolve and check if there are 2 public keys in the DID document
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        assert_eq!(resolve_result.did_document.key_agreement.len(), 2);
        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn can_update_did_remove_public_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let create_operation = operations::create();
        let create_output = match create_operation {
            Ok(value) => value,
            Err(err) => return Err(Box::from(format!(" {}", err))),
        };
        let json = serde_json::to_string(&create_output)?;
        let create_response: DIDCreateResult = serde_json::from_str(&json)?;

        let key_pair = secp256k1::KeyPair::random();
        let update_key =
            key_pair.to_public_key("update_key".into(), Some([Purpose::Agreement].to_vec()));

        let patch: Patch = Patch::RemovePublicKeys(sidetree_client::RemovePublicKeys {
            ids: vec!["update_key".to_string()],
        });

        let update_commitment = multihash::canonicalize_then_double_hash_then_encode(&update_key)?;

        let update_payload = DidUpdatePayload {
            update_key: create_response.update_key,
            update_commitment,
            patches: vec![patch],
        };

        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        let result = did_handler
            .did_update(
                &format!(
                    "did:evan:{}",
                    "EiC5_bIqTpMDGHBra-XnjoVV1r4mZwBt9pYNx8VaSaEZtQ"
                ),
                &"{}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        let respone = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };
        println!("did update result: {}", &respone);

        assert_eq!(result.is_ok(), true);
        Ok(())
    }

    #[tokio::test]
    async fn can_update_did_add_service_endpoints() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        // first create a new DID on sidetree
        let result = did_handler.did_create("did:evan", "{}", "{}").await;

        let response = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServiceEndpoints(sidetree_client::AddServices {
            service_endpoints: vec![service],
        });

        let update_commitment = multihash::canonicalize_then_hash_then_encode(
            &create_response.update_key,
            multihash::HashAlgorithm::Sha256,
        );

        let update_payload = DidUpdatePayload {
            update_key: create_response.update_key,
            update_commitment,
            patches: vec![patch],
        };

        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                &"{}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);

        // after update, resolve and check if there is the new added service
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
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
    async fn can_update_did_remove_services() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();

        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());
        // first create a new DID on sidetree
        let result = did_handler.did_create("did:evan", "{}", "{}").await;

        let response = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServiceEndpoints(sidetree_client::AddServices {
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
            update_key: create_response.update_key.clone(),
            update_commitment,
            patches: vec![patch],
        };

        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                &"{}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);

        // after update, resolve and check if there is the new added service
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        let did_document_services = resolve_result
            .did_document
            .service
            .ok_or("No Services defined")?;
        assert_eq!(did_document_services.len(), 1);
        assert_eq!(did_document_services[0].service_endpoint, service_endpoint);

        let patch: Patch = Patch::RemoveServiceEndpoints(sidetree_client::RemoveServices {
            ids: vec!["sds".to_string()],
        });

        let update_commitment =
            multihash::canonicalize_then_hash_then_encode(&patch, multihash::HashAlgorithm::Sha256);

        let update_payload = DidUpdatePayload {
            update_key: (&update1_key_pair).into(),
            update_commitment,
            patches: vec![patch],
        };

        let result = did_handler
            .did_update(
                &create_response.did.did_document.id,
                &"{}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);

        // after update, resolve and check if the service is removed
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result.as_ref() {
            Ok(VadePluginResultValue::Success(Some(value))) => value.to_string(),
            Ok(_) => "Unknown Result".to_string(),
            Err(e) => e.to_string(),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        assert_eq!(resolve_result.did_document.service.is_none(), true);
        Ok(())
    }
}
