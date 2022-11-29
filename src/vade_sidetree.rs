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
use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use vade::{VadePlugin, VadePluginResultValue};
use vade_sidetree_client::{
    did::JsonWebKey,
    operations::{self, DeactivateOperationInput, OperationInput},
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

/// Options for DID creation. If keys are not provided, they will be generated automatically
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidOptions {
    pub r#type: String,
    pub update_key: Option<JsonWebKey>,
    pub recovery_key: Option<JsonWebKey>,
}

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
    /// * `options` - serialized object of CreateDidOptions
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
        let options: CreateDidOptions = serde_json::from_str(options)?;
        let config = OperationInput {
            public_keys: None,
            services: None,
            update_key: options.update_key,
            recovery_key: options.recovery_key,
        };
        let create_operation = operations::create(Some(config));
        let create_output = match create_operation {
            Ok(value) => value,
            Err(err) => return Err(Box::from(format!("{}", err))),
        };
        let json = serde_json::to_string(&create_output)?;
        let mut api_url = self.config.sidetree_rest_api_url.clone();
        api_url.push_str("operations");
        let create_result: DIDCreateResult = serde_json::from_str(&json)?;

        let client = reqwest::Client::new();
        let res = client
            .post(api_url)
            .json(&create_result.operation_request)
            .send()
            .await?
            .text()
            .await?;
        dbg!(&res);
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
        let client = reqwest::Client::new();

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
        dbg!(serde_json::to_string(&update_output.operation_request)?);
        let res = client
            .post(api_url)
            .json(&update_output.operation_request)
            .send()
            .await?
            .text()
            .await?;

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

    #[tokio::main]
    #[test]
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

    #[tokio::main]
    #[test]
    #[serial]
    async fn can_create_did_with_predefined_keys() -> Result<(), Box<dyn std::error::Error>> {
        enable_logging();
        let mut did_handler = VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok());

        let options = r###"{
            "type": "sidetree",
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

        let result = did_handler.did_create("did:evan", options, "{}").await;

        assert_eq!(result.is_ok(), true);

        let result_value = match result {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let parsed_options: CreateDidOptions = serde_json::from_str(options)?;
        let parsed_result_value: DidCreateResponse = serde_json::from_str(&result_value)?;

        assert_eq!(
            serde_json::to_string(&parsed_result_value.update_key)?,
            serde_json::to_string(&parsed_options.update_key)?,
        );
        assert_eq!(
            serde_json::to_string(&parsed_result_value.recovery_key)?,
            serde_json::to_string(&parsed_options.recovery_key)?,
        );

        Ok(())
    }

    #[tokio::main]
    #[test]
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
        thread::sleep(Duration::from_millis(40000));

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

    #[tokio::main]
    #[test]
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
            key_pair.to_public_key("update_key".into(), Some([Purpose::KeyAgreement].to_vec()));

        let patch: Patch = Patch::AddPublicKeys(vade_sidetree_client::AddPublicKeys {
            public_keys: vec![update_key.clone()],
        });

        let update_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&update_key.public_key_jwk)?;

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

        let _response = match result? {
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
    #[serial]
    async fn can_update_did_remove_public_keys() -> Result<(), Box<dyn std::error::Error>> {
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

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(40000));

        let create_response: DidCreateResponse = serde_json::from_str(&response)?;

        // then add a new public key to the DID
        let key_pair = secp256k1::KeyPair::random();
        let update_key =
            key_pair.to_public_key("update_key".into(), Some([Purpose::KeyAgreement].to_vec()));

        let patch: Patch = Patch::AddPublicKeys(vade_sidetree_client::AddPublicKeys {
            public_keys: vec![update_key.clone()],
        });

        let update_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&update_key.public_key_jwk)?;

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

        let _response = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(40000));

        // after update, resolve and check if there are 2 public keys in the DID document
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
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
        let new_update_key = new_key_pair.to_public_key(
            "new_update_key".into(),
            Some([Purpose::KeyAgreement].to_vec()),
        );

        let patch: Patch = Patch::RemovePublicKeys(vade_sidetree_client::RemovePublicKeys {
            ids: vec!["update_key".to_string()],
        });

        let update_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&new_update_key)?;

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(JsonWebKey::from(&key_pair)),
            update_commitment: Some(update_commitment),
            patches: Some(vec![patch]),
            recovery_commitment: None,
            recovery_key: None,
        };

        let result = did_handler
            .did_update(
                &format!("did:evan:{}", &create_response.did.did_document.id),
                &"{\"type\":\"sidetree\"}",
                &serde_json::to_string(&update_payload)?,
            )
            .await;

        assert_eq!(result.is_ok(), true);
        let _respone = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(40000));

        // after update, resolve and check if there are 2 public keys in the DID document
        let result = did_handler
            .did_resolve(&create_response.did.did_document.id)
            .await;

        let did_resolve = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;
        assert_eq!(
            resolve_result.did_document.verification_method.is_some(),
            false
        );
        Ok(())
    }

    #[tokio::main]
    #[test]
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
            service_endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServices(vade_sidetree_client::AddServices {
            services: vec![service],
        });

        // then add a new public key to the DID
        let key_pair = secp256k1::KeyPair::random();
        let update_key =
            key_pair.to_public_key("update_key".into(), Some([Purpose::KeyAgreement].to_vec()));

        let update_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&update_key.public_key_jwk)?;

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

        let _response = match result? {
            VadePluginResultValue::Success(Some(value)) => value.to_string(),
            _ => return Err(Box::from("Unknown Result".to_string())),
        };

        // Sleep is required to let the create or update operation take effect
        thread::sleep(Duration::from_millis(40000));

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

    #[tokio::main]
    #[test]
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
            service_endpoint: service_endpoint.clone(),
        };

        let patch: Patch = Patch::AddServices(vade_sidetree_client::AddServices {
            services: vec![service],
        });

        let update1_key_pair = secp256k1::KeyPair::random();
        let mut update1_public_key: JsonWebKey = (&update1_key_pair).into();
        update1_public_key.d = None;

        let update_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&update1_public_key)?;

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
        thread::sleep(Duration::from_millis(40000));

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

        let patch: Patch = Patch::RemoveServices(vade_sidetree_client::RemoveServices {
            ids: vec!["sds".to_string()],
        });

        let update2_key_pair = secp256k1::KeyPair::random();
        let mut update2_public_key: JsonWebKey = (&update2_key_pair).into();
        update2_public_key.d = None;
        let update_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&update2_public_key)?;

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
        thread::sleep(Duration::from_millis(40000));

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

    #[tokio::main]
    #[test]
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
        thread::sleep(Duration::from_millis(30000));

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
                    .to_public_key("doc_key".into(), Some([Purpose::KeyAgreement].to_vec()))],
                services: None,
            },
        });

        let recovery_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&recover1_public_key)?;

        let update_commitment =
            multihash::canonicalize_then_double_hash_then_encode(&update1_public_key)?;

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
        thread::sleep(Duration::from_millis(30000));

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

        let resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve)?;

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
