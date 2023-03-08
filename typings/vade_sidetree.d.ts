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

export enum UpdateType {
  Update = 'update',
  Recovery = 'recovery',
  Deactivate = 'deactivate',
}

export enum PublicKeyPurpose {
  Authentication = 'authentication',
  AssertionMethod = 'assertionMethod',
  CapabilityInvocation = 'capabilityInvocation',
  CapabilityDelegation = 'capabilityDelegation',
  KeyAgreement = 'keyAgreement',
}

export type Extensible = Record<string, any>;

/**
 * Defines the result of a DID resolution operation.
 *
 * @see https://www.w3.org/TR/did-core/#did-resolution
 */
export interface DidResolutionResult {
  '@context'?: 'https://w3id.org/did-resolution/v1' | string | string[];
  didResolutionMetadata: DIDResolutionMetadata;
  didDocument: DidDocument | null;
  didDocumentMetadata: DidDocumentMetadata;
}

/**
 * Represents metadata about the DID document resulting from a resolve operation.
 *
 * @see https://www.w3.org/TR/did-core/#did-document-metadata
 */
export interface DidDocumentMetadata extends Extensible {
  created?: string;
  updated?: string;
  deactivated?: boolean;
  versionId?: string;
  nextUpdate?: string;
  nextVersionId?: string;
  equivalentId?: string;
  canonicalId?: string;
}

/**
 * Represents the Verification Relationship between a DID subject and a Verification Method.
 *
 * @see https://www.w3.org/TR/did-core/#verification-relationships
 */
export type KeyCapabilitySection =
  | 'authentication'
  | 'assertionMethod'
  | 'keyAgreement'
  | 'capabilityInvocation'
  | 'capabilityDelegation';

/**
 * Represents a DID document.
 *
 * @see https://www.w3.org/TR/did-core/#did-document-properties
 */
export type DidDocument = {
  '@context'?: 'https://www.w3.org/ns/did/v1' | string | string[];
  id: string;
  alsoKnownAs?: string[];
  controller?: string | string[];
  verificationMethod?: VerificationMethod[];
  service?: Service[];
  /**
   * @deprecated
   */
  publicKey?: VerificationMethod[];
} & {
  [x in KeyCapabilitySection]?: (string | VerificationMethod)[];
};

/**
 * Represents a Service entry in a DID document.
 *
 * @see https://www.w3.org/TR/did-core/#services
 * @see https://www.w3.org/TR/did-core/#service-properties
 */
export interface Service {
  id: string;
  type: string;
  serviceEndpoint: ServiceEndpoint | ServiceEndpoint[];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

/**
 * Represents an endpoint of a Service entry in a DID document.
 *
 * @see https://www.w3.org/TR/did-core/#dfn-serviceendpoint
 * @see https://www.w3.org/TR/did-core/#services
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ServiceEndpoint = string | Record<string, any>;

/**
 * Represents the properties of a Verification Method listed in a DID document.
 *
 * This data type includes public key representations that are no longer present in the spec but are still used by
 * several DID methods / resolvers and kept for backward compatibility.
 *
 * @see https://www.w3.org/TR/did-core/#verification-methods
 * @see https://www.w3.org/TR/did-core/#verification-method-properties
 */
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyBase58?: string;
  publicKeyBase64?: string;
  publicKeyJwk?: JsonWebKey;
  publicKeyHex?: string;
  publicKeyMultibase?: string;
  blockchainAccountId?: string;
  ethereumAddress?: string;
}

/**
 * URI params resulting from parsing a DID URI
 */
export interface Params {
  [index: string]: string;
}

export interface DidCreateOptions {
  type: 'sidetree';
  waitForCompletion?: boolean;
}

export interface DidCreatePayload {
  updateKey?: JsonWebKey;
  recoveryKey?: JsonWebKey;
  publicKeys?: PublicKeyModel[];
  services?: Service[];
}

export interface DidCreateResponse {
  updateKey?: JsonWebKey;
  recoveryKey?: JsonWebKey;
  did?: SidetreeDidDocument;
}

export interface MethodMetadata {
  published: boolean;
  updateCommitment?: string;
  recoveryCommitment?: string;
}

export interface DidDocumentMetadata {
  method: MethodMetadata;
  deactivated?: boolean;
}

export interface SidetreeDidDocument {
  '@context': string;
  didDocument: DidDocument;
  didDocumentMetadata: DidDocumentMetadata;
}

export interface DidUpdateOptions {
  type: 'sidetree';
  waitForCompletion?: boolean;
}
export interface DidUpdatePayload {
  updateType: UpdateType;
  updateKey?: JsonWebKey;
  recoveryKey?: JsonWebKey;
  nextUpdateKey?: JsonWebKey;
  nextRecoveryKey?: JsonWebKey;
  patches: Patch[];
}

export interface DidRecoverPayload {
  updateType: UpdateType;
  updateKey?: JsonWebKey;
  recoveryKey?: JsonWebKey;
  nextUpdateKey?: JsonWebKey;
  nextRecoveryKey?: JsonWebKey;
  patches: Patch[];
}

export interface DidDeactivatePayload {
  updateType: UpdateType;
  recoveryKey: JsonWebKey;
}

export interface PublicKeyModel {
  id: string;
  type: string;
  publicKeyJwk: JsonWebKeyWithNonce;
  purposes: PublicKeyPurpose[];
  controller?: string;
}

export enum PublicKeyPurpose {
  Authentication = 'authentication',
  AssertionMethod = 'assertionMethod',
  CapabilityInvocation = 'capabilityInvocation',
  CapabilityDelegation = 'capabilityDelegation',
  KeyAgreement = 'keyAgreement',
}

export interface AddPublicKeysAction {
  action: 'add-public-keys';
  publicKeys: PublicKeyModel[];
}

export interface RemovePublicKeysAction {
  action: 'remove-public-keys';
  ids: string[];
}

export interface ServiceModel {
  id: string;
  type: string;
  serviceEndpoint: string | object;
}

export interface AddServicesAction {
  action: 'add-services';
  services: ServiceModel[];
}

export interface RemoveServicesAction {
  action: 'remove-services';
  ids: string[];
}

export interface ReplaceAction {
  action: 'replace';
  services?: ServiceModel[];
  publicKeys?: PublicKeyModel[];
}

export interface IetfJsonPatch {
  action: 'ietf-json-patch';
  patches: {
    op: string;
    path: string;
    value: Record<string, unknown>;
  }[];
}

export type Patch =
  | AddPublicKeysAction
  | RemovePublicKeysAction
  | AddServicesAction
  | RemoveServicesAction
  | ReplaceAction
  | IetfJsonPatch;

export interface JsonWebKeyWithNonce extends JsonWebKey {
  nonce?: string | number;
}
