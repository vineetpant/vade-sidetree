# Rust client library for managing DID operations for [Sidetree](https://github.com/decentralized-identity/sidetree) API services

![Crates.io](https://img.shields.io/crates/v/sidetree-client)

This library provides a set of client services to help work with DID operations for the Sidetree REST API. The goal is to provide access to Sidetree based DID methods using a cross platform library.

## Requirements

This library requires sidetree node to be running and expose API interface. Check the [ION](https://github.com/decentralized-identity/ion) and [Element](https://github.com/decentralized-identity/element) implementations for running a node locally.

## Usage

You can use the library directly in your code, or use the provided CLI to generate requests in console.

### Using the library in your code

Install from [crates.io](https://crates.io/crates/sidetree-client)

```toml
sidetree-client = "*"
```

### Using the CLI from terminal

Install the CLI with

```bash
cargo install sidetree-client
```

Generate `create` request

```
sidetree-client create
```

See a list of all commands supported

```
sidetree-client --help
```

## Specifications

- [Sidetree Protocol](https://identity.foundation/sidetree/spec/)
- [Sidetree REST API](https://identity.foundation/sidetree/api/)

## Sidetree Operations

This library provides objects that are compatible with the API spec. The objects can be converted to JSON using Rust's `serde_json` crate.

### Create Operation

To generate new DID, you can use the `create()` or `create_config(OperationInput)` methods.

#### Create new DID

To generate a request for new DID use the `create()` function. It will generate a request and document with random EC key for `secp256k1` curve:

```rust
use sidetree_client::*;

let create_operation = operations::create().unwrap();

// generate JSON request for use with API spec
let json = serde_json::to_string_pretty(&create_operation.operation_request);

println!("did:ion:{}", create_operation.did_suffix);
println!("{}", json);
```

This operation returns an object of type `OperationOutput` which has the following fields

- `operation_request` - an object that can be serialized to JSON and sent to the `POST /operations` endpoint of the Sidetree service
- `did_siffix` - this is the unique DID suffix that represents the identifier in your DID. It should be appended to your DID to get the full DID identifier, ex. `did:ion:123abc`
- `signing_key` - this field will contain the random key will become part of your DID Document. By default, this key will be of type `EcdsaSecp256k1VerificationKey2019` with a key id `key-1`. To pass your own key, use the `create_config()` method instead
- `update_key` - this key is required to make updates to your DID Document. It will not become part of your public DID Document, it is only used for Sidetree operations. Store this key somewhere secure.
- `recovery_key` - this key is required to recover access to your DID Document. It will not become part of your public DID Document, it is only used for Sidetree operations. Store this key somewhere secure.


### Update Operation

#### Add key to your DID Document

TODO

#### Remove key from your DID Document

TODO

#### Add service entry to your DID Document

TODO

#### Remove service entry from your DID Document

TODO

### Recover Operation

TODO

### Deactivate Operation

TODO

## License

[Apache 2.0](LICENSE)
