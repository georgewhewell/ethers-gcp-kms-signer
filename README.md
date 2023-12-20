# ethers-gcp-kms-signer

[![Crates.io](https://img.shields.io/crates/v/ethers-gcp-kms-signer.svg)](https://crates.io/crates/ethers-gcp-kms-signer)
[![Docs.rs](https://docs.rs/ethers-gcp-kms-signer/badge.svg)](https://docs.rs/ethers-gcp-kms-signer)
[![CI](https://github.com/georgewhewell/ethers-gcp-kms-signer/workflows/CI/badge.svg)](https://github.com/georgewhewell/ethers-gcp-kms-signer/actions)

## Installation

### Cargo

```shell
cargo add ethers-gcp-kms-signer
```

### Usage
#### Signer
```rust
use ethers::prelude::*;
use ethers_gcp_kms_signer::{GcpKeyRingRef, GcpKmsProvider, GcpKmsSigner};

let project_id = std::env::var("GOOGLE_PROJECT_ID").expect("GOOGLE_PROJECT_ID");
let location = std::env::var("GOOGLE_LOCATION").expect("GOOGLE_LOCATION");
let keyring = std::env::var("GOOGLE_KEYRING").expect("GOOGLE_KEYRING");
let key_name = std::env::var("GOOGLE_KEY_NAME").expect("GOOGLE_KEY_NAME");

let keyring = GcpKeyRingRef::new(&project_id, &location, &keyring);
let provider = GcpKmsProvider::new(keyring)
    .await
    .expect("Failed to create GCP KMS provider");
let signer = GcpKmsSigner::new(provider, key_name.to_string(), 1, 1)
    .await
    .expect("get key");
```

You can then use it as regular `ethers` signer:

```rust
let provider = Provider::<Http>::try_from(RPC_URL).unwrap().with_signer(signer);
```

#### Credentials

The library will attempt to load credentials in the typical fashion for GCP-

- If the application is running in a k8s cluster, it should automatically pick up credentials
- If the `GOOGLE_APPLICATION_CREDENTIALS` environment is set, attempt to load a service account JSON from this path

## Demo

An example app is included in the repo, with terraform manifests
to provision a HSM-based key, create a service account with permission to sign using the key, and export a json key with the credentials of this service account.

First, init and apply the terraform:

    $ cd example/terraform
    $ terraform init
    $ terraform apply

Output the service account credentials:

    $ terraform output service_account_key > service_account_key.json

To export the service account key in a usable format:

    $ cat service_account_key.json | jq -r | base64 -d > ../demo-app/service_account_key.json

To run the example:

```shell
❯ export GOOGLE_PROJECT_ID=<project_id>
❯ export GOOGLE_LOCATION=<location>
❯ export GOOGLE_KEYRING=<keyring-name>
❯ export GOOGLE_KEY_NAME=<key-name>
❯ export GOOGLE_APPLICATION_CREDENTIALS=service_account_key.json
❯ cargo run
   Compiling demo-app v0.1.0 (/home/grw/src/ethers-gcp-kms-signer/example/demo-app)
    Finished dev [unoptimized + debuginfo] target(s) in 6.14s
     Running `target/debug/demo-app`
Created signer: GcpKmsSigner { ... }
Signer address: 0xa2e83c0ecc9ffeddb34e027bf3c44971c45fca12
Anvil running at `http://localhost:40023`
Sent 1 ETH to the signer
Sent 1 Wei from the signer
Signer balance: 999960621324999999
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

See [CONTRIBUTING.md](CONTRIBUTING.md).
