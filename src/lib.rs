use async_trait::async_trait;
use ethers::prelude::k256::pkcs8::DecodePublicKey;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::transaction::eip712::Eip712;
use ethers::{
    prelude::k256::{
        ecdsa::{RecoveryId, Signature as KSig, VerifyingKey},
        FieldBytes,
    },
    signers::Signer,
    types::{Address, Signature, H256, U256},
    utils::{hash_message, keccak256},
};
use gcloud_sdk::{
    google::cloud::kms::{
        self,
        v1::{
            key_management_service_client::KeyManagementServiceClient, AsymmetricSignRequest,
            GetPublicKeyRequest,
        },
    },
    GoogleApi, GoogleAuthMiddleware,
};
use std::fmt::Debug;
use tonic::Request;
use tracing::{debug, instrument};

mod error;
pub use error::CKMSError;

/// Convert a verifying key to an ethereum address
fn verifying_key_to_address(key: &VerifyingKey) -> Address {
    // false for uncompressed
    let uncompressed_pub_key = key.to_encoded_point(false);
    let public_key = uncompressed_pub_key.to_bytes();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);
    Address::from_slice(&hash[12..])
}

pub fn apply_eip155(sig: &mut Signature, chain_id: u64) {
    let v = (chain_id * 2 + 35) + sig.v;
    sig.v = v;
}

/// Makes a trial recovery to check whether an RSig corresponds to a known
/// `VerifyingKey`
fn check_candidate(
    sig: &KSig,
    recovery_id: RecoveryId,
    digest: [u8; 32],
    vk: &VerifyingKey,
) -> bool {
    VerifyingKey::recover_from_prehash(digest.as_slice(), sig, recovery_id)
        .map(|key| key == *vk)
        .unwrap_or(false)
}

pub fn sig_from_digest_bytes_trial_recovery(
    sig: &KSig,
    digest: [u8; 32],
    vk: &VerifyingKey,
) -> Signature {
    let r_bytes: FieldBytes = sig.r().into();
    let s_bytes: FieldBytes = sig.s().into();
    let r = U256::from_big_endian(r_bytes.as_slice());
    let s = U256::from_big_endian(s_bytes.as_slice());

    if check_candidate(sig, RecoveryId::from_byte(0).unwrap(), digest, vk) {
        Signature { r, s, v: 0 }
    } else if check_candidate(sig, RecoveryId::from_byte(1).unwrap(), digest, vk) {
        Signature { r, s, v: 1 }
    } else {
        panic!("bad sig");
    }
}

#[derive(Clone, Debug)]
pub struct GcpKeyRingRef {
    pub google_project_id: String,
    pub location: String,
    pub key_ring: String,
}

impl GcpKeyRingRef {
    pub fn new(google_project_id: &str, location: &str, key_ring: &str) -> Self {
        Self {
            google_project_id: google_project_id.to_string(),
            location: location.to_string(),
            key_ring: key_ring.to_string(),
        }
    }

    fn to_google_ref(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}",
            self.google_project_id, self.location, self.key_ring
        )
    }

    fn to_key_version_ref(&self, key_id: &str, key_version: u64) -> String {
        format!(
            "{}/cryptoKeys/{}/cryptoKeyVersions/{}",
            self.to_google_ref(),
            key_id,
            key_version,
        )
    }
}

#[derive(Clone)]
pub struct GcpKmsProvider {
    client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    kms_key_ref: GcpKeyRingRef,
}

impl Debug for GcpKmsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsProvider")
            .field("kms_key_ref", &self.kms_key_ref)
            .finish()
    }
}

impl GcpKmsProvider {
    pub async fn new(kms_key_ref: GcpKeyRingRef) -> Result<Self, CKMSError> {
        debug!(
            "Initialising Google KMS envelope encryption for {}",
            kms_key_ref.to_google_ref()
        );

        let client = GoogleApi::from_function(
            KeyManagementServiceClient::new,
            "https://cloudkms.googleapis.com",
            None,
        )
        .await?;

        Ok(Self {
            kms_key_ref,
            client,
        })
    }

    pub async fn get_verifying_key(
        &self,
        key_id: &str,
        key_version: u64,
    ) -> Result<VerifyingKey, CKMSError> {
        let request = tonic::Request::new(GetPublicKeyRequest {
            name: self.kms_key_ref.to_key_version_ref(key_id, key_version),
        });
        let response = self.client.get().get_public_key(request).await?;
        let pem = response.into_inner().pem;
        let public_key = VerifyingKey::from_public_key_pem(&pem)?;
        Ok(public_key)
    }

    pub async fn sign_digest(
        &self,
        key_id: &str,
        key_version: u64,
        digest: &[u8],
    ) -> Result<Vec<u8>, CKMSError> {
        let req = Request::new(AsymmetricSignRequest {
            name: self.kms_key_ref.to_key_version_ref(key_id, key_version),
            digest: Some(kms::v1::Digest {
                digest: Some(kms::v1::digest::Digest::Sha256(digest.to_vec())),
            }),
            ..Default::default()
        });
        let response = self.client.get().asymmetric_sign(req).await?;
        let signature = response.into_inner().signature;
        Ok(signature)
    }
}

#[derive(Clone, Debug)]
pub struct GcpKmsSigner {
    provider: GcpKmsProvider,
    key_id: String,
    key_version: u64,
    chain_id: u64,
    verifying_key: VerifyingKey,
}

impl GcpKmsSigner {
    pub async fn new(
        provider: GcpKmsProvider,
        key_id: String,
        key_version: u64,
        chain_id: u64,
    ) -> Result<Self, CKMSError> {
        let verifying_key = provider.get_verifying_key(&key_id, key_version).await?;
        Ok(Self {
            provider,
            key_id,
            key_version,
            chain_id,
            verifying_key,
        })
    }

    /// Sign a digest with this signer's key
    pub async fn sign_digest(&self, digest: [u8; 32]) -> Result<KSig, CKMSError> {
        let signature = self
            .provider
            .sign_digest(self.key_id.as_ref(), self.key_version, digest.as_ref())
            .await?;
        let sig = KSig::from_der(&signature)?;
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig)
    }

    /// Sign a digest with this signer's key and add the eip155 `v` value
    /// corresponding to the input chain_id
    #[instrument(err, skip(digest))]
    async fn sign_digest_with_eip155(
        &self,
        digest: H256,
        chain_id: u64,
    ) -> Result<Signature, CKMSError> {
        let sig = self.sign_digest(digest.into()).await?;
        let mut sig =
            sig_from_digest_bytes_trial_recovery(&sig, digest.into(), &self.verifying_key);
        apply_eip155(&mut sig, chain_id);
        Ok(sig)
    }
}

#[async_trait]
impl Signer for GcpKmsSigner {
    type Error = CKMSError;

    /// Signs the message
    #[instrument(err, skip(message))]
    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        let message = message.as_ref();
        let message_hash = hash_message(message);
        self.sign_digest_with_eip155(message_hash, self.chain_id)
            .await
    }

    /// Signs the transaction
    #[instrument(err)]
    async fn sign_transaction(&self, tx: &TypedTransaction) -> Result<Signature, Self::Error> {
        let mut tx_with_chain = tx.clone();
        let chain_id = tx_with_chain
            .chain_id()
            .map(|id| id.as_u64())
            .unwrap_or(self.chain_id);
        tx_with_chain.set_chain_id(chain_id);

        let sighash = tx_with_chain.sighash();
        self.sign_digest_with_eip155(sighash, chain_id).await
    }

    /// Encodes and signs the typed data according EIP-712.
    /// Payload must implement Eip712 trait.
    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error> {
        let digest = payload
            .encode_eip712()
            .map_err(|e| CKMSError::Eip712Error(e.to_string()))?;

        let sig = self.sign_digest(digest).await?;
        let sig = sig_from_digest_bytes_trial_recovery(&sig, digest, &self.verifying_key);

        Ok(sig)
    }

    /// Returns the signer's Ethereum Address
    fn address(&self) -> Address {
        verifying_key_to_address(&self.verifying_key)
    }

    /// Returns the signer's chain id
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Sets the signer's chain id
    #[must_use]
    fn with_chain_id<T: Into<u64>>(self, chain_id: T) -> Self {
        let mut this = self;
        this.chain_id = chain_id.into();
        this
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test(tokio::test)]
    async fn it_works() {
        // skip test if no credentials are provided
        if std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_err() {
            return;
        }

        let project_id = std::env::var("GOOGLE_PROJECT_ID").expect("GOOGLE_PROJECT_ID");
        let location = std::env::var("GOOGLE_LOCATION").expect("GOOGLE_LOCATION");
        let keyring = std::env::var("GOOGLE_KEYRING").expect("GOOGLE_KEYRING");
        let key_name = std::env::var("GOOGLE_KEY_NAME").expect("GOOGLE_KEY_NAME");

        let keyring = GcpKeyRingRef::new(&project_id, &location, &keyring);
        let provider = GcpKmsProvider::new(keyring)
            .await
            .expect("Failed to create GCP KMS provider");
        let signer = GcpKmsSigner::new(provider, key_name, 1, 1)
            .await
            .expect("get key");

        let message = vec![0, 1, 2, 3];
        let sig = signer.sign_message(&message).await.unwrap();
        sig.verify(message, signer.address()).expect("valid sig");
    }
}
