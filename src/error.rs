use ethers::{
    prelude::k256::{self, pkcs8},
    types::SignatureError,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CKMSError {
    #[error("GCloud sdk error: {0}")]
    GoogleKmsError(#[from] gcloud_sdk::error::Error),

    #[error("Request error: {0}")]
    RequestError(#[from] tonic::Status),

    #[error("IO error: {0}")]
    SpkiError(#[from] pkcs8::spki::Error),

    // #[error("Key error: {0}")]
    // KeyError(#[from] spki::der::Error),
    #[error("VerifyingKey error: {0}")]
    VerifyingKeyError(#[from] k256::ecdsa::signature::Error),

    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("EIP712 error: {0}")]
    Eip712Error(String),
}
