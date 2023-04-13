use ethers::utils::Anvil;
use ethers::{prelude::*, utils::WEI_IN_ETHER};
use ethers_gcp_kms_signer::{GcpKeyRingRef, GcpKmsProvider, GcpKmsSigner};

#[tokio::main]
async fn main() {
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
    println!("Created signer: {:?}", signer);

    // get the address of the signer
    let address = signer.address();
    println!("Signer address: {:?}", address);

    // Spawn an anvil instance
    let anvil = Anvil::default().chain_id(Chain::Mainnet).spawn();
    let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
    println!("Anvil running at `{}`", anvil.endpoint());

    // Transfer some eth from the dev account to the signer
    let tx = TransactionRequest::pay(address, WEI_IN_ETHER);
    provider
        .send_transaction(tx, None)
        .await
        .unwrap()
        .await
        .unwrap();
    println!("Sent 1 ETH to the signer");

    // Send 1 wei back to the dev account
    let tx = TransactionRequest::pay(anvil.addresses()[0], U256::one()).from(address);
    provider
        .clone()
        .with_signer(signer)
        .send_transaction(tx, None)
        .await
        .unwrap()
        .await
        .unwrap();
    println!("Sent 1 Wei from the signer");

    let balance = provider.get_balance(address, None).await.unwrap();
    println!("Signer balance: {:?}", balance);
}
