# Configure Google Cloud provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create new keychain in KMS
resource "google_kms_key_ring" "key_ring" {
  name     = "my-key-ring"
  location = "global"
}

# Create new key for signing sec256p1 keys
resource "google_kms_crypto_key" "crypto_key" {
  name     = "my-crypto-key"
  key_ring = google_kms_key_ring.key_ring.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    protection_level = "HSM"
    algorithm        = "EC_SIGN_SECP256K1_SHA256"
  }
}

# Create new service account with IAM permissions to sign stuff with this key
resource "google_service_account" "service_account" {
  account_id   = "kms-signer"
  display_name = "KMS Signer Service Account"
}

# Grant the service account permission to sign with the key
resource "google_kms_crypto_key_iam_member" "key_signer" {
  crypto_key_id = google_kms_crypto_key.crypto_key.id
  role          = "roles/cloudkms.signer"
  member        = "serviceAccount:${google_service_account.service_account.email}"
}

# Grant the service account permission to view the public key
resource "google_kms_crypto_key_iam_member" "pubkey_viewer" {
  crypto_key_id = google_kms_crypto_key.crypto_key.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.service_account.email}"
}


# Create JSON key for the service account and include it in Terraform outputs
resource "google_service_account_key" "key" {
  service_account_id = google_service_account.service_account.id
  private_key_type   = "TYPE_GOOGLE_CREDENTIALS_FILE"
}

# Output the private key
output "service_account_key" {
  value     = google_service_account_key.key.private_key
  sensitive = true
}
