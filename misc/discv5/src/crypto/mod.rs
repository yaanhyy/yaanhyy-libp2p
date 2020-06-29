//! Implementation for generating session keys in the Discv5 protocol.
//! Currently, Diffie-Hellman key agreement is performed with known public key types. Session keys
//! are then derived using the HKDF (SHA2-256) key derivation function.
//!
//! There is no abstraction in this module as the specification explicitly defines a singular
//! encryption and key-derivation algorithms. Future versions may abstract some of these to allow
//! for different algorithms.

//use crate::node_info::NodeContact;
use crate::packet::{AuthHeader, AuthResponse, AuthTag, Nonce};
use ecdh_ident::EcdhIdent;
use enr::{CombinedKey, CombinedPublicKey, NodeId};
use hkdf::Hkdf;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use secp256k1::Signature;
use sha2::{Digest, Sha256};

mod ecdh_ident;

const NODE_ID_LENGTH: usize = 32;
const INFO_LENGTH: usize = 26 + 2 * NODE_ID_LENGTH;
const KEY_LENGTH: usize = 16;
const KEY_AGREEMENT_STRING: &str = "discovery v5 key agreement";
const KNOWN_SCHEME: &str = "gcm";
const NONCE_PREFIX: &str = "discovery-id-nonce";

type Key = [u8; KEY_LENGTH];

/* Session key generation */

/// Generates session and auth-response keys for a nonce and remote ENR. This currently only
/// supports Secp256k1 signed ENR's. This returns four keys; initiator key, responder key, auth
/// response key and the ephemeral public key.
pub(crate) fn generate_session_keys(
    local_id: &NodeId,
    remote_key: &CombinedPublicKey,
    remote_id: &NodeId,
    id_nonce: &Nonce,
) -> Result<(Key, Key, Key, Vec<u8>), String> {
    let (secret, ephem_pk) = {
        match remote_key {
            CombinedPublicKey::Secp256k1(remote_pk) => {
                let mut rng = rand::thread_rng();
                let ephem_sk = secp256k1::SecretKey::random(&mut rng);
                let ephem_pk = secp256k1::PublicKey::from_secret_key(&ephem_sk);
                let secret = secp256k1::SharedSecret::<EcdhIdent>::new(&remote_pk, &ephem_sk)
                    .map_err(|_| "Discv5Error::KeyDerivationFailed".to_string())?;
                // store as uncompressed, strip the first byte and send only 64 bytes.
                let ephem_pk = ephem_pk.serialize()[1..].to_vec();
                (secret, ephem_pk)
            }
            CombinedPublicKey::Ed25519(_) => {
                return Err("Discv5Error::KeyTypeNotSupported(Ed25519)".to_string())
            }
        }
    };

    let (initiator_key, responder_key, auth_resp_key) =
        derive_key(secret.as_ref(), local_id, remote_id, id_nonce)?;

    Ok((initiator_key, responder_key, auth_resp_key, ephem_pk))
}

fn derive_key(
    secret: &[u8],
    first_id: &NodeId,
    second_id: &NodeId,
    id_nonce: &Nonce,
) -> Result<(Key, Key, Key), String> {
    let mut info = [0u8; INFO_LENGTH];
    info[0..26].copy_from_slice(KEY_AGREEMENT_STRING.as_bytes());
    info[26..26 + NODE_ID_LENGTH].copy_from_slice(&first_id.raw());
    info[26 + NODE_ID_LENGTH..].copy_from_slice(&second_id.raw());

    let hk = Hkdf::<Sha256>::new(Some(id_nonce), secret);

    let mut okm = [0u8; 3 * KEY_LENGTH];
    hk.expand(&info, &mut okm)
        .map_err(|_| "Discv5Error::KeyDerivationFailed".to_string())?;

    let mut initiator_key: Key = Default::default();
    let mut responder_key: Key = Default::default();
    let mut auth_resp_key: Key = Default::default();
    initiator_key.copy_from_slice(&okm[0..KEY_LENGTH]);
    responder_key.copy_from_slice(&okm[KEY_LENGTH..2 * KEY_LENGTH]);
    auth_resp_key.copy_from_slice(&okm[2 * KEY_LENGTH..3 * KEY_LENGTH]);

    Ok((initiator_key, responder_key, auth_resp_key))
}

/// Derives the session keys for a public key type that matches the local keypair.
pub(crate) fn derive_keys_from_pubkey(
    local_key: &CombinedKey,
    local_id: &NodeId,
    remote_id: &NodeId,
    id_nonce: &Nonce,
    ephem_pubkey: &[u8],
) -> Result<(Key, Key, Key), String> {
    let secret = {
        match local_key {
            CombinedKey::Secp256k1(key) => {
                // convert remote pubkey into secp256k1 public key
                // the key type should match our own node record
                let remote_pubkey = secp256k1::PublicKey::parse_slice(ephem_pubkey, None)
                    .map_err(|_| "Discv5Error::InvalidRemotePublicKey".to_string())?;

                let secret = secp256k1::SharedSecret::<EcdhIdent>::new(&remote_pubkey, key)
                    .map_err(|_| "Discv5Error::KeyDerivationFailed".to_string())?;
                secret.as_ref().to_vec()
            }
            CombinedKey::Ed25519(_) => return Err("Discv5Error::KeyTypeNotSupported(Ed25519)".to_string()),
        }
    };

    derive_key(&secret, remote_id, local_id, id_nonce)
}

/* Nonce Signing */

/// Generates a signature of a nonce given a keypair. This prefixes the `NONCE_PREFIX` to the
/// signature.
pub(crate) fn sign_nonce(
    signing_key: &CombinedKey,
    nonce: &Nonce,
    ephem_pubkey: &[u8],
) -> Result<Vec<u8>, String> {
    let signing_nonce = generate_signing_nonce(nonce, ephem_pubkey);

    match signing_key {
        CombinedKey::Secp256k1(key) => {
            let m = secp256k1::Message::parse_slice(&signing_nonce)
                .map_err(|_| "Discv5Error::Custom(Could not parse nonce for signing)".to_string())?;

            Ok(secp256k1::sign(&m, key).0.serialize().to_vec())
        }
        CombinedKey::Ed25519(_) => Err("Discv5Error::KeyTypeNotSupported(Ed25519)".to_string()),
    }
}

/// Verifies the authentication header nonce.
pub(crate) fn verify_authentication_nonce(
    remote_pubkey: &CombinedPublicKey,
    remote_ephem_pubkey: &[u8],
    nonce: &Nonce,
    sig: &[u8],
) -> bool {
    let signing_nonce = generate_signing_nonce(nonce, remote_ephem_pubkey);

    match remote_pubkey {
        CombinedPublicKey::Secp256k1(key) => Signature::parse_slice(sig)
            .and_then(|s| {
                secp256k1::Message::parse_slice(&signing_nonce)
                    .map(|m| secp256k1::verify(&m, &s, key))
            })
            .unwrap_or(false),
        CombinedPublicKey::Ed25519(_) => {
            // key not yet supported
            false
        }
    }
}

/// Builds the signature for a given nonce.
///
/// This takes the SHA256 hash of the nonce.
fn generate_signing_nonce(id_nonce: &Nonce, ephem_pubkey: &[u8]) -> Vec<u8> {
    let mut nonce = NONCE_PREFIX.as_bytes().to_vec();
    nonce.append(&mut id_nonce.to_vec());
    nonce.append(&mut ephem_pubkey.to_vec());
    Sha256::digest(&nonce).to_vec()
}

/* Decryption related functions */

/// Verifies the encoding and nonce signature given in the authentication header. If
/// the header contains an updated ENR, it is returned.
pub(crate) fn decrypt_authentication_header(
    auth_resp_key: &Key,
    header: &AuthHeader,
) -> Result<AuthResponse, String> {
    if header.auth_scheme_name != KNOWN_SCHEME {
        return Err("Discv5Error::Custom Invalid authentication scheme".to_string());
    }

    // decrypt the auth-response
    let rlp_auth_response = decrypt_message(auth_resp_key, [0u8; 12], &header.auth_response, &[])?;
    let auth_response =
        rlp::decode::<AuthResponse>(&rlp_auth_response).map_err(|e| format!("Discv5Error::RLPError: {:?}", e))?;
    Ok(auth_response)
}

/// Decrypt messages that are post-fixed with an authenticated MAC.
pub(crate) fn decrypt_message(
    key: &Key,
    nonce: AuthTag,
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if message.len() < 16 {
        return Err("Discv5Error::DecryptionFail Message not long enough to contain a MAC".to_string());
    }

    let mut mac: [u8; 16] = Default::default();
    mac.copy_from_slice(&message[message.len() - 16..]);

    decrypt_aead(
        Cipher::aes_128_gcm(),
        key,
        Some(&nonce),
        aad,
        &message[..message.len() - 16],
        &mac,
    )
        .map_err(|e| {
            let e = format!("v5Error::DecryptionFail Could not decrypt message. Error: {:?}", e);
            e
        })
}

/* Encryption related functions */

/// A wrapper around the underlying default AES_GCM implementation. This may be abstracted in the
/// future.
pub(crate) fn encrypt_message(
    key: &Key,
    nonce: AuthTag,
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let mut mac: [u8; 16] = Default::default();
    let mut msg_cipher = encrypt_aead(
        Cipher::aes_128_gcm(),
        key,
        Some(&nonce),
        aad,
        message,
        &mut mac,
    )
        .map_err(|e| format!("Discv5Error::EncryptionFail:{:?}", e))?;

    // concat the ciphertext with the MAC
    msg_cipher.append(&mut mac.to_vec());
    Ok(msg_cipher)
}

