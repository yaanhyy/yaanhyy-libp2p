use super::protocol::{Keypair, PublicKey, SecretKey, AuthenticKeypair, ProtocolParams, KeypairIdentity};
use zeroize::Zeroize;
use lazy_static::lazy_static;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use rand::Rng;
use secio::identity::{self, ed25519};
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Sha512, Digest};

///use x25519_spec
/// Prefix of static key signatures for domain separation.
const STATIC_KEY_DOMAIN: &str = "noise-libp2p-static-key:";

lazy_static! {
    static ref PARAMS_IK: ProtocolParams = "Noise_IK_25519_ChaChaPoly_SHA256"
        .parse()
        .map(ProtocolParams)
        .expect("Invalid protocol name");

    static ref PARAMS_IX: ProtocolParams = "Noise_IX_25519_ChaChaPoly_SHA256"
        .parse()
        .map(ProtocolParams)
        .expect("Invalid protocol name");

    static ref PARAMS_XX: ProtocolParams = "Noise_XX_25519_ChaChaPoly_SHA256"
        .parse()
        .map(ProtocolParams)
        .expect("Invalid protocol name");
}

/// A X25519 key.
#[derive(Clone)]
pub struct X25519Spec([u8; 32]);

impl AsRef<[u8]> for X25519Spec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Zeroize for X25519Spec {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}


/// Noise protocols for X25519 with libp2p-spec compliant signatures.
///
/// **Note**: Only the XX handshake pattern is currently guaranteed to be
/// interoperable with other libp2p implementations.
impl X25519Spec {
    pub fn params_ik() -> ProtocolParams {
        PARAMS_IK.clone()
    }

    pub fn params_ix() -> ProtocolParams {
        PARAMS_IX.clone()
    }

    pub fn params_xx() -> ProtocolParams {
        PARAMS_XX.clone()
    }

    pub fn public_from_bytes(bytes: &[u8]) -> Result<PublicKey, String> {
        if bytes.len() != 32 {
            return Err("NoiseError::InvalidKey".to_string())
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(bytes);
        Ok(PublicKey(X25519Spec(pk)))
    }

    pub fn verify(id_pk: &identity::PublicKey, dh_pk: &PublicKey, sig: &Option<Vec<u8>>) -> bool
    {
        sig.as_ref().map_or(false, |s| {
            id_pk.verify(&[STATIC_KEY_DOMAIN.as_bytes(), dh_pk.as_ref()].concat(), s)
        })
    }

    pub fn sign(id_keys: &identity::Keypair, dh_pk: &PublicKey) -> Result<Vec<u8>, String> {
        Ok(id_keys.sign(&[STATIC_KEY_DOMAIN.as_bytes(), dh_pk.as_ref()].concat())?)
    }
}

impl Keypair {
    /// An "empty" keypair as a starting state for DH computations in `snow`,
    /// which get manipulated through the `snow::types::Dh` interface.
    pub(super) fn default() -> Self {
        Keypair {
            secret: SecretKey(X25519Spec([0u8; 32])),
            public: PublicKey(X25519Spec([0u8; 32]))
        }
    }

    /// Create a new X25519 keypair.
    pub fn new() -> Keypair {
        let mut sk_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut sk_bytes);
        let sk = SecretKey(X25519Spec(sk_bytes)); // Copy
        sk_bytes.zeroize();
        Self::from(sk)
    }

    /// Creates an X25519 `Keypair` from an [`identity::Keypair`], if possible.
    ///
    /// The returned keypair will be [associated with](KeypairIdentity) the
    /// given identity keypair.
    ///
    /// Returns `None` if the given identity keypair cannot be used as an X25519 keypair.
    ///
    /// > **Note**: If the identity keypair is already used in the context
    /// > of other cryptographic protocols outside of Noise, e.g. for
    /// > signing in the `secio` protocol, it should be preferred to
    /// > create a new static X25519 keypair for use in the Noise protocol.
    /// >
    /// > See also:
    /// >
    /// >  * [Noise: Static Key Reuse](http://www.noiseprotocol.org/noise.html#security-considerations)
    pub fn from_identity(id_keys: &identity::Keypair) -> Option<AuthenticKeypair> {
        match id_keys {
            identity::Keypair::Ed25519(p) => {
                let kp = Keypair::from(SecretKey::from_ed25519(&p.secret()));
                let id = KeypairIdentity {
                    public: id_keys.public(),
                    signature: None
                };
                Some(AuthenticKeypair {
                    keypair: kp,
                    identity: id
                })
            }
            _ => None
        }
    }
}

/// Promote a X25519 secret key into a keypair.
impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        let public = PublicKey(X25519Spec(x25519((secret.0).0, X25519_BASEPOINT_BYTES)));
        Keypair { secret, public }
    }
}

impl PublicKey {
    /// Construct a curve25519 public key from an Ed25519 public key.
    pub fn from_ed25519(pk: &ed25519::PublicKey) -> Self {
        PublicKey(X25519Spec(CompressedEdwardsY(pk.encode())
            .decompress()
            .expect("An Ed25519 public key is a valid point by construction.")
            .to_montgomery().0))
    }
}

impl SecretKey {
    /// Construct a X25519 secret key from a Ed25519 secret key.
    ///
    /// > **Note**: If the Ed25519 secret key is already used in the context
    /// > of other cryptographic protocols outside of Noise, e.g. for
    /// > signing in the `secio` protocol, it should be preferred to
    /// > create a new keypair for use in the Noise protocol.
    /// >
    /// > See also:
    /// >
    /// >  * [Noise: Static Key Reuse](http://www.noiseprotocol.org/noise.html#security-considerations)
    /// >  * [Ed25519 to Curve25519](https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519)
    pub fn from_ed25519(ed25519_sk: &ed25519::SecretKey) -> Self {
        // An Ed25519 public key is derived off the left half of the SHA512 of the
        // secret scalar, hence a matching conversion of the secret key must do
        // the same to yield a Curve25519 keypair with the same public key.
        // let ed25519_sk = ed25519::SecretKey::from(ed);
        let mut curve25519_sk: [u8; 32] = [0; 32];
        let hash = Sha512::digest(ed25519_sk.as_ref());
        curve25519_sk.copy_from_slice(&hash.as_ref()[..32]);
        let sk = SecretKey(X25519Spec(curve25519_sk)); // Copy
        curve25519_sk.zeroize();
        sk
    }
}

#[doc(hidden)]
impl snow::types::Dh for Keypair {
    fn name(&self) -> &'static str { "25519" }
    fn pub_len(&self) -> usize { 32 }
    fn priv_len(&self) -> usize { 32 }
    fn pubkey(&self) -> &[u8] { self.public.as_ref() }
    fn privkey(&self) -> &[u8] { self.secret.as_ref() }

    fn set(&mut self, sk: &[u8]) {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&sk[..]);
        self.secret = SecretKey(X25519Spec(secret)); // Copy
        self.public = PublicKey(X25519Spec(x25519(secret, X25519_BASEPOINT_BYTES)));
        secret.zeroize();
    }

    fn generate(&mut self, rng: &mut dyn snow::types::Random) {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        self.secret = SecretKey(X25519Spec(secret)); // Copy
        self.public = PublicKey(X25519Spec(x25519(secret, X25519_BASEPOINT_BYTES)));
        secret.zeroize();
    }

    fn dh(&self, pk: &[u8], shared_secret: &mut [u8]) -> Result<(), ()> {
        let mut p = [0; 32];
        p.copy_from_slice(&pk[.. 32]);
        let ss = x25519((self.secret.0).0, p);
        shared_secret[.. 32].copy_from_slice(&ss[..]);
        Ok(())
    }
}