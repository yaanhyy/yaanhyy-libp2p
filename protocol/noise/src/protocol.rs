use secio::identity;
use rand::SeedableRng;
use crate::x25519::X25519Spec;
use zeroize::Zeroize;


/// The parameters of a Noise protocol, consisting of a choice
/// for a handshake pattern as well as DH, cipher and hash functions.
#[derive(Clone)]
pub struct ProtocolParams(pub snow::params::NoiseParams);

impl ProtocolParams {
    /// Turn the protocol parameters into a session builder.
    pub fn into_builder(self) -> snow::Builder<'static> {
        snow::Builder::with_resolver(self.0, Box::new(Resolver))
    }
}

/// DH keypair.
#[derive(Clone)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// A DH keypair that is authentic w.r.t. a [`identity::PublicKey`].
#[derive(Clone)]
pub struct AuthenticKeypair {
    pub keypair: Keypair,
    pub identity: KeypairIdentity
}

impl AuthenticKeypair {
    /// Extract the public [`KeypairIdentity`] from this `AuthenticKeypair`,
    /// dropping the DH `Keypair`.
    pub fn into_identity(self) -> KeypairIdentity {
        self.identity
    }
}

impl std::ops::Deref for AuthenticKeypair {
    type Target = Keypair;

    fn deref(&self) -> &Self::Target {
        &self.keypair
    }
}

/// The associated public identity of a DH keypair.
#[derive(Clone)]
pub struct KeypairIdentity {
    /// The public identity key.
    pub public: identity::PublicKey,
    /// The signature over the public DH key.
    pub signature: Option<Vec<u8>>
}

impl Keypair {
    /// The public key of the DH keypair.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The secret key of the DH keypair.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Turn this DH keypair into a [`AuthenticKeypair`], i.e. a DH keypair that
    /// is authentic w.r.t. the given identity keypair, by signing the DH public key.
    pub fn into_authentic(self, id_keys: &identity::Keypair) -> Result<AuthenticKeypair, String>
    {
        let sig = X25519Spec::sign(id_keys, &self.public)?;

        let identity = KeypairIdentity {
            public: id_keys.public(),
            signature: Some(sig)
        };

        Ok(AuthenticKeypair { keypair: self, identity })
    }
}

/// DH secret key.
#[derive(Clone)]
pub struct PublicKey(pub X25519Spec);

impl PartialEq for PublicKey{
    fn eq(&self, other: &PublicKey) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for PublicKey {}

impl AsRef<[u8]> for PublicKey{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// DH secret key.
#[derive(Clone)]
pub struct SecretKey(pub X25519Spec);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl  AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Custom `snow::CryptoResolver` which delegates to either the
/// `RingResolver` on native or the `DefaultResolver` on wasm
/// for hash functions and symmetric ciphers, while using x25519-dalek
/// for Curve25519 DH.
struct Resolver;

impl snow::resolvers::CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        Some(Box::new(Rng(rand::rngs::StdRng::from_entropy())))
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        if let snow::params::DHChoice::Curve25519 = choice {
            Some(Box::new(Keypair::default()))
        } else {
            None
        }
    }

    fn resolve_hash(&self, choice: &snow::params::HashChoice) -> Option<Box<dyn snow::types::Hash>> {
        {
            snow::resolvers::RingResolver.resolve_hash(choice)
        }
    }

    fn resolve_cipher(&self, choice: &snow::params::CipherChoice) -> Option<Box<dyn snow::types::Cipher>> {
        {
                snow::resolvers::RingResolver.resolve_cipher(choice)
        }
    }
}

/// Wrapper around a CSPRNG to implement `snow::Random` trait for.
struct Rng(rand::rngs::StdRng);

impl rand::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl rand::CryptoRng for Rng {}

impl snow::types::Random for Rng {}