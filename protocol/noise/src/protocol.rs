pub mod x25519;
use secio::identity::PublicKey;


/// DH keypair.
#[derive(Clone)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

/// The associated public identity of a DH keypair.
#[derive(Clone)]
pub struct KeypairIdentity {
    /// The public identity key.
    pub public: PublicKey,
    /// The signature over the public DH key.
    pub signature: Option<Vec<u8>>
}