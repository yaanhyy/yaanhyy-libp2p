pub mod handshake;
pub mod payload;
pub mod protocol;
pub mod io;
pub mod x25519;
use x25519::X25519Spec;
use protocol::{AuthenticKeypair, ProtocolParams};

#[derive(Clone)]
pub struct NoiseConfig {
    pub dh_keys: AuthenticKeypair,
    pub params: ProtocolParams,
}

impl NoiseConfig
{
    /// Create a new `NoiseConfig` for the `XX` handshake pattern.
    pub fn xx(dh_keys: AuthenticKeypair) -> Self {
        NoiseConfig {
            dh_keys,
            params: X25519Spec::params_xx(),
        }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
