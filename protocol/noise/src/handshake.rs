use futures::prelude::AsyncRead;
use futures::prelude::AsyncWrite;
use crate::payload::NoiseHandshakePayload;
use prost::Message;
use secio::identity;
use crate::protocol::{KeypairIdentity, PublicKey};
use crate::io::{NoiseOutput, SnowState};
use futures::prelude::*;
use async_std::sync::Mutex;
use std::{fmt, sync::{Arc}, task::{Context, Poll}, pin::Pin};
use crate::x25519::X25519Spec;
/// Handshake state.
//pub struct State {
//
//    /// The associated public identity of the local node's static DH keypair,
//    /// which can be sent to the remote as part of an authenticated handshake.
//    identity: KeypairIdentity,
//    /// The received signature over the remote's static DH public key, if any.
//    dh_remote_pubkey_sig: Option<Vec<u8>>,
//    /// The known or received public identity key of the remote, if any.
//    id_remote_pubkey: Option<identity::PublicKey>,
//    /// Whether to send the public identity key of the local node to the remote.
//    send_identity: bool,
//}

//impl State {
//    /// Initializes the state for a new Noise handshake, using the given local
//    /// identity keypair and local DH static public key. The handshake messages
//    /// will be sent and received on the given I/O resource and using the
//    /// provided session for cryptographic operations according to the chosen
//    /// Noise handshake pattern.
//    fn new(
//
//        identity: KeypairIdentity,
//        identity_x: IdentityExchange
//    ) -> Self {
//        let (id_remote_pubkey, send_identity) = match identity_x {
//            IdentityExchange::Mutual => (None, true),
//            IdentityExchange::Send { remote } => (Some(remote), true),
//            IdentityExchange::Receive => (None, false),
//            IdentityExchange::None { remote } => (Some(remote), false)
//        };
//
//        State {
//
//            identity,
//            dh_remote_pubkey_sig: None,
//            id_remote_pubkey,
//            send_identity
//        }
//    }
//}

//impl State
//{
//    /// Finish a handshake, yielding the established remote identity and the
//    /// [`NoiseOutput`] for communicating on the encrypted channel.
//    fn finish<T>(self, io: NoiseOutput<T>) -> ()
//        where
//            T: AsyncRead + Unpin,
//    {
//        let dh_remote_pubkey = match io.session.get_remote_static() {
//            None => None,
//            Some(k) => match C::public_from_bytes(k) {
//                Err(e) => return Err(e),
//                Ok(dh_pk) => Some(dh_pk)
//            }
//        };
//        match self.io.session.into_transport_mode() {
//            Err(e) => Err(e.into()),
//            Ok(s) => {
//                let remote = match (self.id_remote_pubkey, dh_remote_pubkey) {
//                    (_, None) => RemoteIdentity::Unknown,
//                    (None, Some(dh_pk)) => RemoteIdentity::StaticDhKey(dh_pk),
//                    (Some(id_pk), Some(dh_pk)) => {
//                        if C::verify(&id_pk, &dh_pk, &self.dh_remote_pubkey_sig) {
//                            RemoteIdentity::IdentityKey(id_pk)
//                        } else {
//                            return Err(NoiseError::InvalidKey)
//                        }
//                    }
//                };
//                Ok((remote, NoiseOutput { session: SnowState::Transport(s), .. self.io }))
//            }
//        }
//    }
//}

/// The identity of the remote established during a handshake.
pub enum RemoteIdentity {
    /// The remote provided no identifying information.
    ///
    /// The identity of the remote is unknown and must be obtained through
    /// a different, out-of-band channel.
    Unknown,

    /// The remote provided a static DH public key.
    ///
    /// The static DH public key is authentic in the sense that a successful
    /// handshake implies that the remote possesses a corresponding secret key.
    ///
    /// > **Note**: To rule out active attacks like a MITM, trust in the public key must
    /// > still be established, e.g. by comparing the key against an expected or
    /// > otherwise known public key.
    StaticDhKey(PublicKey),

    /// The remote provided a public identity key in addition to a static DH
    /// public key and the latter is authentic w.r.t. the former.
    ///
    /// > **Note**: To rule out active attacks like a MITM, trust in the public key must
    /// > still be established, e.g. by comparing the key against an expected or
    /// > otherwise known public key.
    IdentityKey(identity::PublicKey)
}


/// The options for identity exchange in an authenticated handshake.
///
/// > **Note**: Even if a remote's public identity key is known a priori,
/// > unless the authenticity of the key is [linked](Protocol::linked) to
/// > the authenticity of a remote's static DH public key, an authenticated
/// > handshake will still send the associated signature of the provided
/// > local [`KeypairIdentity`] in order for the remote to verify that the static
/// > DH public key is authentic w.r.t. the known public identity key.
pub enum IdentityExchange {
    /// Send the local public identity to the remote.
    ///
    /// The remote identity is unknown (i.e. expected to be received).
    Mutual,
    /// Send the local public identity to the remote.
    ///
    /// The remote identity is known.
    Send { remote: identity::PublicKey },
    /// Don't send the local public identity to the remote.
    ///
    /// The remote identity is unknown, i.e. expected to be received.
    Receive,
    /// Don't send the local public identity to the remote.
    ///
    /// The remote identity is known, thus identities must be mutually known
    /// in order for the handshake to succeed.
    None { remote: identity::PublicKey }
}


/// Finish a handshake, yielding the established remote identity and the
/// [`NoiseOutput`] for communicating on the encrypted channel.
fn finish<T>(io: NoiseOutput<T>) -> Result<(RemoteIdentity, NoiseOutput<T>), String>
        where
            T: AsyncWrite  +  AsyncRead + Send + Unpin + 'static
{
    let dh_remote_pubkey = match io.session.get_remote_static() {
        None => None,
        Some(k) => match X25519Spec::public_from_bytes(k) {
            Err(e) => return Err(e),
            Ok(dh_pk) => Some(dh_pk)
        }
    };
    match io.session.into_transport_mode() {
        Err(e) => Err(e.to_string()),
        Ok(s) => {
            let remote = match (io.id_remote_pubkey.clone(), dh_remote_pubkey) {
                (_, None) => RemoteIdentity::Unknown,
                (None, Some(dh_pk)) => RemoteIdentity::StaticDhKey(dh_pk),
                (Some(id_pk), Some(dh_pk)) => {
                    if X25519Spec::verify(&id_pk, &dh_pk, &io.dh_remote_pubkey_sig) {
                        RemoteIdentity::IdentityKey(id_pk)
                    } else {
                        return Err("NoiseError::InvalidKey".to_string())
                    }
                }
            };
            Ok((remote, NoiseOutput { session: SnowState::Transport(s), .. io }))
        }
    }
}

/// A future for receiving a Noise handshake message with a payload
/// identifying the remote.
async fn recv_identity<T>(socket: &mut NoiseOutput<T>) -> Result<(), String>
    where
        T: AsyncWrite  +  AsyncRead + Send + Unpin + 'static
{
    let payload_buf = socket.read().await.unwrap();
    println!("payload_buf res:{:?}", payload_buf);
    let pb = match NoiseHandshakePayload::decode(&payload_buf[..]) {
        Ok(prop) => prop,
        Err(_) => {
            println!("NoiseHandshakePayload::decode");
            return Err("NoiseHandshakePayload::decode".to_string());
         }
    };



    if !pb.identity_key.is_empty() {
        let pk = identity::PublicKey::from_protobuf_encoding(&pb.identity_key)
            .map_err(|_| "NoiseError::InvalidKey".to_string())?;
        if let Some(ref k) = socket.id_remote_pubkey {
            if k != &pk {
                return Err("NoiseError::InvalidKey".to_string())
            }
        }
        socket.id_remote_pubkey = Some(pk);
    }
    if !pb.identity_sig.is_empty() {
        socket.dh_remote_pubkey_sig = Some(pb.identity_sig);
    }

    Ok(())
}

/// Send a Noise handshake message with a payload identifying the local node to the remote.
async fn send_identity<T>(socket: &mut NoiseOutput<T>) -> Result<(), String>
    where
        T: AsyncWrite  +  AsyncRead + Send + Unpin + 'static
{
    let mut pb = NoiseHandshakePayload::default();
    if socket.send_identity {
        pb.identity_key = socket.identity.public.clone().into_protobuf_encoding()
    }
    if let Some(ref sig) = socket.identity.signature {
        pb.identity_sig = sig.clone()
    }
    let mut buf = Vec::with_capacity(pb.encoded_len());
    pb.encode(&mut buf).expect("Vec<u8> provides capacity as needed");
    println!("msg:{:?}", buf);
    let res = socket.send(& mut buf).await;
    Ok(())
}

/// A future for sending a Noise handshake message with an empty payload.
pub async fn send_empty<T>(socket: &mut NoiseOutput<T>) -> Result<(), String>
    where
        T: AsyncWrite  +  AsyncRead + Send + Unpin + 'static
{
    let res = socket.send(& mut vec![]).await;

    Ok(())
}

/// A future for receiving a Noise handshake message with an empty payload.
pub async fn recv_empty<T>(socket: &mut NoiseOutput<T>) -> Result<(), String>
    where
        T: AsyncWrite  +  AsyncRead + Send + Unpin + 'static
{
    let res = socket.read().await;
    println!("recv_empty res:{:?}", res);
    Ok(())
}

/// Creates an authenticated Noise handshake for the initiator of a
/// 1.5-roundtrip (3 message) handshake pattern.
///
/// Subject to the chosen [`IdentityExchange`], this message sequence expects
/// the remote to identify itself in the second message payload and
/// identifies the local node to the remote in the third message payload.
/// The first (unencrypted) message payload is always empty.
///
/// This message sequence is suitable for authenticated 3-message Noise handshake
/// patterns where the static keys of the responder and initiator are either known
/// (i.e. appear in the pre-message pattern) or are sent with the second and third
/// message, respectively (e.g. `XX`).
///
/// ```raw
/// initiator --{}--> responder
/// initiator <-{id}- responder
/// initiator -{id}-> responder
/// ```
pub async fn rt15_initiator<T>(
    io: T,
    session: snow::HandshakeState,
    identity: KeypairIdentity,
    identity_x: IdentityExchange
) -> Result<(RemoteIdentity, NoiseOutput<T>), String>
    where
        T: AsyncWrite + AsyncRead + Unpin + Send + 'static,

{
        let mut noise_io =  NoiseOutput::new(io, SnowState::Handshake(session), identity, identity_x);
        send_empty(&mut noise_io).await;
        recv_identity(&mut noise_io).await;
        send_identity(&mut noise_io).await;
        finish(noise_io)
}

/// Creates an authenticated Noise handshake for the responder of a
/// 1.5-roundtrip (3 message) handshake pattern.
///
/// Subject to the chosen [`IdentityExchange`], this message sequence
/// identifies the local node in the second message payload and expects
/// the remote to identify itself in the third message payload. The first
/// (unencrypted) message payload is always empty.
///
/// This message sequence is suitable for authenticated 3-message Noise handshake
/// patterns where the static keys of the responder and initiator are either known
/// (i.e. appear in the pre-message pattern) or are sent with the second and third
/// message, respectively (e.g. `XX`).
///
/// ```raw
/// initiator --{}--> responder
/// initiator <-{id}- responder
/// initiator -{id}-> responder
/// ```
pub async fn rt15_responder<T>(
    io: T,
    session: snow::HandshakeState,
    identity: KeypairIdentity,
    identity_x: IdentityExchange
) -> Result<(RemoteIdentity, NoiseOutput<T>), String>
    where
        T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
        //let noise_io =  Arc::new(Mutex::new(NoiseOutput::new(io, SnowState::Handshake(session))));
        let mut noise_io =  NoiseOutput::new(io, SnowState::Handshake(session), identity, identity_x);
        recv_empty(&mut noise_io).await;
        send_identity(&mut noise_io).await;
        recv_identity(&mut noise_io).await;
        finish(noise_io)

}

mod tests {
    //use super::handshake;
    use super::{IdentityExchange, rt15_responder, rt15_initiator};
    use secio::identity;
    use std::thread::sleep;
    use std::time;
    use sha2::{Digest as ShaDigestTrait, Sha256};
    use crate::protocol::{Keypair};
    use super::super::NoiseConfig;
    #[test]
    fn handshake_server_test() -> Result<(), String> {
        async_std::task::block_on(async move {
            let server_id = identity::Keypair::generate_ed25519();
            let server_id_public = server_id.public();
            let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
            let connec = listener.accept().await.unwrap().0;
            let server_dh = Keypair::new().into_authentic(&server_id).unwrap();
            let config = NoiseConfig::xx(server_dh);
            let session = config.params.into_builder()
                .local_private_key(config.dh_keys.secret().as_ref())
                .build_responder()
                .map_err(|_|"NoiseError::from".to_string());
            if let Ok(state) = session {
                let res = rt15_responder(connec.clone(), state, config.dh_keys.into_identity(),IdentityExchange::Mutual).await;
                if let Ok((remote, mut noise_io)) = res {
                    let mut n = noise_io.read().await;
                    println!("data:{:?}", n.unwrap());
                    noise_io.send(&mut "ok baby".as_bytes().to_vec()).await;
                }
            }
        });
        Ok(())
    }

    #[test]
    fn handshake_client_test() -> Result<(), String> {
        async_std::task::block_on(async move {
            let client_id = identity::Keypair::generate_ed25519();
            let client_id_public = client_id.public();
            let connec = async_std::net::TcpStream::connect("128.127.69.224:13000").await.unwrap();
            let client_dh = Keypair::new().into_authentic(&client_id).unwrap();
            let config = NoiseConfig::xx(client_dh);
            let session = config.params.into_builder()
                .local_private_key(config.dh_keys.secret().as_ref())
                .build_initiator()
                .map_err(|_|"NoiseError::from".to_string());
            if let Ok(state) = session {
                let res = rt15_initiator(connec.clone(), state, config.dh_keys.into_identity(),IdentityExchange::Mutual).await;
                if let Ok((remote, mut noise_io)) = res {
                    println!("send msg");
                    noise_io.send(&mut "ok baby".as_bytes().to_vec()).await;
                    let mut n = noise_io.read().await;
                    println!("data:{:?}", n.unwrap());
                }
            }
        });
        Ok(())
    }
}