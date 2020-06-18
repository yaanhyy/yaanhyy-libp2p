//use futures::prelude::AsyncRead;
//use futures::prelude::AsyncWrite;
//use crate::payload::NoiseHandshakePayload;
//use prost::Message;
//use secio::identity;
//use crate::protocol::{KeypairIdentity};
//use crate::io::NoiseOutput;
//
///// Handshake state.
//struct State {
//    session: snow::HandshakeState,
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
//
//impl State {
//    /// Initializes the state for a new Noise handshake, using the given local
//    /// identity keypair and local DH static public key. The handshake messages
//    /// will be sent and received on the given I/O resource and using the
//    /// provided session for cryptographic operations according to the chosen
//    /// Noise handshake pattern.
//    fn new(
//        session: snow::HandshakeState,
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
//            session,
//            identity,
//            dh_remote_pubkey_sig: None,
//            id_remote_pubkey,
//            send_identity
//        }
//    }
//}
//
////impl State
////{
////    /// Finish a handshake, yielding the established remote identity and the
////    /// [`NoiseOutput`] for communicating on the encrypted channel.
////    fn finish<T>(self, io: NoiseOutput<T>) -> ()
////        where
////            T: AsyncRead + Unpin,
////    {
////        let dh_remote_pubkey = match io.session.get_remote_static() {
////            None => None,
////            Some(k) => match C::public_from_bytes(k) {
////                Err(e) => return Err(e),
////                Ok(dh_pk) => Some(dh_pk)
////            }
////        };
////        match self.io.session.into_transport_mode() {
////            Err(e) => Err(e.into()),
////            Ok(s) => {
////                let remote = match (self.id_remote_pubkey, dh_remote_pubkey) {
////                    (_, None) => RemoteIdentity::Unknown,
////                    (None, Some(dh_pk)) => RemoteIdentity::StaticDhKey(dh_pk),
////                    (Some(id_pk), Some(dh_pk)) => {
////                        if C::verify(&id_pk, &dh_pk, &self.dh_remote_pubkey_sig) {
////                            RemoteIdentity::IdentityKey(id_pk)
////                        } else {
////                            return Err(NoiseError::InvalidKey)
////                        }
////                    }
////                };
////                Ok((remote, NoiseOutput { session: SnowState::Transport(s), .. self.io }))
////            }
////        }
////    }
////}
//
///// The options for identity exchange in an authenticated handshake.
/////
///// > **Note**: Even if a remote's public identity key is known a priori,
///// > unless the authenticity of the key is [linked](Protocol::linked) to
///// > the authenticity of a remote's static DH public key, an authenticated
///// > handshake will still send the associated signature of the provided
///// > local [`KeypairIdentity`] in order for the remote to verify that the static
///// > DH public key is authentic w.r.t. the known public identity key.
//pub enum IdentityExchange {
//    /// Send the local public identity to the remote.
//    ///
//    /// The remote identity is unknown (i.e. expected to be received).
//    Mutual,
//    /// Send the local public identity to the remote.
//    ///
//    /// The remote identity is known.
//    Send { remote: identity::PublicKey },
//    /// Don't send the local public identity to the remote.
//    ///
//    /// The remote identity is unknown, i.e. expected to be received.
//    Receive,
//    /// Don't send the local public identity to the remote.
//    ///
//    /// The remote identity is known, thus identities must be mutually known
//    /// in order for the handshake to succeed.
//    None { remote: identity::PublicKey }
//}
//
///// A future for receiving a Noise handshake message with a payload
///// identifying the remote.
//async fn recv_identity<T>(state: &mut State, socket: T) -> Result<(), NoiseError>
//    where
//        T: AsyncRead + Unpin,
//{
//    let mut len_buf = [0,0];
//    socket.read_exact(&mut len_buf).await?;
//    let len = u16::from_be_bytes(len_buf) as usize;
//
//    let mut payload_buf = vec![0; len];
//    socket.read_exact(&mut payload_buf).await?;
//    let pb = NoiseHandshakePayload::decode(&payload_buf[..])?;
//
//    if !pb.identity_key.is_empty() {
//        let pk = PublicKey::from_protobuf_encoding(&pb.identity_key)
//            .map_err(|_| NoiseError::InvalidKey)?;
//        if let Some(ref k) = state.id_remote_pubkey {
//            if k != &pk {
//                return Err(NoiseError::InvalidKey)
//            }
//        }
//        state.id_remote_pubkey = Some(pk);
//    }
//    if !pb.identity_sig.is_empty() {
//        state.dh_remote_pubkey_sig = Some(pb.identity_sig);
//    }
//
//    Ok(())
//}
//
///// Send a Noise handshake message with a payload identifying the local node to the remote.
//async fn send_identity<T>(state: &mut State, socket: T) -> Result<(), NoiseError>
//    where
//        T: AsyncWrite + Unpin,
//{
//    let mut pb = NoiseHandshakePayload::default();
//    if state.send_identity {
//        pb.identity_key = state.identity.public.clone().into_protobuf_encoding()
//    }
//    if let Some(ref sig) = state.identity.signature {
//        pb.identity_sig = sig.clone()
//    }
//    let mut buf = Vec::with_capacity(pb.encoded_len());
//    pb.encode(&mut buf).expect("Vec<u8> provides capacity as needed");
//    let len = (buf.len() as u16).to_be_bytes();
//    socket.write_all(&len).await?;
//    socket.write_all(&buf).await?;
//    socket.flush().await?;
//    Ok(())
//}
//
///// A future for sending a Noise handshake message with an empty payload.
//pub async fn send_empty<T>(state: &mut State, socket: T) -> Result<(), NoiseError>
//    where
//        T: AsyncWrite + Unpin
//{
//    socket.write(&[]).await?;
//    socket.flush().await?;
//    Ok(())
//}
//
///// A future for receiving a Noise handshake message with an empty payload.
//pub async fn recv_empty<T>(state: &mut State, socket: T) -> Result<(), NoiseError>
//    where
//        T: AsyncRead + Unpin
//{
//    socket.read(&mut []).await?;
//    Ok(())
//}
//
///// Creates an authenticated Noise handshake for the initiator of a
///// 1.5-roundtrip (3 message) handshake pattern.
/////
///// Subject to the chosen [`IdentityExchange`], this message sequence expects
///// the remote to identify itself in the second message payload and
///// identifies the local node to the remote in the third message payload.
///// The first (unencrypted) message payload is always empty.
/////
///// This message sequence is suitable for authenticated 3-message Noise handshake
///// patterns where the static keys of the responder and initiator are either known
///// (i.e. appear in the pre-message pattern) or are sent with the second and third
///// message, respectively (e.g. `XX`).
/////
///// ```raw
///// initiator --{}--> responder
///// initiator <-{id}- responder
///// initiator -{id}-> responder
///// ```
//pub async fn rt15_initiator<T>(
//    io: T,
//    session: Result<snow::HandshakeState, NoiseError>,
//    identity: KeypairIdentity,
//    identity_x: IdentityExchange
//) -> ()
//    where
//        T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
//
//{
//        let mut state = State::new(session, identity, identity_x)?;
//        send_empty(&mut state, io).await?;
//        recv_identity(&mut state, io).await?;
//        send_identity(&mut state, io).await?;
//        state.finish()
//}
//
///// Creates an authenticated Noise handshake for the responder of a
///// 1.5-roundtrip (3 message) handshake pattern.
/////
///// Subject to the chosen [`IdentityExchange`], this message sequence
///// identifies the local node in the second message payload and expects
///// the remote to identify itself in the third message payload. The first
///// (unencrypted) message payload is always empty.
/////
///// This message sequence is suitable for authenticated 3-message Noise handshake
///// patterns where the static keys of the responder and initiator are either known
///// (i.e. appear in the pre-message pattern) or are sent with the second and third
///// message, respectively (e.g. `XX`).
/////
///// ```raw
///// initiator --{}--> responder
///// initiator <-{id}- responder
///// initiator -{id}-> responder
///// ```
//pub async fn rt15_responder<T>(
//    io: T,
//    session: snow::HandshakeState,
//    identity: KeypairIdentity,
//    identity_x: IdentityExchange
//)
//    where
//        T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
//{
//        let mut state = State::new( session, identity, identity_x);
//        recv_empty(&mut state, io.clone()).await;
//        send_identity(&mut state, io.clone()).await;
//        recv_identity(&mut state, io).await;
//        //state.finish();
//}
//
//mod tests {
//    //use super::handshake;
//    use super::{IdentityExchange, rt15_responder};
//    use secio::identity;
//    use std::thread::sleep;
//    use std::time;
//    use sha2::{Digest as ShaDigestTrait, Sha256};
//    use crate::protocol::{Keypair};
//    use super::super::NoiseConfig;
//    #[test]
//    fn handshake_test() -> Result<(), String> {
//        async_std::task::block_on(async move {
//            let server_id = identity::Keypair::generate_ed25519();
//            let server_id_public = server_id.public();
//            let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
//            let connec = listener.accept().await.unwrap().0;
//            let server_dh = Keypair::new().into_authentic(&server_id).unwrap();
//            let config = NoiseConfig::xx(server_dh);
//            let session = config.params.into_builder()
//                .local_private_key(config.dh_keys.secret().as_ref())
//                .build_responder()
//                .map_err(NoiseError::from);
//            if let Ok(state) = session {
//                rt15_responder(connec, state, config.dh_keys.into_identity(),IdentityExchange::Mutual).await;
//            }
//        });
//        Ok(())
////        loop{
////            println!("wait");
////            let ten_millis = time::Duration::from_secs(10);
////            sleep(ten_millis);
////        };
//    }
//}