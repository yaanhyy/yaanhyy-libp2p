use futures::ready;
use futures::prelude::*;
use log::{debug, trace};
use snow;
use std::{cmp::min, fmt, pin::Pin, ops::DerefMut, task::{Context, Poll}};
use futures::prelude::*;
use futures::prelude::AsyncRead;
use futures::prelude::AsyncWrite;
use futures_util::io;
use crate::protocol::{KeypairIdentity, PublicKey};
use secio::identity;
use crate::handshake::IdentityExchange;
/// Max. size of a noise package.
const MAX_NOISE_PKG_LEN: usize = 65535;
/// Extra space given to the encryption buffer to hold key material.
const EXTRA_ENCRYPT_SPACE: usize = 1024;
/// Max. output buffer size before forcing a flush.
const MAX_WRITE_BUF_LEN: usize = MAX_NOISE_PKG_LEN - EXTRA_ENCRYPT_SPACE;

static_assertions::const_assert! {
    MAX_WRITE_BUF_LEN + EXTRA_ENCRYPT_SPACE <= MAX_NOISE_PKG_LEN
}

/// A passthrough enum for the two kinds of state machines in `snow`
pub enum SnowState {
    Transport(snow::TransportState),
    Handshake(snow::HandshakeState)
}

impl SnowState {
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error> {
        match self {
            SnowState::Handshake(session) => session.read_message(message, payload),
            SnowState::Transport(session) => session.read_message(message, payload),
        }
    }

    pub fn write_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error> {
        match self {
            SnowState::Handshake(session) => session.write_message(message, payload),
            SnowState::Transport(session) => session.write_message(message, payload),
        }
    }

    pub fn get_remote_static(&self) -> Option<&[u8]> {
        match self {
            SnowState::Handshake(session) => session.get_remote_static(),
            SnowState::Transport(session) => session.get_remote_static(),
        }
    }

    pub fn into_transport_mode(self) -> Result<snow::TransportState, snow::Error> {
        match self {
            SnowState::Handshake(session) => session.into_transport_mode(),
            SnowState::Transport(_) => Err(snow::Error::State(snow::error::StateProblem::HandshakeAlreadyFinished)),
        }
    }
}

/// A noise session to a remote.
///
/// `T` is the type of the underlying I/O resource.
pub struct NoiseOutput<T> {
    pub io: T,
    pub session: SnowState,
    /// The associated public identity of the local node's static DH keypair,
    /// which can be sent to the remote as part of an authenticated handshake.
    pub identity: KeypairIdentity,
    /// The received signature over the remote's static DH public key, if any.
    pub dh_remote_pubkey_sig: Option<Vec<u8>>,
    /// The known or received public identity key of the remote, if any.
    pub id_remote_pubkey: Option<identity::PublicKey>,
    /// Whether to send the public identity key of the local node to the remote.
    pub send_identity: bool,
//    pub read_buffer: Vec<u8>,
//    pub write_buffer: Vec<u8>,
//    pub decrypt_buffer: Vec<u8>,
//    pub encrypt_buffer: Vec<u8>
}


impl<T: AsyncWrite  + AsyncRead + Send + Unpin + 'static> NoiseOutput<T> {
    pub fn new(io: T, session: SnowState, identity: KeypairIdentity, identity_x: IdentityExchange) -> Self {
        let (id_remote_pubkey, send_identity) = match identity_x {
            IdentityExchange::Mutual => (None, true),
            IdentityExchange::Send { remote } => (Some(remote), true),
            IdentityExchange::Receive => (None, false),
            IdentityExchange::None { remote } => (Some(remote), false)
        };

        NoiseOutput {
            io,
            session,
            identity,
            dh_remote_pubkey_sig: None,
            id_remote_pubkey,
            send_identity
//            read_buffer: Vec::new(),
//            write_buffer: Vec::new(),
//            decrypt_buffer: Vec::new(),
//            encrypt_buffer: Vec::new()
        }
    }

    pub async fn read(&mut self) -> Result<Vec<u8>,String>{
        let mut len = [0; 2];
        self.io.read_exact(&mut len).await.unwrap();
        let mut n = u16::from_be_bytes(len) as usize;
        let mut read_buf = vec![0u8; n];
        self.io.read_exact(&mut read_buf).await.unwrap();
        println!("noise read buf_len:{},buf:{:?}", n, read_buf);
        let mut decrypt_buffer = vec![0u8; n];
        let res  = self.session.read_message(&read_buf, &mut decrypt_buffer);
        println!("decrypt_buffer:{:?}", decrypt_buffer);
        return Ok(decrypt_buffer.to_owned());
    }


    pub async fn send(&mut self, buf: &mut Vec<u8>) -> Result<(), String> {
        let mut encrypt_buffer = vec![0u8; buf.len() + EXTRA_ENCRYPT_SPACE];
        let encrypt_len = self.session.write_message(&buf, &mut encrypt_buffer).unwrap();

//        self.encoding_cipher.encrypt(buf.as_mut());
//        let signature = self.encoding_hmac.sign(buf.as_mut());
//        buf.extend_from_slice(signature.as_ref());
        println!("encrypt_buffer:{:?}", encrypt_buffer);
        let mut buf_len = (encrypt_len as u16).to_be_bytes();
        println!("send buf_len:{:?}", buf_len);
        let mut res = self.io.write_all(&buf_len).await;
        if let Ok(_) = res {
            res = self.io.write_all(&encrypt_buffer[..encrypt_len]).await;
            if let Err(e) = res {
                return Err("secio send fail".to_string());
            }
        } else {
            return Err("secio send fail".to_string());
        }
        Ok(())
    }
}