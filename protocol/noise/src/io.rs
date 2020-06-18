use futures::ready;
use futures::prelude::*;
use log::{debug, trace};
use snow;
use std::{cmp::min, fmt, pin::Pin, ops::DerefMut, task::{Context, Poll}};
use futures::prelude::*;
use futures::prelude::AsyncRead;
use futures::prelude::AsyncWrite;
use futures_util::io;
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
    pub read_buffer: Vec<u8>,
    pub write_buffer: Vec<u8>,
    pub decrypt_buffer: Vec<u8>,
    pub encrypt_buffer: Vec<u8>
}


impl<T: AsyncWrite  + AsyncRead + Send + Unpin + 'static> NoiseOutput<T> {
    pub fn new(io: T, session: SnowState) -> Self {
        NoiseOutput {
            io,
            session,
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            decrypt_buffer: Vec::new(),
            encrypt_buffer: Vec::new()
        }
    }

    pub async fn read(&mut self) -> Result<Vec<u8>,String>{
        let mut len = [0; 2];
        self.io.read_exact(&mut len).await.unwrap();
        let mut n = u16::from_be_bytes(len) as usize;
        let mut read_buf = vec![0u8; n];
        self.io.read_exact(&mut read_buf).await.unwrap();
        debug!("secio read buf_len:{},buf:{:?}", n, read_buf);

        return Ok("ok".to_string().into_bytes());
    }

}