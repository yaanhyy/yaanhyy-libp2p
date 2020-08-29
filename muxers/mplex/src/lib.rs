use futures::prelude::*;
use futures::{future, select, join};
use async_std::sync::Mutex;
use std::{fmt, sync::{Arc}, task::{Context, Poll}, pin::Pin};
use std::collections::HashMap;
use futures::future::Future;
use futures::{channel::{mpsc, oneshot}};
use std::time::Duration;
use async_std::task;
use futures::future::Either;
use secio::identity::Keypair;
use noise::io::NoiseOutput;
use noise::handshake::{rt15_initiator, rt15_responder, IdentityExchange};
use futures::{AsyncRead, AsyncWrite};
use utils::get_conn_varint_var;
pub mod codec;
use codec::{Elem, Endpoint};


// Struct shared throughout the implementation.
pub struct MultiplexInner<C> {

    // Underlying stream.
    inner: Arc<Mutex<NoiseOutput<C>>>,
    // The original configuration.
//    config: MplexConfig,
    // Buffer of elements pulled from the stream but not processed yet.
//    buffer: Vec<codec::Elem>,
    // List of Ids of opened substreams. Used to filter out messages that don't belong to any
    // substream. Note that this is handled exclusively by `next_match`.
    // The `Endpoint` value denotes who initiated the substream from our point of view
    // (see note [StreamId]).
  //  opened_substreams: FnvHashSet<(u32, Endpoint)>,
    // Id of the next outgoing substream.
    next_outbound_stream_id: u32,

    /// If true, the connection has been shut down. We need to be careful not to accidentally
    /// call `Sink::poll_complete` or `Sink::start_send` after `Sink::close`.
    is_shutdown: bool,
}

/// Active attempt to open an outbound substream.
pub struct OutboundSubstream {
    /// Substream number.
    num: u32,
    state: OutboundSubstreamState,
}

enum OutboundSubstreamState {
    /// We need to send `Elem` on the underlying stream.
    SendElem(codec::Elem),
    /// We need to flush the underlying stream.
    Flush,
    /// The substream is open and the `OutboundSubstream` is now useless.
    Done,
}

/// Active substream to the remote.
pub struct Substream {
    /// Substream number.
    num: u32,

    endpoint: Endpoint,
    /// If true, our writing side is still open.
    local_open: bool,
    /// If true, the remote writing side is still open.
    remote_open: bool,
}



pub fn split_header_from_package(mut input: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut varint_buf: Vec<u8> = Vec::new();
    loop {
        let item = input.remove(0);

        if item & 0x80 == 0 {
            varint_buf.push(item);
            break;
        } else {
            varint_buf.push(item& 0x7f);
        }
    }
    (input, varint_buf)
}


pub async fn receive_frame<T>(conn: Arc<Mutex<NoiseOutput<T>>>) -> Result<Elem, String>
where T:  AsyncWrite + AsyncRead + Send + Unpin + 'static
{
    let mut data =  (*conn.lock().await).read().await.unwrap();


    let (header,  data)  = unsigned_varint::decode::u128(&data).unwrap();
    let (len,  data) = unsigned_varint::decode::u128(&data).unwrap();
    let frame_type = header & 0x3;
    let substream_id = (header >>3) as u32;
    println!("frame_type:{:?}", frame_type);
    let out = match frame_type {
        0 => Elem::Open { substream_id },
        1 => Elem::Data { substream_id, endpoint: Endpoint::Listener, data: data.to_vec()},
        2 => Elem::Data { substream_id, endpoint: Endpoint::Dialer, data: data.to_vec() },
        3 => Elem::Close { substream_id, endpoint: Endpoint::Listener },
        4 => Elem::Close { substream_id, endpoint: Endpoint::Dialer },
        5 => Elem::Reset { substream_id, endpoint: Endpoint::Listener },
        6 => Elem::Reset { substream_id, endpoint: Endpoint::Dialer },
        _ => {
            let msg = format!("Invalid mplex header value 0x{:x}", header);
            return Err(format!("IoErrorKind::InvalidData, msg:{:?}", msg));
        },
    };
    println!("Elem:{:?}", out);
    Ok(out)
}

pub async fn open_stream() {

}

#[test]
fn clinet_test() {
    async_std::task::block_on(async move {
        let connec = async_std::net::TcpStream::connect("127.0.0.1:8981").await.unwrap();

    });
}

#[test]
fn server_test() {
    async_std::task::block_on(async move {
        let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
        let mut connec = listener.accept().await.unwrap().0;
        let mut len_buf = [0u8; 1];
        let mut varint_buf: Vec<u8> = Vec::new();
        loop {
            let header = get_conn_varint_var(connec.clone()).await;
            println!("header:{}", header);
            let len = get_conn_varint_var(connec.clone()).await;
            println!("len:{}", len);
            if len > 0 {
                let mut read_buf = vec![0u8; len as usize];
                connec.read_exact(&mut read_buf).await.unwrap();
                println!("data:{:?}", read_buf);
            }
        }
    });
}