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
use unsigned_varint::{encode};
use log::trace;

/// Configuration for the multiplexer.
#[derive(Debug, Clone)]
pub struct MplexConfig {
    /// Maximum number of simultaneously-open substreams.
    pub max_substreams: usize,
    /// Maximum number of elements in the internal buffer.
    pub max_buffer_len: usize,
    /// Behaviour when the buffer size limit is reached.
    //max_buffer_behaviour: MaxBufferBehaviour,
    /// When sending data, split it into frames whose maximum size is this value
    /// (max 1MByte, as per the Mplex spec).
    pub split_send_size: usize,
}

impl Default for MplexConfig {
    fn default() -> MplexConfig {
        MplexConfig {
            max_substreams: 128,
            max_buffer_len: 4096,
          //  max_buffer_behaviour: MaxBufferBehaviour::CloseAll,
            split_send_size: 1024,
        }
    }
}

// Struct shared throughout the implementation.
pub struct MultiplexInner<C> {

    // Underlying stream.
    inner: Arc<Mutex<NoiseOutput<C>>>,
    // The original configuration.
    config: MplexConfig,
    // Buffer of elements pulled from the stream but not processed yet.
    buffer: Vec<codec::Elem>,
    // List of Ids of opened substreams. Used to filter out messages that don't belong to any
    // substream. Note that this is handled exclusively by `next_match`.
    // The `Endpoint` value denotes who initiated the substream from our point of view
    // (see note [StreamId]).
    opened_substreams: HashMap<u32, Endpoint>,
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


pub async fn receive_frame<T>(conn: Arc<Mutex<NoiseOutput<T>>>) -> Result<Vec<Elem>, String>
where T:  AsyncWrite + AsyncRead + Send + Unpin + 'static
{
    let mut data =  (*conn.lock().await).read().await.unwrap();
    let mut out = Vec::new();
    while  data.len() != 0 {
        let (header, data_length) = unsigned_varint::decode::u128(&data).unwrap();
        let (len, mut data_body) = unsigned_varint::decode::u128(&data_length).unwrap();
        let frame_type = header & 0x3;
        let substream_id = (header >> 3) as u32;
        trace!("frame_type:{:?}, len:{:?}", frame_type, len);
        let mut data_body = data_body.to_vec();
        data = data_body.drain((len as usize)..).collect();
        let elem = match frame_type {
            0 => Elem::Open { substream_id },
            1 => Elem::Data { substream_id, endpoint: Endpoint::Listener, data: data_body.to_vec() },
            2 => Elem::Data { substream_id, endpoint: Endpoint::Dialer, data: data_body.to_vec() },
            3 => Elem::Close { substream_id, endpoint: Endpoint::Listener },
            4 => Elem::Close { substream_id, endpoint: Endpoint::Dialer },
            5 => Elem::Reset { substream_id, endpoint: Endpoint::Listener },
            6 => Elem::Reset { substream_id, endpoint: Endpoint::Dialer },
            _ => {
                let msg = format!("Invalid mplex header value 0x{:x}", header);
                return Err(format!("IoErrorKind::InvalidData, msg:{:?}", msg));
            },
        };
        out.push(elem);
    }
    Ok(out)
}


pub async fn send_frame<T>(conn: Arc<Mutex<NoiseOutput<T>>>, elem: Elem) -> Result<(), String>
    where T:  AsyncWrite + AsyncRead + Send + Unpin + 'static
{
    let (header, mut data) = match elem {
        Elem::Open { substream_id } => {
            (u64::from(substream_id) << 3, Vec::new())
        },
        Elem::Data { substream_id, endpoint: Endpoint::Listener, data } => {
            (u64::from(substream_id) << 3 | 1, data)
        },
        Elem::Data { substream_id, endpoint: Endpoint::Dialer, data } => {
            (u64::from(substream_id) << 3 | 2, data)
        },
        Elem::Close { substream_id, endpoint: Endpoint::Listener } => {
            (u64::from(substream_id) << 3 | 3, Vec::new())
        },
        Elem::Close { substream_id, endpoint: Endpoint::Dialer } => {
            (u64::from(substream_id) << 3 | 4, Vec::new())
        },
        Elem::Reset { substream_id, endpoint: Endpoint::Listener } => {
            (u64::from(substream_id) << 3 | 5, Vec::new())
        },
        Elem::Reset { substream_id, endpoint: Endpoint::Dialer } => {
            (u64::from(substream_id) << 3 | 6, Vec::new())
        },
    };

    let mut send_frame = Vec::new();
    let mut header_buf = encode::u64_buffer();
    trace!("header:{}", header);
    let header_bytes = encode::u64(header, &mut header_buf);

    let data_len = data.len();
    let mut data_buf = encode::usize_buffer();
    let data_len_bytes = encode::usize(data_len, &mut data_buf);
    send_frame.append(& mut header_bytes.to_vec());
    send_frame.append(& mut  data_len_bytes.to_vec());
    send_frame.append(& mut data);
    trace!("send_frame{:?}", send_frame);
    (*conn.lock().await).send(& mut send_frame).await.unwrap();
    Ok(())
}

pub async fn send_tcp_frame<T>(mut conn: T, elem: Elem) -> Result<(), String>
    where T:  AsyncWrite + AsyncRead + Send + Unpin + 'static
{
    let (header, mut data) = match elem {
        Elem::Open { substream_id } => {
            (u64::from(substream_id) << 3, Vec::new())
        },
        Elem::Data { substream_id, endpoint: Endpoint::Listener, data } => {
            (u64::from(substream_id) << 3 | 1, data)
        },
        Elem::Data { substream_id, endpoint: Endpoint::Dialer, data } => {
            (u64::from(substream_id) << 3 | 2, data)
        },
        Elem::Close { substream_id, endpoint: Endpoint::Listener } => {
            (u64::from(substream_id) << 3 | 3, Vec::new())
        },
        Elem::Close { substream_id, endpoint: Endpoint::Dialer } => {
            (u64::from(substream_id) << 3 | 4, Vec::new())
        },
        Elem::Reset { substream_id, endpoint: Endpoint::Listener } => {
            (u64::from(substream_id) << 3 | 5, Vec::new())
        },
        Elem::Reset { substream_id, endpoint: Endpoint::Dialer } => {
            (u64::from(substream_id) << 3 | 6, Vec::new())
        },
    };

    let mut send_frame = Vec::new();
    let mut header_buf = encode::u64_buffer();
    trace!("header:{}", header);
    let header_bytes = encode::u64(header, &mut header_buf);

    let data_len = data.len();
    let mut data_buf = encode::usize_buffer();
    let data_len_bytes = encode::usize(data_len, &mut data_buf);
    send_frame.append(& mut header_bytes.to_vec());
    send_frame.append(& mut  data_len_bytes.to_vec());
    send_frame.append(& mut data);
    trace!("send_frame{:?}", send_frame);
    conn.write_all(&send_frame).await;
    Ok(())
}

pub async fn open_stream() {

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

pub fn receive_frame_raw(mut data: Vec<u8>) -> Result<Vec<Elem>, String>
{

    let mut out = Vec::new();
    while  data.len() != 0 {
        let (header, data_length) = unsigned_varint::decode::u128(&data).unwrap();
        let (len, mut data_body) = unsigned_varint::decode::u128(&data_length).unwrap();
        let frame_type = header & 0x3;
        let substream_id = (header >> 3) as u32;
        println!("frame_type:{:?}, len:{:?}", frame_type, len);
        let mut data_body = data_body.to_vec();
        data = data_body.drain((len as usize)..).collect();
        let elem = match frame_type {
            0 => Elem::Open { substream_id },
            1 => Elem::Data { substream_id, endpoint: Endpoint::Listener, data: data_body.to_vec() },
            2 => Elem::Data { substream_id, endpoint: Endpoint::Dialer, data: data_body.to_vec() },
            3 => Elem::Close { substream_id, endpoint: Endpoint::Listener },
            4 => Elem::Close { substream_id, endpoint: Endpoint::Dialer },
            5 => Elem::Reset { substream_id, endpoint: Endpoint::Listener },
            6 => Elem::Reset { substream_id, endpoint: Endpoint::Dialer },
            _ => {
                let msg = format!("Invalid mplex header value 0x{:x}", header);
                return Err(format!("IoErrorKind::InvalidData, msg:{:?}", msg));
            },
        };
        out.push(elem);
    }
    Ok(out)
}

#[test]
fn receive_frame_test() {

    let mut data:Vec<u8> = vec![ 2, 0x80, 8  , 247, 15, 18, 244, 15, 18, 201, 15, 199, 24, 244, 194, 2, 100, 0, 0, 0, 177, 20, 96, 105, 40, 142, 55, 48, 69, 211, 21, 205, 215, 67, 235, 56, 188, 153, 124, 241, 222, 28, 197, 8, 176, 249, 199, 137, 53, 7, 91, 201, 240, 190, 74, 203, 69, 50, 186, 218, 89, 59, 184, 12, 162, 49, 183, 221, 18, 194, 84, 106, 186, 159, 57, 62, 151, 189, 211, 202, 151, 221, 73, 40, 122, 253, 68, 229, 246, 121, 92, 238, 27, 98, 189, 128, 8, 23, 76, 25, 68, 7, 5, 119, 106, 235, 144, 97, 182, 154, 141, 100, 96, 129, 167, 71, 118, 232, 3, 0, 0, 0, 0, 0, 92, 37, 0, 0, 0, 0, 0, 0, 34, 186, 97, 82, 47, 8, 192, 234, 168, 64, 230, 9, 108, 130, 148, 122, 158, 158, 161, 186, 94, 33, 254, 18, 63, 76, 97, 170, 105, 252, 80, 244, 19, 132, 34, 100, 92, 148, 113, 225, 191, 246, 75, 60, 164, 62, 48, 86, 202, 226, 118, 68, 186, 212, 217, 118, 164, 72, 109, 44, 57, 69, 34, 3, 84, 0, 0, 0, 145, 127, 160, 171, 242, 250, 208, 0, 200, 49, 81, 126, 10, 159, 113, 57, 176, 33, 199, 61, 17, 85, 231, 253, 170, 233, 5, 53, 248, 138, 5, 30, 75, 207, 94, 152, 221, 171, 77, 43, 242, 62, 110, 245, 49, 89, 88, 84, 6, 72, 19, 150, 210, 241, 155, 82, 90, 58, 208, 234, 108, 74, 109, 4, 200, 206, 74, 217, 59, 24, 0, 163, 46, 152, 89, 69, 22, 26, 77, 145, 179, 37, 227, 173, 95, 192, 126, 90, 215, 125, 3, 45, 212, 124, 226, 32, 71, 157, 163, 54, 59, 208, 255, 190, 238, 47, 204, 236, 178, 22, 104, 155, 69, 13, 163, 71, 138, 168, 248, 35, 228, 60, 12, 112, 227, 221, 239, 84, 14, 246, 0, 0, 0, 0, 0, 0, 176, 105, 252, 181, 208, 203, 83, 175, 23, 57, 193, 87, 247, 113, 145, 161, 189, 5, 60, 132, 120, 74, 230, 90, 6, 139, 230, 210, 161, 55, 151, 249, 112, 111, 97, 112, 72, 114, 122, 101, 47, 84, 101, 57, 105, 103, 77, 112, 47, 106, 114, 122, 86, 67, 70, 68, 65, 90, 68, 100, 118, 70, 107, 69, 220, 0, 0, 0, 220, 0, 0, 0, 220, 0, 0, 0, 143, 11, 0, 0, 143, 11, 0, 0, 44, 0, 0, 0, 33, 1, 0, 0, 22, 2, 0, 0, 11, 3, 0, 0, 0, 4, 0, 0, 245, 4, 0, 0, 234, 5, 0, 0, 223, 6, 0, 0, 212, 7, 0, 0, 201, 8, 0, 0, 190, 9, 0, 0, 228, 0, 0, 0, 117, 232, 3, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 34, 186, 97, 82, 47, 8, 192, 234, 168, 64, 230, 9, 108, 130, 148, 122, 158, 158, 161, 186, 94, 33, 254, 18, 63, 76, 97, 170, 105, 252, 80, 244, 66, 31, 0, 0, 0, 0, 0, 0, 154, 58, 224, 132, 1, 229, 139, 84, 76, 187, 209, 2, 159, 75, 218, 110, 199, 213, 196, 243, 88, 89, 17, 24, 246, 27, 107, 4, 244, 91, 2, 154, 67, 31, 0, 0, 0, 0, 0, 0, 89, 129, 71, 92, 164, 135, 218, 80, 75, 127, 87, 59, 94, 181, 196, 204, 254, 95, 208, 139, 175, 144, 2, 237, 141, 56, 227, 218, 86, 6, 250, 39, 183, 175, 253, 171, 138, 129, 127, 131, 240, 67, 24, 75, 119, 174, 215, 180, 109, 155, 118, 21, 230, 102, 122, 179, 74, 8, 126, 87, 229, 213, 74, 52, 19, 208, 167, 78, 17, 149, 121, 185, 126, 208, 40, 17, 16, 75, 191, 140, 7, 79, 64, 249, 238, 19, 114, 23, 155, 15, 166, 85, 65, 148, 5, 136, 213, 60, 138, 148, 5, 58, 115, 74, 184, 70, 110, 177, 115, 109, 149, 75, 252, 44, 166, 224, 225, 240, 158, 212, 126, 207, 70, 223, 238, 252, 172, 199, 127, 255, 223, 254, 244, 223, 254, 245, 223, 15, 247, 117, 251, 228, 255, 252, 2, 228, 0, 0, 0, 117, 232, 3, 0, 0, 0, 0, 0, 4, 0, 150, 85, 2, 4, 66, 31, 9, 40, 24, 154, 58, 224, 132, 1, 229, 139, 238, 245, 0, 5, 245, 240, 117, 137, 107, 111, 3, 192, 56, 48, 238, 43, 243, 16, 48, 12, 171, 74, 249, 219, 15, 221, 49, 196, 237, 75, 160, 181, 35, 104, 209, 215, 200, 0, 239, 134, 198, 137, 129, 179, 205, 56, 180, 108, 227, 225, 246, 32, 210, 101, 14, 3, 188, 138, 46, 96, 62, 184, 72, 52, 139, 162, 109, 205, 62, 199, 202, 231, 134, 108, 9, 255, 58, 175, 103, 226, 10, 66, 103, 201, 196, 119, 132, 162, 128, 34, 192, 125, 68, 229, 154, 56, 223, 104, 75, 28, 184, 43, 236, 251, 237, 181, 233, 201, 31, 255, 255, 245, 237, 80, 125, 247, 143, 237, 31, 3, 228, 0, 0, 0, 117, 45, 234, 0, 1, 9, 204, 0, 0, 254, 234, 1, 190, 234, 1, 240, 113, 173, 202, 178, 21, 73, 46, 172, 52, 162, 25, 240, 157, 164, 255, 255, 113, 137, 72, 130, 67, 201, 238, 250, 189, 232, 243, 164, 34, 5, 115, 111, 190, 47, 76, 200, 55, 249, 210, 249, 185, 218, 1, 216, 74, 75, 213, 219, 49, 11, 26, 125, 122, 100, 28, 45, 117, 109, 150, 28, 173, 164, 110, 98, 255, 148, 48, 104, 104, 149, 180, 98, 111, 196, 89, 202, 14, 253, 72, 45, 198, 13, 186, 80, 65, 165, 88, 97, 124, 138, 163, 108, 206, 16, 175, 6, 91, 255, 255, 187, 187, 175, 151, 253, 231, 191, 246, 219, 255, 243, 78, 255, 255, 3, 228, 29, 245, 0, 2, 254, 245, 0, 218, 245, 0, 240, 113, 169, 227, 135, 40, 88, 214, 124, 182, 79, 250, 2, 92, 197, 206, 90, 54, 37, 96, 207, 154, 13, 2, 249, 7, 45, 126, 176, 63, 149, 125, 10, 212, 220, 34, 138, 87, 86, 66, 216, 134, 156, 164, 37, 172, 100, 102, 27, 250, 183, 22, 65, 17, 222, 76, 26, 108, 174, 240, 98, 81, 46, 110, 41, 207, 102, 252, 31, 118, 88, 204, 91, 245, 199, 122, 82, 2, 11, 72, 169, 8, 245, 198, 77, 166, 157, 214, 21, 71, 242, 105, 192, 69, 198, 53, 187, 174, 99, 202, 192, 183, 255, 239, 219, 159, 181, 250, 175, 239, 191, 242, 254, 219, 191, 255, 111, 3, 228, 29, 245, 0, 6, 254, 245, 0, 218, 245, 0, 240, 113, 179, 14, 156, 242, 86, 52, 128, 208, 68, 163, 211, 172, 170, 107, 55, 58, 166, 59, 98, 192, 166, 78, 204, 254, 83, 217, 120, 155, 58, 91, 187, 47, 9, 248, 253, 20, 110, 81, 36, 233, 61, 61, 105, 200, 110, 106, 131, 161, 10, 60, 137, 152, 77, 94, 217, 122, 124, 169, 167, 142, 86, 177, 172, 251, 240, 149, 238, 133, 43, 191, 120, 214, 254, 19, 177, 168, 71, 128, 241, 185, 19, 147, 199, 197, 15, 63, 175, 146, 164, 245, 91, 2, 92, 56, 55, 36, 228, 245, 63, 126, 247, 247, 55, 255, 233, 255, 171, 243, 255, 127, 207, 246, 7, 228, 29, 245, 0, 9, 254, 245, 0, 218, 245, 0, 240, 113, 161, 240, 206, 137, 229, 89, 159, 130, 217, 72, 199, 98, 114, 58, 6, 136, 59, 14, 250, 240, 147, 33, 254, 242, 11, 115, 214, 247, 164, 85, 75, 125, 147, 181, 179, 181, 121, 247, 75, 60, 61, 20, 196, 203, 56, 182, 248, 245, 19, 242, 126, 96, 86, 214, 189, 6, 30, 100, 8, 36, 198, 222, 97, 14, 250, 125, 130, 18, 229, 235, 156, 202, 188, 58, 170, 93, 54, 73, 9, 151, 160, 133, 186, 195, 32, 52, 161, 253, 90, 178, 219, 66, 148, 52, 251, 106, 191, 159, 253, 239, 255, 175, 191, 119, 231, 237, 246, 207, 183, 250, 181, 252, 5, 228, 29, 245, 0, 7, 254, 245, 0, 218, 245, 0, 240, 113, 160, 20, 121, 73, 212, 252, 59, 19, 211, 235, 83, 68, 70, 129, 74, 189, 45, 231, 202, 79, 90, 215, 171, 90, 219, 237, 58, 41, 85, 141, 71, 158, 188, 229, 113, 150, 123, 152, 197, 167, 76, 185, 64, 22, 231, 240, 50, 90, 25, 148, 225, 226, 236, 181, 179, 6, 1, 14, 126, 13, 247, 209, 144, 165, 209, 224, 177, 220, 123, 96, 156, 4, 29, 186, 133, 188, 226, 73, 72, 109, 8, 179, 47, 213, 62, 252, 127, 208, 71, 113, 163, 15, 184, 171, 101, 101, 219, 136, 247, 127, 229, 191, 249, 255, 111, 241, 255, 125, 247, 207, 125, 255, 3, 228, 29, 245, 0, 10, 254, 245, 0, 218, 245, 0, 240, 113, 143, 138, 165, 205, 116, 48, 242, 233, 87, 115, 199, 238, 41, 39, 105, 89, 241, 58, 70, 79, 10, 169, 59, 142, 23, 100, 88, 186, 127, 75, 238, 87, 142, 68, 176, 23, 164, 222, 68, 18, 189, 83, 26, 174, 245, 135, 82, 75, 11, 86, 229, 55, 84, 139, 229, 127, 67, 10, 103, 250, 78, 83, 50, 159, 34, 75, 186, 127, 119, 135, 217, 240, 74, 202, 26, 157, 60, 82, 89, 64, 47, 6, 215, 127, 123, 92, 40, 90, 29, 162, 233, 226, 206, 223, 59, 148, 223, 123, 255, 141, 191, 255, 155, 251, 249, 187, 191, 255, 247, 83, 253, 223, 2, 228, 29, 245, 17, 1, 254, 190, 5, 190, 190, 5, 240, 113, 180, 182, 34, 30, 228, 173, 212, 90, 18, 99, 214, 186, 75, 56, 93, 59, 152, 135, 194, 179, 171, 35, 174, 146, 165, 232, 53, 116, 6, 122, 14, 148, 12, 13, 157, 208, 109, 14, 135, 254, 83, 35, 239, 198, 35, 49, 71, 15, 8, 198, 74, 40, 176, 229, 90, 144, 138, 126, 189, 62, 195, 205, 146, 2, 239, 249, 53, 43, 85, 195, 77, 226, 150, 227, 44, 81, 248, 177, 72, 114, 182, 6, 56, 221, 21, 184, 216, 137, 227, 231, 125, 210, 144, 18, 128, 71, 245, 247, 247, 255, 247, 255, 255, 125, 255, 159, 255, 79, 223, 221, 247, 143, 7, 228, 29, 245, 0, 8, 13, 246, 254, 245, 0, 190, 245, 0, 240, 113, 166, 177, 219, 51, 197, 177, 247, 18, 251, 117, 95, 69, 147, 50, 140, 144, 117, 35, 20, 158, 160, 98, 143, 37, 55, 253, 76, 36, 37, 215, 8, 2, 114, 98, 103, 4, 248, 212, 12, 106, 164, 175, 61, 161, 8, 149, 241, 158, 23, 36, 8, 76, 198, 161, 54, 124, 215, 119, 120, 75, 134, 219, 237, 130, 17, 230, 140, 183, 169, 236, 129, 44, 12, 245, 46, 49, 190, 82, 241, 108, 43, 217, 149, 88, 248, 226, 118, 216, 51, 87, 34, 183, 36, 228, 72, 47, 123, 191, 169, 247, 255, 255, 251, 190, 239, 239, 253, 45, 255, 191, 213, 111, 3, 228, 29, 245, 22, 248, 10, 254, 168, 7, 198, 168, 7, 240, 112, 178, 36, 155, 118, 194, 126, 171, 168, 242, 209, 75, 158, 153, 52, 103, 9, 84, 79, 253, 7, 30, 13, 148, 192, 72, 254, 211, 144, 21, 100, 145, 174, 81, 19, 253, 108, 192, 194, 20, 49, 205, 195, 249, 19, 226, 191, 29, 98, 9, 109, 200, 184, 104, 251, 227, 33, 84, 29, 162, 47, 127, 27, 118, 222, 64, 82, 227, 119, 222, 125, 46, 178, 201, 156, 100, 45, 141, 199, 153, 243, 175, 138, 138, 193, 223, 206, 100, 24, 78, 119, 28, 242, 94, 191, 47, 184, 198, 195, 253, 249, 221, 255, 215, 63, 172, 243, 173, 251, 107, 255, 76, 255, 7, 34, 38, 47, 101, 116, 104, 50, 47, 101, 55, 97, 55, 53, 100, 53, 97, 47, 98, 101, 97, 99, 111, 110, 95, 98, 108, 111, 99, 107, 47, 115, 115, 122, 95, 115, 110, 97, 112, 112, 121]; //len:2044

    receive_frame_raw(data);
}