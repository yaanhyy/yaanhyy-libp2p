use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite};
use yamux::session::{SecioSessionWriter, SecioSessionReader};
use secio::codec::{SecureHalfConnWrite, SecureHalfConnRead};
pub use futures_util::io::{ReadHalf, WriteHalf};
use futures::{channel::{mpsc, oneshot}};
use yamux::Config;
use secio::identity::Keypair;
use secio::config::SecioConfig;
use yamux::session::{Mode, ControlCommand, StreamCommand};
use secio::handshake::handshake;
/// The encoded form of a multistream-select 1.0.0 header message.
pub const MSG_MULTISTREAM_1_0: &[u8] = b"/multistream/1.0.0\n";

pub fn split_length_from_package(mut input: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
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


pub fn get_varint_len(mut buf: Vec<u8>) -> u32 {
    let mut len: u32 = 0;
    let step: u32 = 7;
    let mut len_item = None;
    loop {
        len_item = buf.pop();
        if let Some(item) = len_item{
            len = (item as u32) | len<<step;

        } else {
            break;
        }
    }
    len
}

pub async fn get_conn_varint_len<S>(mut conn: S) -> Vec<u8>
  where S: AsyncRead + AsyncWrite + Send + Unpin + 'static + std::clone::Clone
{
    let mut len_buf = [0u8; 1];
    let mut varint_buf: Vec<u8> = Vec::new();
    loop {
        conn.read_exact(&mut len_buf).await.unwrap();

        if len_buf[0] & 0x80 == 0 {
            varint_buf.push(len_buf[0]);
            break;
        } else {
            varint_buf.push(len_buf[0]& 0x7f);
        }
    }
    let len = get_varint_len(varint_buf);
    let mut read_buf = vec![0u8; len as usize];
    conn.read_exact(&mut read_buf).await.unwrap();
    read_buf
}

pub async fn upgrade_secio_protocol<S>(mut connec: S, local_key: Keypair, mode: Mode) -> Result<( SecioSessionReader<ReadHalf<S>>,  SecioSessionWriter<WriteHalf<S>>), String>
    where S: AsyncRead + AsyncWrite + Send + Unpin + 'static + std::clone::Clone
{
    
    let mut config = SecioConfig::new(local_key);
    let mut res = handshake(connec.clone(), config).await;
    println!("after handshake");
    match res {
        Ok((mut secure_conn_writer, mut secure_conn_reader) ) => {
            let (stream_sender, stream_receiver) = mpsc::channel(10);
            let mut session_reader = SecioSessionReader::new(secure_conn_reader, Config::default(), mode,  stream_sender);
            let mut session_writer = SecioSessionWriter::new(secure_conn_writer, stream_receiver);
            return Ok((session_reader, session_writer))
        },
        Err(e) => Err(format!("handshake res:{:?}", e)),
    }
}