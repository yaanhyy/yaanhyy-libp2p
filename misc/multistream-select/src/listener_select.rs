use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite};
use crate::protocol;
use super::GetVarintLen;
use secio::config::SecioConfig;
use secio::handshake::handshake;
use secio::identity::Keypair;
use secio::codec::{SecureHalfConnWrite, SecureHalfConnRead};
use futures::future::Future;
use futures::{future, select, join};
use futures::{channel::{mpsc, oneshot}};
use yamux::session::{SecioSessionWriter, SecioSessionReader};
use yamux::Config;
use yamux::frame::Frame;
use yamux::session::{Mode, ControlCommand, StreamCommand};
use yamux::session::{get_stream, open_stream, subscribe_stream};
use futures::prelude::*;
use async_std::task;
use std::time::Duration;
use utils::init_log;
use std::sync::{Arc};
use async_std::sync::Mutex;
pub use futures_util::io::{ReadHalf, WriteHalf};

pub fn get_len_buf_from_buf(mut input: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
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



pub async fn period_send( sender: mpsc::Sender<ControlCommand>) {
    let res = open_stream(sender).await;
    let mut index = 0;
    if let Ok(mut stream) = res {
        let mut stream_clone = stream.clone();
        let mut data_receiver = stream.data_receiver.unwrap();
        task::spawn(async move {
            loop {
                let buf = data_receiver.next().await;
                println!("receive:{:?}", buf);
            }
        });
        loop {
            index +=1;
            let frame = Frame::data(stream_clone.id(), format!("love and peace:{}", index).into_bytes()).unwrap();
            stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
       //     task::sleep(Duration::from_secs(10)).await;

        }
    } else {
        println!("fail open stream");
    }
}



pub async fn remote_stream_deal(mut frame_sender: mpsc::Sender<StreamCommand>, mut sender: mpsc::Sender<ControlCommand>) {
    let res = subscribe_stream(sender.clone()).await;
    if let Ok(mut stream)= res{
        loop {
            let mut stream = stream.next().await.unwrap();

            if !stream.cache.is_empty() {
                let mut  data: Vec<u8> = stream.cache.drain(4..).collect();
                let mut len_buf = [0u8;4];
                len_buf.copy_from_slice(stream.cache.as_slice());
                let len = u32::from_be_bytes(len_buf);

                let ping_proto: Vec<u8> = data.drain(20..).collect();
                let out = std::str::from_utf8(&data.clone()).unwrap().to_string();
                let out1 = std::str::from_utf8(&ping_proto.clone()).unwrap().to_string();
                println!("chache len:{}, buf:{:?},ping:{:?}", len, out, out1);


                let len:u8 = protocol::MSG_MULTISTREAM_1_0.len() as u8;
                data.clear();
                data.push(len);
                data.append(& mut protocol::MSG_MULTISTREAM_1_0.to_vec()) ;

                let mut stream_clone = stream.clone();
                let frame = Frame::data(stream_clone.id(), data).unwrap();
                stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                let frame = Frame::data(stream_clone.id(), ping_proto).unwrap();
                stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                //let mut stream_spawn = stream.clone();
            }
            let mut stream_spawn = stream.clone();
            let mut data_receiver = stream.data_receiver.unwrap();

            task::spawn(async move {

              //  loop {
                    let mut buf = data_receiver.next().await;
                    let (mut data, varint_buf) = get_len_buf_from_buf(buf.clone().unwrap());
                    let mut len = GetVarintLen(varint_buf);
                    println!("remote send receive:{:?}", buf.clone());
                    buf = data_receiver.next().await;
                    data = buf.clone().unwrap();
                    let ping_proto: Vec<u8> = data.drain(20..).collect();
                    let mut stream_clone = stream_spawn.clone();
//                  let frame = Frame::data(stream_clone.id(), data).unwrap();
//                  stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                    //send back ping protocol for negotiate
                    let frame = Frame::data(stream_clone.id(), ping_proto).unwrap();
                    stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                   // let buf = std::str::from_utf8(&buf.unwrap()).unwrap().to_string();
                    println!("remote send receive:{:?}", buf);
                    buf = data_receiver.next().await;
                    println!("remote send receive:{:?}", buf.clone());

                    buf = data_receiver.next().await;
                    let frame = Frame::data(stream_spawn.id(), buf.unwrap()).unwrap();
                    stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
              //  }
            });
           //break;
        }


    }else {
        println!("get_stream fail :{:?}", res);
    }
}

pub async fn listener_select_proto_secio<R, W>(mut reader: Arc<Mutex<SecureHalfConnRead<R>>>, mut writer: Arc<Mutex<SecureHalfConnWrite<W>>>, protocols: Vec<String>) -> Result<Vec<String>, String>
where R: AsyncRead + Send + Unpin + 'static, W: AsyncWrite + Send + Unpin + 'static
{
    let mut protos: Vec<String> = Vec::new();
    let mut data = (*reader.lock().await).read().await.unwrap();
    let (mut data, varint_buf) = get_len_buf_from_buf(data);
    let mut len = GetVarintLen(varint_buf);
    let mut rest: Vec<_> = data.drain((len as usize)..).collect();
    let proto = std::str::from_utf8(&data).unwrap().to_string();
    println!("secio rec proto:{:?}", proto);

    if !data.eq(&protocol::MSG_MULTISTREAM_1_0.to_vec()) {
        return Err("listener_select_proto_secio MULTISTREAM not match".to_string());
    }
    let mut len_buf = [0u8; 1];
    //len_buf[0] = protocol::MSG_MULTISTREAM_1_0.len() as u8;
   // let res = (*writer.lock().await).send(& mut len_buf.to_vec()).await;
   // let res = (*writer.lock().await).send(& mut data).await;

    if rest.is_empty() {
        data = (*reader.lock().await).read().await.unwrap();
    } else {
        data = rest;
    }
    let (mut data, varint_buf) = get_len_buf_from_buf(data);
    len = GetVarintLen(varint_buf);
    let mut tail: Vec<_> = data.drain((len as usize)..).collect();
    let proto = std::str::from_utf8(&data.clone()).unwrap().to_string();
    println!("secio rec proto:{:?}", proto);
    if protocols.contains(&proto) {
        len_buf[0] = data.len() as u8;
        println!("yamux len:{:?}", len_buf);
        let res = (*writer.lock().await).send(&mut len_buf.to_vec()).await;
        println!("send yamux:{:?}", data);
        let res = (*writer.lock().await).send(&mut data).await;
        protos.push(proto);
        return Ok(protos)
    }
    Err("not match proto".to_string())
}

pub async fn upgrade_secio_protocol<S>(mut connec: S) -> Result<( SecioSessionReader<ReadHalf<S>>,  SecioSessionWriter<WriteHalf<S>>), String>
 where S: AsyncRead + AsyncWrite + Send + Unpin + 'static + std::clone::Clone
{
    let key1 = Keypair::generate_ed25519();
    let mut config = SecioConfig::new(key1);
    let mut res = handshake(connec.clone(), config).await;
    println!("after handshake");
    match res {
        Ok((mut secure_conn_writer, mut secure_conn_reader) ) => {
            let (stream_sender, stream_receiver) = mpsc::channel(10);
            let mut session_reader = SecioSessionReader::new(secure_conn_reader, Config::default(), Mode::Server,  stream_sender);
            let mut session_writer = SecioSessionWriter::new(secure_conn_writer, stream_receiver);
            return Ok((session_reader, session_writer))
        },
        Err(e) => Err(format!("handshake res:{:?}", e)),
    }
}


pub async fn listener_select_proto<S>(mut connec: S, protocols: Vec<String>) -> Result<Vec<String>, String>
 where S: AsyncRead + AsyncWrite + Send + Unpin + 'static + std::clone::Clone
{
    let mut match_proto = Vec::new();
    let mut len_buf = [0u8; 1];
    let mut varint_buf: Vec<u8> = Vec::new();
    loop {
        connec.read_exact(&mut len_buf).await.unwrap();

        if len_buf[0] & 0x80 == 0 {
            varint_buf.push(len_buf[0]);
            break;
        } else {
            varint_buf.push(len_buf[0]& 0x7f);
        }
    }
    let mut len =  GetVarintLen(varint_buf);

    let mut read_buf = vec![0u8; len as usize];
    connec.read_exact(&mut read_buf).await.unwrap();
    let proto_name = std::str::from_utf8(&read_buf.to_owned()).unwrap().to_string();
    if !read_buf.eq(&protocol::MSG_MULTISTREAM_1_0.to_vec()) {
        return Err("MULTISTREAM not match".to_string());
    }
    println!("buf_len:{},buf:{:?}", len, read_buf);
    len_buf[0] = protocol::MSG_MULTISTREAM_1_0.len() as u8;
    let res = connec.write_all(&len_buf).await;
    let res = connec.write_all(protocol::MSG_MULTISTREAM_1_0).await;
    match res {
        Ok(()) => (),
        Err(e) => println!("write err:{:?}", e),
    }

    //negotiate protocol
    // fix me! how quit the negotiate when not match any protocol?
    loop {
        //receive remote proto
        let mut varint_buf: Vec<u8> = Vec::new();
        loop {
            connec.read_exact(&mut len_buf).await.unwrap();

            if len_buf[0] & 0x80 == 0 {
                varint_buf.push(len_buf[0]);
                break;
            } else {
                varint_buf.push(len_buf[0]& 0x7f);
            }
        }
        len = GetVarintLen(varint_buf);
        let mut read_buf = vec![0u8; len as usize];
        connec.read_exact(&mut read_buf).await.unwrap();
        let proto_name = std::str::from_utf8(&read_buf.to_owned()).unwrap().to_string();
        println!("rec proto:{}", proto_name.clone());
        if protocols.contains(&proto_name) {
            len_buf[0] = read_buf.len() as u8;
            let res = connec.write_all(&len_buf).await;
            let res = connec.write_all(&read_buf).await;
            match_proto.push(proto_name);
            break;
        }
        else {
            len_buf[0] = 3;
            let res = connec.write_all(&len_buf).await;
            let res = connec.write_all(&[0x6e, 0x61, 0xa]).await;
        }
    }
    Ok(match_proto)
}

#[test]
fn server_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
        let mut connec = listener.accept().await.unwrap().0;
        let res = listener_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/proto2\n".to_string()]).await;
        match res {
            Ok(protos) => {
                if protos.contains(&("/secio/1.0.0\n".to_string())) {
                    let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone()).await.unwrap();
                    let arc_reader = session_reader.socket.clone();
                    let arc_writer = session_writer.socket.clone();
                    listener_select_proto_secio(arc_reader, arc_writer, vec!["/yamux/1.0.0\n".to_string()]).await;
                    let (control_sender, control_receiver) = mpsc::channel(10);
                    let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone());
                    //   let period_send = period_send( control_sender);
                    let receive_process = session_reader.receive_loop( control_receiver);
                    let send_process = session_writer.send_process();
                    join!{receive_process, send_process, deal_remote_stream};//period_send,
                }
            },
            Err(e) => println!("err:{}","not match protocol".to_string()),
        }
        loop {
            let mut read_buf = vec![0u8; 10];
            let res = connec.read_exact(&mut read_buf).await;

            println!("res:{:?},receive:{:?}", res, read_buf);
        }
    })
}