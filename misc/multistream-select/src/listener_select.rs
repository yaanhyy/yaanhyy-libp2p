use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite};
use crate::protocol;
use super::GetVarintLen;
use secio::config::SecioConfig;
use secio::handshake::handshake;
use secio::identity::Keypair;
use futures::future::Future;
use futures::{future, select, join};
use futures::{channel::{mpsc, oneshot}};
use yamux::session::{SecioSessionWriter, SecioSessionReader};
use yamux::Config;
use yamux::frame::Frame;
use yamux::session::{Mode, ControlCommand, StreamCommand};
use yamux::session::{get_stream, open_stream};
use futures::prelude::*;
use async_std::task;
use std::time::Duration;
use utils::init_log;

pub async fn listener_secio_select_proto() ->Vec<String> {
    let mut match_proto = Vec::new();
    match_proto.push("no proto".to_string());
    match_proto
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
    loop {
        let res = get_stream(1, sender.clone()).await;
        if let Ok(mut stream)= res{
            if !stream.cache.is_empty() {
                let data: Vec<u8> = stream.cache.drain(4..).collect();
                let mut len_buf = [0u8;4];
                len_buf.copy_from_slice(stream.cache.as_slice());
                let len = u32::from_be_bytes(len_buf);
                println!("chache len:{}", len);

            }
            let mut data_receiver = stream.data_receiver.unwrap();
            task::spawn(async move {
                loop {
                    let buf = data_receiver.next().await;
                    println!("remote send receive:{:?}", buf);
                }
            });
            break;
        } else {
            //println!("get_stream fail :{:?}", res);
        }
        task::sleep(Duration::from_secs(1)).await;

    }
}

pub async fn listener_select_proto<S>(mut connec: S, protocols: Vec<String>) -> Vec<String>
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
    println!("buf_len:{},buf:{:?}", len, read_buf);
    len_buf[0] = protocol::MSG_MULTISTREAM_1_0.len() as u8;
    let res = connec.write_all(&len_buf).await;
    let res = connec.write_all(protocol::MSG_MULTISTREAM_1_0).await;
    match res {
        Ok(()) => (),
        Err(e) => println!("write err:{:?}", e),
    }


    //negotiate protocol


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

            let key1 = Keypair::generate_ed25519();
            let mut config = SecioConfig::new(key1);
            let mut res = handshake(connec.clone(), config).await;
            match res {
                Ok((mut secure_conn_writer, mut secure_conn_reader) ) => {
                    let mut data = secure_conn_reader.read().await.unwrap();

                    let mut varint_buf: Vec<u8> = Vec::new();
                    loop {
                        let item = data.remove(0);

                        if item & 0x80 == 0 {
                            varint_buf.push(item);
                            break;
                        } else {
                            varint_buf.push(item& 0x7f);
                        }
                    }
                    len = GetVarintLen(varint_buf);
                    let mut rest: Vec<_> = data.drain((len as usize)..).collect();
                    let proto = std::str::from_utf8(&data).unwrap().to_string();
                    println!("rec proto:{:?}", proto);

                    let mut varint_buf: Vec<u8> = Vec::new();
                    loop {
                        let item = rest.remove(0);

                        if item & 0x80 == 0 {
                            varint_buf.push(item);
                            break;
                        } else {
                            varint_buf.push(item& 0x7f);
                        }
                    }
                    len = GetVarintLen(varint_buf);
                    let mut tail: Vec<_> = rest.drain((len as usize)..).collect();
                    let proto = std::str::from_utf8(&rest).unwrap().to_string();
                    println!("rec proto:{:?}", proto);
                    len_buf[0] = rest.len() as u8;
                    let res = secure_conn_writer.send(& mut len_buf.to_vec()).await;
                    let res = secure_conn_writer.send(& mut rest).await;
//                    let mut data = secure_conn_reader.read().await.unwrap();
//                    println!("buf: {:?}", data);
                    let (control_sender, control_receiver) = mpsc::channel(10);
                    let (stream_sender, stream_receiver) = mpsc::channel(10);
                    let mut session_reader = SecioSessionReader::new(secure_conn_reader, Config::default(), Mode::Server,  stream_sender);
                    let mut session_writer = SecioSessionWriter::new(secure_conn_writer, stream_receiver);
                    let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone());
                 //   let period_send = period_send( control_sender);
                    let receive_process = session_reader.receive_loop( control_receiver);
                    let send_process = session_writer.send_process();
                    join!{receive_process, send_process,  deal_remote_stream};//period_send,


                },
                Err(e) => println!("res:{:?}", e),
            }
            break;
        } //else if  proto_name.eq("/secio/1.0.0\n") {

        //}
        else {
            len_buf[0] = 3;
            let res = connec.write_all(&len_buf).await;
            let res = connec.write_all(&[0x6e, 0x61, 0xa]).await;
        }
    }


    match_proto
}

#[test]
fn server_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
        let mut connec = listener.accept().await.unwrap().0;
        let res = listener_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/proto2\n".to_string()]).await;
        println!("res:{:?}", res);
        loop {
            let mut read_buf = vec![0u8; 10];
            let res = connec.read_exact(&mut read_buf).await;

            println!("res:{:?},receive:{:?}", res, read_buf);
        }
    })
}