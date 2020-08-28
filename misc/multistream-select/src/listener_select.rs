use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite};
use crate::protocol::{get_varint_len, split_length_from_package, MSG_MULTISTREAM_1_0, upgrade_secio_protocol, get_conn_varint_len};
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
use noise::io::NoiseOutput;

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

pub async fn listener_select_proto_secio<R, W>(mut reader: Arc<Mutex<SecureHalfConnRead<R>>>, mut writer: Arc<Mutex<SecureHalfConnWrite<W>>>, protocols: Vec<String>) -> Result<String, String>
where R: AsyncRead + Send + Unpin + 'static, W: AsyncWrite + Send + Unpin + 'static
{
    let mut data = (*reader.lock().await).read().await.unwrap();
    let (mut data, varint_buf) = split_length_from_package(data);
    let mut len = get_varint_len(varint_buf);
    let mut rest: Vec<_> = data.drain((len as usize)..).collect();
    let proto = std::str::from_utf8(&data).unwrap().to_string();
    println!("secio rec proto:{:?}", proto);

    if !data.eq(&MSG_MULTISTREAM_1_0.to_vec()) {
        return Err("listener_select_proto_secio MULTISTREAM not match".to_string());
    }

    let mut len_buf = [0u8; 1];
    //len_buf[0] = protocol::MSG_MULTISTREAM_1_0.len() as u8;
   // let res = (*writer.lock().await).send(& mut len_buf.to_vec()).await;
   // let res = (*writer.lock().await).send(& mut data).await;
    loop {
        if rest.is_empty() {
            data = (*reader.lock().await).read().await.unwrap();
        } else {
            data = rest;
        }
        let (mut data, varint_buf) = split_length_from_package(data);
        len = get_varint_len(varint_buf);
        rest = data.drain((len as usize)..).collect();
        let proto = std::str::from_utf8(&data.clone()).unwrap().to_string();
        println!("secio rec proto:{:?}", proto);
        if protocols.contains(&proto) {
            len_buf[0] = data.len() as u8;
            println!("yamux len:{:?}", len_buf);
            let res = (*writer.lock().await).send(&mut len_buf.to_vec()).await;
            println!("send yamux:{:?}", data);
            let res = (*writer.lock().await).send(&mut data).await;

            return Ok(proto)
        }
    }
    Err("not match proto".to_string())
}

pub async fn listener_select_proto<S>(mut connec: S, protocols: Vec<String>) -> Result<String, String>
 where S: AsyncRead + AsyncWrite + Send + Unpin + 'static + std::clone::Clone
{

    let mut read_buf =  get_conn_varint_len(connec.clone()).await;

    let proto_name = std::str::from_utf8(&read_buf.to_owned()).unwrap().to_string();
    if !read_buf.eq(&MSG_MULTISTREAM_1_0.to_vec()) {
        return Err("MULTISTREAM not match".to_string());
    }
    println!("buf_len:{},buf:{:?}", read_buf.len(), read_buf);
    let mut len_buf = [0u8; 1];
    len_buf[0] = MSG_MULTISTREAM_1_0.len() as u8;
    let res = connec.write_all(&len_buf).await;
    let res = connec.write_all(MSG_MULTISTREAM_1_0).await;
    match res {
        Ok(()) => (),
        Err(e) => println!("write err:{:?}", e),
    }

    //negotiate protocol
    // fix me! how quit the negotiate when not match any protocol?
    loop {
        //receive remote proto
        read_buf =  get_conn_varint_len(connec.clone()).await;

        let proto_name = std::str::from_utf8(&read_buf.to_owned()).unwrap().to_string();
        println!("rec proto:{}", proto_name.clone());
        if protocols.contains(&proto_name) {
            len_buf[0] = read_buf.len() as u8;
            let res = connec.write_all(&len_buf).await;
            let res = connec.write_all(&read_buf).await;
            return Ok(proto_name);
        }
        else {
            len_buf[0] = 3;
            let res = connec.write_all(&len_buf).await;
            let res = connec.write_all(&[0x6e, 0x61, 0xa]).await;
        }
    }
    Err("not match".to_string())
}


pub async fn listener_select_proto_noise<T>(mut io: Arc<Mutex<NoiseOutput<T>>>, protocols: Vec<String>) -> Result<String, String>
    where T: AsyncWrite + AsyncRead + Send + Unpin + 'static
{
    let mut data = (*io.lock().await).read().await.unwrap();
    let (mut data, varint_buf) = split_length_from_package(data);
    let mut len = get_varint_len(varint_buf);
    let mut rest: Vec<_> = data.drain((len as usize)..).collect();
    let proto = std::str::from_utf8(&data).unwrap().to_string();
    println!("secio rec proto:{:?}", proto);

    if !data.eq(&MSG_MULTISTREAM_1_0.to_vec()) {
        return Err("listener_select_proto_secio MULTISTREAM not match".to_string());
    }

    let mut len_buf = [0u8; 1];
    //len_buf[0] = protocol::MSG_MULTISTREAM_1_0.len() as u8;
    // let res = (*writer.lock().await).send(& mut len_buf.to_vec()).await;
    // let res = (*writer.lock().await).send(& mut data).await;
    loop {
        if rest.is_empty() {
            data = (*io.lock().await).read().await.unwrap();
        } else {
            data = rest;
        }
        let (mut data, varint_buf) = split_length_from_package(data);
        len = get_varint_len(varint_buf);
        rest = data.drain((len as usize)..).collect();
        let proto = std::str::from_utf8(&data.clone()).unwrap().to_string();
        println!("noise rec proto:{:?}", proto);
        if protocols.contains(&proto) {
            len_buf[0] = data.len() as u8;
            println!("yamux len:{:?}", len_buf);
            let res = (*io.lock().await).send(&mut len_buf.to_vec()).await;
            println!("send yamux:{:?}", data);
            let res = (*io.lock().await).send(&mut data).await;

            return Ok(proto)
        }
    }
    Err("not match proto".to_string())
}

pub async fn remote_stream_deal(mut frame_sender: mpsc::Sender<StreamCommand>, mut sender: mpsc::Sender<ControlCommand>) {
    let res = subscribe_stream(sender.clone()).await;
    let mut  stream_protocol_flag = false;
    if let Ok(mut stream)= res{
        loop {
            let mut stream = stream.next().await.unwrap();
            stream_protocol_flag = false;
            if !stream.cache.is_empty() {
                let mut  data: Vec<u8> = stream.cache.drain(4..).collect();
                let mut len_buf = [0u8;4];
                len_buf.copy_from_slice(stream.cache.as_slice());
                let len = u32::from_be_bytes(len_buf);

                let ping_proto: Vec<u8> = data.drain(20..).collect();
                let out = std::str::from_utf8(&data.clone()).unwrap().to_string();
                let out1 = std::str::from_utf8(&ping_proto.clone()).unwrap().to_string();
                println!("cache len:{}, buf:{:?},ping:{:?}", len, out, out1);


                let len:u8 = MSG_MULTISTREAM_1_0.len() as u8;
                data.clear();
                data.push(len);
                data.append(& mut MSG_MULTISTREAM_1_0.to_vec()) ;

                let mut stream_clone = stream.clone();
                let frame = Frame::data(stream_clone.id(), data).unwrap();
                stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                let frame = Frame::data(stream_clone.id(), ping_proto).unwrap();
                stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                stream_protocol_flag = true;
                //let mut stream_spawn = stream.clone();
            }
            let mut stream_spawn = stream.clone();
            let mut data_receiver = stream.data_receiver.unwrap();

            task::spawn(async move {

                //  loop {
                let mut buf = None;
                if !stream_protocol_flag {
                    stream_protocol_flag = true;
                    buf = data_receiver.next().await;
                    let (mut data, varint_buf) = split_length_from_package(buf.clone().unwrap());
                    let mut len = get_varint_len(varint_buf);
                    println!("remote send receive1:{:?}", buf.clone());
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
                    println!("remote send receive2:{:?}", buf);
                }
                buf = data_receiver.next().await;
                println!("remote send receive3:{:?}", buf.clone());

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

#[test]
fn ping_server_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
        let mut connec = listener.accept().await.unwrap().0;
        let res = listener_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/proto2\n".to_string()]).await;
        match res {
            Ok(protos) => {
                if protos.contains(&("/secio/1.0.0\n".to_string())) {
                    let local_key = Keypair::generate_ed25519();
                    let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), local_key, Mode::Server).await.unwrap();
                    let arc_reader = session_reader.socket.clone();
                    let arc_writer = session_writer.socket.clone();
                    listener_select_proto_secio(arc_reader, arc_writer, vec!["/yamux/1.0.0\n".to_string()]).await;
                    let (control_sender, control_receiver) = mpsc::channel(10);
                    let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone());
                    //   let period_send = period_send( control_sender);
                    let receive_process = session_reader.receive_loop( control_receiver);
                    let send_process = session_writer.send_process();
                    join!{receive_process, send_process, deal_remote_stream};//period_send
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

#[test]
fn mplex_server_test() {
    async_std::task::block_on(async move {
        let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
        let mut connec = listener.accept().await.unwrap().0;
        let res = listener_select_proto(connec.clone(), vec!["/mplex/6.7.0\n".to_string(), "/proto2\n".to_string()]).await;
        match res {
            Ok(protos) => {
                println!("protocol:{:?}", protos);
                let mut len_buf = [0u8; 1];
                let mut varint_buf: Vec<u8> = Vec::new();
                let mut len = 0;
                loop {
                    connec.read_exact(&mut len_buf).await.unwrap();
                    len = len + 1;
                    println!("rec index:{}:{:?}", len, len_buf);
                }

            },
            Err(e) => println!("err:{}","not match protocol".to_string()),
        }
    });
}