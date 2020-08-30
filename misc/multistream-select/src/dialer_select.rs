use futures::prelude::*;
use utils::{init_log, get_conn_varint_var};
use crate::protocol::{get_varint_len, split_length_from_package, MSG_MULTISTREAM_1_0, upgrade_secio_protocol, get_conn_varint_len};
use yamux::session::{Mode, ControlCommand, StreamCommand};
use std::sync::{Arc};
use async_std::sync::Mutex;
use secio::codec::{SecureHalfConnWrite, SecureHalfConnRead};
use futures::{channel::{mpsc, oneshot}};
use futures::{future, select, join};
use crate::listener_select::remote_stream_deal;
use secio::identity::Keypair;
use noise::io::NoiseOutput;
use noise::handshake::{rt15_initiator, rt15_responder, IdentityExchange};
use mplex::MultiplexInner;
use mplex::{send_frame, receive_frame};

pub async fn dialer_select_proto<S>(mut connec: S, protocols: Vec<String>, init_flag: bool) -> Result<Vec<u8>, String>
where S: AsyncRead + AsyncWrite + Send + Unpin + 'static + std::clone::Clone
{
    let mut len_buf = [0u8; 1];
    let mut read_buf = Vec::new();
    //send MULTISTREAM
    if init_flag {

        len_buf[0] = MSG_MULTISTREAM_1_0.len() as u8;
        let res = connec.write_all(&len_buf).await;
        let res = connec.write_all(MSG_MULTISTREAM_1_0).await;

        read_buf = get_conn_varint_len(connec.clone()).await;

        let proto_name = std::str::from_utf8(&read_buf.to_owned()).unwrap().to_string();
        println!("proto:{:?}", proto_name);
        if !read_buf.eq(&MSG_MULTISTREAM_1_0.to_vec()) {
            return Err("remote not agree for MULTISTREAM protocol".to_string());
        }
    }
    //send protocol for negotiate
    for mut proto in protocols {
        len_buf[0] = proto.len() as u8;
        let res = connec.write_all(&len_buf).await;
        let res = connec.write_all(&proto.as_bytes()).await;
        read_buf =  get_conn_varint_len(connec.clone()).await;

        let proto_name = std::str::from_utf8(&read_buf.to_owned()).unwrap().to_string();
        println!("proto:{:?}", proto_name);
        if read_buf.eq(&proto.as_bytes().to_vec()) {
            return Ok(read_buf)
        }
    }

    Err("not match".to_string())
}

pub async fn dialer_select_proto_secio<R, W>(mut reader: Arc<Mutex<SecureHalfConnRead<R>>>, mut writer: Arc<Mutex<SecureHalfConnWrite<W>>>, protocols: Vec<String>) -> Result<String, String>
    where R: AsyncRead + Send + Unpin + 'static, W: AsyncWrite + Send + Unpin + 'static
{
    let mut len_buf = [0u8; 1];
    len_buf[0] = MSG_MULTISTREAM_1_0.len() as u8;
    let res = (*writer.lock().await).send(&mut len_buf.to_vec()).await;
    let res = (*writer.lock().await).send(&mut MSG_MULTISTREAM_1_0.to_vec()).await;


    let mut data =  (*reader.lock().await).read().await.unwrap();
    println!("data:{:?}",data);
    let (mut data, varint_buf) = split_length_from_package(data);
    let mut len = get_varint_len(varint_buf);
    let mut rest: Vec<_> = data.drain((len as usize)..).collect();
    let proto = std::str::from_utf8(&data).unwrap().to_string();
    println!("proto:{:?}", proto);
    if  !data.eq(&MSG_MULTISTREAM_1_0.to_vec()) {
        return Err("remote not agree for MULTISTREAM protocol".to_string());
    }


    //send protocol for negotiate
    for mut proto in protocols {
        len_buf[0] = proto.len() as u8;
        let res = (*writer.lock().await).send(&mut len_buf.to_vec()).await;
        let res = (*writer.lock().await).send(&mut proto.as_bytes().to_vec()).await;

        let mut data = (*reader.lock().await).read().await.unwrap();
        let (mut data, varint_buf) = split_length_from_package(data);
        let mut len = get_varint_len(varint_buf);
        let mut rest: Vec<_> = data.drain((len as usize)..).collect();
        let return_proto = std::str::from_utf8(&data).unwrap().to_string();
        println!("secio rec proto:{:?}", proto);
        if return_proto.eq(&proto) {
            return Ok(proto)
        }
    }

    Err("not match proto".to_string())
}


pub async fn dialer_select_proto_noise<T>(mut io: Arc<Mutex<NoiseOutput<T>>>, protocols: Vec<String>) -> Result<String, String>
    where T: AsyncWrite + AsyncRead + Send + Unpin + 'static
{
    let mut len_buf = [0u8; 1];
    len_buf[0] = MSG_MULTISTREAM_1_0.len() as u8;
    let res = (*io.lock().await).send(&mut len_buf.to_vec()).await;
    let res = (*io.lock().await).send(&mut MSG_MULTISTREAM_1_0.to_vec()).await;


    let mut data =  (*io.lock().await).read().await.unwrap();
    println!("data:{:?}",data);
    let (mut data, varint_buf) = split_length_from_package(data);
    let mut len = get_varint_len(varint_buf);
    let mut rest: Vec<_> = data.drain((len as usize)..).collect();
    let proto = std::str::from_utf8(&data).unwrap().to_string();
    println!("proto:{:?}", proto);
    if  !data.eq(&MSG_MULTISTREAM_1_0.to_vec()) {
        return Err("remote not agree for MULTISTREAM protocol".to_string());
    }


    //send protocol for negotiate
    for mut proto in protocols {
        len_buf[0] = proto.len() as u8;
        let res = (*io.lock().await).send(&mut len_buf.to_vec()).await;
        let res = (*io.lock().await).send(&mut proto.as_bytes().to_vec()).await;

        let mut data = (*io.lock().await).read().await.unwrap();
        let (mut data, varint_buf) = split_length_from_package(data);
        let mut len = get_varint_len(varint_buf);
        let mut rest: Vec<_> = data.drain((len as usize)..).collect();
        let return_proto = std::str::from_utf8(&data).unwrap().to_string();
        println!("noise rec proto:{:?}", proto);
        if return_proto.eq(&proto) {
            return Ok(proto)
        } else {
            println!("remote proto:{:?}", return_proto);
        }
    }

    Err("not match proto".to_string())
}


pub async fn dialer_select_proto_yamux() {

}

#[test]
fn ping_client_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let connec = async_std::net::TcpStream::connect("95.146.89.52:13000").await.unwrap();
        let match_proto = dialer_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string()], true).await;
        if match_proto.is_ok() {
            let local_key = Keypair::generate_ed25519();
            //let local_peer_id = PeerId::from(local_key.public());
            let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), local_key, Mode::Client).await.unwrap();
            let arc_reader = session_reader.socket.clone();
            let arc_writer = session_writer.socket.clone();
            let res = dialer_select_proto_secio(arc_reader, arc_writer, vec!["/yamux/1.0.0\n".to_string()]).await;
            if res.is_ok() {
                let (control_sender, control_receiver) = mpsc::channel(10);
                let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone());
                //let period_send = period_send( control_sender);
                let receive_process = session_reader.receive_loop( control_receiver);
                let send_process = session_writer.send_process();
                join!{receive_process, send_process, deal_remote_stream};//period_send
            }
        }

    })
}


#[test]
fn noise_client_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let connec = async_std::net::TcpStream::connect("172.18.11.36:9000").await.unwrap();
        let match_proto = dialer_select_proto(connec.clone(), vec!["/noise\n".to_string()], true).await;
        if match_proto.is_ok() {
            let proto = match_proto.unwrap();
            if proto.eq(&"/noise\n".as_bytes().to_vec()) {
                let local_key = Keypair::generate_ed25519();
                let client_dh = noise::protocol::Keypair::new().into_authentic(&local_key).unwrap();
                let config = noise::NoiseConfig::xx(client_dh);
                let session = config.params.into_builder()
                    .local_private_key(config.dh_keys.secret().as_ref())
                    .build_initiator()
                    .map_err(|_| "NoiseError::from".to_string());
                if let Ok(state) = session {
                    let res = rt15_initiator(connec.clone(), state, config.dh_keys.into_identity(), IdentityExchange::Mutual).await;
                    if let Ok((remote, mut noise_io)) = res {
                        println!("send msg");
                        let res = dialer_select_proto_noise(noise_io.clone(), vec!["/mplex/6.7.0\n".to_string()]).await;
                        println!("proto:{:?}", res);

                    }
                }
            }
        }

    })
}

#[test]
fn mplex_client_test() {
    async_std::task::block_on(async move {
        let connec = async_std::net::TcpStream::connect("172.18.11.36:9000").await.unwrap();
        let match_proto = dialer_select_proto(connec.clone(), vec!["/noise\n".to_string(),"/secio/1.0.0\n".to_string(), "/yamux/1.0.0\n".to_string()], true).await;
        match match_proto {
            Ok(protos) => {
                let local_key = Keypair::generate_ed25519();
                //let local_peer_id = PeerId::from(local_key.public());
                let client_dh = noise::protocol::Keypair::new().into_authentic(&local_key).unwrap();
                let config = noise::NoiseConfig::xx(client_dh);
                let session = config.params.into_builder()
                    .local_private_key(config.dh_keys.secret().as_ref())
                    .build_initiator()
                    .map_err(|_|"NoiseError::from".to_string());
                if let Ok(state) = session {
                    let res = rt15_initiator(connec.clone(), state, config.dh_keys.into_identity(), IdentityExchange::Mutual).await;
                    if let Ok((remote, mut noise_io)) = res {
                        println!("send msg");
                        let res = dialer_select_proto_noise(noise_io.clone(), vec!["/mplex/6.7.0\n".to_string()]).await;
                        loop {
                            let res =  receive_frame(noise_io.clone()).await;

                            if res.is_ok() {
                                println!("res:{:?}", res);
                                let elem = res.unwrap();
                                if (elem.is_open_msg() || elem.is_close_or_reset_msg()) {

                                } else {
                                    if() {
                                        send_frame(noise_io.clone(), elem).await;
                                    }
                                }

                            }
                        }
                        //open_stream();

                    }
                }
                loop {

                }

            },
            Err(e) => println!("err:{}","not match protocol".to_string()),
        }
    });
}