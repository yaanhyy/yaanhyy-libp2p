use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite};
use crate::protocol;
use super::GetVarintLen;
use secio::config::SecioConfig;
use secio::handshake::handshake;
use secio::identity::Keypair;
use futures::future::Future;
use futures::{channel::{mpsc, oneshot}};
use yamux::session::{SecioSessionWriter, SecioSessionReader};
use yamux::Config;
use yamux::session::Mode;

pub async fn listener_secio_select_proto() ->Vec<String> {
    let mut match_proto = Vec::new();
    match_proto.push("no proto".to_string());
    match_proto
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
                    let mut data = secure_conn_reader.read().await.unwrap();
                    println!("buf: {:?}", data);
                    let (control_sender, control_receiver) = mpsc::channel(10);
                    let (stream_sender, stream_receiver) = mpsc::channel(10);
                    let mut session_reader = SecioSessionReader::new(secure_conn_reader, Config::default(), Mode::Client,  stream_sender);
                    let mut session_writer = SecioSessionWriter::new(secure_conn_writer, stream_receiver);
                    let res = session_reader.open_secio_stream().await;


                    if let Ok(id) = res {
                        session_writer.data_frame_send(id , "hello yamux".to_string().into_bytes()).await;
                        let mut msg = "ok".to_string();
                        println!("open_stream success");
                    } else {
                        println!("open_stream fail" );
                    }
                    // remote_frame_future.await;
                    //    let receive_local_frame_future = session.send_frame();
                    //   let broker = async_std::task::spawn(receive_local_frame_future);

                    session_reader.receive_loop(control_receiver).await;


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