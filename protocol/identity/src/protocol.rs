use futures::prelude::*;
use utils::init_log;
use multistream_select::protocol::{get_varint_len, split_length_from_package, MSG_MULTISTREAM_1_0, upgrade_secio_protocol, get_conn_varint_len};
use yamux::session::{Mode, ControlCommand, StreamCommand};
use std::sync::{Arc};
use async_std::sync::Mutex;
use secio::codec::{SecureHalfConnWrite, SecureHalfConnRead};
use futures::{channel::{mpsc, oneshot}};
use futures::{future, select, join};
use multistream_select::dialer_select::{dialer_select_proto_secio, dialer_select_proto};
use crate::structs::Identify;
use prost::Message;
use parity_multiaddr::Multiaddr;
use parity_multiaddr::Protocol::*;
use std::{
    borrow::Cow,
    convert::TryFrom,
    iter::FromIterator,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr
};

#[test]
fn identity_client_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let mut  connec = async_std::net::TcpStream::connect("127.0.0.1:5679").await.unwrap();
        let match_proto = dialer_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/yamux/1.0.0\n".to_string()], true).await;
        if match_proto.is_ok() {
            let proto = match_proto.unwrap();
            if proto.eq(&"/secio/1.0.0\n".as_bytes().to_vec()) {
                let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), Mode::Client).await.unwrap();
                let arc_reader = session_reader.socket.clone();
                let arc_writer = session_writer.socket.clone();
                let res = dialer_select_proto_secio(arc_reader, arc_writer, vec!["/yamux/1.0.0\n".to_string()]).await;
                if res.is_ok() {
                    println!("into yamux");
//                let (control_sender, control_receiver) = mpsc::channel(10);
//                let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone());
//                //let period_send = period_send( control_sender);
//                let receive_process = session_reader.receive_loop( control_receiver);
//                let send_process = session_writer.send_process();
//                join!{receive_process, send_process, deal_remote_stream};//period_send
                }
            } else {
                // only support yamux
            }
        } else {
            //raw, match apply protocol
            let match_proto = dialer_select_proto(connec.clone(), vec!["/ipfs/id/1.0.0\n".to_string()], false).await;
            println!("match_proto:{:?}", match_proto);
            let mut read_buf = vec![0u8; 10];
            let res = get_conn_varint_len(connec.clone()).await;
            println!("res:{:?}", res);
            let mut  identify_in: Identify = match Identify::decode(&res[..]) {
                Ok(identify) => identify,
                Err(_) => {
                    println!("failed to parse remote's exchage protobuf message");
                    return (); //Err("failed to parse remote's exchange protobuf".to_string());
                }
            };
            println!("Identify:{:?}", identify_in );
            for addr in identify_in.listen_addrs.iter_mut() {
//                let len = addr.len();
//                let mut array = [0u8; 100];
//                array.copy_from_slice(addr.as_slice());
                println!("addr:{:?}", addr);
                let multiaddr: Multiaddr= bincode::deserialize(&addr.to_vec()).unwrap();
        //        println!("multiaddr:{:?}", std::str::from_utf8(addr).unwrap().parse::<Multiaddr>().unwrap());
            }
            connec.read_exact(&mut read_buf).await.unwrap();
            println!("read_buf:{:?}", read_buf );
        }
    })
}