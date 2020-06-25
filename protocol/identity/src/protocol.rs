use futures::prelude::*;
use utils::{init_log, write_varint};
use multistream_select::protocol::{get_varint_len, split_length_from_package, MSG_MULTISTREAM_1_0, upgrade_secio_protocol, get_conn_varint_len};
use yamux::session::{Mode, ControlCommand, StreamCommand};
use std::sync::{Arc};
use async_std::sync::Mutex;
use secio::codec::{SecureHalfConnWrite, SecureHalfConnRead};
use secio::identity::PublicKey;
use futures::{channel::{mpsc, oneshot}};
use futures::{future, select, join};
use multistream_select::dialer_select::{dialer_select_proto_secio, dialer_select_proto};
use multistream_select::listener_select::{listener_select_proto, listener_select_proto_secio};
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
use secio::identity as secio_identity;
use secio::identity::Keypair;
/// Information of a peer sent in `Identify` protocol responses.
#[derive(Debug, Clone)]
pub struct IdentifyInfo {
    /// The public key underlying the peer's `PeerId`.
    pub public_key: PublicKey,
    /// Version of the protocol family used by the peer, e.g. `ipfs/1.0.0`
    /// or `polkadot/1.0.0`.
    pub protocol_version: String,
    /// Name and version of the peer, similar to the `User-Agent` header in
    /// the HTTP protocol.
    pub agent_version: String,
    /// The addresses.rs that the peer is listening on.
    pub listen_addrs: Vec<Multiaddr>,
    /// The list of protocols supported by the peer, e.g. `/ipfs/ping/1.0.0`.
    pub protocols: Vec<String>,
}

pub fn identity_msg() {

}

#[test]
fn identity_client_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let mut  connec = async_std::net::TcpStream::connect("127.0.0.1:5679").await.unwrap();
        let match_proto = dialer_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/yamux/1.0.0\n".to_string()], true).await;
        if match_proto.is_ok() {
            let proto = match_proto.unwrap();
            if proto.eq(&"/secio/1.0.0\n".as_bytes().to_vec()) {
                let local_secret_key = secio_identity::secp256k1::SecretKey::from_bytes(vec![55u8; 32]).unwrap();
                let rar_key = secio_identity::secp256k1::Keypair::from(local_secret_key);
                let local_key = Keypair::Secp256k1( rar_key.clone());
                let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), local_key, Mode::Client).await.unwrap();
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
            let pubkey = PublicKey::from_protobuf_encoding(&identify_in.public_key.unwrap());
            for addr in identify_in.listen_addrs.iter_mut() {
//                let len = addr.len();
//                let mut array = [0u8; 100];
//                array.copy_from_slice(addr.as_slice());
                println!("addr:{:?}", addr);
                let multiaddr: Multiaddr= Multiaddr::try_from(addr.to_vec()).unwrap();
                println!("multiaddr:{:?}", multiaddr.to_string());
            }
            connec.read_exact(&mut read_buf).await.unwrap();
            println!("read_buf:{:?}", read_buf );
        }
    })
}

#[test]
fn identity_server_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
        let mut connec = listener.accept().await.unwrap().0;
        let match_proto = listener_select_proto(connec.clone(), vec!["/ipfs/id/1.0.0\n".to_string(), "/secio/1.0.0\n".to_string(), "/yamux/1.0.0\n".to_string()]).await;
        if match_proto.is_ok() {

            let proto = match_proto.unwrap();
            if proto.eq(&"/secio/1.0.0\n".to_string()) {
                let local_secret_key = secio_identity::secp256k1::SecretKey::from_bytes(vec![55u8; 32]).unwrap();
                let rar_key = secio_identity::secp256k1::Keypair::from(local_secret_key);
                let local_key = Keypair::Secp256k1( rar_key.clone());
                let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), local_key, Mode::Client).await.unwrap();
                let arc_reader = session_reader.socket.clone();
                let arc_writer = session_writer.socket.clone();
                let res = listener_select_proto_secio(arc_reader, arc_writer, vec!["/yamux/1.0.0\n".to_string()]).await;
                if res.is_ok() {
                    println!("into yamux");
//                let (control_sender, control_receiver) = mpsc::channel(10);
//                let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone());
//                //let period_send = period_send( control_sender);
//                let receive_process = session_reader.receive_loop( control_receiver);
//                let send_process = session_writer.send_process();
//                join!{receive_process, send_process, deal_remote_stream};//period_send
                }
            } else if proto.eq(&"/yamux/1.0.0\n".to_string()){
                // only support yamux
            } else if proto.eq(&"/ipfs/id/1.0.0\n".to_string()){
                let send_pubkey = secio::identity::Keypair::generate_ed25519().public();
                let info = IdentifyInfo {
                    public_key: send_pubkey,
                    protocol_version: "proto_version".to_owned(),
                    agent_version: "agent_version".to_owned(),
                    listen_addrs: vec![
                        "/ip4/80.81.82.83/tcp/500".parse().unwrap(),
                        "/ip6/::1/udp/1000".parse().unwrap(),
                    ],
                    protocols: vec!["proto1".to_string(), "proto2".to_string()],
                };

                let observed_addr: Multiaddr = "/ip4/100.101.102.103/tcp/5000".parse().unwrap();

                let listen_addrs = info.listen_addrs
                    .into_iter()
                    .map(|addr| addr.to_vec())
                    .collect();

                let pubkey_bytes = info.public_key.into_protobuf_encoding();

                let message = Identify {
                    agent_version: Some(info.agent_version),
                    protocol_version: Some(info.protocol_version),
                    public_key: Some(pubkey_bytes),
                    listen_addrs: listen_addrs,
                    observed_addr: Some(observed_addr.to_vec()),
                    protocols: info.protocols
                };
                let mut bytes = Vec::with_capacity(message.encoded_len());
                message.encode(&mut bytes).expect("Vec<u8> provides capacity as needed");
                write_varint(&mut connec, bytes.len()).await;
                connec.write_all(&bytes).await;
                connec.close().await;
            }
        }
    })
}