use futures::prelude::*;
use utils::{init_log, write_varint, insert_frame_len};
use multistream_select::protocol::{get_varint_len, split_length_from_package, MSG_MULTISTREAM_1_0, upgrade_secio_protocol, get_conn_varint_len};
use std::sync::{Arc};
use async_std::sync::Mutex;
use secio::codec::{SecureHalfConnWrite, SecureHalfConnRead};
use secio::identity::{ PublicKey, ed25519::SecretKey};
use secio::identity as secio_identity;
use secio::peer_id::PeerId;
use futures::{channel::{mpsc, oneshot}};
use futures::{future, select, join};
use multistream_select::dialer_select::{dialer_select_proto_secio, dialer_select_proto};
use multistream_select::listener_select::{listener_select_proto, listener_select_proto_secio};
use identity::structs::Identify;
use prost::Message;
use multiaddr::{Multiaddr ,multiaddr };
use multiaddr::Protocol::*;
use std::{
    borrow::Cow,
    convert::{TryFrom, From},
    iter::FromIterator,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::{Duration, Instant}
};
use secio::identity::Keypair;
use yamux::Config;
use yamux::frame::Frame;
use yamux::session::{Mode, ControlCommand, StreamCommand};
use yamux::session::{get_stream, open_stream, subscribe_stream};
use futures::prelude::*;
use async_std::task;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use identity::protocol::IdentifyInfo;
use std::{io, iter};
use std::process::id;
use async_std::net::UdpSocket;
use sha2::{Digest, Sha256};
use enr::NodeId;
use crate::packet::{Tag, TAG_LENGTH};

pub async fn tcp_multistream() {
    let mut  connec = async_std::net::TcpStream::connect("176.9.51.216:23500").await.unwrap();
    //  let mut  connec = async_std::net::TcpStream::connect("127.0.0.1:5679").await.unwrap();
    let mut  local_addr: std::net::SocketAddr = connec.local_addr().unwrap();
    println!("localaddr:{:?}", local_addr);
    let addr = format!("/ip4/{}/tcp/{}",local_addr.ip().to_string() ,local_addr.port());
    println!("addr:{:?}", addr);
    //let mut local_addr = addr.parse().unwrap();
    //  let mut local_addr = multiaddr!(local_addr.ip(), Tcp(local_addr.port() as u16));
    let match_proto = dialer_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/yamux/1.0.0\n".to_string()], true).await;
    if match_proto.is_ok() {
        let proto = match_proto.unwrap();
        if proto.eq(&"/secio/1.0.0\n".as_bytes().to_vec()) {
            //let local_key = Keypair::generate_ed25519();
            let local_secret_key = SecretKey::from_bytes(vec![11u8; 32]).unwrap();
            let rar_key = secio_identity::ed25519::Keypair::from(local_secret_key);
            let local_key = Keypair::Ed25519( rar_key.clone());
            let random_bytes = rar_key.public().encode();
            let mh1 = multihash::Sha2_256::digest(&random_bytes);
            let node_id = PeerId::try_from(mh1).unwrap();
            println!("node_id:{:?}", node_id);
            let local_peer_id = PeerId::from(local_key.public());
            println!("local_id:{:?}", local_peer_id);



            let retmoe_secret_key = SecretKey::from_bytes(vec![55u8; 32]).unwrap();
            let rar_key_retmoe = secio_identity::ed25519::Keypair::from(retmoe_secret_key);
            let retmoe_key = Keypair::Ed25519( rar_key_retmoe.clone());
            let random_bytes = rar_key_retmoe.public().encode();
            let mh1 = multihash::Sha2_256::digest(&random_bytes);
            let node_id_remote = PeerId::try_from(mh1).unwrap();

            let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), local_key.clone(),Mode::Client).await.unwrap();
            let arc_reader = session_reader.socket.clone();
            let arc_writer = session_writer.socket.clone();
            let res = dialer_select_proto_secio(arc_reader.clone(), arc_writer.clone(), vec!["/yamux/1.0.0\n".to_string()]).await;
            if res.is_ok() {
                println!("into yamux");
//                    let (control_sender, control_receiver) = mpsc::channel(10);
//                    let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone(), local_peer_id.clone(), local_key.clone(), local_addr);
//                    let period_send = period_send_1( control_sender,local_peer_id ,local_key, retmoe_key);
//                    let receive_process = session_reader.receive_loop( control_receiver);
//                    let send_process = session_writer.send_process();
//                    join!{receive_process, send_process, deal_remote_stream, period_send};//
            }
        }
    }
}


fn tag(src_id: &NodeId, dst_id: &NodeId) -> Tag {
    let hash = Sha256::digest(&dst_id.raw());
    let mut tag: Tag = Default::default();
    for i in 0..TAG_LENGTH {
        tag[i] = hash[i] ^ src_id.raw()[i];
    }
    tag
}

#[cfg(test)]
mod tests {
    use utils::{init_log, write_varint, insert_frame_len};
    use async_std::net::UdpSocket;
    use crate::rpc::{Message, Request, RequestBody};
    use enr::{Enr, secp256k1::SecretKey, CombinedKey};
    use crate::packet::{Magic, Packet};
    use hex;
    use super::tag;
    use hex_literal::*;
    use sha2::{Digest, Sha256};
    use crate::handler::Handler;
    use std::{collections::HashMap, default::Default, net::SocketAddr, sync::atomic::Ordering};
    use crate::node_info::NodeAddress;
    use crate::session::Session;
    use log::error;
    use std::sync::Arc;
    use core::borrow::Borrow;

    #[test]
    fn discv5_client_test() {
        init_log("trace");
        async_std::task::block_on(async move {
            let res = UdpSocket::bind("0.0.0.0:0").await;
            if let Ok(socket) = res {
                let remote_enr_str = "enr:-IS4QDOKuguplQtow8zjKEDXvzqT4K5XUjzZtmvluM8POGOVXP-euJjRnEEh8LMFXONBlJwfui5g_ehd5npZ0ZuDQksBgmlkgnY0gmlwhAAAAACJc2VjcDI1NmsxoQKtB3pwsjc32gv9KR9HY_3QI5Fjf6_aM-bjqUyrUHKZH4N1ZHCCIyg";
               // let remote_enr_str = "enr:-Ku4QJsxkOibTc9FXfBWYmcdMAGwH4bnOOFb4BlTHfMdx_f0WN-u4IUqZcQVP9iuEyoxipFs7-Qd_rH_0HfyOQitc7IBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhLAJM9iJc2VjcDI1NmsxoQL2RyM26TKZzqnUsyycHQB4jnyg6Wi79rwLXtaZXty06YN1ZHCCW8w";
                //let remote_enr: Enr<SecretKey> = remote_enr_str.to_string().parse().unwrap();
                let remote_enr: Enr<CombinedKey> = remote_enr_str.to_string().parse().unwrap();

                // construct a local ENR
                // A fixed key for testing
                let raw_key = hex!("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
                let secret_key = secp256k1::SecretKey::parse_slice(&raw_key).unwrap();
                let mut enr_key = Arc::new(enr::CombinedKey::from(secret_key));

                let local_addr: SocketAddr = socket.local_addr().unwrap();
                println!("local addr:{:?}", local_addr);
                let enr = {
                    let mut builder = enr::EnrBuilder::new("v4");
                    // if an IP was specified, use it
                    builder.ip(local_addr.ip() );
                    // if a port was specified, use it
                    builder.udp(local_addr.port());
                    builder.build(&enr_key.borrow()).unwrap()
                };
                //let addr = "176.9.51.216:25578";
                //let addr = "127.0.0.1:9000";
                let id = 1;
                let distance = 256;
                let message = Message::Request(Request {
                    id,
                    body: RequestBody::FindNode { distance },
                });

                let magic = {
                    let mut hasher = Sha256::new();
                    hasher.input(enr.node_id().raw());
                    hasher.input(b"WHOAREYOU");
                    let mut magic: Magic = Default::default();
                    magic.copy_from_slice(&hasher.result());
                    magic
                };

                let local_id = enr.node_id();
                let mut remote_id = remote_enr.node_id();

                let tag = tag(&local_id, &remote_id);

//                let packet = {
//                    if let Some(session) = self.sessions.get(&node_address) {
//                        // Encrypt the message and send
//                        session
//                            .encrypt_message(tag, &request.clone().encode())
//                            .map_err(|e| RequestError::EncryptionFailed(format!("{:?}", e)))?
//                    } else {
//                        // No session exists, start a new handshake
//                        trace!(
//                            "Starting session. Sending random packet to: {}",
//                            node_address
//                        );
//                        Packet::random(tag)
//                    }
//                };

                let mut handler = Handler {enr: enr.clone(), key: enr_key, node_id: local_id, active_requests_auth: HashMap::new()};
                let packet = Packet::random(tag);
                println!("remote addr:{:?}", remote_enr.udp());
                let send = socket.send_to(&packet.encode(), &remote_enr.udp_socket().unwrap().to_string()).await;
                if let Ok(send) = send {
                    println!("Sent {} bytes to {:?}", send, remote_enr.udp_socket());
                    let mut recv_buffer = [0u8; 1024];
                    let (n, peer) = socket.recv_from(&mut recv_buffer).await.unwrap();
                    let resp = Packet::decode(&recv_buffer[..n], &magic).unwrap();
                    let auth_tag = packet.auth_tag().expect("No challenges here");

                    let remote_addr = NodeAddress {
                        node_id: remote_id,
                        socket_addr: remote_enr.udp_socket().unwrap(),
                    };
                    handler.active_requests_auth.insert(*auth_tag, remote_addr);
                    println!("Received {} bytes from {}, resp: {:?}", n, peer, resp);


                    // Generate a new session and authentication packet
                    // TODO: Remove tags in the update
                    match resp {
                        Packet::WhoAreYou {magic, auth_tag ,id_nonce,enr_seq } => {
                            let (auth_packet, mut session) = match Session::encrypt_with_header(
                                tag,
                                &remote_id,
                                remote_enr.public_key(),
                                enr_key,
                                Some(remote_enr),
                                &local_id,
                                &id_nonce,
                                &[0,1,2]
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    error!("Could not generate a session. Error: {:?}", e);

                                    return;
                                }
                            };
                        },
                        _ => (),
                    }

                } else {
                    println!("udp send err:{:?}", send);
                }
            } else {
                println!("udp bind err:{:?}", res);
            }
        })
    }
}