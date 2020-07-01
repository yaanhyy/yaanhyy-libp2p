use futures::prelude::*;
use utils::{init_log, write_varint};
use multistream_select::protocol::{get_varint_len, split_length_from_package, MSG_MULTISTREAM_1_0, upgrade_secio_protocol, get_conn_varint_len};
use std::sync::{Arc};
use async_std::sync::Mutex;
use secio::codec::{SecureHalfConnWrite, SecureHalfConnRead};
use secio::identity::PublicKey;
use secio::peer_id::PeerId;
use futures::{channel::{mpsc, oneshot}};
use futures::{future, select, join};
use multistream_select::dialer_select::{dialer_select_proto_secio, dialer_select_proto};
use multistream_select::listener_select::{listener_select_proto, listener_select_proto_secio};
use identity::structs::Identify;
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
use secio::identity::Keypair;

use crate::gossipsub::{Rpc,ControlMessage, ControlGraft, ControlPrune, rpc::SubOpts};
use crate::gossipsub::Message as SubMessage;
use crate::topic::Topic;
use yamux::Config;
use yamux::frame::Frame;
use yamux::session::{Mode, ControlCommand, StreamCommand};
use yamux::session::{get_stream, open_stream, subscribe_stream};
use futures::prelude::*;
use async_std::task;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use identity::protocol::IdentifyInfo;
use super::version;
use crate::topic_eth2::{GossipTopic, GossipKind, GossipEncoding};

pub const MSG_MESHSUB_1_0: &[u8] = b"/meshsub/1.0.0\n";

/// A type for gossipsub message ids.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageId(pub String);

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Into<String> for MessageId {
    fn into(self) -> String {
        self.0.into()
    }
}

fn message_id(data: Vec<u8>) -> MessageId {
    let mut s = DefaultHasher::new();
    data.hash(&mut s);
    MessageId(s.finish().to_string())
}


pub fn publish(local_peer_id: PeerId, topic: String, data: Vec<u8>) -> Rpc{
    let mut  rpc_in: Rpc =  Rpc {
        subscriptions: vec![
            SubOpts{
                subscribe: Some(true),
                topic_id: Some("test-net".to_string())
            }
        ],
        publish: Vec::new(),
        control: None,
    };
    let seqence: u64 = rand::random();
    let msg = SubMessage{
        from: Some(local_peer_id.clone().into_bytes()),
        data: Some(data),
        seqno: Some(seqence.to_be_bytes().to_vec()),
        topic_ids: vec!["test-net".to_string()]
    };
    rpc_in.publish.push(msg);
    rpc_in
}

pub async fn remote_stream_deal(mut frame_sender: mpsc::Sender<StreamCommand>, mut sender: mpsc::Sender<ControlCommand>, local_peer_id: PeerId) {
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

                let mut buf = None;
                // not negotiate protocal, now first need negotiate the stream protocol
                if !stream_protocol_flag {
                    stream_protocol_flag = true;
                    buf = data_receiver.next().await;
                    let (mut data, varint_buf) = split_length_from_package(buf.clone().unwrap());
                    let mut len = get_varint_len(varint_buf);
                    println!("remote send receive1:{:?}", buf.clone());
                    buf = data_receiver.next().await;
                    data = buf.clone().unwrap();
                    let mesh_proto: Vec<u8> = data.drain(20..).collect();
                    let mut stream_clone = stream_spawn.clone();

                    //send back multistream_select protocol
                    let frame = Frame::data(stream_clone.id(), data).unwrap();
                    stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                    //send back gossipsub protocol for negotiate
                    let frame = Frame::data(stream_clone.id(), mesh_proto).unwrap();
                    stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                    // let buf = std::str::from_utf8(&buf.unwrap()).unwrap().to_string();
                    println!("remote send receive2:{:?}", buf);
                }
                println!("begin gossip protocol");
                buf = data_receiver.next().await;
                println!("receive gossip data:{:?}", buf);
                buf = data_receiver.next().await;
                println!("receive gossip data body:{:?}", buf);
                let mut  rpc_in: Rpc = match Rpc::decode(&buf.unwrap()[1..]) {
                    Ok(rpc) => rpc,
                    Err(_) => {
                        println!("failed to parse remote's exchage protobuf message");
                        return (); //Err("failed to parse remote's exchange protobuf".to_string());
                    }
                };
                println!("rpc topic:{:?}", rpc_in);

                //receive info from remote node, need subscribe  amd graft to remote node!
                loop {
                    buf = data_receiver.next().await;
                    println!("receive gossip msg body len :{:?}", buf);
                    buf = data_receiver.next().await;
                    println!("receive gossip msg body:{:?}", buf);
                    let mut rpc_in: Rpc = match Rpc::decode(&buf.unwrap()[1..]) {
                        Ok(rpc) => rpc,
                        Err(_) => {
                            println!("failed to parse remote's exchage protobuf message");
                            return (); //Err("failed to parse remote's exchange protobuf".to_string());
                        }
                    };
                    println!("rpc topic:{:?}", rpc_in.clone());

                    for publish in rpc_in.publish {
                        let id = PeerId::from_bytes(publish.from.unwrap());
                        if let Some(data) = publish.data {
                            let message_id = message_id(data);
                            println!("get id {} rpc msg from:{:?}", message_id, id);
                        }
                    }
                }

            });
            //break;

        }
    }else {
        println!("get_stream fail :{:?}", res);
    }
}

pub async fn remote_stream_deal_eth2(mut frame_sender: mpsc::Sender<StreamCommand>, mut sender: mpsc::Sender<ControlCommand>, local_peer_id: PeerId,  localkey: Keypair, local_addr: Multiaddr) {
    let res = subscribe_stream(sender.clone()).await;
    let mut  stream_protocol_flag = false;
    if let Ok(mut stream)= res{
      loop {
         let mut stream = stream.next().await.unwrap();
         stream_protocol_flag = false;
          let localkey_clone = localkey.clone();
          let local_addr_clone = local_addr.clone();
         let mut proto = Vec::new();
         if !stream.cache.is_empty() {
             let mut data: Vec<u8> = stream.cache.drain(4..).collect();
             let mut len_buf = [0u8; 4];
             len_buf.copy_from_slice(stream.cache.as_slice());
             let len = u32::from_be_bytes(len_buf);

             proto = data.drain(20..).collect();
             let out = std::str::from_utf8(&data.clone()).unwrap().to_string();
             let out1 = std::str::from_utf8(&proto.clone()).unwrap().to_string();
             println!("cache len:{}, buf:{:?},ping:{:?}", len, out, out1);


             let len: u8 = MSG_MULTISTREAM_1_0.len() as u8;
             data.clear();
             data.push(len);
             data.append(&mut MSG_MULTISTREAM_1_0.to_vec());

             let mut stream_clone = stream.clone();
             let frame = Frame::data(stream_clone.id(), data).unwrap();
             stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;


             let frame = Frame::data(stream_clone.id(), proto.clone()).unwrap();
             stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
             proto.remove(0);
             stream_protocol_flag = true;
             //let mut stream_spawn = stream.clone();
         }
         let mut stream_spawn = stream.clone();
         let mut data_receiver = stream.data_receiver.unwrap();

         task::spawn(async move {
             let mut buf = None;
             // not negotiate protocal, now first need negotiate the stream protocol
             if !stream_protocol_flag {
                 stream_protocol_flag = true;
                 buf = data_receiver.next().await;
                 let (mut data, varint_buf) = split_length_from_package(buf.clone().unwrap());
                 let mut len = get_varint_len(varint_buf);
                 println!("remote send receive1:{:?}", buf.clone());
                 buf = data_receiver.next().await;
                 data = buf.clone().unwrap();
                 proto = data.drain(20..).collect();
                 let mut stream_clone = stream_spawn.clone();

                 //send back multistream_select protocol
                 let frame = Frame::data(stream_clone.id(), data).unwrap();
                 stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                 //send back gossipsub protocol for negotiate
                 let frame = Frame::data(stream_clone.id(), proto.clone()).unwrap();
                 stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                 // let buf = std::str::from_utf8(&buf.unwrap()).unwrap().to_string();
                 println!("remote send receive2:{:?}", buf);
                 proto.remove(0);
             }


             if proto.eq(&"/ipfs/id/1.0.0\n".as_bytes().to_vec()) {
                 let info = IdentifyInfo {
                     public_key: localkey_clone.public(),
                     /// Version of the protocol family used by the peer, e.g. `ipfs/1.0.0`
                     /// or `polkadot/1.0.0`.
                     protocol_version: "lighthouse/libp2p".into(),
                     agent_version: version(),
                     listen_addrs: vec![
                         local_addr_clone,
                     ],
                     /// The list of protocols supported by the peer, e.g. `/ipfs/ping/1.0.0`.
                     protocols: vec!["/meshsub/1.0.0\n".to_string()],
                 };

                 let observed_addr: Multiaddr = "/ip4/95.146.89.52/tcp/13000".parse().unwrap();

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
                 let mut len: u8 = bytes.len() as u8;
                 println!("rpc id send:{:?}", message);
                 bytes.insert(0, len);
                 println!("rpc id send vec:{:?}", bytes);
                 let frame = Frame::data(stream_spawn.id(), bytes).unwrap();
                 stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
             }

             println!("begin gossip protocol");
             buf = data_receiver.next().await;
             println!("receive gossip data:{:?}", buf);
             buf = data_receiver.next().await;
             println!("receive gossip data body:{:?}", buf);
             let mut rpc_in: Rpc = match Rpc::decode(&buf.unwrap()[1..]) {
                 Ok(rpc) => rpc,
                 Err(_) => {
                     println!("failed to parse remote's exchage protobuf message");
                     return (); //Err("failed to parse remote's exchange protobuf".to_string());
                 }
             };
             println!("rpc topic:{:?}", rpc_in);


             //receive info from remote node, need subscribe  amd graft to remote node!
             loop {
                 buf = data_receiver.next().await;
                 println!("receive gossip msg body len :{:?}", buf);
                 buf = data_receiver.next().await;
                 println!("receive gossip msg body:{:?}", buf);
                 let mut rpc_in: Rpc = match Rpc::decode(&buf.unwrap()[1..]) {
                     Ok(rpc) => rpc,
                     Err(_) => {
                         println!("failed to parse remote's exchage protobuf message");
                         return (); //Err("failed to parse remote's exchange protobuf".to_string());
                     }
                 };
                 println!("rpc topic:{:?}", rpc_in.clone());

                 for publish in rpc_in.publish {
                     let id = PeerId::from_bytes(publish.from.unwrap());
                     if let Some(data) = publish.data {
                         let message_id = message_id(data);
                         println!("get id {} rpc msg from:{:?}", message_id, id);
                     }
                 }
             }
         });
      }
    }else {
        println!("get_stream fail :{:?}", res);
    }
}



pub async fn period_send( sender: mpsc::Sender<ControlCommand>, local_peer_id: PeerId) {
    let res = open_stream(sender).await;
    if let Ok(mut stream) = res {
        let mut stream_clone = stream.clone();
        let mut stream_spawn = stream.clone();
        let mut data_receiver = stream.data_receiver.unwrap();
        let local_peer_id_clone =local_peer_id.clone();
        task::spawn(async move {
                // get negotiate msg
                let mut buf = data_receiver.next().await;
                println!("client receive1:{:?}", buf);
                buf = data_receiver.next().await;
                println!("client receive2:{:?}", buf);
                buf = data_receiver.next().await;
                println!("client receive3:{:?}", buf);
                buf = data_receiver.next().await;
                println!("client receive4:{:?}", buf);

                //send subscribe and graft info. become full-message node.
                let mut  rpc_in: Rpc =  Rpc {
                    subscriptions: vec![
                        SubOpts{
                            subscribe: Some(true),
                            topic_id: Some("test-net".to_string())
                        }
                    ],
                    publish: Vec::new(),
                    control: None,
                };
                println!("rpc topic:{:?}", rpc_in);
                let rpc_graft = ControlGraft {
                    topic_id: Some("test-net".to_string()),
                };


                let rpc_prune = ControlPrune {
                    topic_id: Some("test-net".to_string()),
                };

                // control messages
                let mut control = ControlMessage {
                    ihave: Vec::new(),
                    iwant: Vec::new(),
                    graft: Vec::new(),
                    prune: Vec::new(),
                };
                control.graft.push(rpc_graft);
                //control.prune.push(rpc_prune);
                rpc_in.control = Some(control);
                let mut rpc_buf: Vec<u8> = Vec::with_capacity(rpc_in.encoded_len());
                rpc_in.encode(&mut rpc_buf)
                    .expect("Buffer has sufficient capacity");
                let mut len:u8 = rpc_buf.len() as u8;
                println!("rpc send:{:?}", rpc_in);
                rpc_buf.insert(0, len);
                println!("rpc send vec:{:?}", rpc_buf);
                let frame = Frame::data(stream_spawn.id(), rpc_buf).unwrap();
                stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;

                //publish info to topic test-net, other node subscribe this topic can receive the info
                let out = publish(local_peer_id_clone, "test-net".to_string(), "hello".as_bytes().to_vec());
                rpc_buf = Vec::with_capacity(out.encoded_len());
                out.encode(&mut rpc_buf).expect("Buffer has sufficient capacity");
                len = rpc_buf.len() as u8;
                println!("rpc send:{:?}", out);
                rpc_buf.insert(0, len);
                println!("rpc send vec:{:?}", rpc_buf);
                let frame = Frame::data(stream_spawn.id(), rpc_buf).unwrap();
                stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;

                buf = data_receiver.next().await;
                println!("client receive5:{:?}", buf);

        });
     //   loop {
            let mut data = Vec::new();

            let mut len: u8 = MSG_MULTISTREAM_1_0.len() as u8;
            data.push(len);
            data.append(&mut MSG_MULTISTREAM_1_0.to_vec());


            let frame = Frame::data(stream_clone.id(), data.clone()).unwrap();
            //let frame = Frame::data(stream_clone.id(), format!("love and peace:{}", index).into_bytes()).unwrap();
            stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;

            len = MSG_MESHSUB_1_0.len() as u8;
            data.clear();
            data.push(len);
            data.append(&mut MSG_MESHSUB_1_0.to_vec());

            let frame = Frame::data(stream_clone.id(), data).unwrap();
            //let frame = Frame::data(stream_clone.id(), format!("love and peace:{}", index).into_bytes()).unwrap();
            stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;

            //     task::sleep(Duration::from_secs(10)).await;
      //  }
    } else {
        println!("fail open stream");
    }
}


pub async fn period_send_eth2( sender: mpsc::Sender<ControlCommand>, local_peer_id: PeerId) {
    let res = open_stream(sender).await;
    if let Ok(mut stream) = res {
        let mut stream_clone = stream.clone();
        let mut stream_spawn = stream.clone();
        let mut data_receiver = stream.data_receiver.unwrap();
        let local_peer_id_clone =local_peer_id.clone();
        task::spawn(async move {
            // get negotiate msg
            let mut buf = data_receiver.next().await;
            println!("client receive1:{:?}", buf);
            buf = data_receiver.next().await;
            println!("client receive2:{:?}", buf);
            buf = data_receiver.next().await;
            println!("client receive3:{:?}", buf);
            buf = data_receiver.next().await;
            println!("client receive4:{:?}", buf);

//            let gossip_topic = GossipTopic::new(
//                GossipKind::BeaconBlock,
//                GossipEncoding::default(),
//                fork_digest,
//            );
//            //send subscribe and graft info. become full-message node.
//            let mut  rpc_in: Rpc =  Rpc {
//                subscriptions: vec![
//                    SubOpts{
//                        subscribe: Some(true),
//                        topic_id: Some("beacon_block".to_string())
//                    }
//                ],
//                publish: Vec::new(),
//                control: None,
//            };
//            println!("rpc topic:{:?}", rpc_in);
//            let rpc_graft = ControlGraft {
//                topic_id: Some("beacon_block".to_string()),
//            };
//
//
//            let rpc_prune = ControlPrune {
//                topic_id: Some("test-net".to_string()),
//            };
//
//            // control messages
//            let mut control = ControlMessage {
//                ihave: Vec::new(),
//                iwant: Vec::new(),
//                graft: Vec::new(),
//                prune: Vec::new(),
//            };
//            control.graft.push(rpc_graft);
//            //control.prune.push(rpc_prune);
//            rpc_in.control = Some(control);
//            let mut rpc_buf: Vec<u8> = Vec::with_capacity(rpc_in.encoded_len());
//            rpc_in.encode(&mut rpc_buf)
//                .expect("Buffer has sufficient capacity");
//            let mut len:u8 = rpc_buf.len() as u8;
//            println!("rpc send:{:?}", rpc_in);
//            rpc_buf.insert(0, len);
//            println!("rpc send vec:{:?}", rpc_buf);
//            let frame = Frame::data(stream_spawn.id(), rpc_buf).unwrap();
//            stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;

            //publish info to topic test-net, other node subscribe this topic can receive the info
//                let out = publish(local_peer_id_clone, "test-net".to_string(), "hello".as_bytes().to_vec());
//                rpc_buf = Vec::with_capacity(out.encoded_len());
//                out.encode(&mut rpc_buf).expect("Buffer has sufficient capacity");
//                len = rpc_buf.len() as u8;
//                println!("rpc send:{:?}", out);
//                rpc_buf.insert(0, len);
//                println!("rpc send vec:{:?}", rpc_buf);
//                let frame = Frame::data(stream_spawn.id(), rpc_buf).unwrap();
//                stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;

            buf = data_receiver.next().await;
            println!("client receive5:{:?}", buf);

        });
        //   loop {
        let mut data = Vec::new();

        let mut len: u8 = MSG_MULTISTREAM_1_0.len() as u8;
        data.push(len);
        data.append(&mut MSG_MULTISTREAM_1_0.to_vec());


        let frame = Frame::data(stream_clone.id(), data.clone()).unwrap();
        //let frame = Frame::data(stream_clone.id(), format!("love and peace:{}", index).into_bytes()).unwrap();
        stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;

        len = MSG_MESHSUB_1_0.len() as u8;
        data.clear();
        data.push(len);
        data.append(&mut MSG_MESHSUB_1_0.to_vec());

        let frame = Frame::data(stream_clone.id(), data).unwrap();
        //let frame = Frame::data(stream_clone.id(), format!("love and peace:{}", index).into_bytes()).unwrap();
        stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;

        //     task::sleep(Duration::from_secs(10)).await;
        //  }
    } else {
        println!("fail open stream");
    }
}

#[test]
fn eth2_client_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let mut  connec = async_std::net::TcpStream::connect("95.146.89.52:13000").await.unwrap();
        let mut  local_addr: std::net::SocketAddr = connec.local_addr().unwrap();
        println!("localaddr:{:?}", local_addr);
        let addr = format!("/ip4/{}/tcp/{}",local_addr.ip().to_string() ,local_addr.port());
        println!("addr:{:?}", addr);
        let mut local_addr = addr.parse().unwrap();
        let match_proto = dialer_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/yamux/1.0.0\n".to_string()], true).await;
        if match_proto.is_ok() {
            let proto = match_proto.unwrap();
            if proto.eq(&"/secio/1.0.0\n".as_bytes().to_vec()) {
                let local_key = Keypair::generate_ed25519();
                let local_peer_id = PeerId::from(local_key.public());
                let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), local_key.clone(),Mode::Client).await.unwrap();
                let arc_reader = session_reader.socket.clone();
                let arc_writer = session_writer.socket.clone();
                let res = dialer_select_proto_secio(arc_reader.clone(), arc_writer.clone(), vec!["/yamux/1.0.0\n".to_string()]).await;
                if res.is_ok() {
                    println!("into yamux");
                    let (control_sender, control_receiver) = mpsc::channel(10);
                    let deal_remote_stream = remote_stream_deal_eth2(session_reader.stream_sender.clone(),control_sender.clone(), local_peer_id.clone(), local_key, local_addr);
                    let period_send = period_send_eth2( control_sender,local_peer_id );
                    let receive_process = session_reader.receive_loop( control_receiver);
                    let send_process = session_writer.send_process();
                    join!{receive_process, send_process, deal_remote_stream, period_send};//
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
                let multiaddr: Multiaddr= Multiaddr::try_from(addr.to_vec()).unwrap();
                println!("multiaddr:{:?}", multiaddr.to_string());
            }
            connec.read_exact(&mut read_buf).await.unwrap();
            println!("read_buf:{:?}", read_buf );
        }
    })
}

#[test]
fn chart_client_test() {
    init_log("debug");
    async_std::task::block_on(async move {
        let mut  connec = async_std::net::TcpStream::connect("116.203.82.128:13000").await.unwrap();
        let match_proto = dialer_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/yamux/1.0.0\n".to_string()], true).await;
        if match_proto.is_ok() {
            let proto = match_proto.unwrap();
            if proto.eq(&"/secio/1.0.0\n".as_bytes().to_vec()) {
                let local_key = Keypair::generate_ed25519();
                let local_peer_id = PeerId::from(local_key.public());
                let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), local_key,Mode::Client).await.unwrap();
                let arc_reader = session_reader.socket.clone();
                let arc_writer = session_writer.socket.clone();
                let res = dialer_select_proto_secio(arc_reader.clone(), arc_writer.clone(), vec!["/yamux/1.0.0\n".to_string()]).await;
                if res.is_ok() {
                    println!("into yamux");
                    let (control_sender, control_receiver) = mpsc::channel(10);
                    let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone(), local_peer_id.clone());
                    let period_send = period_send( control_sender,local_peer_id );
                    let receive_process = session_reader.receive_loop( control_receiver);
                    let send_process = session_writer.send_process();
                    join!{receive_process, send_process, deal_remote_stream, period_send};//
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
                let multiaddr: Multiaddr= Multiaddr::try_from(addr.to_vec()).unwrap();
                println!("multiaddr:{:?}", multiaddr.to_string());
            }
            connec.read_exact(&mut read_buf).await.unwrap();
            println!("read_buf:{:?}", read_buf );
        }
    })
}