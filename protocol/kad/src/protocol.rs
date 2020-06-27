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
use parity_multiaddr::{Multiaddr ,multiaddr };
use parity_multiaddr::Protocol::*;
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
//use super::dht::{Message, Record, message};
use super::dht as proto;
use std::{io, iter};
use super::record::{self, Record, Key};
use std::process::id;

pub const MSG_PAD_1_0: &[u8] = b"/ipfs/kad/1.0.0\n";

/// Creates an `io::Error` with `io::ErrorKind::InvalidData`.
fn invalid_data<E>(e: E) -> io::Error
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>
{
    io::Error::new(io::ErrorKind::InvalidData, e)
}
/// Status of our connection to a node reported by the Kademlia protocol.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum KadConnectionType {
    /// Sender hasn't tried to connect to peer.
    NotConnected = 0,
    /// Sender is currently connected to peer.
    Connected = 1,
    /// Sender was recently connected to peer.
    CanConnect = 2,
    /// Sender tried to connect to peer but failed.
    CannotConnect = 3,
}

impl From<proto::message::ConnectionType> for KadConnectionType {
    fn from(raw: proto::message::ConnectionType) -> KadConnectionType {
        use proto::message::ConnectionType::*;
        match raw {
            NotConnected => KadConnectionType::NotConnected,
            Connected => KadConnectionType::Connected,
            CanConnect => KadConnectionType::CanConnect,
            CannotConnect => KadConnectionType::CannotConnect,
        }
    }
}

impl Into<proto::message::ConnectionType> for KadConnectionType {
    fn into(self) -> proto::message::ConnectionType {
        use proto::message::ConnectionType::*;
        match self {
            KadConnectionType::NotConnected => NotConnected,
            KadConnectionType::Connected => Connected,
            KadConnectionType::CanConnect => CanConnect,
            KadConnectionType::CannotConnect => CannotConnect,
        }
    }
}

/// Information about a peer, as known by the sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadPeer {
    /// Identifier of the peer.
    pub node_id: PeerId,
    /// The multiaddresses that the sender think can be used in order to reach the peer.
    pub multiaddrs: Vec<Multiaddr>,
    /// How the sender is connected to that remote.
    pub connection_ty: KadConnectionType,
}

// Builds a `KadPeer` from a corresponding protobuf message.
impl TryFrom<proto::message::Peer> for KadPeer {
    type Error = io::Error;

    fn try_from(peer: proto::message::Peer) -> Result<KadPeer, Self::Error> {
        // TODO: this is in fact a CID; not sure if this should be handled in `from_bytes` or
        //       as a special case here
        let node_id = PeerId::from_bytes(peer.id)
            .map_err(|_| invalid_data("invalid peer id"))?;

        let mut addrs = Vec::with_capacity(peer.addrs.len());
        for addr in peer.addrs.into_iter() {
            let as_ma = Multiaddr::try_from(addr).map_err(invalid_data)?;
            addrs.push(as_ma);
        }
        debug_assert_eq!(addrs.len(), addrs.capacity());

        let connection_ty = proto::message::ConnectionType::from_i32(peer.connection)
            .ok_or_else(|| invalid_data("unknown connection type"))?
            .into();

        Ok(KadPeer {
            node_id,
            multiaddrs: addrs,
            connection_ty
        })
    }
}

impl Into<proto::message::Peer> for KadPeer {
    fn into(self) -> proto::message::Peer {
        proto::message::Peer {
            id: self.node_id.into_bytes(),
            addrs: self.multiaddrs.into_iter().map(|a| a.to_vec()).collect(),
            connection: {
                let ct: proto::message::ConnectionType = self.connection_ty.into();
                ct as i32
            }
        }
    }
}

/// Request that we can send to a peer or that we received from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KadRequestMsg {
    /// Ping request.
    Ping,

    /// Request for the list of nodes whose IDs are the closest to `key`. The number of nodes
    /// returned is not specified, but should be around 20.
    FindNode {
        /// The key for which to locate the closest nodes.
        key: Vec<u8>,
    },

    /// Same as `FindNode`, but should also return the entries of the local providers list for
    /// this key.
    GetProviders {
        /// Identifier being searched.
        key: record::Key,
    },

    /// Indicates that this list of providers is known for this key.
    AddProvider {
        /// Key for which we should add providers.
        key: record::Key,
        /// Known provider for this key.
        provider: KadPeer,
    },

    /// Request to get a value from the dht records.
    GetValue {
        /// The key we are searching for.
        key: record::Key,
    },

    GetPubValue {
        /// The key we are searching for.
        key: Vec<u8>,
    },

    /// Request to put a value into the dht records.
    PutValue {
        record: Record,
    },

    /// Request to put a value into the dht records.
    PutPubValue {
        key: Vec<u8>,
        value: Vec<u8>
    }
}

/// Response that we can send to a peer or that we received from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KadResponseMsg {
    /// Ping response.
    Pong,

    /// Response to a `FindNode`.
    FindNode {
        /// Results of the request.
        closer_peers: Vec<KadPeer>,
    },

    /// Response to a `GetProviders`.
    GetProviders {
        /// Nodes closest to the key.
        closer_peers: Vec<KadPeer>,
        /// Known providers for this key.
        provider_peers: Vec<KadPeer>,
    },

    /// Response to a `GetValue`.
    GetValue {
        /// Result that might have been found
        record: Option<Record>,
        /// Nodes closest to the key
        closer_peers: Vec<KadPeer>,
    },

    /// Response to a `PutValue`.
    PutValue {
        /// The key of the record.
        key: record::Key,
        /// Value of the record.
        value: Vec<u8>,
    },
}

/// Converts a `KadRequestMsg` into the corresponding protobuf message for sending.
fn req_msg_to_proto(kad_msg: KadRequestMsg) -> proto::Message {
    match kad_msg {
        KadRequestMsg::Ping => proto::Message {
            r#type: proto::message::MessageType::Ping as i32,
            .. proto::Message::default()
        },
        KadRequestMsg::FindNode { key } => proto::Message {
            r#type: proto::message::MessageType::FindNode as i32,
            key,
            cluster_level_raw: 10,
            .. proto::Message::default()
        },
        KadRequestMsg::GetProviders { key } => proto::Message {
            r#type: proto::message::MessageType::GetProviders as i32,
            key: key.to_vec(),
            cluster_level_raw: 10,
            .. proto::Message::default()
        },
        KadRequestMsg::AddProvider { key, provider } => proto::Message {
            r#type: proto::message::MessageType::AddProvider as i32,
            cluster_level_raw: 10,
            key: key.to_vec(),
            provider_peers: vec![provider.into()],
            .. proto::Message::default()
        },
        KadRequestMsg::GetValue { key } => proto::Message {
            r#type: proto::message::MessageType::GetValue as i32,
            cluster_level_raw: 10,
            key: key.to_vec(),
            .. proto::Message::default()
        },
        KadRequestMsg::GetPubValue { key } => proto::Message {
            r#type: proto::message::MessageType::GetValue as i32,
            cluster_level_raw: 10,
            key,
            .. proto::Message::default()
        },

        KadRequestMsg::PutValue { record } => proto::Message {
            r#type: proto::message::MessageType::PutValue as i32,
            record: Some(record_to_proto(record)),
            .. proto::Message::default()
        },
        KadRequestMsg::PutPubValue { key, value } => proto::Message {
            r#type: proto::message::MessageType::PutValue as i32,
            key: key.to_vec(),
            record: Some(pubkey_record_to_proto(key, value)),
            cluster_level_raw: 10,
            .. proto::Message::default()
        }
    }
}

/// Converts a `KadResponseMsg` into the corresponding protobuf message for sending.
fn resp_msg_to_proto(kad_msg: KadResponseMsg) -> proto::Message {
    match kad_msg {
        KadResponseMsg::Pong => proto::Message {
            r#type: proto::message::MessageType::Ping as i32,
            .. proto::Message::default()
        },
        KadResponseMsg::FindNode { closer_peers } => proto::Message {
            r#type: proto::message::MessageType::FindNode as i32,
            cluster_level_raw: 9,
            closer_peers: closer_peers.into_iter().map(KadPeer::into).collect(),
            .. proto::Message::default()
        },
        KadResponseMsg::GetProviders { closer_peers, provider_peers } => proto::Message {
            r#type: proto::message::MessageType::GetProviders as i32,
            cluster_level_raw: 9,
            closer_peers: closer_peers.into_iter().map(KadPeer::into).collect(),
            provider_peers: provider_peers.into_iter().map(KadPeer::into).collect(),
            .. proto::Message::default()
        },
        KadResponseMsg::GetValue { record, closer_peers } => proto::Message {
            r#type: proto::message::MessageType::GetValue as i32,
            cluster_level_raw: 9,
            closer_peers: closer_peers.into_iter().map(KadPeer::into).collect(),
            record: record.map(record_to_proto),
            .. proto::Message::default()
        },
        KadResponseMsg::PutValue { key, value } => proto::Message {
            r#type: proto::message::MessageType::PutValue as i32,
            key: key.to_vec(),
            record: Some(proto::Record {
                key: key.to_vec(),
                value,
                .. proto::Record::default()
            }),
            .. proto::Message::default()
        }
    }
}

/// Converts a received protobuf message into a corresponding `KadRequestMsg`.
///
/// Fails if the protobuf message is not a valid and supported Kademlia request message.
fn proto_to_req_msg(message: proto::Message) -> Result<KadRequestMsg, io::Error> {
    let msg_type = proto::message::MessageType::from_i32(message.r#type)
        .ok_or_else(|| invalid_data(format!("unknown message type: {}", message.r#type)))?;

    match msg_type {
        proto::message::MessageType::Ping => Ok(KadRequestMsg::Ping),
        proto::message::MessageType::PutValue => {
            let record = record_from_proto(message.record.unwrap_or_default())?;
            Ok(KadRequestMsg::PutValue { record })
        }
        proto::message::MessageType::GetValue => {
            Ok(KadRequestMsg::GetValue { key: record::Key::from(message.key) })
        }
        proto::message::MessageType::FindNode => {
            Ok(KadRequestMsg::FindNode { key: message.key })
        }
        proto::message::MessageType::GetProviders => {
            Ok(KadRequestMsg::GetProviders { key: record::Key::from(message.key)})
        }
        proto::message::MessageType::AddProvider => {
            // TODO: for now we don't parse the peer properly, so it is possible that we get
            //       parsing errors for peers even when they are valid; we ignore these
            //       errors for now, but ultimately we should just error altogether
            let provider = message.provider_peers
                .into_iter()
                .find_map(|peer| KadPeer::try_from(peer).ok());

            if let Some(provider) = provider {
                let key = record::Key::from(message.key);
                Ok(KadRequestMsg::AddProvider { key, provider })
            } else {
                Err(invalid_data("AddProvider message with no valid peer."))
            }
        }
    }
}

/// Converts a received protobuf message into a corresponding `KadResponseMessage`.
///
/// Fails if the protobuf message is not a valid and supported Kademlia response message.
fn proto_to_resp_msg(message: proto::Message) -> Result<KadResponseMsg, io::Error> {
    let msg_type = proto::message::MessageType::from_i32(message.r#type)
        .ok_or_else(|| invalid_data(format!("unknown message type: {}", message.r#type)))?;

    match msg_type {
        proto::message::MessageType::Ping => Ok(KadResponseMsg::Pong),
        proto::message::MessageType::GetValue => {
            let record =
                if let Some(r) = message.record {
                    Some(record_from_proto(r)?)
                } else {
                    None
                };

            let closer_peers = message.closer_peers.into_iter()
                .filter_map(|peer| KadPeer::try_from(peer).ok())
                .collect();

            Ok(KadResponseMsg::GetValue { record, closer_peers })
        }

        proto::message::MessageType::FindNode => {
            let closer_peers = message.closer_peers.into_iter()
                .filter_map(|peer| KadPeer::try_from(peer).ok())
                .collect();

            Ok(KadResponseMsg::FindNode { closer_peers })
        }

        proto::message::MessageType::GetProviders => {
            let closer_peers = message.closer_peers.into_iter()
                .filter_map(|peer| KadPeer::try_from(peer).ok())
                .collect();

            let provider_peers = message.provider_peers.into_iter()
                .filter_map(|peer| KadPeer::try_from(peer).ok())
                .collect();

            Ok(KadResponseMsg::GetProviders {
                closer_peers,
                provider_peers,
            })
        }

        proto::message::MessageType::PutValue => {
            let key = record::Key::from(message.key);
            let rec = message.record.ok_or_else(|| {
                invalid_data("received PutValue message with no record")
            })?;

            Ok(KadResponseMsg::PutValue {
                key,
                value: rec.value
            })
        }

        proto::message::MessageType::AddProvider =>
            Err(invalid_data("received an unexpected AddProvider message"))
    }
}

fn record_from_proto(record: proto::Record) -> Result<Record, io::Error> {
    let key = record::Key::from(record.key);
    let value = record.value;

//    let publisher =
//        if !record.publisher.is_empty() {
//            PeerId::from_bytes(record.publisher)
//                .map(Some)
//                .map_err(|_| invalid_data("Invalid publisher peer ID."))?
//        } else {
//            None
//        };
//
//    let expires =
//        if record.ttl > 0 {
//            Some(Instant::now() + Duration::from_secs(record.ttl as u64))
//        } else {
//            None
//        };

  //  Ok(Record { key, value, publisher, expires })
    Ok(Record { key, value })
}

fn record_to_proto(record: Record) -> proto::Record {
    proto::Record {
        key: record.key.to_vec(),
        value: record.value,
        //publisher: record.publisher.map(PeerId::into_bytes).unwrap_or_default(),
//        ttl: record.expires
//            .map(|t| {
//                let now = Instant::now();
//                if t > now {
//                    (t - now).as_secs() as u32
//                } else {
//                    1 // because 0 means "does not expire"
//                }
//            })
//            .unwrap_or(0),
        time_received: String::new()
    }
}

fn pubkey_record_to_proto(key: Vec<u8>, value: Vec<u8>) -> proto::Record {
    proto::Record {
        key,
        value,
        //publisher: record.publisher.map(PeerId::into_bytes).unwrap_or_default(),
//        ttl: record.expires
//            .map(|t| {
//                let now = Instant::now();
//                if t > now {
//                    (t - now).as_secs() as u32
//                } else {
//                    1 // because 0 means "does not expire"
//                }
//            })
//            .unwrap_or(0),
        time_received: String::new()
    }
}



pub async fn remote_stream_deal(mut frame_sender: mpsc::Sender<StreamCommand>, mut sender: mpsc::Sender<ControlCommand>, local_peer_id: PeerId, localkey: Keypair, local_addr: Multiaddr) {
    let res = subscribe_stream(sender.clone()).await;
    let mut  stream_protocol_flag = false;
    if let Ok(mut stream)= res{
        loop {
            let mut stream = stream.next().await.unwrap();
            let mut proto = Vec::new();
            stream_protocol_flag = false;
            if !stream.cache.is_empty() {
                let mut  data: Vec<u8> = stream.cache.drain(4..).collect();
                let mut len_buf = [0u8;4];
                len_buf.copy_from_slice(stream.cache.as_slice());
                let len = u32::from_be_bytes(len_buf);

                proto = data.drain(20..).collect();
                let out = std::str::from_utf8(&data.clone()).unwrap().to_string();
                let out1 = std::str::from_utf8(&proto.clone()).unwrap().to_string();
                println!("cache len:{}, buf:{:?},proto:{:?}", len, out, out1);


                let len:u8 = MSG_MULTISTREAM_1_0.len() as u8;
                data.clear();
                data.push(len);
                data.append(& mut MSG_MULTISTREAM_1_0.to_vec()) ;

                let mut stream_clone = stream.clone();
                let frame = Frame::data(stream_clone.id(), data).unwrap();
                stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                let frame = Frame::data(stream_clone.id(), proto.clone()).unwrap();
                stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;
                stream_protocol_flag = true;
                //let mut stream_spawn = stream.clone();
            }
            let mut stream_spawn = stream.clone();
            let mut stream_send = stream.clone();
            let mut data_receiver = stream.data_receiver.unwrap();
            let mut localkey_clone = localkey.clone();
            let mut local_addr_clone = local_addr.clone();
            let mut proto_clone = proto.clone();

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

                }
                if proto_clone.len() > 0 {
                    proto_clone.remove(0);
                } else if proto.len() > 0 {
                    proto.remove(0);
                }

                //protocols same to protocol it support in kad-ht , protocol_version use the first field of protocol and version
                //validRTPeer->
                if proto_clone.eq(&"/ipfs/id/1.0.0\n".as_bytes().to_vec()) ||
                    proto.eq(&"/ipfs/id/1.0.0\n".as_bytes().to_vec())  {
                    let info = IdentifyInfo {
                        public_key: localkey_clone.public(),
                        /// Version of the protocol family used by the peer, e.g. `ipfs/1.0.0`
                         /// or `polkadot/1.0.0`.
                        protocol_version: "ipfs/1.0.0".into(),
                        agent_version: "rust-ipfs-kad".into(),
                        listen_addrs: vec![
                            local_addr_clone,
                        ],
                        /// The list of protocols supported by the peer, e.g. `/ipfs/ping/1.0.0`.
                        protocols: vec!["/ipfs/kad/1.0.0".to_string()],
                    };

                    let observed_addr: Multiaddr = "/ip4/104.131.131.82/tcp/4001".parse().unwrap();

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
                    let mut len:u8 = bytes.len() as u8;
                    println!("rpc send:{:?}", message);
                    bytes.insert(0, len);
                    println!("rpc send vec:{:?}", bytes);
                    let frame = Frame::data(stream_spawn.id(), bytes).unwrap();
                    stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
                }
                // let buf = std::str::from_utf8(&buf.unwrap()).unwrap().to_string();
                println!("remote send receive2:{:?}", buf);

                println!("begin kad protocol");



                buf = data_receiver.next().await;
                println!("receive kad remote data:{:?}", buf);
                buf = data_receiver.next().await;
            });



        }
    }else {
        println!("get_stream fail :{:?}", res);
    }
}

pub async fn period_send( sender: mpsc::Sender<ControlCommand>, local_peer_id: PeerId, localkey: Keypair) { //, addr: multihash::Multihash
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

            //find node
            let mut key = local_peer_id.into_bytes();
            let find_node_msg = KadRequestMsg::FindNode {key:key.clone()};
            let find_node_proto = req_msg_to_proto(find_node_msg);
            let mut bytes = Vec::with_capacity(find_node_proto.encoded_len());
            find_node_proto.encode(&mut bytes).expect("Vec<u8> provides capacity as needed");
            let mut len:u8 = bytes.len() as u8;
            println!("rpc send:{:?}", find_node_proto);
            bytes.insert(0, len);
            println!("rpc send vec:{:?}", bytes);
            let frame = Frame::data(stream_spawn.id(), bytes).unwrap();
            stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
            buf = data_receiver.next().await;
            println!("receive findnode body len :{:?}", buf);
            buf = data_receiver.next().await;
            println!("receive findnode body:{:?}", buf);
            let mut body = buf.unwrap();
            loop {
                if (body[0] & 0x80) == 0x80 {
                    body.remove(0);
                } else {
                    body.remove(0);
                    break;
                }
            }
            let mut find_node_resp: proto::Message = match proto::Message::decode(&body[..]) {
                Ok(find_node_resp) => find_node_resp,
                Err(_) => {
                    println!("failed to parse find_node_resp message");
                    return (); //Err("failed to parse remote's exchange protobuf".to_string());
                }
            };
            println!("findnode struct:{:?}", find_node_resp.clone());
            let msg = proto_to_resp_msg(find_node_resp).unwrap();
            println!("KadResponseMsg:{:?}", msg.clone());

            //put value
            //let mut id = hex::decode("0024080112206f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8").unwrap();
            let mut record = "/pk/".to_string().as_bytes().to_vec();
            record.append(&mut key);
            //let mut record = "/pk/hello".to_string().as_bytes().to_vec();

            // let record = Record{key: Key::from("/pk/hello".to_string().as_bytes().to_vec() ) , value: vec![0x97,0x98]};
            let pubkey = localkey.public().into_protobuf_encoding();
            let put_value_msg = KadRequestMsg::PutPubValue {key: record,  value: pubkey};
            let put_value_proto = req_msg_to_proto(put_value_msg);
            let mut bytes = Vec::with_capacity(put_value_proto.encoded_len());
            put_value_proto.encode(&mut bytes).expect("Vec<u8> provides capacity as needed");
            let mut len:u32 = bytes.len() as u32;
            println!("put value len:{} rpc send:{:?}", len, put_value_proto);
            let mut bytes = insert_frame_len(bytes);

            println!("put value send vec:{:?}", bytes);
            let frame = Frame::data(stream_spawn.id(), bytes).unwrap();
            stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
            buf = data_receiver.next().await;
            println!("receive put value body len :{:?}", buf);
            buf = data_receiver.next().await;
            println!("receive put resp value body:{:?}", buf);
            let mut body = buf.unwrap();
            loop {
                if (body[0] & 0x80) == 0x80 {
                    body.remove(0);
                } else {
                    body.remove(0);
                    break;
                }
            }
            let mut pub_value_resp: proto::Message = match proto::Message::decode(&body[..]) {
                Ok(pub_value_resp) => pub_value_resp,
                Err(_) => {
                    println!("failed to parse remote's exchage protobuf message");
                    return (); //Err("failed to parse remote's exchange protobuf".to_string());
                }
            };
            println!("get value struct:{:?}", pub_value_resp.clone());
            let msg = proto_to_resp_msg(pub_value_resp).unwrap();
            println!("KadResponseMsg:{:?}", msg.clone());
            buf = data_receiver.next().await;
            println!("receive remote  data:{:?}", buf);

        });
        //   loop {
        let mut data = Vec::new();

        let mut len: u8 = MSG_MULTISTREAM_1_0.len() as u8;
        data.push(len);
        data.append(&mut MSG_MULTISTREAM_1_0.to_vec());


        let frame = Frame::data(stream_clone.id(), data.clone()).unwrap();
        //let frame = Frame::data(stream_clone.id(), format!("love and peace:{}", index).into_bytes()).unwrap();
        stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;

        len = MSG_PAD_1_0.len() as u8;
        data.clear();
        data.push(len);
        data.append(&mut MSG_PAD_1_0.to_vec());

        let frame = Frame::data(stream_clone.id(), data).unwrap();
        //let frame = Frame::data(stream_clone.id(), format!("love and peace:{}", index).into_bytes()).unwrap();
        stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;

        //     task::sleep(Duration::from_secs(10)).await;
        //  }
    } else {
        println!("fail open stream");
    }
}


pub async fn period_send_1( sender: mpsc::Sender<ControlCommand>, local_peer_id: PeerId, localkey: Keypair, remote_key: Keypair) {
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

//            let remote_peer = remote_key.public().into_peer_id();
//            println!("remote peerid:{}", remote_peer);
//            let key = remote_peer.into_bytes();
//            let find_node_msg = KadRequestMsg::FindNode {key};
//            let find_node_proto = req_msg_to_proto(find_node_msg);
//            let mut bytes = Vec::with_capacity(find_node_proto.encoded_len());
//            find_node_proto.encode(&mut bytes).expect("Vec<u8> provides capacity as needed");
//            let mut len:u8 = bytes.len() as u8;
//            println!("rpc send:{:?}", find_node_proto);
//            bytes.insert(0, len);
//            println!("rpc send vec:{:?}", bytes);
//            let frame = Frame::data(stream_spawn.id(), bytes).unwrap();
//            stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
//            buf = data_receiver.next().await;
//            println!("receive findnode body len :{:?}", buf);
//            buf = data_receiver.next().await;
//            println!("receive findnode body:{:?}", buf);
//            let mut find_node_resp: proto::Message = match proto::Message::decode(&buf.unwrap()[2..]) {
//                Ok(find_node_resp) => find_node_resp,
//                Err(_) => {
//                    println!("failed to parse remote's exchage protobuf message");
//                    return (); //Err("failed to parse remote's exchange protobuf".to_string());
//                }
//            };
//            println!("findnode struct:{:?}", find_node_resp.clone());
//            let msg = proto_to_resp_msg(find_node_resp).unwrap();
//            println!("KadResponseMsg:{:?}", msg.clone());
//
//            match msg {
//                KadResponseMsg::FindNode{mut closer_peers} => {
//                    for peer in closer_peers.iter_mut() {
//                        println!("peer id:{:?}", peer);
//                        let key =  peer.node_id.clone().into_bytes();
//                        let find_node_msg = KadRequestMsg::FindNode {key};
//                        let find_node_proto = req_msg_to_proto(find_node_msg);
//                        let mut bytes = Vec::with_capacity(find_node_proto.encoded_len());
//                        find_node_proto.encode(&mut bytes).expect("Vec<u8> provides capacity as needed");
//                        let mut len:u8 = bytes.len() as u8;
//                        println!("rpc send:{:?}", find_node_proto);
//                        bytes.insert(0, len);
//                        println!("rpc send vec:{:?}", bytes);
//                        let frame = Frame::data(stream_spawn.id(), bytes).unwrap();
//                        stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
//                        buf = data_receiver.next().await;
//                        println!("receive findnode body len :{:?}", buf);
//                        buf = data_receiver.next().await;
//                        println!("receive findnode body:{:?}", buf);
//                        let mut find_node_resp: proto::Message = match proto::Message::decode(&buf.unwrap()[2..]) {
//                            Ok(find_node_resp) => find_node_resp,
//                            Err(_) => {
//                                println!("failed to parse remote's exchage protobuf message");
//                                return (); //Err("failed to parse remote's exchange protobuf".to_string());
//                            }
//                        };
//                        println!("remote_key findnode struct:{:?}", find_node_resp.clone());
//                        let msg = proto_to_resp_msg(find_node_resp).unwrap();
//                        println!("remote_key KadResponseMsg:{:?}", msg.clone());
//                    }
//                },
//                _ => (),
//            };


            let mut key =  local_peer_id_clone.into_bytes();
            let find_node_msg = KadRequestMsg::FindNode {key:key.clone()};
            let find_node_proto = req_msg_to_proto(find_node_msg);
            let mut bytes = Vec::with_capacity(find_node_proto.encoded_len());
            find_node_proto.encode(&mut bytes).expect("Vec<u8> provides capacity as needed");
            let mut len:u8 = bytes.len() as u8;
            println!("rpc send:{:?}", find_node_proto);
            bytes.insert(0, len);
            println!("rpc send vec:{:?}", bytes);
            let frame = Frame::data(stream_spawn.id(), bytes).unwrap();
            stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
            buf = data_receiver.next().await;
            println!("receive findnode body len :{:?}", buf);
            buf = data_receiver.next().await;
            println!("receive findnode body:{:?}", buf);
            let mut body = buf.unwrap();
            loop {
                if (body[0] & 0x80) == 0x80 {
                    body.remove(0);
                } else {
                    body.remove(0);
                    break;
                }
            }
            let mut find_node_resp: proto::Message = match proto::Message::decode(&body[..]) {
                Ok(find_node_resp) => find_node_resp,
                Err(_) => {
                    println!("failed to parse remote's exchage protobuf message");
                    return (); //Err("failed to parse remote's exchange protobuf".to_string());
                }
            };
            println!("remote_key findnode struct:{:?}", find_node_resp.clone());
            let msg = proto_to_resp_msg(find_node_resp).unwrap();
            println!("remote_key KadResponseMsg:{:?}", msg.clone());

            //get value
            let mut remote = remote_key.public().into_peer_id().into_bytes();
            let mut get_key = "/pk/".to_string().as_bytes().to_vec();
            get_key.append(&mut remote);
            let get_value_msg = KadRequestMsg::GetPubValue {key:get_key};
         //   let get_value_msg = KadRequestMsg::GetPubValue {key:"/v/hello".to_string().as_bytes().to_vec()};
            let get_value_proto = req_msg_to_proto(get_value_msg);
            let mut bytes = Vec::with_capacity(get_value_proto.encoded_len());
            get_value_proto.encode(&mut bytes).expect("Vec<u8> provides capacity as needed");
            let mut len:u8 = bytes.len() as u8;
            println!("get value len:{} rpc send:{:?}", len, get_value_proto);
            bytes.insert(0, len);
            println!("get value send vec:{:?}", bytes);
            let frame = Frame::data(stream_spawn.id(), bytes).unwrap();
            stream_spawn.sender.send(StreamCommand::SendFrame(frame)).await;
            buf = data_receiver.next().await;
            println!("receive get value body len :{:?}", buf);
            buf = data_receiver.next().await;
            println!("receive get value body:{:?}", buf);
            let mut body = buf.unwrap();
            loop {
                if (body[0] & 0x80) == 0x80 {
                    body.remove(0);
                } else {
                    body.remove(0);
                    break;
                }
            }
            let mut get_value_resp: proto::Message = match proto::Message::decode(&body[..]) {
                Ok(get_value_resp) => get_value_resp,
                Err(_) => {
                    println!("failed to parse remote's exchage protobuf message");
                    return (); //Err("failed to parse remote's exchange protobuf".to_string());
                }
            };
            println!("get value struct:{:?}", get_value_resp.clone());
            let msg = proto_to_resp_msg(get_value_resp).unwrap();
            println!("KadResponseMsg:{:?}", msg.clone());

            buf = data_receiver.next().await;
            println!("receive remote  data:{:?}", buf);

            buf = data_receiver.next().await;
            println!("receive remote  data:{:?}", buf);

        });
        //   loop {
        let mut data = Vec::new();

        let mut len: u8 = MSG_MULTISTREAM_1_0.len() as u8;
        data.push(len);
        data.append(&mut MSG_MULTISTREAM_1_0.to_vec());


        let frame = Frame::data(stream_clone.id(), data.clone()).unwrap();
        //let frame = Frame::data(stream_clone.id(), format!("love and peace:{}", index).into_bytes()).unwrap();
        stream_clone.sender.send(StreamCommand::SendFrame(frame)).await;

        len = MSG_PAD_1_0.len() as u8;
        data.clear();
        data.push(len);
        data.append(&mut MSG_PAD_1_0.to_vec());

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
fn kad_client_test() {
    init_log("trace");
    async_std::task::block_on(async move {
        //let mut  connec = async_std::net::TcpStream::connect("104.131.131.82:4001").await.unwrap();
        let mut  connec = async_std::net::TcpStream::connect("127.0.0.1:5679").await.unwrap();
        let mut  local_addr: std::net::SocketAddr = connec.local_addr().unwrap();
        println!("localaddr:{:?}", local_addr);
        let addr = format!("/ip4/{}/tcp/{}",local_addr.ip().to_string() ,local_addr.port());
        println!("addr:{:?}", addr);
        let mut local_addr = addr.parse().unwrap();
      //  let mut local_addr = multiaddr!(local_addr.ip(), Tcp(local_addr.port() as u16));
        let match_proto = dialer_select_proto(connec.clone(), vec!["/secio/1.0.0\n".to_string(), "/yamux/1.0.0\n".to_string()], true).await;
        if match_proto.is_ok() {
            let proto = match_proto.unwrap();
            if proto.eq(&"/secio/1.0.0\n".as_bytes().to_vec()) {
                //let local_key = Keypair::generate_ed25519();
//                let local_secret_key = secio_identity::secp256k1::SecretKey::from_bytes(vec![55u8; 32]).unwrap();
//                let rar_key = secio_identity::secp256k1::Keypair::from(local_secret_key);
//                let local_key = Keypair::Secp256k1( rar_key.clone());
                let local_secret_key = SecretKey::from_bytes(vec![55u8; 32]).unwrap();
                let rar_key = secio_identity::ed25519::Keypair::from(local_secret_key);
                let local_key = Keypair::Ed25519( rar_key.clone());
//                let random_bytes = rar_key.public().encode();
//                let mh1 = multihash::Sha2_256::digest(&random_bytes);
//                let node_id = PeerId::try_from(mh1.clone()).unwrap();
//                println!("node_id:{:?}", node_id);
                let local_peer_id = PeerId::from(local_key.public());
                println!("local_id:{:?}", local_peer_id);
                let (mut session_reader, mut session_writer) = upgrade_secio_protocol(connec.clone(), local_key.clone(),Mode::Client).await.unwrap();
                let arc_reader = session_reader.socket.clone();
                let arc_writer = session_writer.socket.clone();
                let res = dialer_select_proto_secio(arc_reader.clone(), arc_writer.clone(), vec!["/yamux/1.0.0\n".to_string()]).await;
                if res.is_ok() {
                    println!("into yamux");
                    let (control_sender, control_receiver) = mpsc::channel(10);
                    let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone(), local_peer_id.clone(), local_key.clone(), local_addr);
                    let period_send = period_send( control_sender,local_peer_id ,local_key);
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
fn kad_client1_test() {
    init_log("trace");
    async_std::task::block_on(async move {
        //let mut  connec = async_std::net::TcpStream::connect("104.131.131.82:4001").await.unwrap();
        let mut  connec = async_std::net::TcpStream::connect("127.0.0.1:5679").await.unwrap();
        let mut  local_addr: std::net::SocketAddr = connec.local_addr().unwrap();
        println!("localaddr:{:?}", local_addr);
        let addr = format!("/ip4/{}/tcp/{}",local_addr.ip().to_string() ,local_addr.port());
        println!("addr:{:?}", addr);
        let mut local_addr = addr.parse().unwrap();
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
                    let (control_sender, control_receiver) = mpsc::channel(10);
                    let deal_remote_stream = remote_stream_deal(session_reader.stream_sender.clone(),control_sender.clone(), local_peer_id.clone(), local_key.clone(), local_addr);
                    let period_send = period_send_1( control_sender,local_peer_id ,local_key, retmoe_key);
                    let receive_process = session_reader.receive_loop( control_receiver);
                    let send_process = session_writer.send_process();
                    join!{receive_process, send_process, deal_remote_stream, period_send};//
                }
            }
        }
    })
}