use std::{collections::HashMap, default::Default, net::SocketAddr, sync::atomic::Ordering};
use crate::packet::{AuthHeader, AuthTag, Magic, Nonce, Packet, Tag, TAG_LENGTH};
use crate::rpc::{Message, Request, RequestBody, RequestId, Response, ResponseBody};
use enr::{CombinedKey, NodeId, Enr, secp256k1::SecretKey};
use crate::node_info::NodeAddress;
use std::sync::Arc;

pub struct Handler {
    /// The local node id to save unnecessary read locks on the ENR. The NodeID should not change
/// during the operation of the server.
    pub node_id: NodeId,
    /// The local ENR.
    pub enr: Enr<CombinedKey>,
    /// The key to sign the ENR and set up encrypted communication with peers.
    pub key: Arc<CombinedKey>,
    pub active_requests_auth: HashMap<AuthTag, NodeAddress>,
}