use std::{collections::HashMap, default::Default, net::SocketAddr, sync::atomic::Ordering};
use crate::packet::{AuthHeader, AuthTag, Magic, Nonce, Packet, Tag, TAG_LENGTH};
use crate::rpc::{Message, Request, RequestBody, RequestId, Response, ResponseBody};
use enr::{CombinedKey, NodeId, Enr, secp256k1::SecretKey};
use crate::node_info::NodeAddress;
use std::sync::Arc;
use crate::session::Session;
use sha2::{Digest,Sha256};

pub struct Handler {
    /// The local node id to save unnecessary read locks on the ENR. The NodeID should not change
/// during the operation of the server.
    pub node_id: NodeId,
    /// The local ENR.
    pub enr: Enr<CombinedKey>,
    /// The key to sign the ENR and set up encrypted communication with peers.
    pub key: CombinedKey,
    pub active_requests_auth: HashMap<AuthTag, NodeAddress>,
    pub sessions: HashMap<NodeAddress, Session>,
}

impl Handler {
    pub fn new_session(&mut self, node_address: NodeAddress, session: Session) {
        self.sessions.insert(node_address, session);
    }

    pub fn src_id(&self, tag: &Tag) -> NodeId {
        let hash = Sha256::digest(&self.node_id.raw());
        let mut src_id: [u8; 32] = Default::default();
        for i in 0..32 {
            src_id[i] = hash[i] ^ tag[i];
        }
        NodeId::new(&src_id)
    }

}