/// Record represents a dht record that contains a value
/// for a key value pair
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Record {
    /// The key that references this record
    #[prost(bytes, tag="1")]
    pub key: std::vec::Vec<u8>,
    /// The actual value this record is storing
    #[prost(bytes, tag="2")]
    pub value: std::vec::Vec<u8>,
    // Note: These fields were removed from the Record message
    // hash of the authors public key
    //optional string author = 3;
    // A PKI signature for the key+value+author
    //optional bytes signature = 4;

    /// Time the record was received, set by receiver
    #[prost(string, tag="5")]
    pub time_received: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    /// defines what type of message it is.
    #[prost(enumeration="message::MessageType", tag="1")]
    pub r#type: i32,
    /// defines what coral cluster level this query/response belongs to.
    /// in case we want to implement coral's cluster rings in the future.
    #[prost(int32, tag="10")]
    pub cluster_level_raw: i32,
    /// Used to specify the key associated with this message.
    /// PUT_VALUE, GET_VALUE, ADD_PROVIDER, GET_PROVIDERS
    #[prost(bytes, tag="2")]
    pub key: std::vec::Vec<u8>,
    /// Used to return a value
    /// PUT_VALUE, GET_VALUE
    #[prost(message, optional, tag="3")]
    pub record: ::std::option::Option<Record>,
    /// Used to return peers closer to a key in a query
    /// GET_VALUE, GET_PROVIDERS, FIND_NODE
    #[prost(message, repeated, tag="8")]
    pub closer_peers: ::std::vec::Vec<message::Peer>,
    /// Used to return Providers
    /// GET_VALUE, ADD_PROVIDER, GET_PROVIDERS
    #[prost(message, repeated, tag="9")]
    pub provider_peers: ::std::vec::Vec<message::Peer>,
}
pub mod message {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Peer {
        /// ID of a given peer.
        #[prost(bytes, tag="1")]
        pub id: std::vec::Vec<u8>,
        /// multiaddrs for a given peer
        #[prost(bytes, repeated, tag="2")]
        pub addrs: ::std::vec::Vec<std::vec::Vec<u8>>,
        /// used to signal the sender's connection capabilities to the peer
        #[prost(enumeration="ConnectionType", tag="3")]
        pub connection: i32,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum MessageType {
        PutValue = 0,
        GetValue = 1,
        AddProvider = 2,
        GetProviders = 3,
        FindNode = 4,
        Ping = 5,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ConnectionType {
        /// sender does not have a connection to peer, and no extra information (default)
        NotConnected = 0,
        /// sender has a live connection to peer
        Connected = 1,
        /// sender recently connected to peer
        CanConnect = 2,
        /// sender recently tried to connect to peer repeatedly but failed to connect
        /// ("try" here is loose, but this should signal "made strong effort, failed")
        CannotConnect = 3,
    }
}
