use async_std::net::UdpSocket;
use std::{convert::TryFrom as _, fmt, io, net::Ipv4Addr, net::SocketAddr, str, time::{Duration, Instant}};
lazy_static! {
    static ref IPV4_MDNS_MULTICAST_ADDRESS: SocketAddr = SocketAddr::from((
        Ipv4Addr::new(224, 0, 0, 251),
        5353,
    ));
}

pub struct MdnsService {
    /// Main socket for listening.
    pub socket: UdpSocket,
    /// Socket for sending queries on the network.
    pub query_socket: UdpSocket,
    /// Interval for sending queries.
    //query_interval: Interval,
    /// Whether we send queries on the network at all.
    /// Note that we still need to have an interval for querying, as we need to wake up the socket
    /// regularly to recover from errors. Otherwise we could simply use an `Option<Interval>`.
    pub silent: bool,
    /// Buffer used for receiving data from the main socket.
    pub recv_buffer: [u8; 2048],
    /// Buffers pending to send on the main socket.
    pub send_buffers: Vec<Vec<u8>>,
    /// Buffers pending to send on the query socket.
    pub query_send_buffers: Vec<Vec<u8>>,
}

impl MdnsService {
    /// Starts a new mDNS service.
    pub fn new() -> io::Result<MdnsService> {
        Self::new_inner(false)
    }

    /// Same as `new`, but we don't automatically send queries on the network.
    pub fn silent() -> io::Result<MdnsService> {
        Self::new_inner(true)
    }

    /// Starts a new mDNS service.
    fn new_inner(silent: bool) -> io::Result<MdnsService> {
        let socket = {
            fn platform_specific(s: &net2::UdpBuilder) -> io::Result<()> {
                net2::unix::UnixUdpBuilderExt::reuse_port(s, true)?;
                Ok(())
            }

            let builder = net2::UdpBuilder::new_v4()?;
            builder.reuse_address(true)?;
            platform_specific(&builder)?;
            builder.bind(("0.0.0.0", 5353))?
        };

        let socket = UdpSocket::from(socket);
        socket.set_multicast_loop_v4(true)?;
        socket.set_multicast_ttl_v4(255)?;
        // TODO: correct interfaces?
        socket.join_multicast_v4(From::from([224, 0, 0, 251]), Ipv4Addr::UNSPECIFIED)?;

        Ok(MdnsService {
            socket,
            // Given that we pass an IP address to bind, which does not need to be resolved, we can
            // use std::net::UdpSocket::bind, instead of its async counterpart from async-std.
            query_socket: std::net::UdpSocket::bind((Ipv4Addr::from([0u8, 0, 0, 0]), 0u16))?.into(),
           // query_interval: Interval::new_at(Instant::now(), Duration::from_secs(20)),
            silent,
            recv_buffer: [0; 2048],
            send_buffers: Vec::new(),
            query_send_buffers: Vec::new(),
        })
    }
}

/// A received mDNS service discovery query.
pub struct MdnsServiceDiscovery {
    /// Sender of the address.
    pub from: SocketAddr,
    /// Id of the received DNS query. We need to pass this ID back in the results.
    pub query_id: u16,
}

impl fmt::Debug for MdnsServiceDiscovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsServiceDiscovery")
            .field("from", &self.from)
            .field("query_id", &self.query_id)
            .finish()
    }
}

/// A peer discovered by the service.
pub struct MdnsPeer {
    addrs: Vec<Multiaddr>,
    /// Id of the peer.
    peer_id: PeerId,
    /// TTL of the record in seconds.
    ttl: u32,
}


/// A received mDNS response.
pub struct MdnsResponse {
    pub peers: Vec<MdnsPeer>,
    pub from: SocketAddr,
}

impl MdnsResponse {
    /// Returns the list of peers that have been reported in this packet.
    ///
    /// > **Note**: Keep in mind that this will also contain the responses we sent ourselves.
    pub fn discovered_peers(&self) -> impl Iterator<Item = &MdnsPeer> {
        self.peers.iter()
    }

    /// Source address of the packet.
    #[inline]
    pub fn remote_addr(&self) -> &SocketAddr {
        &self.from

    }

impl fmt::Debug for MdnsResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsResponse")
            .field("from", self.remote_addr())
            .finish()
    }
}
