pub mod service;

/// Hardcoded name of the mDNS service. Part of the mDNS libp2p specifications.
const SERVICE_NAME: &[u8] = b"_p2p._udp.local";
/// Hardcoded name of the service used for DNS-SD.
const META_QUERY_SERVICE: &[u8] = b"_services._dns-sd._udp.local";

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
