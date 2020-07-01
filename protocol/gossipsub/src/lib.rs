pub mod gossipsub;
pub mod protocol;
pub mod topic;
pub mod topic_eth2;

use target_info::Target;

const TRACK: &str = "unstable";

/// Provides the current platform
pub fn platform() -> String {
    format!("{}-{}", Target::arch(), Target::os())
}

/// Version of the beacon node.
// TODO: Find the sha3 hash, date and rust version used to build the beacon_node binary
pub fn version() -> String {
    format!(
        "Lighthouse/v{}-{}/{}",
        env!("CARGO_PKG_VERSION"),
        TRACK,
        platform()
    )
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
