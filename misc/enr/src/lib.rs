use enr::{EnrBuilder, secp256k1::SecretKey, Enr, ed25519_dalek::Keypair, CombinedKey};
use std::net::Ipv4Addr;
use rand::thread_rng;
use rand::Rng;



#[test]
fn it_works() {
    let mut env = "enr:-Ku4QJsxkOibTc9FXfBWYmcdMAGwH4bnOOFb4BlTHfMdx_f0WN-u4IUqZcQVP9iuEyoxipFs7-Qd_rH_0HfyOQitc7IBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhLAJM9iJc2VjcDI1NmsxoQL2RyM26TKZzqnUsyycHQB4jnyg6Wi79rwLXtaZXty06YN1ZHCCW8w";


// generate a random secp256k1 key
    let mut rng = thread_rng();
    let key = SecretKey::random(&mut rng);
    let ip = Ipv4Addr::new(192,168,0,1);
    let enr_secp256k1 = EnrBuilder::new("v4").ip(ip.into()).tcp(8000).build(&key).unwrap();

// encode to base64
    let base64_string_secp256k1 = enr_secp256k1.to_base64();

// generate a random ed25519 key
    let key = Keypair::generate(&mut rng);
    let enr_ed25519 = EnrBuilder::new("v4").ip(ip.into()).tcp(8000).build(&key).unwrap();

// encode to base64
    let base64_string_ed25519 = enr_ed25519.to_base64();
    println!("base64_string_ed25519:{:?}", base64_string_ed25519);

    let decoded_enr_eth2: Enr<SecretKey> = env.to_string().parse().unwrap();
    println!("decoded_enr_eth2 ip:{:?}", decoded_enr_eth2.ip() );
    println!("decoded_enr_eth2 pubkey:{:?}", decoded_enr_eth2.public_key() );
    println!("decoded_enr_eth2 udp port:{:?}", decoded_enr_eth2.udp());
    println!("decoded_enr_eth2 tcp port:{:?}", decoded_enr_eth2.tcp() );
    println!("decoded_enr_eth2 node id:{:?}", decoded_enr_eth2.node_id() );
    println!("decoded_enr_eth2 signature:{:?}", decoded_enr_eth2.signature() );
    println!("decoded_enr_eth2 verify:{:?}", decoded_enr_eth2.verify() );
    println!("decoded_enr_eth2 seq:{:?}", decoded_enr_eth2.seq() );
    println!("decoded_enr_eth2 id:{:?}", decoded_enr_eth2.id() );
// decode base64 strings of varying key types
// decode the secp256k1 with default Enr
   // let decoded_enr_secp256k1: Enr = base64_string_secp256k1.parse().unwrap();
// decode ed25519 ENRs
    let decoded_enr_ed25519: Enr<Keypair> = base64_string_ed25519.parse().unwrap();

// use the combined key to be able to decode either
    let decoded_enr: Enr<CombinedKey> = base64_string_secp256k1.parse().unwrap();
  //  let decoded_enr: Enr<CombinedKey> = base64_string_ed25519.parse().unwrap();

}
