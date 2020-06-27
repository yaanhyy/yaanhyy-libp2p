use env_logger;
use log::debug;
use futures::prelude::*;

pub async fn write_varint(socket: &mut (impl AsyncWrite + Unpin), len: usize)
                          -> Result<(), String>
{
    let mut len_data = unsigned_varint::encode::usize_buffer();
    let encoded_len = unsigned_varint::encode::usize(len, &mut len_data).len();
    socket.write_all(&len_data[..encoded_len]).await;
    Ok(())
}

pub fn insert_frame_len(mut raw_data: Vec<u8>) -> Vec<u8>{
    let mut len_data = unsigned_varint::encode::usize_buffer();
    let len= raw_data.len();
    let encoded_len = unsigned_varint::encode::usize(len, &mut len_data).len();
    let mut head_length = len_data[..encoded_len].to_vec();
    head_length.append(& mut raw_data);
    head_length
}

pub fn init_log(log_level: &str){
    use std::io::Write;
    use chrono::Local;
    let env = env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV,log_level);
    env_logger::Builder::from_env(env).format(|buf,record|{
        writeln!(
            buf,
            "{} {} [{}:{}] {} {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.module_path().unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            record.target(),
            &record.args()
        )
    }).init();
    debug!("log config success")
}

#[test]
fn insert_frame_len_test() {
    let mut raw = vec![0x55u8; 131];
    let raw = insert_frame_len(raw);
    println!("insert data:{:?}", raw);
}