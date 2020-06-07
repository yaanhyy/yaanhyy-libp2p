mod protocol;

use futures_util::io::{AsyncReadExt, AsyncWriteExt};


fn get_varint_len() -> u32 {
    0
}


#[test]
fn server_test() {
    async_std::task::block_on(async move {
        let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
        let mut connec = listener.accept().await.unwrap().0;
        let mut len_buf = [0u8; 1];
        let mut len: u32 = 0;
        let step: u32 = 7;
        let mut pos: u32 = 0;
     //   let mut test_buf: Vec<u8> = vec![0x02, 0xac];
        loop {
            connec.read_exact(&mut len_buf).await.unwrap();
       //     len_buf[0] =test_buf.pop().unwrap();
            if len_buf[0] & 0x80 == 0 {
                len = ((len_buf[0]  as u32) << pos)  | len;
                break;
            } else {
                len = (((len_buf[0]&0x7f) as u32) << pos)| len;
                pos += step;
            }
        }



        let mut read_buf = vec![0u8; len as usize];
        connec.read_exact(&mut read_buf).await.unwrap();
        println!("buf_len:{},buf:{:?}", len, read_buf);
        len_buf[0] = protocol::MSG_MULTISTREAM_1_0.len() as u8;
        let res = connec.write_all(&len_buf).await;
        let res = connec.write_all(protocol::MSG_MULTISTREAM_1_0).await;
        match res {
            Ok(()) => (),
            Err(e) => println!("write err:{:?}", e),
        }
        let mut read_buf = vec![0u8; 2];
        connec.read_exact(&mut read_buf).await.unwrap();
        println!("buf_len:{},buf:{:?}", len, read_buf);
    });
}
