mod protocol;
mod listener_select;
mod dialer_select;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use protocol::get_varint_len;


#[test]
fn server_test() {
    async_std::task::block_on(async move {
        let listener = async_std::net::TcpListener::bind("127.0.0.1:5679").await.unwrap();
        let mut connec = listener.accept().await.unwrap().0;
        let mut len_buf = [0u8; 1];
        let mut varint_buf: Vec<u8> = Vec::new();
        loop {
            connec.read_exact(&mut len_buf).await.unwrap();

            if len_buf[0] & 0x80 == 0 {
                varint_buf.push(len_buf[0]);
                break;
            } else {
                varint_buf.push(len_buf[0]& 0x7f);
            }
        }
        let mut len =  get_varint_len(varint_buf);

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

        let mut varint_buf: Vec<u8> = Vec::new();
        loop {
            connec.read_exact(&mut len_buf).await.unwrap();

            if len_buf[0] & 0x80 == 0 {
                varint_buf.push(len_buf[0]);
                break;
            } else {
                varint_buf.push(len_buf[0]& 0x7f);
            }
        }
        len =  get_varint_len(varint_buf);
        let mut read_buf = vec![0u8; len as usize];
        connec.read_exact(&mut read_buf).await.unwrap();
        println!("buf_len:{},buf:{:?}", len, read_buf);
        len_buf[0] = read_buf.len() as u8;
        let res = connec.write_all(&len_buf).await;
        let res = connec.write_all(&read_buf).await;
    });
}
