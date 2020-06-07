
/// The encoded form of a multistream-select 1.0.0 header message.
pub const MSG_MULTISTREAM_1_0: &[u8] = b"/multistream/1.0.0\n";

fn get_varint_len(mut buf: Vec<u8>) -> u32 {
    let mut len: u32 = 0;
    let step: u32 = 7;
    let mut pos: u32 = 0;
    let mut len_buf = [0u8; 1];
    loop {
        len_buf[0] = buf.pop().unwrap();
        if len_buf[0] & 0x80 == 0 {
            len = ((len_buf[0]  as u32) << pos)  | len;
            break;
        } else {
            len = (((len_buf[0]&0x7f) as u32) << pos)| len;
            pos += step;
        }
    }
    len
}
