
/// The encoded form of a multistream-select 1.0.0 header message.
pub const MSG_MULTISTREAM_1_0: &[u8] = b"/multistream/1.0.0\n";

pub fn GetVarintLen(mut buf: Vec<u8>) -> u32 {
    let mut len: u32 = 0;
    let step: u32 = 7;
    let mut len_item = None;
    loop {
        len_item = buf.pop();
        if let Some(item) = len_item{
            len = (item as u32) | len<<step;

        } else {
            break;
        }
    }
    len
}
