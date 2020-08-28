
/// The endpoint roles associated with a peer-to-peer communication channel.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// The socket comes from a dialer.
    Dialer,
    /// The socket comes from a listener.
    Listener,
}

// Maximum size for a packet: 1MB as per the spec.
// Since data is entirely buffered before being dispatched, we need a limit or remotes could just
// send a 4 TB-long packet full of zeroes that we kill our process with an OOM error.
pub(crate) const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub enum Elem {
    Open { substream_id: u32 },
    Data { substream_id: u32, endpoint: Endpoint, data: Vec<u8>},
    Close { substream_id: u32, endpoint: Endpoint },
    Reset { substream_id: u32, endpoint: Endpoint },
}

impl Elem {
    /// Returns the ID of the substream of the message.
    pub fn substream_id(&self) -> u32 {
        match *self {
            Elem::Open { substream_id } => substream_id,
            Elem::Data { substream_id, .. } => substream_id,
            Elem::Close { substream_id, .. } => substream_id,
            Elem::Reset { substream_id, .. } => substream_id,
        }
    }

    pub fn endpoint(&self) -> Option<Endpoint> {
        match *self {
            Elem::Open { .. } => None,
            Elem::Data { endpoint, .. } => Some(endpoint),
            Elem::Close { endpoint, .. } => Some(endpoint),
            Elem::Reset { endpoint, .. } => Some(endpoint)
        }
    }

    /// Returns true if this message is `Close` or `Reset`.
    #[inline]
    pub fn is_close_or_reset_msg(&self) -> bool {
        match self {
            Elem::Close { .. } | Elem::Reset { .. } => true,
            _ => false,
        }
    }

    /// Returns true if this message is `Open`.
    #[inline]
    pub fn is_open_msg(&self) -> bool {
        if let Elem::Open { .. } = self {
            true
        } else {
            false
        }
    }
}

//fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
//    loop {
//        match mem::replace(&mut self.decoder_state, CodecDecodeState::Poisoned) {
//            CodecDecodeState::Begin => {
//                match self.varint_decoder.decode(src)? {
//                    Some(header) => {
//                        self.decoder_state = CodecDecodeState::HasHeader(header);
//                    },
//                    None => {
//                        self.decoder_state = CodecDecodeState::Begin;
//                        return Ok(None);
//                    },
//                }
//            },
//            CodecDecodeState::HasHeader(header) => {
//                match self.varint_decoder.decode(src)? {
//                    Some(len) => {
//                        if len as usize > MAX_FRAME_SIZE {
//                            let msg = format!("Mplex frame length {} exceeds maximum", len);
//                            return Err(IoError::new(IoErrorKind::InvalidData, msg));
//                        }
//
//                        self.decoder_state = CodecDecodeState::HasHeaderAndLen(header, len as usize);
//                    },
//                    None => {
//                        self.decoder_state = CodecDecodeState::HasHeader(header);
//                        return Ok(None);
//                    },
//                }
//            },
//            CodecDecodeState::HasHeaderAndLen(header, len) => {
//                if src.len() < len {
//                    self.decoder_state = CodecDecodeState::HasHeaderAndLen(header, len);
//                    let to_reserve = len - src.len();
//                    src.reserve(to_reserve);
//                    return Ok(None);
//                }
//
//                let buf = src.split_to(len);
//                let substream_id = (header >> 3) as u32;
//                let out = match header & 7 {
//                    0 => Elem::Open { substream_id },
//                    1 => Elem::Data { substream_id, endpoint: Endpoint::Listener, data: buf.freeze() },
//                    2 => Elem::Data { substream_id, endpoint: Endpoint::Dialer, data: buf.freeze() },
//                    3 => Elem::Close { substream_id, endpoint: Endpoint::Listener },
//                    4 => Elem::Close { substream_id, endpoint: Endpoint::Dialer },
//                    5 => Elem::Reset { substream_id, endpoint: Endpoint::Listener },
//                    6 => Elem::Reset { substream_id, endpoint: Endpoint::Dialer },
//                    _ => {
//                        let msg = format!("Invalid mplex header value 0x{:x}", header);
//                        return Err(IoError::new(IoErrorKind::InvalidData, msg));
//                    },
//                };
//
//                self.decoder_state = CodecDecodeState::Begin;
//                return Ok(Some(out));
//            },
//
//            CodecDecodeState::Poisoned => {
//                return Err(IoError::new(IoErrorKind::InvalidData, "Mplex codec poisoned"));
//            }
//        }
//    }
//}
//
//
//fn encode(item: Elem, dst: &mut BytesMut) -> Result<(), Self::Error> {
//    let (header, data) = match item {
//        Elem::Open { substream_id } => {
//            (u64::from(substream_id) << 3, Bytes::new())
//        },
//        Elem::Data { substream_id, endpoint: Endpoint::Listener, data } => {
//            (u64::from(substream_id) << 3 | 1, data)
//        },
//        Elem::Data { substream_id, endpoint: Endpoint::Dialer, data } => {
//            (u64::from(substream_id) << 3 | 2, data)
//        },
//        Elem::Close { substream_id, endpoint: Endpoint::Listener } => {
//            (u64::from(substream_id) << 3 | 3, Bytes::new())
//        },
//        Elem::Close { substream_id, endpoint: Endpoint::Dialer } => {
//            (u64::from(substream_id) << 3 | 4, Bytes::new())
//        },
//        Elem::Reset { substream_id, endpoint: Endpoint::Listener } => {
//            (u64::from(substream_id) << 3 | 5, Bytes::new())
//        },
//        Elem::Reset { substream_id, endpoint: Endpoint::Dialer } => {
//            (u64::from(substream_id) << 3 | 6, Bytes::new())
//        },
//    };
//
//    let mut header_buf = encode::u64_buffer();
//    let header_bytes = encode::u64(header, &mut header_buf);
//
//    let data_len = data.as_ref().len();
//    let mut data_buf = encode::usize_buffer();
//    let data_len_bytes = encode::usize(data_len, &mut data_buf);
//
//    if data_len > MAX_FRAME_SIZE {
//        return Err(IoError::new(IoErrorKind::InvalidData, "data size exceed maximum"));
//    }
//
//    dst.reserve(header_bytes.len() + data_len_bytes.len() + data_len);
//    dst.put(header_bytes);
//    dst.put(data_len_bytes);
//    dst.put(data);
//    Ok(())
//}
