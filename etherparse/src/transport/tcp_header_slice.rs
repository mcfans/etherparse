use crate::{
    err::{ValueTooBigError, ValueType},
    *,
};

/// A slice containing an tcp header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeaderSlice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> TcpHeaderSlice<'a> {
    /// Creates a slice containing an tcp header.
    pub fn from_slice(slice: &'a [u8]) -> Result<TcpHeaderSlice<'a>, err::tcp::HeaderSliceError> {
        use err::tcp::{HeaderError::*, HeaderSliceError::*};

        //check length
        if slice.len() < TcpHeader::MIN_LEN {
            return Err(Len(err::LenError {
                required_len: TcpHeader::MIN_LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::TcpHeader,
                layer_start_offset: 0,
            }));
        }

        // SAFETY:
        // Safe as it is checked at the start of the function that the
        // length of the slice is at least TcpHeader::MIN_LEN (20).
        let header_len = unsafe {
            // The length of the TCP header can be determined via
            // the data offset field of the TCP header. "data offset"
            // stores the offset in 4 byte steps from the start of the
            // header to the payload of the header.
            //
            // "data offset" is stored in the upper 4 bits
            // (aka 0b1111_0000) of byte 12. To get to total length
            // in bytes of the header data offset has to be multiplied
            // by 4. So the naive version to get the length of
            // the header would be:
            //
            // ```
            // let data_offset = (*slice.get_unchecked(12) & 0xf0) >> 4;
            // let len = data_offset * 4;
            // ```
            //
            // But a multiplication by 4 can be replaced by 2
            // left shift:
            //
            // ```
            // let data_offset = (*slice.get_unchecked(12) & 0xf0) >> 4;
            // let len = data_offset << 2;
            // ```
            //
            // And finally the shifts can be combined to one:
            //
            // ```
            // let len = (*slice.get_unchecked(12) & 0xf0) >> 2;
            // ```
            usize::from((*slice.get_unchecked(12) & 0xf0) >> 2)
        };

        if header_len < TcpHeader::MIN_LEN {
            Err(Content(DataOffsetTooSmall {
                data_offset: (header_len >> 2) as u8,
            }))
        } else if slice.len() < header_len {
            Err(Len(err::LenError {
                required_len: header_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::TcpHeader,
                layer_start_offset: 0,
            }))
        } else {
            //done
            Ok(TcpHeaderSlice::<'a> {
                // SAFETY:
                // Safe as there is a check above that the slice length
                // is at least len.
                slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), header_len) },
            })
        }
    }

    /// Returns the slice containing the tcp header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the source port number.
    #[inline]
    pub fn source_port(&self) -> u16 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr()) }
    }

    /// Read the destination port number.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Read the sequence number of the first data octet in this segment (except when SYN is present).
    ///
    /// If SYN is present the sequence number is the initial sequence number (ISN)
    /// and the first data octet is ISN+1.
    /// \[copied from RFC 793, page 16\]
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(4)) }
    }

    /// Reads the acknowledgment number.
    ///
    /// If the ACK control bit is set this field contains the value of the
    /// next sequence number the sender of the segment is expecting to
    /// receive.
    ///
    /// Once a connection is established this is always sent.
    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(8)) }
    }

    /// Read the number of 32 bit words in the TCP Header.
    ///
    /// This indicates where the data begins.  The TCP header (even one including options) is an
    /// integral number of 32 bits long.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { (*self.slice.get_unchecked(12) & 0b1111_0000) >> 4 }
    }

    /// ECN-nonce - concealment protection (experimental: see RFC 3540)
    #[inline]
    pub fn ns(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(12) & 0b0000_0001) }
    }

    /// Read the fin flag (no more data from sender).
    #[inline]
    pub fn fin(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0000_0001) }
    }

    /// Reads the syn flag (synchronize sequence numbers).
    #[inline]
    pub fn syn(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0000_0010) }
    }

    /// Reads the rst flag (reset the connection).
    #[inline]
    pub fn rst(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0000_0100) }
    }

    /// Reads the psh flag (push function).
    #[inline]
    pub fn psh(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0000_1000) }
    }

    /// Reads the ack flag (acknowledgment field significant).
    #[inline]
    pub fn ack(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0001_0000) }
    }

    /// Reads the urg flag (Urgent Pointer field significant).
    #[inline]
    pub fn urg(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0010_0000) }
    }

    /// Read the ECN-Echo flag (RFC 3168).
    #[inline]
    pub fn ece(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0100_0000) }
    }

    /// Reads the cwr flag (Congestion Window Reduced).
    ///
    /// This flag is set by the sending host to indicate that it received a TCP
    /// segment with the ECE flag set and had responded in congestion control
    /// mechanism (added to header by RFC 3168).
    #[inline]
    pub fn cwr(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b1000_0000) }
    }

    /// The number of data octets beginning with the one indicated in the
    /// acknowledgment field which the sender of this segment is willing to
    /// accept.
    #[inline]
    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe { [*self.slice.get_unchecked(14), *self.slice.get_unchecked(15)] },
        )
    }

    /// Checksum (16 bit one's complement) of the pseudo ip header, this tcp header and the payload.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe { [*self.slice.get_unchecked(16), *self.slice.get_unchecked(17)] },
        )
    }

    /// This field communicates the current value of the urgent pointer as a
    /// positive offset from the sequence number in this segment.
    ///
    /// The urgent pointer points to the sequence number of the octet following
    /// the urgent data.  This field is only be interpreted in segments with
    /// the URG control bit set.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe { [*self.slice.get_unchecked(18), *self.slice.get_unchecked(19)] },
        )
    }

    /// Options of the header
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.slice[TcpHeader::MIN_LEN..self.data_offset() as usize * 4]
    }

    /// Returns an iterator that allows to iterate through all known TCP header options.
    #[inline]
    pub fn options_iterator(&self) -> TcpOptionsIterator {
        TcpOptionsIterator::from_slice(self.options())
    }

    /// Decode all the fields and copy the results to a TcpHeader struct
    pub fn to_header(&self) -> TcpHeader {
        TcpHeader {
            source_port: self.source_port(),
            destination_port: self.destination_port(),
            sequence_number: self.sequence_number(),
            acknowledgment_number: self.acknowledgment_number(),
            ns: self.ns(),
            fin: self.fin(),
            syn: self.syn(),
            rst: self.rst(),
            psh: self.psh(),
            ack: self.ack(),
            ece: self.ece(),
            urg: self.urg(),
            cwr: self.cwr(),
            window_size: self.window_size(),
            checksum: self.checksum(),
            urgent_pointer: self.urgent_pointer(),
            options: {
                let options_slice = self.options();
                let mut options = TcpOptions {
                    len: options_slice.len() as u8,
                    buf: [0; 40],
                };
                options.buf[..options_slice.len()].clone_from_slice(options_slice);
                options
            },
        }
    }

    /// Calculates the TCP header checksum based on a ipv4 header and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4(
        &self,
        ip_header: &Ipv4HeaderSlice,
        payload: &[u8],
    ) -> Result<u16, ValueTooBigError<usize>> {
        self.calc_checksum_ipv4_raw(ip_header.source(), ip_header.destination(), payload)
    }

    /// Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4_raw(
        &self,
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        payload: &[u8],
    ) -> Result<u16, ValueTooBigError<usize>> {
        // check that the total length fits into the field
        let header_len = self.slice.len() as u16;
        let max_payload = usize::from(core::u16::MAX) - usize::from(header_len);
        if max_payload < payload.len() {
            return Err(ValueTooBigError {
                actual: payload.len(),
                max_allowed: max_payload,
                value_type: ValueType::TcpPayloadLengthIpv4,
            });
        }

        // calculate the checksum
        let tcp_len = header_len + (payload.len() as u16);
        Ok(self.calc_checksum_post_ip(
            checksum::Sum16BitWords::new()
                .add_4bytes(source_ip)
                .add_4bytes(destination_ip)
                .add_2bytes([0, ip_number::TCP.0])
                .add_2bytes((tcp_len).to_be_bytes()),
            payload,
        ))
    }

    /// Calculates the TCP header checksum based on a ipv6 header and returns the result. This does NOT set the checksum..
    pub fn calc_checksum_ipv6(
        &self,
        ip_header: &Ipv6HeaderSlice,
        payload: &[u8],
    ) -> Result<u16, ValueTooBigError<usize>> {
        self.calc_checksum_ipv6_raw(ip_header.source(), ip_header.destination(), payload)
    }

    /// Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(
        &self,
        source: [u8; 16],
        destination: [u8; 16],
        payload: &[u8],
    ) -> Result<u16, ValueTooBigError<usize>> {
        // check that the total length fits into the field
        let header_len = self.slice.len() as u32;
        let max_payload = (core::u32::MAX as usize) - (header_len as usize);
        if max_payload < payload.len() {
            return Err(ValueTooBigError {
                actual: payload.len(),
                max_allowed: max_payload,
                value_type: ValueType::TcpPayloadLengthIpv6,
            });
        }

        // calculate the checksum
        let tcp_len = header_len + (payload.len() as u32);
        Ok(self.calc_checksum_post_ip(
            checksum::Sum16BitWords::new()
                .add_16bytes(source)
                .add_16bytes(destination)
                .add_2bytes([0, ip_number::TCP.0])
                .add_4bytes((tcp_len).to_be_bytes()),
            payload,
        ))
    }

    /// This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(
        &self,
        ip_pseudo_header_sum: checksum::Sum16BitWords,
        payload: &[u8],
    ) -> u16 {
        ip_pseudo_header_sum
            .add_slice(&self.slice[..16]) //until checksum
            .add_slice(&self.slice[18..self.slice.len()])
            .add_slice(payload)
            .ones_complement()
            .to_be()
    }
}

#[cfg(test)]
mod test {
    use std::io::IoSlice;

    use crate::{
        err::{
            tcp::{HeaderError::*, HeaderSliceError::*},
            ValueTooBigError, ValueType,
        },
        test_gens::*,
        TcpOptionElement::*,
        *,
    };
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn debug(header in tcp_any()) {
            let buffer = header.to_bytes();
            let slice = TcpHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                format!("{:?}", slice),
                format!("TcpHeaderSlice {{ slice: {:?} }}", slice.slice())
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(header in tcp_any()) {
            let bytes = header.to_bytes();
            let slice = TcpHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice.clone(), slice);
        }
    }

    proptest! {
        #[test]
        fn from_slice(header in tcp_any()) {
            // ok case
            {
                let bytes = {
                    let mut bytes = header.to_bytes();
                    bytes.try_extend_from_slice(
                        &([0u8;TcpHeader::MAX_LEN])[..bytes.remaining_capacity()]
                    ).unwrap();
                    bytes
                };

                let slice = TcpHeaderSlice::from_slice(&bytes[..]).unwrap();
                assert_eq!(slice.slice(), &bytes[..header.header_len() as usize]);
                assert_eq!(slice.to_header(), header);
            }

            // data offset error
            for data_offset in 0..TcpHeader::MIN_DATA_OFFSET {
                let bytes = {
                    let mut bytes = header.to_bytes();
                    bytes[12] = (bytes[12] & 0xf) | ((data_offset << 4) & 0xf0);
                    bytes
                };
                assert_eq!(
                    TcpHeaderSlice::from_slice(&bytes[..]),
                    Err(Content(DataOffsetTooSmall{ data_offset }))
                );
            }

            // length error
            {
                let bytes = header.to_bytes();
                for len in 0..(header.header_len() as usize) {
                    assert_eq!(
                        TcpHeaderSlice::from_slice(&bytes[..len])
                            .unwrap_err(),
                        Len(err::LenError {
                            required_len: if len < TcpHeader::MIN_LEN {
                                TcpHeader::MIN_LEN
                            } else {
                                header.header_len() as usize
                            },
                            len: len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::TcpHeader,
                            layer_start_offset: 0,
                        })
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn getters(header in tcp_any()) {
            let bytes = header.to_bytes();
            let slice = TcpHeaderSlice::from_slice(&bytes).unwrap();

            assert_eq!(header.source_port, slice.source_port());
            assert_eq!(header.destination_port, slice.destination_port());
            assert_eq!(header.sequence_number, slice.sequence_number());
            assert_eq!(header.acknowledgment_number, slice.acknowledgment_number());
            assert_eq!(header.data_offset(), slice.data_offset());
            assert_eq!(header.ns, slice.ns());
            assert_eq!(header.fin, slice.fin());
            assert_eq!(header.syn, slice.syn());
            assert_eq!(header.rst, slice.rst());
            assert_eq!(header.psh, slice.psh());
            assert_eq!(header.ack, slice.ack());
            assert_eq!(header.urg, slice.urg());
            assert_eq!(header.ece, slice.ece());
            assert_eq!(header.cwr, slice.cwr());
            assert_eq!(header.window_size, slice.window_size());
            assert_eq!(header.checksum, slice.checksum());
            assert_eq!(header.urgent_pointer, slice.urgent_pointer());
            assert_eq!(header.options.as_slice(), slice.options());
        }
    }

    proptest! {
        #[test]
        fn options_iterator(header in tcp_any()) {
            let bytes = header.to_bytes();
            let slice = TcpHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(
                TcpOptionsIterator::from_slice(header.options.as_slice()),
                slice.options_iterator()
            );
        }
    }

    proptest! {
        #[test]
        fn to_header(header in tcp_any()) {
            let bytes = header.to_bytes();
            let slice = TcpHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(header, slice.to_header());
        }
    }

    #[test]
    fn calc_checksum_ipv4() {
        // checksum == 0xf (no carries) (aka sum == 0xffff)
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];

            // setup headers
            let tcp = TcpHeader::new(0, 0, 40905, 0);
            let ip_header = Ipv4Header::new(
                //payload length
                tcp.header_len_u16() + (tcp_payload.len() as u16),
                //time to live
                0,
                ip_number::TCP,
                //source ip address
                [0; 4],
                //destination ip address
                [0; 4],
            )
            .unwrap();

            // setup slices
            let ip_bytes = ip_header.to_bytes();
            let ip_slice = Ipv4HeaderSlice::from_slice(&ip_bytes).unwrap();

            let tcp_bytes = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_bytes).unwrap();

            assert_eq!(
                Ok(0x0),
                tcp_slice.calc_checksum_ipv4(&ip_slice, &tcp_payload)
            );
        }

        //a header with options
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];

            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;
            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            let ip_header = Ipv4Header::new(
                //payload length
                tcp.header_len_u16() + (tcp_payload.len() as u16),
                //time to live
                20,
                ip_number::TCP,
                //source ip address
                [192, 168, 1, 42],
                //destination ip address
                [192, 168, 1, 1],
            )
            .unwrap();

            // setup slices
            let ip_buffer = ip_header.to_bytes();
            let ip_slice = Ipv4HeaderSlice::from_slice(&ip_buffer).unwrap();

            let tcp_buffer = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer).unwrap();

            assert_eq!(
                Ok(0xdeeb),
                tcp_slice.calc_checksum_ipv4(&ip_slice, &tcp_payload)
            );
        }

        //a header with an uneven number of options
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8, 9];

            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;
            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            let ip_header = Ipv4Header::new(
                //payload length
                tcp.header_len_u16() + (tcp_payload.len() as u16),
                //time to live
                20,
                ip_number::TCP,
                //source ip address
                [192, 168, 1, 42],
                //destination ip address
                [192, 168, 1, 1],
            )
            .unwrap();

            // setup slices
            let ip_buffer = ip_header.to_bytes();
            let ip_slice = Ipv4HeaderSlice::from_slice(&ip_buffer[..]).unwrap();

            let tcp_buffer = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

            assert_eq!(
                Ok(0xd5ea),
                tcp_slice.calc_checksum_ipv4(&ip_slice, &tcp_payload)
            );
        }

        // value error
        {
            // write the tcp header
            let tcp: TcpHeader = Default::default();
            let len = (core::u16::MAX - tcp.header_len_u16()) as usize + 1;
            let mut tcp_payload = Vec::with_capacity(len);
            tcp_payload.resize(len, 0);
            let ip_header = Ipv4Header::new(0, 0, ip_number::TCP, [0; 4], [0; 4]).unwrap();

            // setup slices
            let ip_buffer = ip_header.to_bytes();
            let ip_slice = Ipv4HeaderSlice::from_slice(&ip_buffer).unwrap();

            let tcp_buffer = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer).unwrap();

            assert_eq!(
                tcp_slice.calc_checksum_ipv4(&ip_slice, &tcp_payload),
                Err(ValueTooBigError {
                    actual: len,
                    max_allowed: usize::from(core::u16::MAX - tcp.header_len_u16()),
                    value_type: ValueType::TcpPayloadLengthIpv4,
                })
            );
        }
    }

    #[test]
    fn calc_checksum_ipv4_raw_with_slices() {
        let data = "AAABL3siY3B1X3V0aWxfdG90YWwiOjcuMzY4NjY2MjI3MTU4ODgyMSwiY3B1X3V0aWxfdXNlciI6MC40NDQ1MDkzMDk4ODQ0NzY3MywiY3B1X3V0aWxfc3lzdGVtIjo2LjkyNDE1NjkxNzI3NDQwNTcsInNlbmRlcl9oYXNfcmV0cmFuc21pdHMiOjAsInN0cmVhbXMiOlt7ImlkIjoxLCJieXRlcyI6MTE3ODUyMDc4MDgsInJldHJhbnNtaXRzIjotMSwiaml0dGVyIjowLCJlcnJvcnMiOjAsIm9taXR0ZWRfZXJyb3JzIjowLCJwYWNrZXRzIjowLCJvbWl0dGVkX3BhY2tldHMiOjAsInN0YXJ0X3RpbWUiOjAsImVuZF90aW1lIjoxMC4wMDM2MX1dfQ4=";
        let tcp_payload = base64::decode(data).unwrap();
        let mut tcp = TcpHeader::new(5201, 51700, 1498745178, 32768);
        tcp.ack = true;
        tcp.acknowledgment_number = 388221267;

        tcp.set_options(&[WindowScale(5)]).unwrap();

        assert_eq!(
            tcp.calc_checksum_ipv4_raw([192, 168, 100, 1], [10, 0, 0, 1], &tcp_payload)
                .unwrap(),
            tcp.calc_checksum_ipv4_raw_with_slices_simd(
                [192, 168, 100, 1],
                [10, 0, 0, 1],
                &[IoSlice::new(&tcp_payload)]
            )
            .unwrap()
        );
        let payload_8_byte = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            tcp.calc_checksum_ipv4_raw([192, 168, 100, 1], [10, 0, 0, 1], &payload_8_byte)
                .unwrap(),
            tcp.calc_checksum_ipv4_raw_with_slices_simd(
                [192, 168, 100, 1],
                [10, 0, 0, 1],
                &[IoSlice::new(&payload_8_byte)]
            )
            .unwrap()
        );

        let mut payload = [0; 256 + 7];
        rand::thread_rng().fill(&mut payload[..]);
        assert_eq!(
            tcp.calc_checksum_ipv4_raw([192, 168, 100, 1], [10, 0, 0, 1], &payload)
                .unwrap(),
            tcp.calc_checksum_ipv4_raw_with_slices_simd(
                [192, 168, 100, 1],
                [10, 0, 0, 1],
                &[IoSlice::new(&payload)]
            )
            .unwrap()
        );

        let mut payload = [0; 2893];
        rand::thread_rng().fill(&mut payload[..]);

        assert_eq!(
            tcp.calc_checksum_ipv4_raw([192, 168, 100, 1], [10, 0, 0, 1], &payload)
                .unwrap(),
            tcp.calc_checksum_ipv4_raw_with_slices_simd(
                [192, 168, 100, 1],
                [10, 0, 0, 1],
                &[
                    IoSlice::new(&payload[..1499]),
                    IoSlice::new(&payload[1499..])
                ]
            )
            .unwrap()
        );
        assert_eq!(
            tcp.calc_checksum_ipv4_raw([192, 168, 100, 1], [10, 0, 0, 1], &payload)
                .unwrap(),
            tcp.calc_checksum_ipv4_raw_with_slices_simd(
                [192, 168, 100, 1],
                [10, 0, 0, 1],
                &[
                    IoSlice::new(&payload[..1]),
                    IoSlice::new(&payload[1..2]),
                    IoSlice::new(&payload[2..257]),
                    IoSlice::new(&payload[257..257 + 256]),
                    IoSlice::new(&payload[257 + 256..])
                ]
            )
            .unwrap()
        );
    }

    #[test]
    fn calc_checksum_special_data() {
        // let data = "FwMDAkXI6HIcQ71zvBY62gucH4nPrs3ybPLTav3vxi1dn4I+7YFTRB/M14ndUOc63EVvLv7G9tnUnCxGPJpYPrFzPpN+RfqkzWO00go0LC7kxWKrmzU0hvtholueSONQWSY5KzoKkWy5XdrTzQ+GOdPmLTEt8+4xRaDMhkE+iwQUux34J8JImtHxlpToE+MiFtR8Hrwed41QeqibheutEgVXc1O01AbcZOUh2gazRSGwVTLZcGp/uRV4cRLtM0GAKqToNSfLVzoe7lKcsD3QMQtYIwe5gGJXpab1xW1QBXzDSA6w4U1ZQGGK1C8jr59aeYzhStig1ES896XJLBlboxNJ58wPQ8UHJqgDetQRwpx0lIzTPWFdx1fXohCthC4qcuG1wOOU1yK6Ko2W4ORVp0ngLMJIqG8XXMNsfFBNPVRtpIrU2gQH2HamsZY3FZTU+9QonygIEt+KzkcJi9V2pNOCPQA5pVfaVgWatcJeHZw2D5oXb3GdZRKqkLtu7tT6spStUnbwoBFqg1BjHFUAL853VgRvO6dufB+9Ru3mJ/p1+bYNfQRucT2lhD7Zr+C7y/WrP8rDHpMroFCq5pnZB3ewUDY2CGLt76o0YlvP9hfDNbgCHarmRFRtDXXqKLFg3qnwd62UVfo6OlCAVUv8quBG+ut0HSljvMTYT9Pio063DgQtsJ6Ou3UWpprFvJUCKUYOwMkEIjFynsKv/Oes+jnSk9vkk7T1a7RyhTeXdTH7AwUfY8mCwYqEwkduZvHO8S0A0LFx4+IV1RcDAwA5bUIe7ju49tnYf+rkRNgues+sBy722EL9VOIhN5vksmTrVyLH8+y6bFXdbZ8OkXS1RCkJriuRxVufFwMDABpYNvrwhEYplXGxr0UTUiozqT0L+K9GlxDlUA==";
        // let tcp_payload = base64::decode(data).unwrap();
        let mut tcp = TcpHeader::new(443, 61679, 3584924199, 32768);
        tcp.ack = true;
        tcp.acknowledgment_number = 1092746182;

        tcp.set_options(&[WindowScale(5)]).unwrap();

        let source_ip = [10, 2, 0, 4];
        let dest_ip = [10, 0, 0, 1];

        let payload1: [u8; 648] = [
            23, 3, 3, 2, 69, 34, 214, 241, 83, 110, 120, 19, 97, 127, 116, 149, 192, 131, 142, 161,
            3, 65, 80, 113, 188, 137, 19, 217, 241, 143, 143, 28, 162, 155, 51, 27, 82, 23, 87, 4,
            163, 199, 139, 50, 212, 61, 206, 49, 30, 102, 117, 24, 109, 113, 39, 58, 35, 250, 123,
            63, 122, 2, 137, 171, 152, 189, 44, 28, 213, 73, 216, 85, 45, 135, 250, 38, 246, 234,
            72, 133, 221, 157, 241, 115, 4, 82, 106, 167, 162, 109, 166, 176, 126, 165, 166, 113,
            183, 35, 29, 223, 90, 97, 20, 36, 235, 94, 120, 246, 81, 132, 23, 136, 25, 142, 236,
            156, 84, 221, 123, 247, 205, 98, 213, 253, 140, 231, 219, 26, 155, 254, 204, 195, 59,
            140, 217, 49, 16, 238, 41, 13, 69, 169, 47, 181, 241, 149, 185, 5, 118, 100, 142, 18,
            164, 179, 121, 228, 39, 156, 5, 234, 208, 56, 174, 204, 155, 3, 128, 177, 24, 235, 82,
            69, 142, 167, 251, 215, 46, 233, 118, 158, 245, 6, 10, 182, 168, 141, 0, 80, 122, 61,
            132, 229, 62, 23, 139, 7, 210, 88, 19, 175, 154, 157, 6, 173, 41, 121, 135, 185, 158,
            244, 210, 14, 25, 9, 88, 120, 131, 63, 152, 16, 84, 141, 97, 160, 19, 137, 26, 149, 51,
            26, 195, 23, 227, 66, 226, 26, 66, 42, 150, 19, 2, 151, 214, 167, 150, 162, 87, 88,
            188, 62, 189, 6, 226, 32, 58, 235, 209, 228, 141, 152, 181, 159, 103, 171, 87, 149, 98,
            112, 255, 80, 97, 245, 31, 117, 187, 255, 228, 74, 253, 64, 243, 57, 92, 103, 36, 110,
            23, 62, 85, 191, 138, 83, 52, 86, 35, 30, 178, 213, 107, 132, 106, 115, 165, 105, 214,
            49, 165, 233, 43, 62, 233, 11, 96, 66, 85, 64, 117, 95, 54, 219, 49, 111, 223, 74, 123,
            238, 194, 185, 109, 31, 19, 94, 232, 56, 115, 185, 76, 55, 6, 187, 13, 180, 216, 21,
            189, 79, 203, 235, 124, 180, 30, 97, 40, 72, 230, 32, 122, 167, 245, 134, 52, 253, 181,
            136, 100, 6, 66, 161, 231, 156, 118, 52, 59, 167, 195, 92, 46, 47, 8, 195, 91, 7, 184,
            218, 249, 23, 247, 2, 42, 240, 240, 181, 199, 231, 144, 25, 197, 9, 123, 92, 63, 186,
            207, 150, 110, 141, 145, 19, 161, 68, 45, 211, 13, 72, 225, 108, 205, 77, 136, 143,
            245, 238, 204, 23, 148, 234, 149, 204, 21, 54, 162, 195, 64, 8, 116, 10, 90, 239, 139,
            40, 237, 113, 143, 51, 3, 36, 162, 221, 187, 5, 56, 14, 16, 239, 30, 216, 179, 32, 238,
            43, 12, 141, 183, 97, 65, 15, 135, 52, 123, 60, 57, 206, 195, 156, 129, 25, 24, 67,
            178, 225, 93, 52, 68, 76, 34, 195, 21, 16, 247, 201, 117, 79, 111, 70, 184, 203, 75,
            192, 197, 181, 195, 21, 238, 228, 167, 192, 221, 115, 254, 128, 12, 92, 199, 69, 41,
            181, 35, 147, 241, 18, 41, 191, 164, 26, 245, 188, 95, 167, 171, 113, 199, 201, 34,
            147, 155, 21, 146, 254, 234, 18, 11, 32, 61, 176, 175, 70, 254, 2, 1, 251, 67, 107,
            210, 6, 9, 39, 67, 73, 18, 54, 142, 99, 251, 56, 81, 175, 169, 195, 189, 44, 173, 43,
            254, 44, 62, 221, 210, 12, 200, 213, 214, 208, 0, 54, 36, 157, 23, 3, 3, 0, 57, 192,
            244, 202, 132, 160, 229, 231, 35, 168, 125, 247, 46, 146, 164, 20, 19, 171, 66, 246,
            171, 246, 229, 255, 221, 208, 125, 25, 52, 145, 189, 54, 239, 142, 186, 76, 169, 56,
            24, 173, 64, 210, 250, 17, 198, 53, 228, 36, 107, 159, 203, 190, 185, 85, 44, 132, 219,
            51,
        ];
        let payload2: [u8; 31] = [
            23, 3, 3, 0, 26, 173, 226, 184, 214, 130, 48, 65, 20, 184, 7, 29, 140, 66, 231, 207,
            170, 253, 19, 200, 17, 54, 157, 17, 156, 58, 9,
        ];

        let mut final_payload = payload1.to_vec();
        final_payload.extend_from_slice(&payload2);

        assert_eq!(
            tcp.calc_checksum_ipv4_raw(source_ip, dest_ip, &final_payload)
                .unwrap(),
            0x4246
        );

        // assert_eq!(
        //     tcp.calc_checksum_ipv4_raw(source_ip, dest_ip, &final_payload)
        //         .unwrap(),
        //     tcp.calc_checksum_ipv4_raw_with_slices(
        //         source_ip,
        //         dest_ip,
        //         &[IoSlice::new(&final_payload)]
        //     )
        //     .unwrap()
        // );

        let simd_checksum = tcp
            .calc_checksum_ipv4_raw_with_slices_simd(
                source_ip,
                dest_ip,
                &[IoSlice::new(&payload1), IoSlice::new(&payload2)],
            )
            .unwrap();

        assert_eq!(
            tcp.calc_checksum_ipv4_raw(source_ip, dest_ip, &final_payload)
                .unwrap(),
            simd_checksum
        );

        // assert_eq!(
        //     tcp.calc_checksum_ipv4_raw_with_slices(
        //         source_ip,
        //         dest_ip,
        //         &[IoSlice::new(&payload1), IoSlice::new(&payload2),]
        //     )
        //     .unwrap(),
        //     0x992
        // );
    }

    #[test]
    fn calc_checksum_ipv4_raw() {
        // checksum == 0xf (no carries) (aka sum == 0xffff)

        //a header with options
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];

            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;
            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            // setup slices
            let tcp_buffer = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer).unwrap();

            assert_eq!(
                Ok(0xdeeb),
                tcp_slice.calc_checksum_ipv4_raw([192, 168, 1, 42], [192, 168, 1, 1], &tcp_payload)
            );
        }

        //a header with an uneven number of options
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8, 9];

            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;
            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            // setup slices
            let tcp_buffer = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

            assert_eq!(
                Ok(0xd5ea),
                tcp_slice.calc_checksum_ipv4_raw([192, 168, 1, 42], [192, 168, 1, 1], &tcp_payload)
            );
        }

        // value error
        {
            // write the tcp header
            let tcp: TcpHeader = Default::default();
            let len = (core::u16::MAX - tcp.header_len_u16()) as usize + 1;
            let mut tcp_payload = Vec::with_capacity(len);
            tcp_payload.resize(len, 0);

            // setup slices
            let tcp_buffer = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer).unwrap();

            assert_eq!(
                tcp_slice.calc_checksum_ipv4_raw([0; 4], [0; 4], &tcp_payload),
                Err(ValueTooBigError {
                    actual: len,
                    max_allowed: usize::from(core::u16::MAX - tcp.header_len_u16()),
                    value_type: ValueType::TcpPayloadLengthIpv4,
                })
            );
        }
    }

    #[test]
    fn calc_checksum_ipv6() {
        // ok case
        {
            let tcp_payload = [51, 52, 53, 54, 55, 56, 57, 58];

            // setup tcp header
            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;

            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            use crate::TcpOptionElement::*;
            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            // setup ip header
            let ip_header = Ipv6Header {
                traffic_class: 1,
                flow_label: 0x81806.try_into().unwrap(),
                payload_length: tcp_payload.len() as u16 + tcp.header_len_u16(),
                next_header: ip_number::TCP,
                hop_limit: 40,
                source: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                destination: [
                    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
                ],
            };

            // setup slices
            let ip_buffer = ip_header.to_bytes();
            let ip_slice = Ipv6HeaderSlice::from_slice(&ip_buffer[..]).unwrap();

            let tcp_bytes = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_bytes).unwrap();

            // verify checksum
            assert_eq!(
                Ok(0x786e),
                tcp_slice.calc_checksum_ipv6(&ip_slice, &tcp_payload)
            );
        }

        // error
        #[cfg(target_pointer_width = "64")]
        {
            //write the udp header
            let tcp: TcpHeader = Default::default();
            let len = (core::u32::MAX - tcp.header_len() as u32) as usize + 1;

            //lets create a slice of that size that points to zero
            //(as most systems can not allocate blocks of the size of u32::MAX)
            let tcp_payload = unsafe {
                //NOTE: The pointer must be initialized with a non null value
                //      otherwise a key constraint of slices is not fulfilled
                //      which can lead to crashes in release mode.
                use core::ptr::NonNull;
                core::slice::from_raw_parts(NonNull::<u8>::dangling().as_ptr(), len)
            };
            let ip_header = Ipv6Header {
                traffic_class: 1,
                flow_label: 0x81806.try_into().unwrap(),
                payload_length: 0, //lets assume jumbograms behavior (set to 0, as bigger then u16)
                next_header: ip_number::TCP,
                hop_limit: 40,
                source: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                destination: [
                    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
                ],
            };

            // setup slices
            let mut ip_buffer = Vec::new();
            ip_header.write(&mut ip_buffer).unwrap();
            let ip_slice = Ipv6HeaderSlice::from_slice(&ip_buffer[..]).unwrap();

            let mut tcp_buffer = Vec::new();
            tcp.write(&mut tcp_buffer).unwrap();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

            // check for an error during checksum calc
            assert_eq!(
                tcp_slice.calc_checksum_ipv6(&ip_slice, &tcp_payload),
                Err(ValueTooBigError {
                    actual: len,
                    max_allowed: core::u32::MAX as usize - tcp.header_len() as usize,
                    value_type: ValueType::TcpPayloadLengthIpv6,
                })
            );
        }
    }

    #[test]
    fn calc_checksum_ipv6_raw() {
        // ok case
        {
            let tcp_payload = [51, 52, 53, 54, 55, 56, 57, 58];

            //write the tcp header
            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;

            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            use crate::TcpOptionElement::*;
            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            // setup slice
            let tcp_buffer = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

            // verify checksum
            assert_eq!(
                Ok(0x786e),
                tcp_slice.calc_checksum_ipv6_raw(
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,],
                    &tcp_payload
                )
            );
        }

        // error
        #[cfg(target_pointer_width = "64")]
        {
            //write the udp header
            let tcp: TcpHeader = Default::default();
            let len = (core::u32::MAX - tcp.header_len() as u32) as usize + 1;

            //lets create a slice of that size that points to zero
            //(as most systems can not allocate blocks of the size of u32::MAX)
            let tcp_payload = unsafe {
                //NOTE: The pointer must be initialized with a non null value
                //      otherwise a key constraint of slices is not fulfilled
                //      which can lead to crashes in release mode.
                use core::ptr::NonNull;
                core::slice::from_raw_parts(NonNull::<u8>::dangling().as_ptr(), len)
            };

            // setup slice
            let tcp_buffer = tcp.to_bytes();
            let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer).unwrap();

            // expect an length error
            assert_eq!(
                tcp_slice.calc_checksum_ipv6_raw(
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,],
                    &tcp_payload
                ),
                Err(ValueTooBigError {
                    actual: len,
                    max_allowed: core::u32::MAX as usize - tcp.header_len() as usize,
                    value_type: ValueType::TcpPayloadLengthIpv6,
                })
            );
        }
    }
}
