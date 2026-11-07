//! Parses raw Ethernet II frames into structured views.
//!
//! The parser is intentionally zero-copy: every field returned by the
//! accessors is a borrowed slice into the caller's buffer. This keeps the
//! library usable on hot paths where allocating a `Vec` per frame would be
//! wasteful.
//!
//! The trade-off is that the parsed views borrow from the input, so the
//! input must outlive the view. Callers that need to keep a frame around
//! must copy the bytes themselves.
//!
//! ## Scope
//!
//! Only Ethernet II frames are supported. IEEE 802.3 length fields (values
//! `<= 1500`) are rejected with [`ParseError::NotEthernetII`] rather than
//! guessed at. Up to 8 VLAN tags (802.1Q and 802.1ad) are unwrapped; the
//! outermost tag is reported first.

use std::fmt;

/// Minimum size of an Ethernet II frame header: 6 byte destination MAC,
/// 6 byte source MAC, and a 2 byte EtherType.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Size of a single 802.1Q / 802.1ad VLAN tag, including the 2 byte TPID
/// and the 2 byte TCI.
pub const VLAN_TAG_LEN: usize = 4;

/// The largest value an 802.3 length field can hold. EtherType values at or
/// below this are not Ethernet II.
const MAX_802_3_LENGTH: u16 = 1500;

/// TPID for 802.1Q VLAN tags.
pub const TPID_802_1Q: u16 = 0x8100;
/// TPID for 802.1ad provider bridging (QinQ) tags.
pub const TPID_802_1AD: u16 = 0x88A8;
/// TPID for legacy 802.1QinQ tags.
pub const TPID_802_1QINQ: u16 = 0x9100;

/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType for IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Cap on how many stacked VLAN tags we will unwrap. Eight is well beyond
/// any real deployment; the limit exists so a maliciously crafted frame
/// cannot make the parser loop over a long chain of 4 byte tags.
const MAX_VLAN_TAGS: usize = 8;

/// A 48-bit MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Returns the address as a plain byte array.
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// True for the broadcast address `ff:ff:ff:ff:ff:ff`.
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    /// True when the least significant bit of the first octet is set, i.e.
    /// the I/G (individual/group) bit. Multicast and broadcast addresses
    /// both satisfy this.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// True when the second least significant bit of the first octet is
    /// clear, meaning the address is globally administered.
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// A single VLAN tag, as it appears on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VlanTag {
    /// The tag protocol identifier: 0x8100, 0x88A8, or 0x9100.
    pub tpid: u16,
    /// The 3-bit priority code point.
    pub pcp: u8,
    /// The drop eligible indicator.
    pub dei: bool,
    /// The 12-bit VLAN identifier.
    pub vid: u16,
}

/// Errors that can be produced while parsing a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer is shorter than a bare Ethernet II header.
    TooShort { needed: usize, got: usize },
    /// The 16-bit field after the MAC addresses is `<= 1500`, which marks
    /// this as an IEEE 802.3 frame rather than Ethernet II.
    NotEthernetII(u16),
    /// A VLAN tag was announced but the buffer ended before the TCI.
    TruncatedVlanTag { offset: usize },
    /// More than [`MAX_VLAN_TAGS`] tags were stacked. This is treated as an
    /// error rather than silently stopping, because a frame with that many
    /// tags is almost certainly malformed or hostile.
    TooManyVlanTags,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort { needed, got } => {
                write!(f, "frame too short: need {} bytes, have {}", needed, got)
            }
            ParseError::NotEthernetII(value) => {
                write!(f, "not an Ethernet II frame: length field {}", value)
            }
            ParseError::TruncatedVlanTag { offset } => {
                write!(f, "truncated VLAN tag at offset {}", offset)
            }
            ParseError::TooManyVlanTags => write!(f, "too many stacked VLAN tags"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed Ethernet II frame, borrowing from the original buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    destination: MacAddr,
    source: MacAddr,
    vlan_tags: [VlanTag; MAX_VLAN_TAGS],
    vlan_count: usize,
    ethertype: u16,
    payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// The destination MAC address.
    pub fn destination(&self) -> MacAddr {
        self.destination
    }

    /// The source MAC address.
    pub fn source(&self) -> MacAddr {
        self.source
    }

    /// The VLAN tags in the order they appeared, outermost first.
    pub fn vlan_tags(&self) -> &[VlanTag] {
        &self.vlan_tags[..self.vlan_count]
    }

    /// The EtherType of the encapsulated payload. If any VLAN tags were
    /// present, this is the EtherType that followed the innermost tag.
    pub fn ethertype(&self) -> u16 {
        self.ethertype
    }

    /// The bytes after the header and any VLAN tags. May be empty.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Parses `bytes` as an Ethernet II frame.
///
/// Returns a borrowed view on success. The input must contain at least a
/// bare header; a valid frame with an empty payload is accepted.
pub fn parse(bytes: &[u8]) -> Result<EthernetFrame<'_>, ParseError> {
    if bytes.len() < ETHERNET_HEADER_LEN {
        return Err(ParseError::TooShort {
            needed: ETHERNET_HEADER_LEN,
            got: bytes.len(),
        });
    }

    let mut destination = [0u8; 6];
    destination.copy_from_slice(&bytes[0..6]);
    let mut source = [0u8; 6];
    source.copy_from_slice(&bytes[6..12]);

    let mut offset = 12usize;
    let mut ethertype = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;

    if ethertype <= MAX_802_3_LENGTH {
        return Err(ParseError::NotEthernetII(ethertype));
    }

    let mut vlan_tags = [VlanTag {
        tpid: 0,
        pcp: 0,
        dei: false,
        vid: 0,
    }; MAX_VLAN_TAGS];
    let mut vlan_count = 0usize;

    while is_vlan_tpid(ethertype) {
        if vlan_count == MAX_VLAN_TAGS {
            return Err(ParseError::TooManyVlanTags);
        }
        if offset + VLAN_TAG_LEN > bytes.len() {
            return Err(ParseError::TruncatedVlanTag { offset });
        }
        let tci = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let next_ethertype =
            u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        vlan_tags[vlan_count] = VlanTag {
            tpid: ethertype,
            pcp: ((tci >> 13) & 0x07) as u8,
            dei: (tci & 0x1000) != 0,
            vid: tci & 0x0FFF,
        };
        vlan_count += 1;
        ethertype = next_ethertype;
        offset += VLAN_TAG_LEN;
    }

    Ok(EthernetFrame {
        destination: MacAddr(destination),
        source: MacAddr(source),
        vlan_tags,
        vlan_count,
        ethertype,
        payload: &bytes[offset..],
    })
}

/// True for the three TPIDs we recognise as VLAN tags.
fn is_vlan_tpid(value: u16) -> bool {
    matches!(value, TPID_802_1Q | TPID_802_1AD | TPID_802_1QINQ)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a frame with the given header fields and payload. No VLAN tags.
    fn plain_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ETHERNET_HEADER_LEN + payload.len());
        out.extend_from_slice(&dst);
        out.extend_from_slice(&src);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_minimal_frame_with_empty_payload() {
        let frame = plain_frame([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], ETHERTYPE_IPV4, &[]);
        let parsed = parse(&frame).expect("valid frame");
        assert_eq!(parsed.destination(), MacAddr([1, 2, 3, 4, 5, 6]));
        assert_eq!(parsed.source(), MacAddr([7, 8, 9, 10, 11, 12]));
        assert_eq!(parsed.ethertype(), ETHERTYPE_IPV4);
        assert_eq!(parsed.payload(), &[] as &[u8]);
        assert!(parsed.vlan_tags().is_empty());
    }

    #[test]
    fn payload_is_borrowed_from_input() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let frame = plain_frame([0; 6], [0; 6], ETHERTYPE_ARP, &payload);
        let parsed = parse(&frame).expect("valid frame");
        // Borrowed slice must alias the original buffer, not a copy.
        let base = frame.as_ptr() as usize;
        let got = parsed.payload().as_ptr() as usize;
        assert_eq!(got, base + ETHERNET_HEADER_LEN);
        assert_eq!(parsed.payload(), &payload[..]);
    }

    #[test]
    fn rejects_buffer_shorter_than_header() {
        let short = [0u8; ETHERNET_HEADER_LEN - 1];
        match parse(&short) {
            Err(ParseError::TooShort { needed, got }) => {
                assert_eq!(needed, ETHERNET_HEADER_LEN);
                assert_eq!(got, ETHERNET_HEADER_LEN - 1);
            }
            other => panic!("expected TooShort, got {:?}", other),
        }
    }

    #[test]
    fn rejects_empty_buffer() {
        assert_eq!(
            parse(&[]),
            Err(ParseError::TooShort { needed: ETHERNET_HEADER_LEN, got: 0 })
        );
    }

    #[test]
    fn rejects_802_3_length_field_at_boundary() {
        // 1500 is the largest 802.3 length; it is not an EtherType.
        let frame = plain_frame([0; 6], [0; 6], 1500, &[]);
        assert_eq!(parse(&frame), Err(ParseError::NotEthernetII(1500)));
    }

    #[test]
    fn accepts_ethertype_just_above_802_3_boundary() {
        // 1501 is not a registered EtherType but is a legal Ethernet II
        // value: anything above the max 802.3 length is treated as an
        // EtherType, and the parser does not police the registry.
        let frame = plain_frame([0; 6], [0; 6], 1501, &[]);
        let parsed = parse(&frame).expect("1501 is a valid Ethernet II ethertype");
        assert_eq!(parsed.ethertype(), 1501);
    }

    #[test]
    fn parses_single_vlan_tag() {
        // dst, src, TPID 0x8100, TCI (pcp=5, dei=1, vid=100), EtherType IPv4, payload
        let tci: u16 = (5 << 13) | 0x1000 | 100;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&TPID_802_1Q.to_be_bytes());
        frame.extend_from_slice(&tci.to_be_bytes());
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&[0xAA, 0xBB]);

        let parsed = parse(&frame).expect("valid tagged frame");
        let tags = parsed.vlan_tags();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].tpid, TPID_802_1Q);
        assert_eq!(tags[0].pcp, 5);
        assert!(tags[0].dei);
        assert_eq!(tags[0].vid, 100);
        assert_eq!(parsed.ethertype(), ETHERTYPE_IPV4);
        assert_eq!(parsed.payload(), &[0xAA, 0xBB]);
    }

    #[test]
    fn parses_stacked_vlan_tags_outermost_first() {
        // Outer 0x88A8 (vid 1), inner 0x8100 (vid 2), then IPv6.
        let outer_tci: u16 = 1;
        let inner_tci: u16 = 2;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&TPID_802_1AD.to_be_bytes());
        frame.extend_from_slice(&outer_tci.to_be_bytes());
        frame.extend_from_slice(&TPID_802_1Q.to_be_bytes());
        frame.extend_from_slice(&inner_tci.to_be_bytes());
        frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let parsed = parse(&frame).expect("valid QinQ frame");
        let tags = parsed.vlan_tags();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].tpid, TPID_802_1AD);
        assert_eq!(tags[0].vid, 1);
        assert_eq!(tags[1].tpid, TPID_802_1Q);
        assert_eq!(tags[1].vid, 2);
        assert_eq!(parsed.ethertype(), ETHERTYPE_IPV6);
    }

    #[test]
    fn accepts_legacy_9100_tpid() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&TPID_802_1QINQ.to_be_bytes());
        frame.extend_from_slice(&7u16.to_be_bytes());
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        let parsed = parse(&frame).expect("valid frame with 0x9100 tag");
        assert_eq!(parsed.vlan_tags().len(), 1);
        assert_eq!(parsed.vlan_tags()[0].tpid, TPID_802_1QINQ);
        assert_eq!(parsed.vlan_tags()[0].vid, 7);
        assert_eq!(parsed.ethertype(), ETHERTYPE_ARP);
    }

    #[test]
    fn rejects_truncated_vlan_tag() {
        // TPID present but only 1 of the 2 TCI bytes follows.
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&TPID_802_1Q.to_be_bytes());
        frame.push(0x00);
        match parse(&frame) {
            Err(ParseError::TruncatedVlanTag { offset }) => assert_eq!(offset, 14),
            other => panic!("expected TruncatedVlanTag, got {:?}", other),
        }
    }

    #[test]
    fn rejects_more_than_max_vlan_tags() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0; 6]);
        // MAX_VLAN_TAGS + 1 tags, each pointing at the next.
        for _ in 0..(MAX_VLAN_TAGS + 1) {
            frame.extend_from_slice(&TPID_802_1Q.to_be_bytes());
            frame.extend_from_slice(&0u16.to_be_bytes());
        }
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        assert_eq!(parse(&frame), Err(ParseError::TooManyVlanTags));
    }

    #[test]
    fn accepts_exactly_max_vlan_tags() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[0; 6]);
        for i in 0..MAX_VLAN_TAGS {
            frame.extend_from_slice(&TPID_802_1Q.to_be_bytes());
            frame.extend_from_slice(&(i as u16).to_be_bytes());
        }
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let parsed = parse(&frame).expect("exactly MAX_VLAN_TAGS is allowed");
        assert_eq!(parsed.vlan_tags().len(), MAX_VLAN_TAGS);
        assert_eq!(parsed.vlan_tags()[MAX_VLAN_TAGS - 1].vid, (MAX_VLAN_TAGS - 1) as u16);
        assert_eq!(parsed.ethertype(), ETHERTYPE_IPV4);
    }

    #[test]
    fn mac_address_helpers() {
        let broadcast = MacAddr([0xFF; 6]);
        assert!(broadcast.is_broadcast());
        assert!(broadcast.is_multicast());
        assert!(!broadcast.is_unicast());

        let unicast = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!unicast.is_broadcast());
        assert!(!unicast.is_multicast());
        assert!(unicast.is_unicast());

        let multicast = MacAddr([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]);
        assert!(multicast.is_multicast());
        assert!(!multicast.is_broadcast());
        assert!(!multicast.is_unicast());
    }

    #[test]
    fn mac_address_display_is_colon_separated_hex() {
        let mac = MacAddr([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
        assert_eq!(format!("{:?}", mac), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn error_display_is_non_empty() {
        let e = ParseError::TooShort { needed: 14, got: 3 };
        assert!(e.to_string().contains("14"));
        assert!(e.to_string().contains("3"));
        let e = ParseError::NotEthernetII(42);
        assert!(e.to_string().contains("42"));
        let e = ParseError::TruncatedVlanTag { offset: 14 };
        assert!(e.to_string().contains("14"));
        assert!(!ParseError::TooManyVlanTags.to_string().is_empty());
    }
}
