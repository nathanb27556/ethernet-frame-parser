# ethernet-frame-parser

Parse raw Ethernet II frames, including stacked VLAN tags, into a borrowed
structured view.

```rust
use ethernet_frame_parser::{parse, ETHERTYPE_IPV4, TPID_802_1Q};

// dst, src, one 802.1Q tag (pcp=5, dei=0, vid=100), EtherType IPv4, payload.
let tci: u16 = (5 << 13) | 100;
let mut frame = Vec::new();
frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
frame.extend_from_slice(&TPID_802_1Q.to_be_bytes());
frame.extend_from_slice(&tci.to_be_bytes());
frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
frame.extend_from_slice(&[0x45, 0x00]);

let parsed = parse(&frame).expect("valid frame");
assert_eq!(parsed.destination().to_string(), "00:11:22:33:44:55");
assert_eq!(parsed.ethertype(), ETHERTYPE_IPV4);
assert_eq!(parsed.vlan_tags().len(), 1);
assert_eq!(parsed.vlan_tags()[0].vid, 100);
assert_eq!(parsed.payload(), &[0x45, 0x00]);
```

## Why this exists

The problem is narrow: you have a byte slice from a socket, a pcap file, or a
test fixture, and you want the MAC addresses, VLAN metadata, and EtherType
without an allocation per frame. `EthernetFrame` borrows from the input, so
`payload()` is a sub-slice of the original buffer rather than a copy. That is
the trade-off: the input must outlive the view, and callers who need to keep a
frame around must copy it themselves. In exchange, parsing a frame on a hot
path costs a handful of `u16` reads and no heap traffic.

## The awkward edge

A 16-bit field after the MAC addresses is ambiguous. Values `<= 1500` are an
IEEE 802.3 length, not an EtherType. This library does not guess: it returns
`ParseError::NotEthernetII` for those, so a frame whose length happens to fall
in that range is rejected rather than silently misread. Everything above 1500
is accepted as an EtherType, including unregistered values, because the parser
does not police the IANA registry.

VLAN tags are unwrapped up to eight deep. The ninth tag is an error
(`ParseError::TooManyVlanTags`) rather than a silent stop, because a frame
with that many stacked tags is malformed or hostile.

## API

`parse(bytes: &[u8]) -> Result<EthernetFrame<'_>, ParseError>`

The returned `EthernetFrame` exposes:

- `destination() -> MacAddr`
- `source() -> MacAddr`
- `vlan_tags() -> &[VlanTag]` (outermost first; empty for untagged frames)
- `ethertype() -> u16` (the EtherType after the innermost tag)
- `payload() -> &[u8]`

`MacAddr` has `octets()`, `is_broadcast()`, `is_multicast()`, and
`is_unicast()`. `VlanTag` has public fields `tpid`, `pcp`, `dei`, and `vid`.

Constants: `ETHERNET_HEADER_LEN`, `VLAN_TAG_LEN`, `TPID_802_1Q`,
`TPID_802_1AD`, `TPID_802_1QINQ`, `ETHERTYPE_IPV4`, `ETHERTYPE_ARP`,
`ETHERTYPE_IPV6`.

Errors: `TooShort`, `NotEthernetII`, `TruncatedVlanTag`, `TooManyVlanTags`.
All implement `std::error::Error` and `Display`.

No dependencies outside the standard library.
