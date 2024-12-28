% YAF Frequently Asked Questions

# [What is uniflow vs biflow?](#what-is-biflow) {#what-is-biflow}

A unidirectional flow record (uniflow) contains packets sent from a single
endpoint to another single endpoint. A bidirectional flow record (biflow)
contains packets sent in both directions between two endpoints. These
concepts are formally defined in [RFC 5103][RFC5103] Bidirectional Flow
Export using IPFIX.

By default, YAF exports a mix of biflow and uniflow records. YAF creates
biflows when it is able, but uniflows are almost always also present for
many reasons: network protocols that are unidirectional by design (e.g,
NetFlow v5), YAF only seeing half the conversation due to asymmetric
routing, network scanning, et cetera. If **yaf** is given the **--uniflow**
flag at runtime, it splits each biflow info two uniflows (using the Record
Adjacency method in section 3 of [RFC 5103][RFC5103]), which can be useful
when the collecting process downstream from YAF is not biflow-aware.

# [How are reverse elements represented?](#reverse-representation) {#reverse-representation}

According to [the standard][RFC5103], the reverse counterpart of a standard
([IANA-defined][]) information element is created by setting the enterprise
bit of the elementId (elementId | 0x8000) and using the private enterprise
number (PEN) of 29305. As an example, the PEN/ID of the reverse element for
the standard element packetDeltaCount (ID=2) is 29305/2.

Within the [CERT Private Enterprise&mdash;PEN 6871][CERT-registry], reverse
elements are designated by setting the most significant (non-enterprise) bit
of the elementId (elementId | 0x4000). The PEN/ID of the reverse element for
initialTCPFlags (6871/14) is 6871/16398.

When the NetSA tools display IPFIX records as text, they use the standard
information element name for values in the forward direction (e.g.,
packetDeltaCount, initialTCPFlags) and prepend `reverse` to the capitalized
element name for values in the reverse direction (reversePacketDeltaCount,
reverseInitialTCPFlags).

# [How does YAF determine flow direction of a biflow?](#flow-direction) {#flow-direction}

By [definition][RFC5103], the *forward direction* of biflow record represents
packets from the source address and port to the destination address and
port. Packets from the destination address and port to the source address
and port are in *reverse direction*.

The first packet of a biflow *seen by YAF* determines the direction of the
flow record. That is, the source of the first packet seen by YAF in an IPv4
flow record is stored in the sourceIPv4Address and the destination is stored
in the destinationIPv4Address.

Typically in an IPv4 biflow created by YAF the sourceIPv4Address is the
endpoint that initiated the connection (the client: a user's web browser
making a request, for example) and the destinationIPv4Address is the server
(a web server receiving the client's request and responding to the client),
but this is not always the case.

Occasionally YAF may see packets in the server's reply before it sees
packets in the client's request. This may happen if

-   packets are collected by the capture device and/or delivered to YAF
    out-of-order (see [pcap-tstamp][] for reasons this may happen),

-   either the capture device or YAF does not see the initial packet, or

-   the client retransmits request packets because the client does not
    receive the server's response packets

# [What does YAF use to determine a flow?](#determine-a-flow) {#determine-a-flow}

YAF uses the source IP, destination IP, source port, destination port,
protocol and vlan identifier to determine which packets to group into flows.
These elements are often called the "5-tuple and vlanId". When the
**--no-vlan-in-key** option is specified on the **yaf** command line, only
the 5-tuple is used.

For a TCP biflow, YAF closes the record when it sees a graceful connection
shutdown (FIN and ACK packets sent by each side) or it sees a packet with
the RST flag set.

YAF may also close a TCP record based on timeouts, and these timeouts are
the only mechanism YAF uses to close non-TCP flows:

-   YAF considers a flow idle and flushes it from the flow table if no
    packets are received for IDLE\_TIMEOUT seconds. If a packet arrives with
    the same 5-tuple and vlanId after the IDLE\_TIMEOUT, a new record is
    created. The default flow idle timeout of 300 seconds (5 minutes) may be
    changed with the **--idle-timeout** command line option or
    `idle_timeout` [initialization file][yaf.init] setting.

-   YAF flushes and emits any flow lasting longer than ACTIVE\_TIMEOUT
    seconds, and YAF creates a new record in the flow table to represent the
    ongoing connection. The default flow active timeout is 1800 seconds (30
    minutes); use the **--active-timeout** option or the `active_timeout`
    initialization file setting to modify it.

The **--silk** option may also cause records to be closed, as described
[below](#silk-option).

When the **--udp-uniflow** option is given, YAF creates a flow record for
each UDP packet seen on the specified port.

YAF can also create a [record for each packet](#flow-per-packet).

# [How can I make YAF create a flow record for each packet?](#flow-per-packet) {#flow-per-packet}

Setting the IDLE\_TIMEOUT to zero causes YAF to create a flow record for
each packet. This may be done using **--idle-timeout=0** on the command line
or by specifying `idle_timeout = 0` in the YAF's Lua-based initialization
file, [yaf.init][].

# [What is a flowKeyHash?](#flowkeyhash) {#flowkeyhash}

The YAF flowKeyHash is a numeric value that YAF computes for every flow
record. The flow key hash is computed from the IP protocol, the source and
destination IP addresses, the source and destination ports, and the vlan
identifier. The flowKeyHash is mainly used to help quickly identify and
search for specific flows in a large collection and when taken alongside the
flow start time creates a relatively unique flow identifier.

# [Why is there a --silk option? Is --silk required to send data to SiLK?](#silk-option) {#silk-option}

If the **--silk** flag is present, YAF will export flows in [SiLK][] mode.
This introduces the following incompatibilities with standard IPFIX export:

-   totalOctetCount and reverseTotalOctetCount are clamped to 32 bits. Any
    packet that would cause either of these counters to overflow 32 bits
    will cause the flow to close with flowEndReason 0x02 (active timeout),
    and will become the first packet of a new flow. This is analogous to
    forcing an active timeout when the octet counters overflow.

-   The high-order bit of the flowEndReason IE is set on any flow created on
    a counter overflow, as above.

-   The high-order bit of the flowEndReason IE is set on any flow created on
    an active timeout.

Since this changes the semantics of the exported flowEndReason IE, it should
only be used when generating flows and exporting to
[**rwflowpack**][rwflowpack], [**flowcap**][flowcap], or writing files for
processing with [**rwipfix2silk**][rwipfix2silk].

The **--silk** flag is recommended but not required when writing to SiLK.
However without the switch, because SiLK supports only 32 bit values for the
octet and packet counts, SiLK does not properly reflect the true octet and
packet counts for flows that have values exceeding SiLK's maximum.

# [How can I change the way appLabel and DPI are processed?](#applabel-and-dpi) {#applabel-and-dpi}

The behavior of both [application labeling (appLabel)][applabeling] and
[Deep Packet Inspection (DPI)][deeppacketinspection] are controlled by the
the YAF DPI rules configuration file. You can specify a configuration file
at runtime with the **--dpi-rules-file** flag or you can modify the default
file found in the default location of /usr/local/etc/yafDPIRules.conf.

# [How can I read the output of YAF?](#read-yaf-output) {#read-yaf-output}

YAF outputs files using the binary IPFIX file format. These files are not
human readable as-is because the information is densely encoded to save
space. To view IPFIX files directly, it is recommended to use tools such as
[**ipfixDump**][ipfixDump] or [**ipfix2json**][ipfix2json] which are
packaged as part of the [libfixbuf][] installation. You may also use the
JSON output mode of [super_mediator][].

[//]: # (Which versions are compatible with each other?)
[//]: # (TODO: This should really be like a big chart somewhere and we should just link that as the answer to this question.)


[IANA-defined]: https://www.iana.org/assignments/ipfix/ipfix.xhtml
[RFC5103]:      https://tools.ietf.org/html/rfc5103
[pcap-tstamp]:  https://www.tcpdump.org/manpages/pcap-tstamp.7.html

[CERT-registry]:        /cert-ipfix-registry/cert_ipfix_formatted.html
[SiLK]:                 /silk/index.html
[libfixbuf]:            /fixbuf/index.html
[flowcap]:              /silk/flowcap.html
[ipfix2json]:           /fixbuf/ipfix2json.html
[ipfixDump]:            /fixbuf/ipfixDump.html
[rwflowpack]:           /silk/rwflowpack.html
[rwipfix2silk]:         /silk/rwipfix2silk.html
[super_mediator]:       /super_mediator/super_mediator.html

[applabeling]:          applabeling.html
[deeppacketinspection]: deeppacketinspection.html
[yaf.init]:             yaf.init.html


[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
