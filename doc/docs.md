% YAF: Documentation

# [Description of YAF as a Whole](#yaf-whole) {#yaf-whole}

YAF's purpose is to consume packets and turn them into flows to be processed
by downstream tools enabling analysts to provide network situational
awareness. YAF emits data in the IPFIX format ([RFC 7011][rfc7011]). All
data fields are defined by IPFIX information elements with fixed binary
types. YAF's job is to build flows augmented with enrichments and deep
packet inspection (DPI) metadata that are contained in named fields. These
fields are in prescribed locations in the record, allowing downstream tools
to know where to access them. Other downstream tools may carve records to
make them more usable as a final product for analysts. YAF's goal is to
produce flows as fast as possible with as much data as possible with data
organized in an accessible manner.

The manner in which YAF does this can be configured to serve your particular
data needs. YAF's processing can be broken down into four main sections,
each of which can be configured independently: Packet Consumption, Building
and Managing the Flow Table, Data Stored and Enrichments for Each Flow, and
Emitting Data. While there are defaults for almost every option, utilizing
YAF's options can provide data tailored for use by your analysts.

There are also ways to manage the YAF program itself such as Logging,
Privileges, and Configuration Files that are more about YAF as a process
than about flow generation.

# [Packet Consumption](#packet-consumption) {#packet-consumption}

The user must specify the source of the packets for YAF to consume. The two
broad categories of options are live capture from a network or reading PCAP
files. One the source is declared, there are decoding options that allow the
filtering of packets, and ways to configuring fragment handling regardless
of the input source type. If the data will come from PCAP, there are
additional capabilities available to index them and query for the packets
making up a particular flow.

## [Input Specification](#input-specification) {#input-specification}

### [Live Packet Capture](#live-packet) {#live-packet}

The **--live** option declares the data will be consumed from an active
interface and specifies the overall type of interface. These interface types
include **pfring**, **dag**, **napatech**, **netronome**, **zc** (pfring
zero copy), and **pcap** (reading packets using libpcap). The interfaces
details are declared with **--in**. To have physical interface details added
to flows, specify **--export-interface**, and values will appear in
**ingressInterface** and **egressInterface** fields of flow records.

**Example yaf command for Napatech**

    /usr/local/bin/yaf --live pcap --in napa_lb0    \
        --out /data/test_napa_lb0.ipfix --silk      \
        --dpi --max-payload 2048 --verbose          \
        --log=/data/manual/logs/test_napa_lb0.log

NOTE: The Napatech card allowed for having multiple interfaces to process
incoming packets. The interface is labeled as "napa\_lbx", where x is an
integer. You have (at least) up to 16 interfaces running at once (napa\_lb0,
napa\_lb1,... napa\_lb14, napa\_lb15).

**Example yaf command for Netronome**

    /usr/local/bin/yaf --live pcap --in netro_intf_0    \
        --out /data/test_netro_intf_0.ipfix --silk      \
        --dpi --max-payload 2048 --verbose              \
        --log=/data/manual/logs/test_netro_intf_0.log

NOTE: The Netronome card had 4 network interfaces already named. The name of
the interfaces were not actually netro\_intf\_x, where x is an integer. They
were preset and the names were not easy to remember. The command for
Netronome is very similar to the command for Napatech.

#### [Integration with Specific Network Cards](#network-cards) {#network-cards}

See [this](networkcards.html) page.

### [Reading from PCAP Files](#pcap-files) {#pcap-files}

YAF can consume packets from a fixed set of PCAP files in three ways:

-   Specifying a particular PCAP file with **--in**

        /usr/local/bin/yaf --in my-packets.pcap         \
            --out /data/test_my-packets.ipfix --silk    \
            --dpi --max-payload 2048 --verbose          \
            --log=/data/manual/logs/test_my-packets.log

-   Reading PCAP data from the standard input

        cat my-packets.pcap                             \
        | /usr/local/bin/yaf                            \
            --out /data/test_my-packets.ipfix           \
            --silk --dpi --max-payload 2048 --verbose   \
            --log=/data/manual/logs/test_my-packets.log

-   Specifying a list of PCAP files to process in a text file and providing
    that file to **--in** while adding **--caplist** to the command line
    options.

        /usr/local/bin/yaf --in file-list.txt --caplist \
            --noerror --out /data/test_caplist.ipfix    \
            --silk --dpi --max-payload 2048 --verbose   \
            --log=/data/manual/logs/test_caplist.log

    When using a caplist, **--noerror** prevents YAF from halting processing
    if it encounters an error while reading a file.

For all input categories, a BPF filter may be used to filter incoming data
with the **--filter** options. This is available when reading live packets
using libpcap (not dag, napatech, or netronome), or reading from PCAP files.
The **--filter** option takes a parameter of a filter string as described by
the **tcpdump(1)** and **pcap-filter(7)** manual pages.

### [Input Options](#input-options) {#input-options}

-   **--in** *INPUT\_SPECIFIER*

    If **--live** is also given, this is the name of an interface (e.g.
    `eth0`, `en0`, `dag0`, `nt3g`, `nt3g0:1`, `0:0`) to capture packets
    from. If reading from PCAP files, it is a filename of a PCAP or a
    caplist. The string `-` may be used to read from standard input. See
    **--live** for more information on formats for Napatech, Dag, and
    Netronome Interface formats. If **--in** is not given, **yaf** reads
    from the standard input.

-   **--caplist**

    If present, treat the filename in *INPUT\_SPECIFIER* as an ordered
    newline-delimited list of pathnames to PCAP files. Blank lines and lines
    beginning with the character `#` are ignored. All pathnames are
    evaluated with respect to the working directory **yaf** is run in. These
    PCAP files are processed in order using the same flow table, so they
    must be listed in ascending time order. This option is intended to ease
    the use of yaf with rotated or otherwise split **tcpdump(1)** output.

-   **--noerror**

    Used only with the **--caplist** option. When present, this causes
    **yaf** to ignore read errors it encounters while processing the list of
    PCAP files. **yaf** continues to process all files given in the
    *INPUT\_SPECIFIER* despite errors within those files.

-   **--live** *LIVE\_TYPE*

    If present, capture packets from an interface named in the
    *INPUT\_SPECIFIER*. Depending on the features included when **yaf** was
    [built][installation], *LIVE\_TYPE* may be one of

    -    **pcap** for packet capture via libpcap.

    -    **pfring** for packet capture via libpfring. **pfring** is only
         available if **yaf** was built with PF\_RING support.

    -    **zc** for packet capture via PF\_RING ZC (zero copy). See the
         **yafzcbalance(1)** man page for using **yaf** with PF\_RING ZC.

    -    **dag** for packet capture via an Endace DAG interface using
         libdag. **dag** is only available if **yaf** was built with Endace
         DAG support.

    -    **napatech** for packet capture via a Napatech Adapter.
         **napatech** is only available if **yaf** was built with Napatech
         API support. The *INPUT\_SPECIFIER* given to **--in** should be in
         the form nt3g\[\<streamID\>:\<ports\>\]. StreamID and Ports are
         optional. StreamID if given, is the ID that the traffic stream will
         be assigned to on the incoming ports. Ports may be a
         comma-separated list of ports to listen on. If Ports is not
         specified, the default is to listen on all ports. StreamID defaults
         to 0.

    -    **netronome** for packet capture via a Netronome NFE card.
         **netronome** is only available if **yaf** was built with Netronome
         API support. The *INPUT\_SPECIFIER* given to **--in** should be in
         the form \<device\>:\<ring\> where device is the NFE card ID,
         typically 0. Ring is the capture ring ID which is configured via a
         modprobe configuration file and resides in
         /etc/modprobe.d/pcd.conf.

-   **--promisc-off**

    If present, **yaf** will not put the interface into promiscuous mode
    when performing live capture.

-   **--export-interface**

    (This switch is only available when **yaf** was [built][installation]
    with DAG, Netronome, or Napatech support.) If given, **yaf** notes the
    interface on which a packet was received, and when **yaf** exports flow
    records it adds the **ingressInterface** and **egressInterface**
    elements to the output. The **ingressinterface** field will be the
    physical interface which captured the packet while the
    **egressinterface** will be the physical interface \| 0x100. This can be
    used to separate traffic based on DAG physical ports. For use with the
    DAG card, traffic received on separate ports will be separated into
    different flows if **yaf** is configured with the
    **--enable-daginterface** option. Otherwise the physical port will
    simply be exported in the **ingressInterface** or **egressInterface**
    fields in the IPFIX record (flows can exist over multiple interfaces).
    To separate traffic received on separate ports into separate flows, you
    must use **--enable-daginterface** when configuring **yaf**.

-   **--filter** *BPF\_FILTER*

    If present, enable Berkeley Packet Filtering (BPF) in **yaf** with
    *BPF\_FILTER* as the incoming traffic filter. Syntax of *BPF\_FILTER*
    follows the expression format described in the **tcpdump(1)** or
    **pcap-filter(7)** man page. This option is not currently supported if
    **--live** is set to **dag** or **napatech** or **netronome** as BPF
    filtering is implemented with libpcap. However, you may be able to use a
    BPF filter by running **yaf** with the DAG, Napatech, or Netronome
    implementations of libpcap.

-   **--decompress** *DECOMPRESS\_DIR*

    If present and the input file(s) are compressed with **gzip(1)**,
    **yaf** decompresses the file to a temporary file within
    *DECOMPRESS\_DIR*. If **--caplist** is also present, all files will be
    decompressed to *DECOMPRESS\_DIR*. If this option is not present,
    **yaf** decompresses files to the variable specified by the TMPDIR
    environment variable or /tmp if TMPDIR is not set. The zlib library must
    be installed to use this feature.

## [Packet Decoding](#packet-decoding) {#packet-decoding}

The **yaf** packet decoder's behavior can be modified with these options.
None of these options are required; the default behavior for each option
when not present is noted.

YAF can be configured to read only IPv4 or IPv6 packets with **--ip4-only**
and **--ip6-only** respectively.

YAF attempts to reassemble packet fragments by default with a 30 second
fragment timeout. It can be configured to ignore all fragmented packets with
**--no-frag.** The maximum number of fragments that YAF holds onto can be
specified with **--max-frags,** with a default of no maximum.

Packets encapsulated with GRE version 0 can be extracted to make flows of
encapsulated packets with **--gre-decode.** The default is that packets in
GRE tunnels are not extracted, and those flows have IP protocol 47.

-   **--ip4-only**

    If present, ignore all IPv6 packets and export IPv4 flows only. The
    default is to process both IPv4 and IPv6 packets.

-   **--ip6-only**

    If present, ignore all IPv4 packets and export IPv6 flows only. The
    default is to process both IPv4 and IPv6 packets.

-   **--no-frag**

    If present, ignore all fragmented packets. By default, **yaf** will
    reassemble fragments with a 30 second fragment timeout.

-   **--max-frags** *FRAG\_TABLE\_MAX*

    If present, limit the number of outstanding, not-yet reassembled
    fragments in the fragment table to *FRAG\_TABLE\_MAX* by prematurely
    expiring fragments from the table. This option is provided to limit
    **yaf** resource usage when operating on data from very large networks
    or networks with abnormal fragmentation. The fragment table may exceed
    this limit slightly due to limits on how often **yaf** prunes the
    fragment table (every 5 seconds). By default, there is no fragment table
    limit, and the fragment table can grow to resource exhaustion. There are
    no recommended values for this option as it is network dependent and
    will need tested and evaluated to achieve desired output.

-   **--gre-decode**

    If present, attempt to decode GRE version 0 encapsulated packets. Flows
    will be created from packets within the GRE tunnels. Undecodeable GRE
    packets will be dropped. Without this option, GRE traffic is exported as
    IP protocol 47 flows. This option is presently experimental.

## [PCAP Creation and Indexing](#pcap-creation) {#pcap-creation}

YAF has the capability to write the packets it is processing into rolling
PCAP files. This feature is enabled with **--pcap**. These packets can come
live from the wire or from input PCAP files. The files YAF writes can be
bounded by output file size using **--max-pcap** (default 5MB) and by time
using **--pcap-timer** (unlimited by default). Instead of rolling PCAP files
containing packets from all flows YAF can be configured to write the packets
from each flow into individual pcaps with **--pcap-per-flow**. YAF will only
write **--max-payload** bytes of each packet to the PCAP file. The contents
of an output PCAP file can be restricted to an individual flow by specifying
the flow key hash on the command line using **--hash**. The specificity of
**--hash** can be enhanced by adding the start time of the flow with
**--stime.**

Independent of writing its own PCAP files, YAF can create a file listing the
PCAP files containing packets that make up each flow. This is done by
specifying a filename prefix using **--pcap-meta-file**. That file will have
entries containing: {yafFlowKeyhash, flowStartMilliseconds, PCAP file name},
where the filename is the output PCAP if **--pcap** is present, or the input
file that packets were read from if not. This file will have 1 line per
{flow, pcap file} combination. The file will rotate after 4.5 million lines,
around 2GB.

Taking PCAP indexing a step farther, YAF can write one line to the meta file
per packet, with the additional specification of the offset into that PCAP,
and the length of the packet. This is enabled with **--index-pcap**. The
creation of this advanced meta file enables a separate program,
**yafMeta2Pcap** to retrieve the packets that make up an individual flow and
write them to a new PCAP file. **--pcap-meta-file** must be present to
enable full pcap indexing.

-   **--pcap** *PCAP\_FILE\_PREFIX*

    This option turns on rolling PCAP export in **yaf**. It will capture and
    write packets for all network traffic **yaf** has received and processed
    to PCAP files with the given *PCAP\_FILE\_PREFIX*. **yaf** will not
    create file directories. If **yaf** cannot write to the file, **yaf**
    will turn off PCAP export. PCAP files will have names in the form of
    PCAP\_FILE\_PREFIX\[datetime\]\_serialno.pcap". **yaf** will write to a
    file until the file size has reached **--max-pcap** or every
    **--pcap-timer** seconds (whichever happens first). By default, **yaf**
    rotates files every 5 MB. Files will be "locked" (`.lock` will be
    appended to the filename) until **yaf** has closed the file. Be aware
    that your operating system will have a limit on the maximum number of
    files in a directory and a maximum file size. If this limit is reached,
    **yaf** will write warning messages and terminate PCAP export. This may
    effect flow generation if **yaf** is also writing IPFIX files. If
    **--pcap** is used in conjunction with **--hash** and **--stime**, the
    *PCAP\_FILE\_PREFIX* should be the name of the PCAP file to write to (it
    will not be used as a file prefix).

-   **--pcap-per-flow**

    If present, **yaf** will write a pcap file for each flow in the output
    directory given to **--pcap**. *PCAP\_FILE\_PREFIX* given to **--pcap**
    must be a file directory. This option is experimental and should only be
    used when reading pcap files of reasonable size. **yaf** only writes up
    to **--max-payload** bytes of each packet to the pcap file. Therefore,
    **--max-payload** must be set to an appropriate size to prevent packets
    from being truncated in the pcap file. **yaf** will use the last three
    digits of the flowStartMilliseconds as the directory and the flow key
    hash, flowStartMilliseconds, and serial number as the filename. See the
    included **getFlowKeyHash** program to easily calculate the name of the
    file for a given flow. When the pcap file has reached **--max-pcap**
    size, **yaf** will close the file, increment the serial number, and open
    a new pcap file with the same naming convention. Note that your
    operating system has a limit to the number of open file handles **yaf**
    can maintain at any given time. Therefore, the performance of **yaf**
    degrades when the number of open flows is greater than the maximum
    number of file handles.

-   **--max-pcap** *MAX\_FILE\_MB*

    If present, set the maximum file size of pcap files to *MAX\_FILE\_MB*
    MB. The default is 5 MB.

-   **--pcap-timer** *PCAP\_ROTATE\_DELAY*

    If present, **yaf** will rotate rolling pcap files every
    *PCAP\_ROTATE\_DELAY* seconds or when the file reaches **--max-pcap**
    size, whichever happens first. By default, **yaf** only rotates files
    based on file size.

-   **--pcap-meta-file** *META\_FILENAME*

    If present and **--pcap** is also present, **yaf** will export metadata
    on the flows contained in each rolling pcap file **yaf** is writing to
    the filename specified by *META\_FILENAME*. **yaf** will write a line in
    the form:

        flow_key_hash | flowStartMilliseconds | pcap_file_name

    for each flow in the pcap. If a flow exists across 3 pcap files, there
    will be 3 lines in *META\_FILENAME* for that flow (each line having a
    different filename). The *META\_FILENAME* will rotate approximately
    every 4.5 million lines (or approx 2G). A new file will be created in
    the form *META\_FILENAME*\[datetime\]\_serialno.meta. This file can be
    uploaded to a database for flow correlation and flow-to-pcap analysis.

    If **--pcap-meta-file** is present and **--pcap** is not present,
    **yaf** will export information about the pcap file(s) it is presently
    reading, as opposed to the pcap files **yaf** is writing.

-   **--index-pcap**

    If present and **--pcap** and **--pcap-meta-file** are also present,
    export offset and length information about the packets **yaf** is
    writing to the rolling pcap files. This option can also be used when
    **--pcap** is not present, in which case it will write information about
    the file it is reading. Adding this option will force **yaf** to write
    one line per packet to the **pcap-meta-file** in the form:

        flow_key_hash | flowStartMilliseconds | pcap_file_name/file_num | offset | length

    If **--pcap** is present, the *pcap\_file\_name* is the name of the PCAP
    file **yaf** is writing. Otherwise, `file_num` will represent the
    sequential file number that **yaf** has processed. If **yaf** was given
    a single pcap file, this number will always be 0. *offset* is the offset
    into the pcap file of the beginning of the packet, at the start of the
    pcap packet header. *length* is the length of the packet including the
    pcap packet header. Using this offset, a separate program, such as
    **yafMeta2Pcap**, will be able to quickly extract packets for a flow.
    This file only rotates if *META\_FILE* reaches max size.

-   **--hash** *FLOW\_KEY\_HASH*

    If present, only write PCAP data for the flow(s) with *FLOW\_KEY\_HASH*.
    This option is only valid with the **--pcap** option.

-   **--stime** *FLOW\_START\_TIMEMS*

    If present, only write PCAP data for the flow(s) with
    *FLOW\_START\_TIMEMS* and *FLOW\_KEY\_HASH* given to **--hash**. This
    option is only valid when used with the **--hash** and **--pcap**
    options.

# [Building and Managing the Flow Table](#flow-table) {#flow-table}

YAF uses the 5-tuple (source IP, destination IP, source port, destination
port, protocol) plus the VLAND ID to group packets into flows. To have YAF
not factor VLAN ID into determining flow uniqueness, specify
**--no-vlan-in-key**. When there isn't a packet indicating that the flow
should be closed and emited, such as a TCP FIN packet, YAF has other
mechanisms to manage the flow table and close flows on its own. YAF closes
flows due to inactivity. This interval can be set with **--idle-timeout**,
with a default of 300 seconds (5 minutes). By default, YAF will flush a flow
that has been active for 1800 seconds (30 minutes). This threshold can be
changed with **--active-timeout**. A maximum number of active flows can be
specified with **--max-flows**. If this is set, YAF will begin to expire
flows that have been idle for the longest time when the maximum active flow
count has been reached.

-   **--idle-timeout** *IDLE\_TIMEOUT*

    Set flow idle timeout in seconds. Flows are considered idle and flushed
    from the flow table if no packets are received for *IDLE\_TIMEOUT*
    seconds. The default flow idle timeout is 300 seconds (5 minutes).
    Setting *IDLE\_TIMEOUT* to 0 creates a flow for each packet.

-   **--active-timeout** *ACTIVE\_TIMEOUT*

    Set flow active timeout in seconds. Any flow lasting longer than
    *ACTIVE\_TIMEOUT* seconds will be flushed from the flow table. The
    default flow active timeout is 1800 seconds (30 minutes).

-   **--max-flows** *FLOW\_TABLE\_MAX*

    If present, limit the number of open flows in the flow table to
    *FLOW\_TABLE\_MAX* by prematurely expiring the flows with the least
    recently received packets; this is analogous to an adaptive idle
    timeout. This option is provided to limit **yaf** resource usage when
    operating on data from large networks. By default, there is no flow
    table limit, and the flow table can grow to resource exhaustion.

-   **--force-read-all**

    If present, **yaf** will process out-of-sequence packets. However, it
    will still reject out-of-sequence fragments.

-   **--no-vlan-in-key**

    If present, **yaf** will NOT use the VLAN ID in the flow key hash
    calculation for flows. This means that packets within the active/idle
    timeouts that have the same 5-tuple but different VLAN IDs will be
    aggregated into 1 flow and the VLAN ID of the first packet in each
    direction will be exported in the **vlanId** and **reverseVlanId**
    fields.

# [Data Stored for Each Flow and Enhancements](#flow-data) {#flow-data}

In addition to basic flow information, YAF can augment flows with
information as specified by the user. This section describes all of the
additional options beyond standard flow fields that YAF can provide.

##   [Flow Settings](#flow-settings) {#flow-settings}

These settings change what, and how, YAF stores flow information.

-   **--max-payload** *PAYLOAD\_OCTETS*

    If present, capture at most *PAYLOAD\_OCTETS* octets from the start of
    each direction of each flow. Non-TCP flows will only capture payload
    from the first packet unless **--udp-payload** is set. If not present,
    **yaf** does capture payload. Payload capture must be enabled for
    payload export (**--export-payload**), application labeling
    (**--applabel**), deep packet inspection (**--dpi**), entropy evaluation
    (**--entropy**), [p0f][libp0f] fingerprinting (**--p0fprint**),
    fingerprinting export (**--fpexport**), and [nDPI][] application
    labeling (**--ndpi**).

-   **--silk**

    If present, export flows in "SiLK mode". This introduces the following
    incompatibilities with standard IPFIX export:

    -   **totalOctetCount** and **reverseTotalOctetCount** are clamped to 32
        bits. Any packet that would cause either of these counters to
        overflow 32 bits will cause the flow to close with **flowEndReason**
        0x02 (active timeout), and will become the first packet of a new
        flow. This is analogous to forcing an active timeout when the octet
        counters overflow.

    -   The high-order bit of the **flowEndReason** IE is set on any flow
        created on a counter overflow, as above.

    -   The high-order bit of the **flowEndReason** IE is set on any flow
        created on an active timeout.

    Since this changes the semantics of the exported **flowEndReason** IE,
    it should only be used when generating flows and exporting to
    `rwflowpack`, `flowcap`, or writing files for processing with
    `rwipfix2silk`.

-   **--udp-payload**

    If present, capture at most *PAYLOAD\_OCTETS* octets fom the start of
    each direction of each UDP flow, where *PAYLOAD\_OCTETS* is set using
    the **--max-payload** flag.

-   **--force-ip6-export**

    If present, force IPv4 flows to be exported with IPv6-mapped IPv4
    addresses in ::ffff/96. This will cause all flows to appear to
    be IPv6 flows.

-   **--udp-uniflow** *PORT*

    If present, export each UDP packet on the given port (or 1 for all
    ports) as a single flow, with **flowEndReason** set to 0x1F. This will
    not close the flow. The flow will stay open until it closes naturally by
    the idle and active timeouts. Most useful with **--export-payload** in
    order to export every UDP payload on a specific port.

## [Flow Enhancements](#flow-enhancements) {#flow-enhancements}

Each of these settings add data to every flow. Some are additional fields
pulled from individual packets, while others add metadata about the packets
that make up a flow. All of the options in this section may be used together
in any combination. None of the settings below are on by default. Other than
**--dpi**, each of the settings adds fields to the core, or top-level, flow
record. **--dpi** tells YAF to populate **yafDPIList**, the subTemplateList
used to store deep packet inspection metadata tailored to the specific
protocol used by the flow. The contents of the **yafDPIList**
subTemplateList are determined by the value in the **silkAppLabel** field.

Since many of these options in this section examine the packet payload, you
must also supply the **--max-payload** option when using them. Some of these
options may not be available and depend on how your version of **yaf** was
[built][installation].

-   **--applabel**

    If present, **yaf** examines the protocol details of packets from each
    flow to try to determine the application protocol being used in the
    flow. The applabel is stored in the **silkAppLabel** element; **yaf**
    support only one application label per flow. Requires **--max-payload**;
    a minimum value of 384 is recommended. See [YAF Application
    Labeling][applabeling] for further information. This option is only
    available when **yaf** is [built][installation] with applabel support.

-   **--dpi**

    If present, **yaf** performs deep packet inspection to locate, capture,
    and export useful information about the protocol. Requires
    **--max-payload**; a minimum value of 2000 is recommended. Automatically
    turns on application labeling as it is required for deep packet
    inspection. See [YAF Deep Packet Inspection][dpi] for further
    information. This option is only available when **yaf** is
    [built][installation] with DPI support.

-   **--dpi-rules-file** *RULES\_FILE*

    Takes a path to a file that specifies the configuration for application
    labeling and deep packet inspection. This configuration file is written
    in [Lua][]. The default file which comes pre-installed with **yaf** is
    in /usr/local/etc/yafDPIRules.conf.

-   **--dpi-select** *APPLABEL\_LIST*

    Limits the **--dpi** option to perform DPI only on the comma separated
    list of applabels. If this flag is not specified, DPI will be performed
    on all protocols. For example, **--dpi** **--dpi-select=53,80,21** will
    perform DPI for DNS, HTTP and FTP only.

-   **--ndpi**

    Tells **yaf** to examine the packet payload using [nDPI][] and determine
    an application protocol and sub-protocol, which are stored in the
    **ndpiL7Protocol** and **ndpiL7SubProtocol** elements. nDPI is a version
    of OpenDPI as maintained by [ntop][]. Requires **--max-payload**;
    a minimum value of 384 is recommended. This option is only
    available when **yaf** is [built][installation] with nDPI support.

-   **--ndpi-protocol-file** *FILE*

    Specify the protocol file that **--ndpi** uses for sub-protocol and
    port-based protocol detection.

-   **--export-payload**

    If present, add **payload** and **reversePayload** elements to the flow
    templates and export the payload from each direction of the flow record.
    The maximum size of the exported payload is the smaller of the arguments
    to **--max-payload** and **--max-export**. Non-TCP flows will only
    export payload from the first packet. By default, **yaf** does not
    export flow payload.

-   **--payload-applabel-select** *APPLABEL\_LIST*

    Enable payload export (as **--export-payload**) but only for the
    application labels specified in *APPLABEL\_LIST*, a comma separated list
    of applabel values.

-   **--max-export** *MAX\_PAY\_OCTETS*

    If present and payload export is active, export at most
    *MAX\_PAY\_OCTETS* from the start of each direction of each flow. The
    argument to **--max-payload** is the maximum allowed value for
    *MAX\_PAY\_OCTETS*, and it is the default value when this option is not
    specified. Payload export is only active when either
    **--export-payload** or **--payload-applabel-select** is given.

-   **--mac**

    Export MAC-layer information in information elements
    **sourceMacAddress** and **destinationMacAddress**.

-   **--p0fprint**

    If present, export p0f operating system fingerprints. This data consists
    of three related information elements: **osName**, **osVersion**, and
    **osFingerPrint**. Requires **--max-payload**. This option is only
    available when **yaf** is [built][installation] with [p0f][libp0f]
    support.

-   **--p0f-fingerprints** *FILEPATH*

    Location of the p0f fingerprint file(s), `p0f.fp`. Default is
    /usr/local/etc/p0f.fp. This version of **yaf** includes the updated
    CERT p0f fingerprints. See https://tools.netsa.cert.org/p0f/index.html
    for updates.

-   **--fpexport**

    If present, enable export of handshake headers for external OS
    fingerprinters. The related information elements are
    **firstPacketBanner** and **secondPacketBanner**. Requires
    **--max-payload**. This option is only available when **yaf** is
    [built][installation] with fpexporter support.

-   **--entropy**

    If present, export the entropy values for both the forward and reverse
    payloads in the **payloadEntropy** and **reversePacketEntropy**
    elements. Requires **--max-payload**. This option is only available when
    **yaf** is [built][installation] with entropy support.

    **yaf** examines the packet payloads and determines a Shannon Entropy
    value for the payload. The entropy calculation does not include the
    network (IP) or transport (UDP/TCP) headers. The entropy is calculated
    in terms of bits per byte, (log base 2.) The calculation generates a
    real number value between 0.0 and 8.0. That number is then converted
    into an 8-bit integer value between 0 and 255. Roughly, numbers above
    230 are generally compressed (or encrypted) and numbers centered around
    approximately 140 are English text. Lower numbers carry even less
    information content. Another useful piece of information is that SSL/TLS
    tends to zero pad its packets, which causes the entropy of those flows
    to drop quite low.

-   **--plugin-name** *LIBPLUGIN\_NAME\[,LIBPLUGIN\_NAME...\]*

    Specify the plugin(s) to load. The loaded plugin must follow the **yaf**
    plugin framework. *LIBPLUGIN\_NAME* must be the full path to the plugin
    library name. Only one plugin is currently included with **yaf**: a DHCP
    Fingerprinting plugin. This option is only available when **yaf** is
    [built][installation] with plugin support.

-   **--plugin-opts** *OPTIONS\[,OPTIONS...\]*

    Specify the arguments to the plugin given to **--plugin-name**. This
    flag will only be recognized if **yaf** is configured with
    **--enable-plugins** and **--plugin-name** is set to a valid plugin.

-   **--plugin-conf** *CONF\_FILE\_PATH\[,CONF\_FILE\_PATH...\]*

    Specify the path to a configuration file for the plugin given to
    **--plugin-name**. This flag will only be recognized if **yaf** is
    configured with **--enable-plugins** and **--plugin-name** is set to a
    valid plugin. If this switch is not used, but the plugin requires a
    configuration file, the default location /usr/local/etc will be used.

-   **--flow-stats**

    Export extra flow attributes and statistics in flow record. This will
    maintain information such as small packet count, large packet count,
    nonempty packet count, average interarrival times, total data octets,
    and max packet size. See the flow template below for more information
    about each of the fields **yaf** exports.

##   [Flow Changes](#flow-changes) {#flow-changes}

-   **--uniflow**

    If present, export biflows using the Record Adjacency method in section
    3 of RFC 5103. This is useful when exporting to IPFIX Collecting
    Processes that are not biflow-aware.

-   **--observation-domain** *DOMAIN\_ID*

    Set the observationDomainId on each exported IPFIX message to the given
    integer value. If not present, the observationDomainId defaults to 0.

-   **--delta**

    If present, export octet and packet total counts in the delta count
    information elements. This does not change how **yaf** computes the
    counts, it only changes the elements used to report the counts.
    **octetTotalCount** will be exported in **octetDeltaCount** (IE 1),
    **reverseOctetTotalCount** will be exported in
    **reverseOctetDeltaCount**, **packetTotalCount** will be exported in
    **packetDeltaCount** (IE 2), and **reversePacketTotalCount** will be
    exported in **reversePacketDeltaCount**.

-   **--ingress** *INGRESS\_INT*

    If present, set the **ingressInterface** field in the flow template to
    *INGRESS\_INT*. This field will also be populated if **yaf** was
    configured with **--enable-daginterface**. If yaf is running on a dag,
    napatech, or bivio, and the physical interface is available, this value
    will override *INGRESS\_INT*.

-   **--egress** *EGRESS\_INT*

    If present, set the **egressInterface** field in the flow template to
    *EGRESS\_INT*. This field will also be populated if **yaf** was
    configured with **--enable-daginterface**. If yaf is running on a dag,
    napatech, or bivio, and the physical interface is available, this value
    will override *EGRESS\_INT*.

# [Emitting Records and Output](#emitting-records) {#emitting-records}

YAF needs to be told how and where to write the records it generates. All
output will be in the IPFIX format. Using a combination of **--out** and
**--ipfix**, YAF can be configured write records to local files, local
sockets, or remote hosts. Sockets can use SCTP, TCP, or UDP. If no option is
given, YAF writes its output file to standard output.

## [Writing flows to a socket](#write-socket) {#write-socket}

To write flows to a socket, use **--out** to specify the hostname or IP
address of the destination, and **--ipfix** to specify the transport
protocol to use: **tcp**, **udp**, or **sctp**. The port to use may be
specified with **--ipfix-port**. If no port is specified, the default port
of 4739 is used, or 4740 if TLS is utilized (**--tls**).

    yaf --out 192.0.2.3 --ipfix tcp --ipfix-port 18000

## [Writing flows to a single file](#write-single-file) {#write-single-file}

To write all flows to a single file, specify the filename with
**--out**. This can be a full path, or path relative to where YAF is
running.

    yaf --out flows.yaf

    yaf --out /data/flows.yaf

## [Writing flows to a stream of files](#write-stream-files) {#write-stream-files}

The standard use of YAF is long term monitoring of a network, where the
flows cannot fit into one file. YAF can be configured to write to the
current file for a fixed amount of time, then close the file and open a new
one with a different name. This is specified with a combination of **--out**
and **--rotate**. In this case, the parameter passed to **--out** is a file
prefix to use for the series of files. The prefix will be followed by a
suffix containing a timestamp in *YYYYMMDDhhmmss* format, and a decimal
serial number with a `.yaf` file extension. The rotating interval is
specified in seconds with **--rotate**. Files can be locked while being
written to by specifying **--lock**.

To write flows to 5 minute files in /data with the file prefix "example":

    yaf --out /data/example --rotate 300

## [Export Options](#export-options) {#export-options}

-   **--out** *OUTPUT\_SPECIFIER*

    *OUTPUT\_SPECIFIER* is an output specifier. If **--ipfix** is present,
    the *OUTPUT\_SPECIFIER* specifies the hostname or IP address of the
    collector to which the flows will be exported. Otherwise, if
    **--rotate** is present, *OUTPUT\_SPECIFIER* is the prefix name of each
    output file to write to. Otherwise, *OUTPUT\_SPECIFIER* is a filename in
    which the flows will be written; the string `-` may be used to write to
    standard output. If not given, **yaf** writes to the standard output.

-   **--ipfix** *TRANSPORT\_PROTOCOL*

    If present, causes **yaf** to operate as an IPFIX exporter, sending
    IPFIX Messages via the specified transport protocol to the collector
    named in the *OUTPUT\_SPECIFIER*. Valid *TRANSPORT\_PROTOCOL* values are
    **tcp**, **udp**, and **sctp**. SCTP is only available if **yaf** was
    [built][installation] with SCTP support. UDP is not recommended, as it
    is not a reliable transport protocol and cannot guarantee delivery of
    messages. As per the recommendations in RFC 5101, **yaf** will
    retransmit templates three times within the template timeout period
    (configurable using **--udp-temp-timeout** or by default, 10 minutes).
    Use the **--ipfix-port**, **--tls**, **--tls-ca**, **--tls-cert**, and
    **--tls-key** options to further configure the connection to the IPFIX
    collector.

-   **--ipfix-port** *PORT*

    If **--ipfix** is present, export flows to TCP, UDP, or SCTP port
    *PORT*. If not present, the default IPFIX port 4739 is used. If
    **--tls** is also present, the default secure IPFIX port 4740 is used.

-   **--rotate** *ROTATE\_DELAY*

    If present, causes **yaf** to write output to multiple files, opening a
    new output file every *ROTATE\_DELAY* seconds in the input data. Rotated
    files are named using the prefix given in the *OUTPUT\_SPECIFIER*,
    followed by a suffix containing a timestamp in *YYYYMMDDhhmmss* format,
    a decimal serial number, and the file extension `.yaf`.

-   **--lock**

    Use lockfiles for concurrent file access protection on output files.
    This is recommended for interoperating with the Airframe filedaemon
    facility.

-   **--no-output**

    If present, **yaf** will not export IPFIX data. It will ignore any
    argument provided to **--out**. This is typically used when generating
    fresh PCAP from the input packets and / or creating PCAP metadata or
    indexing.

-   **--tls**

    If **--ipfix** is present, use TLS to secure the connection to the IPFIX
    collector. Requires the *TRANSPORT\_PROTOCOL* to be **tcp**, as DTLS
    over UDP or SCTP is not yet supported. Requires the **--tls-ca**,
    **--tls-cert**, and **--tls-key** options to specify the X.509
    certificate and TLS key information.

-   **--tls-ca** *CA\_PEM\_FILE*

    Use the Certificate Authority or Authorities in *CA\_PEM\_FILE* to
    verify the remote IPFIX Collecting Process' X.509 certificate. The
    connection to the Collecting Process will fail if its certificate was
    not signed by this CA (or by a certificate signed by this CA,
    recursively); this prevents export to unauthorized Collecting Processes.
    Required if **--tls** is present.

-   **--tls-cert** *CERT\_PEM\_FILE*

    Use the X.509 certificate in *CERT\_PEM\_FILE* to identify this IPFIX
    Exporting Process. This certificate should contain the public part of
    the private key in *KEY\_PEM\_FILE*. Required if **--tls** is present.

-   **--tls-key** *KEY\_PEM\_FILE*

    Use the private key in *KEY\_PEM\_FILE* for this IPFIX Exporting
    Process. This key should contain the private part of the public key in
    *CERT\_PEM\_FILE*. Required if **--tls** is present. If the key is
    encrypted, the password must be present in the YAF\_TLS\_PASS
    environment variable.

# [Additional Records](#addl-records) {#addl-records}

YAF has three non-flow record types it can generate and emit that
augment the flows it produces. The records give collection systems
additional information on data contents and monitoring mechanics. There
are also IPFIX-related records such as template records (required) and
information element detail records (optional).

-   **YAF Stats:** YAF can periodically emit IPFIX options records
    containing summary statistics of its collection. They include packets
    read, flows emited, fragmentation information, the numbers of dropped
    packets and others. These records are emited every 5 minutes by default.
    The interval can be changed with the **--stats** option, or disabled
    with **--no-stats**.

-   **Tombstone Records:** The NetSA tool suite has a record that can
    pass through the length of the data flow to measure how long it
    takes data to pass through the system The records can be generated
    in YAF or Super Mediator. As each tool receives a tombstone record,
    adds it identifier and a timestamps and passes the record
    downstream. These records are on by default.

-   **Template Metadata:** YAF uses many templates for its flow and DPI
    records to keep data efficiently stored. In addition to the required
    IPFIX template records, we've given templates names and provided
    information about whether the template is for top level or nested
    records. These template metadata records are IPFIX options records.
    They are not emited by default.

-   **Template Records:** The IPFIX standard requires all records to have a
    fixed and defined template. These records are always be sent.

-   **Information Element Records:** YAF uses a large number of enterprise
    defined information elements (IE), particularly for DPI templates. By
    default, YAF emits records that describe these elements ([RFC
    5610][rfc5610]) to inform the collecting processes about the IEs it
    uses. The [cert-ipfix-registry][certipfix] contains these elements. If
    the registry is imported into the collecting process's information
    model, these extended IE records will not be required to be sent.

## [Additional Record Options](#addl-record-options) {#addl-record-options}

-   **--no-template-metadata**

    If present, disables the export of template metadata before flow data.
    The export of template metadata is on by default.

-   **--no-element-metadata**

    If present, disables the export of information element metadata (RFC
    5610 records) before flow data. The export of information element
    metadata is on by default.

-   **--stats** *INTERVAL*

    If present, causes **yaf** to export process statistics every *INTERVAL*
    seconds. The default value for *INTERVAL* is 300 seconds (5 minutes).
    **yaf** uses IPFIX Options Templates and Records to export flow,
    fragment, and decoding statistics. If *INTERVAL* is set to zero, stats
    will not be exported.

-   **--no-stats**

    If present, **yaf** will not export process statistics. **yaf** uses
    IPFIX Options Templates and Records to export flow, fragment, and
    decoding statistics. **--no-stats** takes precedence over **--stats**.

-   **--no-tombstone**

    If present, **yaf** will not export tombstone records. **yaf** uses
    IPFIX Options Templates and Records to export tombstone records.
    Tombstone records will only be exported if stats exporting is also
    active.

-   **--tombstone-configured-id** *IDENTIFIER*

    If present, sets the "certToolExporterConfiguredId" value in tombstone
    records. This value should be less than 65535. The default value is 0.

-   **--udp-temp-timeout** *TEMPLATE\_TIMEOUT*

    Set UDP template timeout in seconds if **--ipfix** is set to **udp**. As
    per RFC 5101 recommendations, **yaf** will attempt to export templates
    three times within *TEMPLATE\_TIMEOUT*. The default template timeout
    period is 600 seconds (10 minutes).

# [YAF Programmatic Options](#yaf-prog-options) {#yaf-prog-options}

These options configure the YAF process, independent of flow related
features. They include dropping privilege, logging, configuration file
specification, and others.

## [Logging Options](#logging-options) {#logging-options}

These options are used to specify how log messages are routed. YAF can log
to standard error, regular files, or the UNIX syslog facility.

-   **--log** *LOG\_SPECIFIER*

    Specifies destination for log messages. *LOG\_SPECIFIER* can be a
    syslog(3) facility name, the special value **stderr** for standard
    error, or the *absolute* path to a file for file logging. The default
    log specifier is **stderr** if available and **yaf** is not running as a
    daemon, or the syslog facility **user** otherwise.

-   **--loglevel** *LOG\_LEVEL*

    Specify minimum level for logged messages. In increasing levels of
    verbosity, the supported log levels are **quiet**, **error**,
    **critical**, **warning**, **message**, **info**, and **debug**. The
    default logging level is **warning**.

-   **--verbose**

    Equivalent to **--loglevel debug**.

## [Privilege Options](#privilege-options) {#privilege-options}

These options are used to cause YAF to drop privileges when running as root
for live capture purposes.

-   **--become-user** *UNPRIVILEGED\_USER*

    After opening the live capture device in **--live** mode, drop privilege
    to the named user. **yaf** exits with an error if **--become-user** is
    used when **yaf** is not run as root or setuid root. This option will
    cause all files written by **yaf** to be owned by the user
    *UNPRIVILEGED\_USER* and the user's primary group; use
    **--become-group** as well to change the group **yaf** runs as for
    output purposes. This option has no effect if live capture is not
    active.

    If running as root for live capture purposes and **--become-user** is
    not present, **yaf** will warn that privilege is not being dropped. We
    highly recommend the use of this option, especially in production
    environments, for security purposes.

-   **--become-group** *UNPRIVILEGED\_GROUP*

    Change the group from the default of the user given in
    **--become-user**. This option has no effect if given without the
    **--become-user** option as well.

## [Configuration File](#configuration-file) {#configuration-file}

The YAF configuration file can be used instead of or in addition to command
line arguments.

-   **--config** *CONFIGURATION\_FILE*

    If present, use the variables set in the *CONFIGURATION\_FILE*. The
    *CONFIGURATION\_FILE* is a [Lua][] configuration file, a plain text file
    that can also be a Lua program. A sample configuration file can be found
    in /usr/local/share/yaf/yaf.init. **yaf** will use the variables set in
    the configuration file along with any command line arguments, with the
    configuration file typically taking precedence.
    
    This file's syntax is described [below](#yaf-config-file).

## [Options for Running as a Daemon](#daemon) {#daemon}

-   **--daemonize**

    If present, **yaf** will run in daemon mode.

-   **--pidfile** *PID\_PATH*

    Used to specify complete path to the file where **yaf** writes its
    process ID when running as a daemon.

## [Information Options](#information-options) {#information-options}

These options provide information about the **yaf** program.

-   **--version**

    If present, print version and copyright information to standard output
    and exit.

-   **--help**

    If present, print abbreviated information about how to invoke **yaf**
    and exit.

-   **--help-all**

    If present, print information about all of **yaf**'s command line
    options and exit.

# [YAF 3 Records and Templates](#yaf-3-rec-tmpl) {#yaf-3-rec-tmpl}

## [Base / Default Bi-FLOW](#base-default-bi-flow) {#base-default-bi-flow}


<table style="font-size: 9pt">
<tr class="header">
<th rowspan="2" align="left" valign="top">Field Name</th>
<th align="left" valign="top">IPFIX<br />(PEN,NUM)</th>
<th align="left" valign="top">Size and Type</th>
<th align="left" valign="top">When it's on</th>
<th align="left" valign="top">SiLK Field Mapping</th></tr>
<tr class="header"><th colspan="4" align="left" style="padding-left: 1.5em">Description</th></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>flowStartMilliseconds</strong></td>
<td valign="top">(0, 152)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">Always</td>
<td valign="top">STIME</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Flow start time in milliseconds since 1970-01-01 00:00:00 UTC</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>flowEndMilliseconds</strong></td>
<td valign="top">(0, 153)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">Always</td>
<td valign="top">ETIME</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Flow end time in milliseconds since 1970-01-01 00:00:00 UTC.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>octetTotalCount</strong></td>
<td valign="top">(0, 85)</td>
<td valign="top">8 bytes unsigned<br />(or 4 if reduced-length encoding)</td>
<td valign="top">not --delta (default)</td>
<td valign="top">BYTES</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Number of bytes in the forward direction of the flow</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseOctetTotalCount</strong></td>
<td valign="top">(29305, 85)</td>
<td valign="top">8 bytes unsigned<br />(or 4 if reduced-length encoding)</td>
<td valign="top">not --delta (default) and<br />not --uniflow (default)</td>
<td valign="top">BYTES</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Number of bytes in the reverse direction of the flow</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>octetDeltaCount</strong></td>
<td valign="top">(0, 1)</td>
<td valign="top">8 bytes unsigned<br />(or 4 if reduced-length encoding)</td>
<td valign="top">--delta</td>
<td valign="top">BYTES</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Number of bytes in the forward direction of the flow</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseOctetDeltaCount</strong></td>
<td valign="top">(29305, 1)</td>
<td valign="top">8 bytes unsigned<br />(or 4 if reduced-length encoding)</td>
<td valign="top">--delta and<br />not --uniflow (default)</td>
<td valign="top">BYTES</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Number of bytes in the reverse direction of the flow</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>packetTotalCount</strong></td>
<td valign="top">(0, 86)</td>
<td valign="top">8 bytes unsigned<br />(or 4 if reduced-length encoding)</td>
<td valign="top">not --delta (default)</td>
<td valign="top">PACKETS</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Number of packets in the forward direction of the flow</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reversePacketTotalCount</strong></td>
<td valign="top">(29305, 86)</td>
<td valign="top">8 bytes unsigned<br />(or 4 if reduced-length encoding)</td>
<td valign="top">not --delta (default) and<br />not --uniflow (default)</td>
<td valign="top">PACKETS</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Number of packets in the reverse direction of the flow</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>packetDeltaCount</strong></td>
<td valign="top">(0, 2)</td>
<td valign="top">8 bytes unsigned<br />(or 4 if reduced-length encoding)</td>
<td valign="top">--delta</td>
<td valign="top">PACKETS</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Number of packets in the forward direction of the flow</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseDeltaTotalCount</strong></td>
<td valign="top">(29305, 2)</td>
<td valign="top">8 bytes unsigned<br />(or 4 if reduced-length encoding)</td>
<td valign="top">--delta and<br />not --uniflow (default)</td>
<td valign="top">PACKETS</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Number of packets in the reverse direction of the flow</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>sourceIPv4Address</strong></td>
<td valign="top">(0, 8)</td>
<td valign="top">4 byte binary IP Address</td>
<td valign="top">Any IPv4 flow</td>
<td valign="top">SIP<br/>(and DIP if biflow)</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">IPv4 address of the flow source or biflow initiator</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>destinationIPv4Address</strong></td>
<td valign="top">(0, 12)</td>
<td valign="top">4 byte binary IP address</td>
<td valign="top">Any IPv4 flow</td>
<td valign="top">DIP<br/>(and SIP if biflow)</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">IPv4 address of the flow destination or biflow responder</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>sourceIPv6Address</strong></td>
<td valign="top">(0, 27)</td>
<td valign="top">16 bytes binary IP address</td>
<td valign="top">Any IPv6 flow</td>
<td valign="top">SIP\_V6<br/>(and DIP\_V6 if biflow)</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">IPv6 address of the flow source or biflow initiator</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>destinationIPv6Address</strong></td>
<td valign="top">(0, 28)</td>
<td valign="top">16 bytes binary IP address</td>
<td valign="top">Any IPv6 flow</td>
<td valign="top">DIP\_V6<br/>(and SIP\_V6 if biflow)</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">IPv6 address of the flow destination or biflow responder</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>sourceTransportPort</strong></td>
<td valign="top">(0, 7)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">Always</td>
<td valign="top">SPORT<br/>(and DPORT if biflow)</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">TCP or UDP port on the flow source or biflow initiator endpoint.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>destinationTransportPort</strong></td>
<td valign="top">(0, 8)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">Always</td>
<td valign="top">DPORT<br/>(and SPORT if biflow)</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">TCP or UDP port on the flow
destination or biflow responder endpoint. For ICMP flows, contains (ICMP-type * 256 + ICMP-code).</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>flowAttributes</strong></td>
<td valign="top">(6871, 40)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">Always</td>
<td valign="top">ATTRIBUTES (Bit 1 only)</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">
<p>Attributes of forward direction of flow:</p>
<p>Bit 1: All packets in the forward direction have fixed size. For TCP flows, only packets that have payload will be considered (to avoid TCP handshakes and teardowns).</p>
<p>Bit 2: At least one packet in the forward direction was received out-of-sequence.</p>
<p>Bit 3: Host may be MP\_CAPABLE (MPTCP-capable). For TCP flows, this bit will be set if a packet in the flow was seen that had the MP\_CAPABLE TCP option or attempted an MP\_JOIN operation.</p>
<p>Bit 4: Forward flow contains packets that were fragmented.</p></td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseFlowAttributes</strong></td>
<td valign="top">(6871, 16424)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">not --uniflow (default)</td>
<td valign="top">ATTRIBUTES (Bit 1 only)</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">
<p>Attributes of reverse direction of flow:</p>
<p>Bit 1: All packets in the reverse direction have fixed size. For TCP flows, only packets that have payload will be considered (to avoid TCP handshakes and teardowns).</p>
<p>Bit 2: At least one packet in the reverse direction was received out-of-sequence</p>
<p>Bit 3: Host may be MP\_CAPABLE (MPTCP-capable) For TCP flows, this bit will be set if a packet in the flow was seen that had the MP\_CAPABLE TCP option or attempted an MP\_JOIN operation.</p>
<p>Bit 4: Reverse flow contains packets that were fragmented.</p></td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>protocolIdentifier</strong></td>
<td valign="top">(0, 4)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Always</td>
<td valign="top">PROTOCOL</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">IP protocol of the flow</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>flowEndReason</strong></td>
<td valign="top">(0, 136)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Always</td>
<td valign="top">ATTRIBUTES<br />(Bits 0x80 and 0x02)</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">
<p>Flow end reason code, as defined by the IPFIX Information Model. Always present. In <strong>--silk</strong> mode, the high-order bit is set if the flow was created by continuation.</p>
<p>0x01: idle timeout The flow was terminated because it was considered to be idle.</p>
<p>0x02: active timeout The flow was terminated for reporting purposes while it was still active, for example, after the maximum lifetime of unreported flows was reached.</p>
<p>0x03: end of flow detected The flow was terminated because the Metering Process detected signals indicating the end of the flow, for example, the TCP FIN flag.</p>
<p>0x04: forced end The flow was terminated because of some external event, for example, a shutdown of the Metering Process initiated by a network management application.</p>
<p>0x05: lack of resources The flow was terminated because of lack of resources available to the Metering Process and/or the Exporting Process.</p>
<p>0x08: continuation Only set in <strong>--silk</strong> mode, indicates that this flow is a continuation of a previous flow that exceeded a timeout.</p>
<p>0x1f: udp-uniflow A special value set for UDP flows created in <strong>--udp-uniflow</strong> mode.</p></td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>silkAppLabel</strong></td>
<td valign="top">(6871, 33)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--applabel or --dpi</td>
<td valign="top">APPLICATION</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Application label, defined as the primary well-known port associated with a given application.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseFlowDeltaMilliseconds</strong></td>
<td valign="top">(6871, 24)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Difference in time in milliseconds between first packet in forward direction and first packet in reverse direction. Correlates with (but does not necessarily represent) round-trip time. Present if flow has a reverse direction.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>vlanId</strong></td>
<td valign="top">(0, 58)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">Always</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">802.1q VLAN tag of the first packet in the forward direction of the flow.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseVlanId</strong></td>
<td valign="top">(29305, 58)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">802.1q VLAN tag of the first packet in the reverse direction of the flow.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>ipClassOfService</strong></td>
<td valign="top">(0, 5)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Always</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">For IPv4 packets, this is the value of the TOS field in the IPv4 header. For IPv6 packets, this is the Traffic Class field in the IPv6 header.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseIpClassOfService</strong></td>
<td valign="top">(29305, 5)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">For IPv4 packets, this is the value of the TOS field in the IPv4 header in the reverse direction. For IPv6 packets, this is the Traffic Class field in the IPv6 header in the reverse direction.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>payloadEntropy</strong></td>
<td valign="top">(6871, 35)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">--entropy</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Shannon Entropy calculation of the forward payload data.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reversePayloadEntropy</strong></td>
<td valign="top">(6871, 16419)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">--entropy</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Shannon Entropy calculation of the reverse payload data.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>mptcpInitialDataSequenceNumber</strong></td>
<td valign="top">(6871, 289)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">Any MPTCP flow</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The initial data sequence number found in the MPTCP Data Sequence Signal (DSS) Option.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>mptcpReceiverToken</strong></td>
<td valign="top">(6871, 290)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">Any MPTCP flow</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The token used to identify an MPTCP connection over multiple subflows. This value is found in the MP\_JOIN TCP Option for the initial SYN of a subflow.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>mptcpMaximumSegmentSize</strong></td>
<td valign="top">(6871, 291)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">Any MPTCP flow</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The maximum segment size reported in the Maximum Segment Size TCP Option. This should be consistent over all subflows.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>mptcpAddressId</strong></td>
<td valign="top">(6871, 292)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Any MPTCP flow</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The address ID of the subflow found in the SYN/ACK of an MP\_JOIN operation.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>mptcpFlags</strong></td>
<td valign="top">(6871, 293)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Any MPTCP flow</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">
<p>Various MPTCP Values:</p>
<p>Bit 1: Priority was changed during the life of the subflow (MP\_PRIO was seen)<br />Bit 2: Subflow has priority at setup (backup flag was not set at initialization).<br />Bit 3: Subflow failed. (MP\_FAIL option was seen).<br />Bit 4: Subflow experienced fast close. (MP\_FASTCLOSE options was seen).</p></td></tr>
<tr>
<td rowspan="2" valign="top"><strong>yafDPIList</strong></td>
<td valign="top">(6871, 432)</td>
<td valign="top">variable-length subTemplateList</td>
<td valign="top">--dpi</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">SubTemplateList containing DPI information for the protocol specified in silkAppLabel</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>sourceMacAddress</strong></td>
<td valign="top">(0, 56)</td>
<td valign="top">6 bytes unsigned</td>
<td valign="top">--mac</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Source MAC Address of the first packet in the forward direction of the flow.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>destinationMacAddress</strong></td>
<td valign="top">(0, 80)</td>
<td valign="top">6 bytes unsigned</td>
<td valign="top">--mac</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Destination MAC Address of the first packet in the reverse direction of the flow.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>osName</strong></td>
<td valign="top">(6871, 36)</td>
<td valign="top">variable-length string</td>
<td valign="top">--p0fprint</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">p0f OS Name for the forward flow based on the SYN packet and p0f SYN Fingerprints. </td></tr>
<tr>
<td rowspan="2" valign="top"><strong>osVersion</strong></td>
<td valign="top">(6871, 37)</td>
<td valign="top">variable-length string</td>
<td valign="top">--p0fprint</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">p0f OS Version for the forward flow based on the SYN packet and p0f SYN Fingerprints.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>osFingerprint</strong></td>
<td valign="top">(6871, 107)</td>
<td valign="top">variable-length string</td>
<td valign="top">--p0fprint</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">p0f OS Fingerprint for the forward flow based on the SYN packet and p0f SYN fingerprints. </td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseOsName</strong></td>
<td valign="top">(6871, 16420)</td>
<td valign="top">variable-length string</td>
<td valign="top">--p0fprint and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">p0f OS Name for the reverse flow based on the SYN packet and p0f SYN Fingerprints.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reverseOsVersion</strong></td>
<td valign="top">(6871, 16421)</td>
<td valign="top">variable-length string</td>
<td valign="top">--p0fprint and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">p0f OS Version for the reverse flow based on the SYN packet and p0f SYN fingerprints.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseOsFingerprint</strong></td>
<td valign="top">(6871, 16491)</td>
<td valign="top">variable-length string</td>
<td valign="top">--p0fprint and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">p0f OS Fingerprint for the reverse flow based on the SYN packet and p0f SYN Fingerprints.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>firstPacketBanner</strong></td>
<td valign="top">(6871, 38)</td>
<td valign="top">variable-length octetArray</td>
<td valign="top">--fpexport</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">IP and transport headers for first packet in forward direction to be used for external OS Fingerprinters.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>secondPacketBanner</strong></td>
<td valign="top">(6871, 39)</td>
<td valign="top">variable-length octetArray</td>
<td valign="top">--fpexport</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">IP and transport headers for second packet in forward direction (third packet in sequence) to be used for external OS Fingerprinters. </td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reverseFirstPacketBanner</strong></td>
<td valign="top">(6871, 16422)</td>
<td valign="top">variable-length octetArray</td>
<td valign="top">--fpexport and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">IP and transport headers for first packet in reverse direction to be used for external OS Fingerprinters.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>payload</strong></td>
<td valign="top">(6871, 18)</td>
<td valign="top">variable-length octetArray</td>
<td valign="top">--export-payload</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Initial <em>n</em> bytes of forward direction of flow payload. </td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reversePayload</strong></td>
<td valign="top">(6871, 16402)</td>
<td valign="top">variable-length octetArray</td>
<td valign="top">--export-payload and<br /> not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Initial <em>n</em> bytes of reverse direction of flow payload.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>ingressInterface</strong></td>
<td valign="top">(0, 10)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--ingress<br />or --export-interface</td>
<td valign="top">IN<br/>(and OUT if biflow)</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The index of the IP interface where packets of this flow are being received.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>egressInterface</strong></td>
<td valign="top">(0,14)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--egress<br />or --export-interface</td>
<td valign="top">OUT<br/>(and IN if biflow)</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The index of the IP interface where packets of this flow are being received.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>dataByteCount</strong></td>
<td valign="top">(6871, 502)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Total bytes transferred as payload.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>averageInterarrivalTime</strong></td>
<td valign="top">(6871, 503)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Average number of milliseconds between packets.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>standardDeviationInterarrivalTime</strong></td>
<td valign="top">(6871, 504)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Standard deviation of the interarrival time for up to the first ten packets.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>tcpUrgTotalCount</strong></td>
<td valign="top">(0, 223)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The number of TCP packets that have the URGENT Flag set.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>smallPacketCount</strong></td>
<td valign="top">(6871, 500)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The number of packets that contain less than 60 bytes of payload.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>nonEmptyPacketCount</strong></td>
<td valign="top">(6871, 501)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The number of packets that contain at least 1 byte of payload.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>largePacketCount</strong></td>
<td valign="top">(6871, 510)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The number of packets that contain more than 225 bytes of payload.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>firstNonEmptyPacketSize</strong></td>
<td valign="top">(6871, 505)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Payload length of the first non-empty packet.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>maxPacketSize</strong></td>
<td valign="top">(6871, 506)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The largest payload length transferred in the flow.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>standardDeviationPayloadLength</strong></td>
<td valign="top">(6871, 508)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The standard deviation of the payload length for up to the first 10 non empty packets.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>firstEightNonEmptyPacketDirections</strong></td>
<td valign="top">(6871, 507)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">--flow-stats</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Represents directionality for the first 8 non-empty packets. 0 for forward direction, 1 for reverse direction.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reverseDataByteCount</strong></td>
<td valign="top">(6871, 16886)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Total bytes transferred as payload in the reverse direction.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseAverageInterarrivalTime</strong></td>
<td valign="top">(6871, 16887)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Average number of milliseconds between packets in reverse direction.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reverseStandardDeviationInterarrivalTime</strong></td>
<td valign="top">(6871, 16888)</td>
<td valign="top">8 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Standard deviation of the interarrival time for up to the first ten packets in the reverse direction.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseTcpUrgTotalCount</strong></td>
<td valign="top">(29305, 223)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The number of TCP packets that have the URGENT Flag set in the reverse direction.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reverseSmallPacketCount</strong></td>
<td valign="top">(6871, 16884)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The number of packets that contain less than 60 bytes of payload in reverse direciton.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseNonEmptyPacketCount</strong></td>
<td valign="top">(6871, 16885)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The number of packets that contain at least 1 byte of payload in reverse direction.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reverseLargePacketCount</strong></td>
<td valign="top">(6871, 16894)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The number of packets that contain more than 225 bytes of payload in the reverse direction.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseFirstNonEmptyPacketSize</strong></td>
<td valign="top">(6871, 16889)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Payload length of the first non-empty packet in the reverse direction.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reverseMaxPacketSize</strong></td>
<td valign="top">(6871, 16890)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The largest payload length transferred in the flow in the reverse direction.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseStandardDeviationPayloadLength</strong></td>
<td valign="top">(6871, 16892)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--flow-stats and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The standard deviation of the payload length for up to the first 10 non empty packets in the reverse direction.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>initialTCPFlags</strong></td>
<td valign="top">(6871, 14)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Any TCP flow</td>
<td valign="top">initialFlags</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">TCP flags of initial packet in the forward direction of the flow.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>unionTCPFlags</strong></td>
<td valign="top">(6871, 15)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Any TCP flow</td>
<td valign="top">sessionFlags</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Union of TCP flags of all packets other than the initial packet in the forward direction of the flow.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>tcpSequenceNumber</strong></td>
<td valign="top">(0, 184)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">Any TCP flow</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Initial sequence number of the forward direction of the flow. </td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseTcpSequenceNumber</strong></td>
<td valign="top">(29305, 184)</td>
<td valign="top">4 bytes unsigned</td>
<td valign="top">Any TCP flow and<br />not --uniflow (default)</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Initial sequence number of the reverse direction of the flow.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>reverseInitialTCPFlags</strong></td>
<td valign="top">(6871, 16398)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Any TCP flow and<br />not --uniflow (default)</td>
<td valign="top">initialFlags</td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">Initial sequence number of the reverse direction of the flow.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>reverseUnionTCPFlags</strong></td>
<td valign="top">(6871, 16399)</td>
<td valign="top">1 byte unsigned</td>
<td valign="top">Any TCP flow and<br />not --uniflow (default)</td>
<td valign="top">sessionFlags</td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Union of TCP flags of all packets other than the initial packet in the reverse direction of the flow.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>ndpiL7Protocol</strong></td>
<td valign="top">(6871, 300)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--ndpi</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The protocol as determined by analysis with [nDPI][], the [ntop][]-maintained superset of the OpenDPI library.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>ndpiL7SubProtocol</strong></td>
<td valign="top">(6871, 301)</td>
<td valign="top">2 bytes unsigned</td>
<td valign="top">--ndpi</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The subprotocol as determined by analysis with [nDPI][].</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>mplsTopLabelStackSection</strong></td>
<td valign="top">(0, 70)</td>
<td valign="top">3 bytes octetArray</td>
<td valign="top">[Built][installation] with MPLS</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The MPLS Label from the top of the MPLS label stack entry. <strong>yaf</strong> does not include the Experimental bits and Bottom of the Stack bit in the export field.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>mplsLabelStackSection2</strong></td>
<td valign="top">(0, 71)</td>
<td valign="top">3 bytes octetArray</td>
<td valign="top">[Built][installation] with MPLS</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">The MPLS Label from the MPLS label stack entry immediately before the top entry. <strong>yaf</strong> does not include the Experimental bits and Bottom of the Stack bit in the export field.</td></tr>
<tr class="odd">
<td rowspan="2" valign="top"><strong>mplsLabelStackSection3</strong></td>
<td valign="top">(0, 72)</td>
<td valign="top">3 bytes octetArray</td>
<td valign="top">[Built][installation] with MPLS</td>
<td valign="top"></td></tr>
<tr class="odd"><td colspan="4" style="padding-left: 1.5em">The MPLS Label from the third entry in the MPLS label stack. <strong>yaf</strong>does not include the Experimental bits and Bottom of the Stack bit in the export field.</td></tr>
<tr>
<td rowspan="2" valign="top"><strong>subTemplateMultiList</strong></td>
<td valign="top">(0, 293)</td>
<td valign="top">variable-length subTemplateMultiList</td>
<td valign="top">[Built][installation] with plugin support</td>
<td valign="top"></td></tr>
<tr><td colspan="4" style="padding-left: 1.5em">Contains non-DPI things. Examples include DHCP Fingerprinting</td></tr>
</table>


[//]: # (We should make this a customizable table based on checkboxes that the)
[//]: # (user selects with uniflow vs biflow, and all other command line)
[//]: # (options to build the records.)

### [DPI](#dpi) {#dpi}

[//]: # (Make better organized tables for YAF dpi rather than what's on the webpage now.)

# [Lua Configuration Files](#lua-configs) {#lua-configs}

## [YAF Configuration File](#yaf-config-file) {#yaf-config-file}

The **yaf** configuration file is an alternative to running **yaf** with
command line options. The YAF configuration file is written in the [Lua][]
language, and this file may be specified on the **yaf** command line with
the **--config** option. A template file is provided in
/usr/local/share/yaf/yaf.init; the file should be copied and customized for
your needs.

The syntax of the configuration file is explained by annotated examples.

    -- This is a comment.
    -- Anything not marked as Required is optional.

    -- The only required variables are "input" and "output".
    -- All other variables are optional.

The sample configuration file must be customized by the user, and to ensure
that happens, it raises an error. Delete the error when customizing the
file.

    -- Remove these lines when you customize this file
    error [[You are attempting to use yaf.init without customizing it.
    You must remove the error statement from the beginning of the file.]]

Specifying the input is required.

     -- A variable named "input" is required; its value must be a table.
     -- It specifies the input to yaf.

This example has **yaf** read PCAP data from an interface.

    input = {

        -- The input table must have a key named "type". The default
        -- input "type" is "file".  Valid values are "pcap", "dag",
        -- "napatech", "netronome", "pfring", "zc", "file", and "caplist".
        type="pcap",

        -- In "pcap", "dag", "napatech", "netronome", "pfring", and "zc",
        -- a "inf" field is required.  Its value is the name of the interface
        -- that yaf will read. In the "zc" case, it is the cluster ID
        -- that yaf should listen to.
        inf="en0",

        -- Optional parameters for all input types
        -- are "export_interface" and "force_read_all".
        -- Both options expect boolean values "true" and "false".
        export_interface=true}

This example has **yaf** read PCAP data from a file.

    input = {

        type = "file",

        -- If type is "file", a "file" is expected with the
        -- full path to the PCAP file.
        file="/pcaps/mypcap.pcap"}

This example has **yaf** read PCAP data from the standard input. The type
does not need to be specified since "file" is the default.

    -- Use a file name of "-" to read from stdin.
    input = {file = "-"}

This example has **yaf** read PCAP data from a list of files.

    input = {
        type = "caplist",
        -- If type is "caplist", a "file" is expected which is
        -- the full path to a text file that contains a list
        -- of PCAP files in the order that they will be processed.
        file = "/data/pcapfile.txt",

        -- An optional parameter to "caplist" types, is "noerror"
        -- which expects a boolean value (true/false). If true,
        -- yaf will continue to process the list if it encounters
        -- an error in a PCAP file.
        noerror = true}

Specifying the output is required.

    -- A variable named "output" is required; its value must be a table.
    -- It specifies the output of yaf.

This example has **yaf** write to a TCP socket.

    output = {
        -- The host where an IPFIX collector is listening
        host = "localhost",

        -- The value to "port" must be in quotation marks.
        port = "18000",

        -- Acceptable protocol types are "tcp", "udp", and "sctp".
        -- If protocol is "udp", the optional "udp_temp_timeout" key is
        -- also available.
        protocol = "tcp"}

This example has **yaf** write to an IPFIX file that rotates every 200
seconds. The output file will be locked until **yaf** has closed the
file.

    output = {
        file = "/data/yaffile.yaf",
        rotate = 200,
        lock = true}

This example has **yaf** write IPFIX data to the standard output.

    -- Use a file name of "-" to write to stdout.
    output = {file = "-"}

Optional keywords.

    -- The "decode" variable is optional. Its value must be a table.
    -- All keywords within the "decode" variable expect a boolean
    -- response (true/false).

    decode = {
        -- If the "gre" variable is set to "true", gre decoding will be enabled.
        gre = false,

        -- If the "ip4_only" variable is set to "true", yaf will only
        -- process IPv4 flows.
       ip4_only = false,

        -- If the "ip6_only" variable is set to "true", yaf will only
        -- process Ipv6 flows.
       ip6_only = false,

        -- If the "nofrag" variable is set to "true", yaf will not
        -- process fragmented packets.
        nofrag = false}

    -- The "export" variable is optional. Its value must be a table.
    -- All keywords within the "export" variable
    -- expect a boolean response (true/false).

    export = {
        -- See the related options in the yaf man page.
        silk = true,
        uniflow = true,
        force_ip6 = false,
        flow_stats = true,
        delta = false,
        mac = true }

    -- The "log" variable is optional. Its value must be a table.

    log = {
        -- The "spec" keyword may be set to a syslog facility name,
        -- stderr, or the absolute path to a file for file logging.
        -- Default is stderr.
        spec = "/var/log/yaf/yaf.log",

        -- The "level" keyword specifies how much to log. The accepted
        -- values are "quiet", "error", "critical", "warning", "message",
        -- and "debug". Default is "warning".
        level = "debug"}

    -- The plugin variable is optional. Its value must be a table of tables.
    -- See the yafdhcp man page for the plugin that is provided with yaf.
    -- To make configuration easier, specify Lua variables that hold
    -- the information for each plugin.

    DHCP_PLUGIN = {
        -- The "name" keyword specifies the full path to the plugin
        -- library name to load.
        name = "/usr/local/lib/yaf/dhcp_fp_plugin.la"

        -- The "options" keyword specifies the arguments given to the
        -- plugin.
        -- options =

        -- The "conf" keyword specifies the path to a configuration
        -- file to be given to the plugin, if it requires one.
        -- conf =
    }

    plugin = {DHCP_PLUGIN}

    -- The pcap variable is used to configure yaf's export of PCAP
    -- data to files.  The pcap variable is optional; if present, its
    -- value must be a table.  See the yaf man page for more
    -- information on yaf's PCAP capabilities.

    pcap = {
        -- The "path" keyword specifies where yaf will write PCAP files.
        path = "/data/pcap/yafpcap",

        -- The "maxpcap" keyword specifies the maximum file size of a
        -- yaf PCAP file.
        maxpcap = 100,

        -- The "pcap_timer" keyword specifies how often the PCAP file
        -- should be rotated.
        pcap_timer = 300,

        -- The "meta" keyword specifies where to write PCAP meta information.
        meta = "/data/meta/yafmeta"}

The following keywords are optional variables. See the yaf man page for
more information.

    -- idle_timeout = IDLE_TIMEOUT (integer)
    -- Set flow idle timeout in seconds.  Default is 300 seconds (5 min)
    -- Setting IDLE_TIMEOUT to 0 creates a flow for each packet.
    idle_timeout = 300

    -- active_timeout = ACTIVE_TIMEOUT (integer)
    -- Set flow active timeout in seconds.  Default is 1800 seconds (30 min)
    active_timeout = 1800

    -- filter = BPF_FILTER
    -- Set Berkeley Packet Filtering (BPF) in YAF with BPF_FILTER.
    filter = "port 53"

    -- APPLICATION LABELING AND DEEP PACKET INSPECTION OPTIONS
    -- Turn on application labeling by setting applabel = true
    -- Turn on deep packet inspection by setting dpi = true
    -- Read the application labeler/DPI rules file from dpi_rules=
    -- If dpi_rules is not set, uses the default location
    applabel = true
    dpi = true
    -- dpi_rules = "/usr/local/etc/yafDPIRules.conf"

    -- maxpayload = PAYLOAD_OCTETS (integer)
    -- Capture at most PAYLOAD_OCTETS octets from the start of each direction
    -- of each flow.  Default is 0.
    maxpayload = 1024

    -- maxexport = MAX_PAY_OCTETS (integer)
    -- Export at most MAX_PAY_OCTETS octets from the start of each direction
    -- of each flow from the PAYLOAD_OCTETS given to maxpayload.
    -- Default is PAYLOAD_OCTETS if export_payload=true
    maxexport = maypayload

    -- export_payload = true/false
    -- If true, export at most PAYLOAD_OCTETS or MAX_PAY_OCTETS given to
    -- maxpayload or maxexport for each direction of the flow.
    -- Default is false.
    export_payload = false

    -- udp_payload = true/false
    -- If true, capture at most PAYLOAD_OCTETS octets from the start of
    -- each UDP flow, where PAYLOAD_OCTETS is set using the maxpayload option
    udp_payload = true

    -- stats = INTERVAL (integer)
    -- If present, yaf will export process statistics every INTERVAL seconds.
    -- If stats is set to 0, no stats records will be exported.
    -- default is 300
    stats = 300

    -- ingress = ingressInterface (integer)
    -- egress = egressInterface (integer)
    -- use the above options to manually set the ingressInterface or
    -- egressInterface in the exported flow record. Default is 0.
    ingress = 0
    egress = 0

    -- obdomain = DOMAIN_ID (integer)
    -- Set the othe observationDomainId on each exported IPFIX message to
    -- DOMAIN_ID.  Default is 0.
    obdomain = 0

    -- maxflows = FLOW_TABLE_MAX (integer)
    -- Limit the number of open flows to FLOW_TABLE_MAX. Default is no limit.
    -- maxflows =

    -- maxfrags = FRAG_TABLE_MAX (integer)
    -- Limit the number of fragments to FRAG_TABLE_MAX. Default is no limit.
    -- maxfrags =

    -- udp_uniflow = PORT (integer)
    -- If set, export each UDP packet on the given PORT (or 1 for all ports)
    -- as a single flow. Default is 0 (off).
    udp_uniflow = 0

    -- Turn on entropy output by setting entropy = true
    entropy = true

    -- no_tombstone = true/false
    -- If true, tombstone records will not be sent.
    -- default is false (that is, to export tombstone records).

    -- no_tombstone =

    -- tombstone_configured_id = TOMBSTONE_IDENTIFIER (integer)
    -- Set the configured identifier for tombstone records generated by YAF.
    -- default is 0

    -- tombstone_configured_id =

    -- no_element_metadata = true/false
    -- If true, element metadata (RFC5610 records) will not be sent.
    -- default is false (that is, to export the RFC5610 records).

    -- no_element_metadata =

    -- no_template_metadata = true/false
    -- If true, template metadata (name, description, other information) will
    -- not be sent
    -- default is false (that is, to export template metadata).

    -- no_template_metadata =

The following options configure the passive OS fingerprinting capabilities in
**yaf**. This capabliity must be configured when **yaf** is
[built][installation].

    -- p0fprint = true/false
    -- p0f_fingerprints = "/usr/local/etc/p0f.fp"
    -- fpexport = true/false
    -- See the yaf man page for more information. YAF must be configured
    -- appropriately to use the following options.
    -- p0fprint = true
    -- fpexport = true
    -- p0f_fingerprints = "/usr/local/etc/p0f.fp"

The following options configure support for the [nDPI][] application
labeler. This capabliity must be configured when **yaf** is
[built][installation].

    -- nDPI OPTIONS
    -- ndpi = true/false
    -- ndpi_proto_file = "PATH"
    -- See the yaf man page for more information. YAF must be configured
    -- appropriately to use the following options.
    -- ndpi = true
    -- ndpi_proto_file = "LOCATION"

## [YAF Applabel and DPI Configuration File](#yafdpi-config) {#yafdpi-config}

This file is described on the [Application Labeling][applabeling] and [Deep
Packet Inspection][dpi] pages.

# [YAF Manual Pages](#yaf-manual-pages) {#yaf-manual-pages}

The following manual pages are available and distributed with YAF:

-   [**yaf**][man_yaf]

     The main **yaf** application, described on this page.

-   [**applabel**][man_applabel]

    A description of the yafDPIRules.conf file, focusing on the settings
    that determine an application label for a flow record.

-   [**yafdpi**][man_yafdpi]

    A description of the yafDPIRules.conf file, focusing on the settings
    that extract values from the payload for deep packet inspection.

-   [**yafdhcp**][man_yafdhcp]

    The DHCP fingerprint plug-in.

-   [**yaf.init**][man_yaf.init]

    The syntax of configuration file that may be used in place of
    command-line arguments.

-   [**yafzcbalance**][man_yafzcbalance]

    The [PF_RING ZC (ZeroCopy)][pfringzc] load balancer application for YAF.

-   [**getFlowKeyHash**][man_getFlowKeyHash]

    YAF flow key calculator application.

-   [**yafMeta2Pcap**][man_yafMeta2Pcap]

    YAF PCAP metadata file parser and PCAP creator application.

-   [**filedaemon**][man_filedaemon]

    Application to invoke another program on files matching a glob pattern.

-   [**airdaemon**][man_airdaemon]

    Application to run a program as a daemon process, restarting it if it
    dies.

-   [**yafscii**][man_yafscii]

    An older tool for printing IPFIX netflow flow records generated by
    **yaf** as text. Its output format is loosely analogous to that produced
    by tcpdump, with one flow per line. It does not support output of the
    DPI data created by **yaf**. The [**ipfix2json**][ipfix2json] and
    [**ipfixDump**][ipfixDump] applications from [libfixbuf][] are able to
    print all records generated by **yaf** (or another IPFIX tool) and
    include support for printing subrecords.



[Lua]:            https://www.lua.org/
[nDPI]:           https://www.ntop.org/products/deep-packet-inspection/ndpi/
[ntop]:           http://www.ntop.org/
[pfringzc]:       https://www.ntop.org/products/packet-capture/pf_ring/pf_ring-zc-zero-copy/
[rfc5610]:        https://datatracker.ietf.org/doc/html/rfc5610.html
[rfc7011]:        https://datatracker.ietf.org/doc/html/rfc7011.html

[certipfix]:      /cert-ipfix-registry/index.html
[libp0f]:         /p0f/libp0f.html
[libfixbuf]:      /fixbuf/index.html
[ipfixDump]:      /fixbuf/ipfixDump.html
[ipfix2json]:     /fixbuf/ipfix2json.html

[applabeling]:          applabeling.html
[dpi]:                  deeppacketinspection.html
[installation]:         install.html
[man_applabel]:         applabel.html
[man_airdaemon]:        airdaemon.html
[man_filedaemon]:       filedaemon.html
[man_getFlowKeyHash]:   getFlowKeyHash.html
[man_yaf]:              yaf.html
[man_yaf.init]:         yaf.init.html
[man_yafMeta2Pcap]:     yafMeta2Pcap.html
[man_yafdhcp]:          yafdhcp.html
[man_yafdpi]:           yafdpi.html
[man_yafscii]:          yafscii.html
[man_yafzcbalance]:     yafzcbalance.html


[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
