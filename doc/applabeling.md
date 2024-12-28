% YAF: Application Labeling

# [Introduction](#introduction) {#introduction}

**yaf** can examine packet payloads to determine the application protocol in
use within a flow and export a 16-bit application label with each flow. The
exported application label (applabel) uses the primary well-known port
number for the protocol. In most cases, the applabel is the official
Internet Assigned Numbers Authority (IANA)-assigned port number, but in some
cases the applabel may be the de facto port for the protocol or a custom
label when a protocol does not have any well-known ports or overlaps with
another applabel. For example, HTTP traffic, independent of what port the
traffic is detected on, will be labeled with a value of 80, the default HTTP
port.

The applabel is exported to the **silkAppLabel** CERT (PEN 6871) Information
Element (IE) 33.

Labels and rules are taken from a configuration file read by **yaf** at
startup time. Since the application labeling and Deep Packet Inspection
(DPI) rules are, as of YAF 3, combined in a single Lua confguration file,
the rule file can be given on the command line with the **--dpi-rules-file**
option or **yaf** will try to read it from the default location of
`/usr/local/etc/yafDPIRules.conf.` (The location may be different depending
on how your **yaf** installation was built.)

> **Note:** The application labeling support in YAF 3 differs greatly from
> that in prior releases. If using a previous release of **yaf**, please
> consult the manual pages for your installation.

### [Required build time options: --enable-applabel](#enable-applabel) {#enable-applabel}

Application labeling is not included in **yaf** by default; the
**--enable-applabel** option must be passed to `configure`.

To check whether your **yaf** installation has application labeling enabled,
run **yaf** **--version** and check the setting of "Application Labeling".

### [Minimum required run time options: --applabel --max-payload](#max-payload) {#max-payload}

Application labeling always requires payload capture to be enabled with the
**--max-payload** option.

Application labeling is generally a "lighter" inspection of the packet
payloads than [deep packet inspection (DPI)][deeppacketinspection]. A
minimum payload capture length of 384 bytes is recommended for best results
if using application labeling without DPI enabled, in which case only the
**--applabel** option is required:

    yaf --daemonize --live pcap --in eth0               \
        --out localhost --ipfix-port=18000 --ipfix tcp  \
        --applabel --max-payload=384

Running **yaf** with application labeling, no DPI, and specifying a
rules file:

    yaf --daemonize --live pcap --in eth0               \
        --out localhost --ipfix-port=18000 --ipfix tcp  \
        --applabel --max-payload=384 --dpi-rules-file=*FILE*

If DPI is to be exported, this implies the use of application labeling and
only the **--dpi** option is required, which will enable both features. When
DPI is enabled, a minimum payload capture length of 2048 bytes is
recommended, but 4096 bytes is ideal for best results (including capture of
full certificate chains):

    yaf --daemonize --live pcap --in eth0               \
        --out localhost --ipfix-port=18000 --ipfix tcp  \
        --dpi --max-payload=4096

# [Configuration File](#configuration-file) {#configuration-file}

While both applabel and DPI-related configuration options are in the
configuration file, here we are focusing only on options relevant to
application labeling.

## [Format](#format) {#format}

The configuration file is written in [Lua][]. For specifics of the Lua
language, see <http://www.lua.org/manual/5.3/manual.html>

Comments in Lua start with double hyphens (`--`) and continue to the end of
the line.

The file must define a variable named `applabels` which is an array of
applabel tables. Each applabel table defines a rule that tells **yaf** how
to assign an applabel, what information elements to create when doing dpi,
and how to assign values to those elements.

An applabel rule has the form

     {label=<APP>,
      label_type="<LABEL_TYPE>",
      value=[=[<EXPRESSION>]=],
      ports={<PORTS>},
      protocol=<PROTO>,
      active=<true|false>,
      <DPI-RELATED-ENTRIES>}

where

-   At least `label`, `label_type`, and `value` keys are required.

-   \<APP\> is the application label to apply, and it is an unsigned 16-bit
    decimal integer in the range 1 to 65535 inclusive. This value must be
    unique across all rules.

-   \<LABEL\_TYPE\> is the type of rule, a string. Three label_types of
    applabel rules are supported: **regex**, **plugin**, and **signature**.
    (Additionally, type of **none** ignores the entry.) These are described
    in more detail in the "Assigning\..." sections below.

-   \<EXPRESSION\> specifies how to recognize the given application protocol
    and is dependent on the \<label\_type\>. It is a string.

    When setting `value`, we recommend using the syntax for a Lua "long
    literal" so that any backslashes in the regular expression do not need
    to be escaped. A long literal is surrounded by a double square brackets
    called "long brackets", and zero or more equal signs (`=`) may appear
    between each set of brackets (the same number on each side),
    `[====[example]====]`. At least one equal sign is recommended when
    specifying a regex to disambiguate from character ranges which also use
    square brackets.

-   \<PORTS\> allows associating multiple ports to an applabel with
    **regex** or **plugin** label_type. If "ports" is not present, only the
    applabel is used to check for matches against a flow's source or
    destination ports. \<PORTS\> MUST be defined as a comma-separated list
    of one or more integers in the range 1 to 65535 inclusive, enclosed in
    curly braces. \<PORTS\> MUST NOT include any applabel value or any other
    "ports" values defined in other rules. They must be non-overlapping.
    Overall, this option helps **yaf** trigger applabel tests more
    efficiently and improves applabel accuracy.

-   \<PROTO\> limits a **regex** label_type to being tested only when the
    flow record's protocolIdentifier matches \<PROTO\> or when \<PROTO\>
    is 0. If "protocol" is not present, the test is performed. \<PROTO\> is
    a value between 0 and 255 inclusive, but only 0, 6, and 17 are relevant
    since **yaf** only runs applabel checks for TCP and UDP records. The
    protocol is ignored for **plugin** label_type rules; that check should
    be performed by the plugin itself. Specifying a protocol is best used to
    avoid false positives.

-   The value of `active` is a boolean indicating whether the rule is
    active, and defaults to true if not present.

-   \<DPI-RELATED-ENTRIES\> are optional. Here, this simply denotes where
    DPI-related rule entries would go, if applicable.

Here is an example giving a complete definition of the `applabels` variable.

    applabels = {
      {label=80, label_type="regex", value=[=[^HTTP/\d]=]}
    }

In this case, any TCP or UDP flow record whose payload starts with "HTTP/"
followed by a digit is assigned the applabel 80, and all other flows are
assigned applabel 0.

### [Assigning an Applabel Using Regular Expressions](#applabel-regex) {#applabel-regex}

A "regex" label_type rule has the following form:

     {label=<APP>,
      label_type="regex",
      active=true,
      protocol=<PROTO>,
      value=[=[<PCRE_REGEX>]=],
      <DPI-RELATED-ENTRIES>}

The \<PCRE\_REGEX\> is a [PCRE][] regular expression (see the PCRE
documentation for details, particularly [pcrepattern][] and [pcresyntax][]).
**yaf** checks the available payload of both directions of the flow with the
\<PCRE\_REGEX\>, and if the expression matches either direction of the
payload the label \<APP\> is applied to the flow.

### [Assigning an Applabel Using A Plugin](#applabel-plugin) {#applabel-plugin}

Plugin rules are used to label application payload using a C dynamically
loaded library, and have the following form:

    {label=\<APP\>,
     label_type="plugin",
     active=true,
     value=[=[<LIBRARY>]=],
     args={[[ARG1]], [[ARG2]], ...},
     <DPI-RELATED-ENTRIES>}

where \<LIBRARY\> is the name of a dynamically loadable library that exists
somewhere within the LD\_LIBRARY\_PATH, the LTDL\_LIBRARY\_PATH, or a system
library path, without the library name extension (usually `.so`). If the
plugin returns 1, the flow will be labeled with \<APP\>. Otherwise, the flow
will be labeled with the value the plugin returns (useful for a plugin that
can identify more than one protocol). See the source code to the plugins
that ship with **yaf** for details.

The `args` key is optional. If present, its value is an array of strings
that are to be passed as arguments to the plugin.

### [Assigning an Applabel Using a Signature](#applabel-signature) {#applabel-signature}

For regular expressions that are not tied to a particular port and when
no DPI is needed, use the signature rule. These are processed before
the regex and plugin type rules. A signature type rule has this form:

    {label=<N>,
     label_type="signature",
     active=true,
     value=[=[<PCRE_REGEX>]=]}

The \<PCRE\_REGEX\> is compared against the available payload of the flow;
if the expression matches, the label \<N\> is applied to the flow.

## [Using the Proxy Plugin](#proxy-plugin) {#proxy-plugin}

If **yaf** is seeing traffic behind a web proxy, it may incorrectly label
https (443) traffic as http (80) due to the HTTP Connect method that occurs
before the Certificate exchange. To accurately label https traffic,
uncomment the following line in the yafDPIRules.conf file at the top of the
`applabels` variable:

    {label=<N>, label_type="plugin", value=[[proxyplugin]]},

and set \<N\> to the port on which the proxy is listening for connections.
This will not label https flows as \<N\>. It will set the application label
to 443 and will allow **yaf** DPI to capture and export X.509 Certificates.

Note, if you enable the proxy plugin and \<N\> is also one of the ports
pre-defined in the HTTP rule, then remove that port from the `ports` key in
the HTTP rule.

# [Tips and Caveats](#tips-and-caveats) {#tips-and-caveats}

## [Match Order Logic](#match-order-logic) {#match-order-logic}

In order to determine the applabel, **yaf** goes through a particular
sequence of checks, which users should be aware of. Ultimately, this
sequence impacts application labeling accuracy, efficiency, and how one
constructs rules for protocols.

Rules must be active to be included in any checks. For each flow that is
passed to the applabel engine, checks are performed in the following
sequence:

Let DEFORD be the order of the rules as defined in the configuration
file

Let PORT\_MATCH be where **sourceTransportPort** or
**destinationTransportPort** = \<APP\> or any value defined in \<PORTS\>, if
present

Let PROTO\_MATCH be where, if regex rule, **protocolIdentifier** =
\<PROTO\>, \<PROTO\> = 0, or \<PROTO\> is not present, or where, if
plugin rule, the protocol check passes in the plugin

1.  In DEFORD, compare each **signature** rule against the forward and/or
    reverse payload

2.  Compare any **regex** or **plugin** rule where PORT\_MATCH and
    PROTO\_MATCH against the *forward* payload

3.  In DEFORD, compare any **regex** or **plugin** rule against the
    *forward* payload

4.  Compare any **regex** or **plugin** rule where PORT\_MATCH and
    PROTO\_MATCH against the reverse payload

5.  In DEFORD, compare any **regex** or **plugin** rule against the reverse
    payload

6.  No match or error, applabel 0 is applied to the flow

Once a match is found, the applabel engine will not continue to find a
"better" match - applabel processing stops on first match and applabel \<N\>
or \<APP\> is applied to the flow.

Given the above sequence, it is clear that the order of the rules as
defined in the configuration file matters.

## [Accuracy](#accuracy) {#accuracy}

Generally around 80% of the traffic that **yaf** observes will not be
positively identified and will have an applabel value of 0. This occurs
for a number of reasons, including but not limited to the following:

-   The vantage point of the sensor (e.g., running outside of firewalls or
    other incoming packet filters), where the sensor is more likely to see
    half-open connections, scanning and other "garbage" internet traffic

-   Unknown, proprietary, malformed, or otherwise unsupported protocols

-   Implementations do not always conform to protocol specs

-   Overly specific or poorly written checks

-   Protocol evolution and outdated checks

## [Rule Tips](#rule-tips) {#rule-tips}

-   More common protocols should have their rules inserted near the top of
    the configuration file.

-   Include all ports that are commonly associated with a given protocol
    (but which do not overlap with other applabel and port definitions).
    This increases the chances that the correct rule will be checked first.

-   Include protocol checks. If a given protocol only ever uses TCP, then a
    rule for that protocol does not need to run against UDP flows. This
    improves applabel accuracy and efficiency.

-   Construct rule regular expressions that target the expected *forward*
    payload for a given protocol, since the forward payload is checked prior
    to the reverse payload. Regular expressions specifically crafted for
    reverse payloads are not recommended; unless there is no chance that
    they will match another protocol in the list.

-   Be aware of similarities between protocols and when those checks are
    performed.

-   If possible, anchor regular expressions to the beginning of the payload
    (e.g., using `^`).

## [Applabel and nDPI](#applabel-and-ndpi) {#applabel-and-ndpi}

The applabel engine and [nDPI][], despite its name, essentially attempt to do
the same thing - identify the application protocol in use within a flow.
While technically these features may be used together at the same time, nDPI
is generally meant to be an alternative to the applabel engine. nDPI will
typically be enabled in one of two ways:

1.  On its own (using **--ndpi**) if only application labeling is needed and
    the user wants an alternative to the **yaf** applabel engine

        yaf --daemonize --live pcap --in eth0              \
            --out localhost --ipfix-port=18000 --ipfix tcp \
            --ndpi --max-payload=384

2.  Each of applabel, DPI, and nDPI features will be enabled (using
    **--ndpi** and **--dpi**) if an alternative application labeling is
    desired along with DPI export. However, **yaf** DPI requires the use of
    the applabel engine, so each of these features will be on, albeit with a
    slight performance hit.

        yaf --daemonize --live pcap --in eth0               \
            --out localhost --ipfix-port=18000 --ipfix tcp  \
            --ndpi --dpi --max-payload=4096

When nDPI is enabled, **yaf** exports the information elements
**ndpiL7Protocol** for the application protocol and **ndpiL7SubProtocol**
for the sub-protocol.

# [Supported Protocols](#supported-protocols) {#supported-protocols}

The following application labels are included, in order, in the YAF 3.x
configuration file:

| Protocol                    | Applabel      | Type    | Active | Notes
| :-------------------------- | ------------: |---------|--------|------
| SSL/Proxied                 | user-defined  | plugin  | false  |
| HTTP                        |      80       | regex   | true   |
| SSH                         |      22       | regex   | true   |
| SMTP                        |      25       | plugin  | true   |
| DNS                         |      53       | plugin  | true   |
| NETBIOS Name Service        |      137      | plugin  | true   | 1
| FTP                         |      21       | regex   | true   |
| SSL/TLS                     |      443      | plugin  | true   |
| QUIC                        |      51443    | regex   | true   |
| SLP                         |      427      | plugin  | true   |
| SMB/NETBIOS Session Service |      139      | regex   | true   |
| IMAP                        |      143      | regex   | true   |
| IRC                         |      194      | plugin  | true   |
| RTSP                        |      554      | regex   | true   |
| SIP                         |      5060     | regex   | true   |
| RSYNC                       |      873      | regex   | true   |
| RDP                         |      3389     | regex   | true   |
| IKE                         |      500      | regex   | true   |
| PPTP                        |      1723     | plugin  | true   |
| NNTP                        |      119      | plugin  | true   |
| TFTP                        |      69       | plugin  | true   |
| Teredo                      |      3544     | plugin  | true   |
| MYSQL                       |      3306     | plugin  | true   |
| POP3                        |      110      | plugin  | true   |
| SNMP                        |      161      | plugin  | true   |
| MQTT                        |      1883     | regex   | true   |
| AIM                         |      5190     | plugin  | true   |
| Gnutella P2P                |      6346     | regex   | true   |
| Yahoo Messenger             |      5050     | regex   | true   |
| SOCKS                       |      1080     | plugin  | true   |
| BGP                         |      179      | plugin  | true   |
| DHCP/BOOTP                  |      67       | plugin  | true   |
| VNC/RFB                     |      5900     | regex   | true   |
| RTP                         |      5004     | plugin  | true   |
| RTCP                        |      5005     | plugin  | true   | 2
| Jabber XMPP                 |      5222     | regex   | true   |
| MSNP                        |      1863     | regex   | true   |
| MSOffice Update             |      2223     | regex   | true   |
| MGCP                        |      2427     | regex   | true   |
| MEGACO                      |      2944     | regex   | true   |
| VMware Server Console       |      902      | regex   | true   |
| BitTorrent                  |      6881     | regex   | true   |
| LDAP                        |      389      | plugin  | true   |
| DNP3                        |      20000    | plugin  | true   |
| MODBUS                      |      502      | plugin  | true   |
| Ethernet/IP                 |      44818    | plugin  | true   |
| NETBIOS Datagram Service    |      138      | plugin  | true   |
| Gh0st RAT                   |      9997     | plugin  | true   |
| Poison Ivy                  |      65534    | plugin  | true   |
| LDP                         |      646      | plugin  | true   |
| Palevo                      |      65533    | plugin  | true   |
| NTP                         |      123      | plugin  | true   |

Notes:

1.  NETBIOS Name Service is not included in the configuration file. It is
    contained in the DNS plugin due to similarities in the protocols.
2.  RTCP is not included in the configuration file. It is contained in the
    RTP plugin due to similarities in the protocols.


[Lua]:          https://www.lua.org/
[PCRE]:         https://www.pcre.org/
[nDPI]:         https://www.ntop.org/products/deep-packet-inspection/ndpi/
[pcrepattern]:  http://www.pcre.org/original/doc/html/pcrepattern.html
[pcresyntax]:   http://www.pcre.org/original/doc/html/pcresyntax.html

[deeppacketinspection]:  deeppacketinspection.html


[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
