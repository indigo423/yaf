% What is New with YAF 3.0

This page documents the new features and incompatible changes in YAF 3.

# [Records and template IDs have changed](#templates) {#templates}

Flow records emitted by YAF have been streamlined to fields more accessible
as the variety of YAF flow customizations are enable. Things like
**--payload**, **--flow-stats**, and **--mac** have their fields moved from
the subTemplateMultiList in yaf 2.x into the main record. This puts more
fields in the main part of the record, making them easier to find
downstream.

A consequence of moving fields into the main flow record is that each
combination of possible user-enabled features creates a new template ID. If
looking for a specific template ID when processing YAF 3 data, you maybe
have to broaden your scope to find what you are looking for.

## [DPI Location](#dpi-location) {#dpi-location}

Within a flow record, the DPI information is now housed in its own named
subTemplateList: **yafDPIList** (IE 6871/432). Rather than the previous
subTemplateMultiList which could have a variety of nested templates for each
record, the **yafDPIList** will only use one template per record,
corresponding to the DPI for the protocol specified in the **silkAppLabel**
field.

The subTemplateMultiList is still used to house data from non-DPI plug-ins,
such as the DHCP fingerprinting.

## [Named IPFIX Lists](#named_lists) {#named_lists}

In YAF 3, most of the IPFIX list structures now have meaningful names that
make the data more readable and accessible. These lists are still of IPFIX
type basicList, subTemplateList, and subTemplateMultiList, but have names we
hope an analyst finds more meaningful. YAF has always thoroughly utilized
IPFIX's list structures for efficiency. This allows YAF to only have fields
in its output that it has valid data for, preventing generally empty records
that try to account for every possible field in fixed columns.

Examples:

-   DPI information is now stored in **yafDPIList**, a subTemplateList.

-   In DNS subrecords:

    -   The sub-record that holds the DNS details is a
        **dnsDetailRecordList**, a subTemplateList whose template varies by
        the type of DNS record. Previously this used the **subTemplateList**
        element.

-   In TLS/SSL records:

    -   The list of certificates is in **sslCertList**, a subTemplateList.

    -   **sslIssuerFieldList** is a subTemplateList holding a key and value
        of fields for the certificate issuer. The **sslSubjectFieldList**
        and **sslExtensionFieldList** are similar.

    -   The list of TLS ciphers is in **sslCipherList**, a basicList of
        **sslCipher** elements.

-   In HTTP records:

    -   The HTTP GET requests are in **httpGetList**, a basicList of
        **httpGet** elements.

    -   The HTTP User-Agent strings are in **httpUserAgentList**, a
        basicList of **httpUserAgent** elements.


# [Improved AppLabel and DPI processing](#improved-applabel) {#improved-applabel}

The regular expressions to determine the application label have been
improved.

New AppLabels have been added.

DPI regexes have been updated.

DPI regexes have been added.

DPI templates have changed.

# [Single AppLabel and DPI Configuration File - Written in Lua.](#lua-dpi) {#lua-dpi}

As part of the DPI changes in YAF 3, the configuration files for
[application labeling][applabeling] and [DPI][deeppacketinspection] options
have been merged into a single file, and the file's syntax has been moved
from a custom format to a [Lua][lua] based file. Below is the new syntax for
the config file, this information can also be found in the file itself.

The file *yafApplabelRules.conf* is no longer used and may be deleted.

**NOTE:** If you have customized *yafApplabelRules.conf* or
*yafDPIRules.conf*, make copies of your files prior to installing YAF,
install YAF, and then modify the new *yafDPIRules.conf* file with your
modifications.

As is standard in Lua, `--` starts a comment, and the rest of the line is a
comment.

The file must define a variable named `applabels` which holds an array of
tables, each of which represents an application label and optional DPI
setting.

~~~~
applabels = {
 -- HTTP
 <ENTRY FOR APPLABEL 80>,
 -- SSH
 <ENTRY FOR APPLABEL 22>,
 ...
 }
~~~~

## [Applabeling](#applabeling) {#applabeling}

Each applabel is represented by a table in the format of:

~~~~
{label = <APP>,
 label_type = "<TYPE>",
 value = [[<EXPRESSION>]],
 ports = <PORT_LIST>,
 protocol = <PROTO>
 dpi_type = "<DPI_TYPE>",
 <OPTIONAL_DPI_SETTINGS>}
~~~~

where

-    \<APP\> is the application label to apply (an unsigned 16-bit decimal
     integer in the range 0 to 65535)

-    \<EXPRESSION\> specifies how to recognize the given application
     protocol. The contents of \<EXPRESSION\> depend on the \<TYPE\>.

-    \<TYPE\> specifies the format of \<EXPRESSION\>. Three types of
     applabel rules are supported: **regex**, **plugin**, and **signature**.

-    The optional ports key has a list of port numbers as its value, for
     example `{ 8080, 8888 }`. The optional \<PORT\_LIST\> tells YAF to
     check this rule when the flow's source or destination port matches
     these values. Values in the \<PORT\_LIST\> must be unique across all
     application labels (\<APP\>) and \<PORT\_LIST\> values defined in the
     configuration file.

-    \<PROTO\> limits rule to being tested only when the flow record's
     protocolIdentifier matches \<PROTO\> or when \<PROTO\> is 0. If the
     protocol key is not present, the test is performed. \<PROTO\> is a
     value between 0 and 255 inclusive, but only 0, 6, and 17 are relevant
     since yaf only runs applabel checks for TCP and UDP records.

-    The dpi\_type key-value pair is optional; see the [DPI][] section
     below.

-    \<OPTIONAL\_DPI\_SETTINGS\> are additional settings that depend on the
     value given to the dpi\_type key.

### [Regular Expression Applabel (regex)](#applabel-regex) {#applabel-regex}

Regular expression (`label_type="regex"`) rules have the following form:

~~~~
{label = <APP>,
 label_type = "regex",
 value = [[<PATTERN>]],
 ports = { <PORT_LIST> },
 protocol = <PROTO>,
 dpi_type = "<DPI_TYPE>",
 <OPTIONAL_DPI_SETTINGS>}
~~~~

The regular expression \<PATTERN\> is compared against the available payload
of both directions of the flow, and if the expression matches either
direction of the payload, the label \<APP\> is applied to the flow.
\<PATTERN\> is a [PCRE][] regular expression; for the syntax and semantics
of \<PATTERN\>, see the PCRE documentation for [patterns][PCREdoc].

Note: The square brackets that surround the expression are "Lua long
brackets" and surround a "long literal", which is useful for writing regular
expressions. Zero or more equal signs (`=`) may appear between each set of
brackets (the same number on each side), `[====[as an example]====]`. At
least one equal sign is recommended when specifying a regex.

When applying applabel rules to a flow, YAF first checks whether the flow's
source or destination port matches a rule's "label" (\<APP\>) or a port in
the \<PORT\_LIST\>; if no rule matching the ports is found, YAF tests the
flow against all applabel rules in the order in which they appear.

Example: Here is the applabel rule for `rsync` traffic:

~~~~
-- RSYNC
{label = 873, label_type = "regex",
 value = [=[^@RSYNCD:]=]},
~~~~

The `dpi_type` is not specified since YAF does not extract any DPI data for
`rsync` traffic.

### [Plug-in Applabel (plugin)](#applabel-plugin) {#applabel-plugin}

Plugin rules (`label_type="plugin"`) are used to label application payload
using a C dynamically loaded library, and have the following form:

~~~~
{label = <APP>,
 label_type = "plugin",
 value = "<LIBRARY>",
 protocol = <PROTO>,
 dpi_type = "<DPI_TYPE>",
 <OPTIONAL_DPI_SETTINGS>}
~~~~

where \<LIBRARY\> is the name of a dynamically loadable library that exists
somewhere within the LD\_LIBRARY\_PATH, the LTDL\_LIBRARY\_PATH, or a system
library path, without the library name extension (usually `.so`). If the
plug-in returns 1, the flow will be labeled with \<APP\>. Otherwise, the flow
will be labeled with whatever value the plug-in returns (useful for a
plug-in that can identify more than 1 protocol). See the source code to the
plug-ins that ship with YAF for details.

Example: Here is the applabel rule for `dhcp` traffic:

~~~~
-- DHCP
{label = 67, label_type = "plugin",
 value = "dhcpplugin"},
~~~~

Note again the lack of `dpi_type`.

### [Signature Applabel (signature)](#applabel-signature) {#applabel-signature}

Signature rules (`label_type="signature"`) have the following form:

~~~~
{label = <APP>,
 label_type = "signature",
 value = [[<EXPRESSION>]],
 dpi_type = "<DPI_TYPE>"}
~~~~

The regular expression \<EXPRESSION\> is compared against the available
payload of the flow, and if the expression matches, the label \<APP\> is
applied to the flow.

Signatures rules are similar to Regex Rules except YAF tests the signature
rules first and they are applied to all flow records regardless of source
and destination port values. For expressions that you want to search for
first before port-based matching, use this format. The expression is a
[PCRE][] regular expression.

## [DPI](#dpi) {#dpi}

The process of deep packet inspection into the labeled flows is now
specified as part of the same configuration. DPI configuration is specified
using one of three `dpi_type` values: **regex**, **plugin**, or
**regex-plugin**. If no DPI processing available or desired, do not include
the `dpi_type` key.

### [Regex DPI](#dpi-regex) {#dpi-regex}

Regex DPI (`dpi_type="regex"`) can be used with with any type of
applabeling. Using the regex DPI type requires that you specify three
additional fields in the applabeling/dpi line: "dpi\_name",
"dpi\_template\_id", and "dpi\_rules":

-   **dpi\_name** (string): This field specifies the name for the protocol
    being labeled and inspected. This string will be used to automatically
    create things like the output template name.

-   **dpi\_template\_id** (number): This field specifies the numeric value
    (ideally specified in hexadecimal for clarity) to be used for the
    template ID for this protocol's DPI. Must be unique.

-   **dpi_rules** (array): This field specifies the list of regex rules that
    will be applied to the payload to generate the output DPI elements. Each
    rule looks like the following:

        {elem_name = "<NAME>", regex = [[<REGEX>]]}

    where both directional payloads are checked for matches of \<REGEX\> and
    any matches are stored in a basicList of the IPFIX information element
    whose name is \<NAME\>. If there is an information element of type
    basicList having the name "\<NAME\>List", that element is used in place
    of a generic basicList.

    If capturing parentheses are used in the pattern, only the text captured
    by the first set of parentheses is stored.

Example: Here is the applabel and a couple of DPI rules for HTTP:

~~~~
-- HTTP
{label = 80, label_type = "regex", active = true,
 value = [=[HTTP/\d]=],
 dpi_type = "regex", dpi_name = "http", dpi_template_id = 0xC600,
 dpi_rules = {
   {elem_name = "httpServerString",
    regex = [=[^Server: ?([-a-zA-Z0-9.~!/:;@#$%^&*=+,_() ]+)]=]},
   {elem_name = "httpUserAgent",
    regex = [=[^User-Agent: ?([-a-zA-Z0-9.~!/:;@#$%^&*=+,_() ]+)]=]},
 }
},
~~~~

Note the use of capturing parentheses to include only the values of the
Server and User-Agent settings but not the keywords.

Matches for the Server string are stored in the **httpServerStringList**
element, a basicList of type **httpServerString**, and similarly for the
**httpUserAgentList** and **httpUserAgent**.

### [Plugin DPI](#dpi-plugin) {#dpi-plugin}

Plugin DPI (`dpi_type="plugin"`) can only be used when the applabel type is
also a plugin, as the same plugin will be responsible for both labeling and
doing the deep packet inspection. The plugin DPI type requires that you
specify additional fields in the applabeling/dpi line: The "dpi\_templates"
field is required; some plugins also require "plugin\_rules":

-    **dpi\_templates** (table of arrays of string): A table where each
     entry represents one template created by this plugin. The set of keys
     are fixed, and each key matches the name of a template defined by the
     plugin. The value for each key is an array of strings containing the
     information elements exported as part of that template. The user may
     comment out (or remove) entries to prevent those elements from being
     exported by the plugin.

-    **plugin\_rules** (table of strings): A table where each key names a
     variable defined in the plugin (the set of keys is fixed). Each value
     is a string containing a PCRE regular expression used by the plugin.

Example: Here is the applabel and DPI setting for TFTP:

~~~~
-- TFTP
{label = 69, label_type = "plugin", active = true,
 value = "tftpplugin", dpi_type = "plugin",
 dpi_templates = {
   yaf_tftp = {
     "tftpFilename",
     "tftpMode",
   },
 },
 plugin_rules = {
   tftpRegex = [=[\x00[\x01|\x02]([-a-zA-Z1-9. ]+)\x00(?i)(netascii|octet|mail)\x00]=],
 },
},
~~~~

### [Regex-plugin DPI](#dpi-regex-plugin) {#dpi-regex-plugin}

This type (`dpi_type="regex-plugin"`) of DPI indicates that a plugin is used
for application labeling but that user specified regexes are used for
extracting the DPI, similar to Regex DPI. The only parameter needed is the
same **dpi_rules** parameter as mentioned above.

# [DPI Enhancements](#dpi-enhancements) {#dpi-enhancements}

## [TLS](#dpi-enhancements-tls) {#dpi-enhancements-tls}

TLS (SSL) deep packet inspection now includes the JA3 hash for server and
client and the string used as the basic for the JA3 hash.

## [SSH](#dpi-enhancements-ssh) {#dpi-enhancements-ssh}

SSH deep packet inspection is greatly enhanced and is now handled by a C
plugin. Information includes the negotiated algorithms, the MD5 of the
server key, the HASSH hash for the server and client, and the string used as
the basis for the HASSH.

# [Template metadata enhancements](#template-metadata) {#template-metadata}

# [Increased Payload Capture](#increased-payload) {#increased-payload}

YAF now supports collecting more than 65535 bytes of payload for performing
deep packet inspection. Note the amount of raw payload YAF may export is
still limited by the maximum size of an IPFIX message.

# [Selective Payload Export](#select-payload) {#select-payload}

YAF can now emit the forward and reverse payloads (up to the lesser of
--max-payload or --max-export, if specified) for only a user-specified list
of application labels using **--payload-applabel-select**. Previously
payload export was all or none, but now maybe you only want payloads for
flows YAF was unable to label, or only the details for DNS flows.

# [Easier application of dpi](#easier-dpi) {#easier-dpi}

# [Field Name Changes](#ie-renaming) {#ie-renaming}

There are significant changes to the names of [CERT enterprise-specific
information elements][certipfix] for data emitted by YAF.

There were several motivations for this change. In some cases the name
veered far from the IPFIX naming idiom. The contents of other elements had
evolved over time necessitating a new name. Some elements were redundant,
while others represented unrelated entities. Some elements related to a
single protocol (such as DNS) used inconsistent naming.

Data is more accessible if field are used in only one place in the record.
While names maybe longer, they are more clear which is the point of naming
fields for analysts to use. A full list of name changes is below.

## [General Rules for Renaming](#gen-rules) {#gen-rules}

Rules we more-or-less ended up with:

1.   Initialisms and acronyms generally in all-caps in the middle of a name
     or all-small at the start of a name.

2.   However, "Id" and "id" for identifiers.

3.   DNS RR type names are in all-caps.

4.   Prefix names that are a concept specific to our tools with a tool name
     or "certTool" for cross-tool stuff.

5.   Do not prefix names that may only be currently produced by our tools,
     but which could be produced by and meaningful to anyone monitoring
     Internet traffic.

For everything we've talked about, this is a rundown on what's changed or
not changed and why, grouped by the rationale of the changes.

YAF 3 does not rename these elements which contain initialisms:

| ID  | NAME |
| --- | ---------- |
| 138 | imapStartTLS |
| 143 | rtspURL |
| 199 | dnsTTL |
| 257 | httpIMEI |
| 258 | httpIMSI |
| 259 | httpMSISDN |
| 270 | httpDNT |
| 326 | smtpStartTLS |
| 329 | smtpURL |
| 335 | smtpURLList |
| 362 | imapStartTLSList |
| 367 | rtspURLList |
| 397 | httpIMEIList |
| 398 | httpIMSIList |
| 399 | httpMSISDNList |
| 409 | httpDNTList |
| 432 | yafDPIList |

YAF 3 renames these information elements to make it clear that they are for
communicating information across CERT tools. (Currently for diagnostic
purposes):

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 550 | tombstoneId                    | certToolTombstoneId |
| 551 | exporterConfiguredId           | certToolExporterConfiguredId |
| 552 | exporterUniqueId               | certToolExporterUniqueId |
| 554 | tombstoneAccessList            | certToolTombstoneAccessList |

YAF 3 renames these to make it clear that these IEs are YAF-specific
statistics information, and not for any other "mean flow rate", etc.:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 100 | expiredFragmentCount           | yafExpiredFragmentCount |
| 101 | assembledFragmentCount         | yafAssembledFragmentCount |
| 102 | meanFlowRate                   | yafMeanFlowRate |
| 103 | meanPacketRate                 | yafMeanPacketRate |
| 104 | flowTableFlushEventCount       | yafFlowTableFlushEventCount |
| 105 | flowTablePeakCount             | yafFlowTablePeakCount |

YAF 3 renames these TLS/SSL-related elements to make their meaning more clear:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | -------------------- |
| 200 | sslCertSubCountryName          | sslCertSubjectCountryName |
| 201 | sslCertSubOrgName              | sslCertSubjectOrgName |
| 202 | sslCertSubOrgUnitName          | sslCertSubjectOrgUnitName |
| 203 | sslCertSubZipCode              | sslCertSubjectZipCode |
| 204 | sslCertSubState                | sslCertSubjectState |
| 205 | sslCertSubCommonName           | sslCertSubjectCommonName |
| 206 | sslCertSubLocalityName         | sslCertSubjectLocalityName |
| 207 | sslCertSubStreetAddress        | sslCertSubjectStreetAddress |
| 309 | sslCertSubTitle                | sslCertSubjectTitle |
| 311 | sslCertSubName                 | sslCertSubjectName |
| 313 | sslCertSubEmailAddress         | sslCertSubjectEmailAddress |
| 315 | sslCertSubDomainComponent      | sslCertSubjectDomainComponent |
|     | &nbsp;                         | |
| 296 | sslCertificate                 | sslBinaryCertificate |


YAF 3 gives names to these super_mediator-specific dedup-related elements
that more clearly denote their meaning and origin:

| ID  | OLD NAME                       | NEW NAME        | NOTE |
| --- | ------------------------------ | --------------- | ---- |
| 927 | dnsRName                       | smDNSData       | 1 |
| 928 | dnsHitCount                    | DEPRECATED      | 2 |
| 929 | observedDataTotalCount         | smDedupHitCount | 2 |
| 930 | observedData                   | smDedupData     | 3 |

1.    Made more generic, because this field is used for other DNS features
      of super_mediator, not just for dedup.
2.    Unified these two into one item, since the meaning here is simply "how
      many times did you see this deduplicated thing".
3.    Made it clear that this is a representation of data that is being
      deduplicated.

YAF 3 gives these pipeline-specific elements names that aren't completely
alien, and labels them to say they're for pipeline:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 305 | DNS\_A\_Record                 | pipelineDNSARecord |
| 306 | DNS\_AAAA\_Record              | pipelineDNSAAAARecord |
| 307 | DNS\_RESOURCE\_RECORD          | pipelineDNSResourceRecord |


YAF 3 uses "Id" as short for identifier instead of "ID":

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 226 | dnsID                          | dnsId |
| 292 | mptcpAddressID                 | mptcpAddressId |


YAF 3 changes these so the first segment of the name (nDPI) isn't mixed-case
on its own:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 300 | nDPIL7Protocol                 | ndpiL7Protocol |
| 301 | nDPIL7SubProtocol              | ndpiL7SubProtocol |


YAF 3 treats "fingerprint" as a single word, since all of the literature
around p0f fingerprinting and DHCP fingerprinting does so:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 107 | osFingerPrint                  | osFingerprint |
| 242 | dhcpFingerPrint                | dhcpFingerprint |


YAF 3 uses a name for "EtherNet/IP™" that makes people less likely to
incorrectly assume that it is ethernet-over-IP:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 286 | ethernetIPData                 | enipData |


YAF 3 does not use hyphens in these names, since those really do not fit
with the IPFIX naming idiom at all:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 254 | httpX-Forwarded-For            | httpXForwardedFor |
| 271 | httpX-Forwarded-Proto          | httpXForwardedProto |
| 272 | httpX-Forwarded-Host           | httpXForwardedHost |
| 273 | httpX-Forwarded-Server         | httpXForwardedServer |
| 274 | httpX-DeviceID                 | httpXDeviceId |
| 275 | httpX-Profile                  | httpXProfile |
| 280 | httpX-UA-Compatible            | httpXUaCompatible |


YAF 3 splits up existing DNSSEC information elements that are used in
multiple places in order to disambiguate them, and renames existing
single-use IEs that do not say what resource record types they're for:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 227 | dnsAlgorithm                   | DEPRECATED, replaced with: |
| 423 | NEW                            | dnsDNSKEYAlgorithm |
| 433 | NEW                            | dnsDSAlgorithm |
| 435 | NEW                            | dnsNSEC3Algorithm |
| 441 | NEW                            | dnsNSEC3PARAMAlgorithm |
| 447 | NEW                            | dnsRRSIGAlgorithm |
|     | &nbsp;                         | |
| 228 | dnsKeyTag                      | DEPRECATED, replaced with |
| 434 | NEW                            | dnsDSKeyTag |
| 448 | NEW                            | dnsRRSIGKeyTag |
|     | &nbsp;                         | |
| 229 | dnsSigner                      | dnsRRSIGSigner |
| 230 | dnsSignature                   | dnsRRSIGSignature |
| 231 | dnsDigest                      | dnsDSDigest |
| 232 | dnsPublicKey                   | dnsDNSKEYPublicKey |
|     | &nbsp;                         | |
| 233 | dnsSalt                        | DEPRECATED, replaced with |
| 439 | NEW                            | dnsNSEC3Salt |
| 444 | NEW                            | dnsNSEC3PARAMSalt |
|     | &nbsp;                         | |
| 234 | dnsHashData                    | DEPRECATED, replaced with |
| 445 | NEW                            | dnsNSECNextDomainName |
| 438 | NEW                            | dnsNSEC3NextHashedOwnerName |
|     | &nbsp;                         | |
| 235 | dnsIterations                  | DEPRECATED, replaced with |
| 437 | NEW                            | dnsNSEC3Iterations |
| 443 | NEW                            | dnsNSEC3PARAMIterations |
|     | &nbsp;                         | |
| 236 | dnsSignatureExpiration         | dnsRRSIGSignatureExpiration |
| 237 | dnsSignatureInception          | dnsRRSIGSignatureInception |
| 238 | dnsDigestType                  | dnsDSDigestType |
| 239 | dnsLabels                      | dnsRRSIGLabels |
| 240 | dnsTypeCovered                 | dnsRRSIGTypeCovered |
| 241 | dnsFlags                       | dnsDNSKEYFlags |
| 304 | dnsKeyProtocolIdentifier       | dnsDNSKEYProtocol |
|     | &nbsp;                         | |
| 449 | NEW [split from dnsTTL]        | dnsRRSIGOriginalTTL |


YAF 3 renames these DNS-related names so they are a bit cleaner and much
more clear about their meaning in relation to DNS information.

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 175 | dnsQRType                      | dnsRRType |
| 177 | dnsNXDomain                    | dnsResponseCode |
| 178 | dnsRRSection                   | dnsSection |
| 179 | dnsQName                       | dnsName |


YAF 3 renames this so that the RR type name is in all caps:

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 180 | dnsCName                       | dnsCNAME |


YAF 3 continues using RR type names in all caps and does not change these:

| ID  | NAME |
| --- | ---------- |
| 181 | dnsMXPreference |
| 182 | dnsMXExchange |
| 183 | dnsNSDName |
| 184 | dnsPTRDName |
| 208 | dnsTXTData |
| 209 | dnsSOASerial |
| 210 | dnsSOARefresh |
| 211 | dnsSOARetry |
| 212 | dnsSOAExpire |
| 213 | dnsSOAMinimum |
| 214 | dnsSOAMName |
| 215 | dnsSOARName |
| 216 | dnsSRVPriority |
| 217 | dnsSRVWeight |
| 218 | dnsSRVPort |
| 219 | dnsSRVTarget |

YAF 3 takes ownership of these elements from Analysis Pipeline, gives them
names consistent with the other DNS-related elements, and uses them in DNS
subrecords place of sourceIPv4Address, sourceIPv6Address, and
protocolIdentifier.

| ID  | OLD NAME                       | NEW NAME |
| --- | ------------------------------ | ------------------- |
| 302 | rrIPv4                         | dnsA |
| 303 | rrIPv6                         | dnsAAAA |
| 304 | DNSKEY\_ProtocolIdentifier     | dnsDNSKEYProtocol |

YAF 3 adds these additional DNSSEC information elements:

| ID  | OLD NAME                       | NEW NAME            | DATA TYPE |
| --- | ------------------------------ | ------------------- | --------- |
| 446 | NEW                            | dnsNSECTypeBitmaps  | octetArray |
| 440 | NEW                            | dnsNSEC3TypeBitMaps | octetArray |
| 436 | NEW                            | dnsNSEC3Flags       | unsigned8 |
| 442 | NEW                            | dnsNSEC3PARAMFlags  | unsigned8 |



## [IE Renames, Sorted by Element ID](#by-id) {#by-id}

This table lists the renamed information elements, sorted by the element
identifier. All IEs use the CERT Enterprise Number, 6871.

| ID  | OLD NAME                   | NEW NAME |
| --- | -------------------------- | -------- |
| 100 | expiredFragmentCount       | yafExpiredFragmentCount |
| 101 | assembledFragmentCount     | yafAssembledFragmentCount |
| 102 | meanFlowRate               | yafMeanFlowRate |
| 103 | meanPacketRate             | yafMeanPacketRate |
| 104 | flowTableFlushEventCount   | yafFlowTableFlushEventCount |
| 105 | flowTablePeakCount         | yafFlowTablePeakCount |
| 107 | osFingerPrint              | osFingerprint |
| 175 | dnsQRType                  | dnsRRType |
| 177 | dnsNXDomain                | dnsResponseCode |
| 178 | dnsRRSection               | dnsSection |
| 179 | dnsQName                   | dnsName |
| 180 | dnsCName                   | dnsCNAME |
| 200 | sslCertSubCountryName      | sslCertSubjectCountryName |
| 201 | sslCertSubOrgName          | sslCertSubjectOrgName |
| 202 | sslCertSubOrgUnitName      | sslCertSubjectOrgUnitName |
| 203 | sslCertSubZipCode          | sslCertSubjectZipCode |
| 204 | sslCertSubState            | sslCertSubjectState |
| 205 | sslCertSubCommonName       | sslCertSubjectCommonName |
| 206 | sslCertSubLocalityName     | sslCertSubjectLocalityName |
| 207 | sslCertSubStreetAddress    | sslCertSubjectStreetAddress |
| 226 | dnsID                      | dnsId |
|     | &nbsp;                     |  |
| 227 | dnsAlgorithm               | DEPRECATED, replaced with: |
| 423 | NEW                        | dnsDNSKEYAlgorithm |
| 433 | NEW                        | dnsDSAlgorithm |
| 435 | NEW                        | dnsNSEC3Algorithm |
| 441 | NEW                        | dnsNSEC3PARAMAlgorithm |
| 447 | NEW                        | dnsRRSIGAlgorithm |
|     | &nbsp;                     | |
| 228 | dnsKeyTag                  | DEPRECATED, replaced with |
| 434 | NEW                        | dnsDSKeyTag |
| 448 | NEW                        | dnsRRSIGKeyTag |
|     | &nbsp;                     |  |
| 229 | dnsSigner                  | dnsRRSIGSigner |
| 230 | dnsSignature               | dnsRRSIGSignature |
| 231 | dnsDigest                  | dnsDSDigest |
| 232 | dnsPublicKey               | dnsDNSKEYPublicKey |
|     | &nbsp;                     |  |
| 233 | dnsSalt                    | DEPRECATED, replaced with |
| 439 | NEW                        | dnsNSEC3Salt |
| 444 | NEW                        | dnsNSEC3PARAMSalt |
|     | &nbsp;                     |  |
| 234 | dnsHashData                | DEPRECATED, replaced with |
| 445 | NEW                        | dnsNSECNextDomainName |
| 438 | NEW                        | dnsNSEC3NextHashedOwnerName |
|     | &nbsp;                     |  |
| 235 | dnsIterations              | DEPRECATED, replaced with |
| 437 | NEW                        | dnsNSEC3Iterations |
| 443 | NEW                        | dnsNSEC3PARAMIterations |
|     | &nbsp;                     |  |
| 236 | dnsSignatureExpiration     | dnsRRSIGSignatureExpiration |
| 237 | dnsSignatureInception      | dnsRRSIGSignatureInception |
| 238 | dnsDigestType              | dnsDSDigestType |
| 239 | dnsLabels                  | dnsRRSIGLabels |
| 240 | dnsTypeCovered             | dnsRRSIGTypeCovered |
| 241 | dnsFlags                   | dnsDNSKEYFlags |
| 242 | dhcpFingerPrint            | dhcpFingerprint |
| 254 | httpX-Forwarded-For        | httpXForwardedFor |
| 271 | httpX-Forwarded-Proto      | httpXForwardedProto |
| 272 | httpX-Forwarded-Host       | httpXForwardedHost |
| 273 | httpX-Forwarded-Server     | httpXForwardedServer |
| 274 | httpX-DeviceID             | httpXDeviceId |
| 275 | httpX-Profile              | httpXProfile |
| 280 | httpX-UA-Compatible        | httpXUaCompatible |
| 286 | ethernetIPData             | enipData |
| 292 | mptcpAddressID             | mptcpAddressId |
| 296 | sslCertificate             | sslBinaryCertificate |
| 300 | nDPIL7Protocol             | ndpiL7Protocol |
| 301 | nDPIL7SubProtocol          | ndpiL7SubProtocol |
| 302 | rrIPv4                     | dnsA |
| 303 | rrIPv6                     | dnsAAAA |
| 304 | DNSKEY\_ProtocolIdentifier | dnsDNSKEYProtocol |
| 305 | DNS\_A\_Record             | pipelineDNSARecord |
| 306 | DNS\_AAAA\_Record          | pipelineDNSAAAARecord |
| 307 | DNS\_RESOURCE\_RECORD      | pipelineDNSResourceRecord |
| 309 | sslCertSubTitle            | sslCertSubjectTitle |
| 311 | sslCertSubName             | sslCertSubjectName |
| 313 | sslCertSubEmailAddress     | sslCertSubjectEmailAddress |
| 315 | sslCertSubDomainComponent  | sslCertSubjectDomainComponent |
| 550 | tombstoneId                | certToolTombstoneId |
| 551 | exporterConfiguredId       | certToolExporterConfiguredId |
| 552 | exporterUniqueId           | certToolExporterUniqueId |
| 554 | tombstoneAccessList        | certToolTombstoneAccessList |
| 927 | dnsRName                   | smDNSData |
|     | &nbsp;                     |  |
| 928 | dnsHitCount                | DEPRECATED, merged into smDedupHitCount(929) |
|     | &nbsp;                     |  |
| 929 | observedDataTotalCount     | smDedupHitCount |
| 930 | observedData               | smDedupData |
|     | &nbsp;                     |  |
| 449 | NEW [split from dnsTTL]    | dnsRRSIGOriginalTTL |
| 446 | NEW                        | dnsNSECTypeBitMaps |
| 440 | NEW                        | dnsNSEC3TypeBitMaps |
| 436 | NEW                        | dnsNSEC3Flags |
| 442 | NEW                        | dnsNSEC3PARAMFlags |


## [IE Renames, Sorted by Old Name](#by-oldname) {#by-oldname}

This table lists the renamed information elements, sorted by the previous
name. All IEs use the CERT Enterprise Number, 6871.

| ID  | OLD NAME                   | NEW NAME |
| --- | -------------------------- | -------- |
| 101 | assembledFragmentCount     | yafAssembledFragmentCount |
| 242 | dhcpFingerPrint            | dhcpFingerprint |
|     | &nbsp;                     |  |
| 227 | dnsAlgorithm               | DEPRECATED, replaced with: |
| 423 | NEW                        | dnsDNSKEYAlgorithm |
| 433 | NEW                        | dnsDSAlgorithm |
| 435 | NEW                        | dnsNSEC3Algorithm |
| 441 | NEW                        | dnsNSEC3PARAMAlgorithm |
| 447 | NEW                        | dnsRRSIGAlgorithm |
|     | &nbsp;                     |  |
| 180 | dnsCName                   | dnsCNAME |
| 231 | dnsDigest                  | dnsDSDigest |
| 238 | dnsDigestType              | dnsDSDigestType |
| 241 | dnsFlags                   | dnsDNSKEYFlags |
|     | &nbsp;                     |  |
| 234 | dnsHashData                | DEPRECATED, replaced with |
| 445 | NEW                        | dnsNSECNextDomainName |
| 438 | NEW                        | dnsNSEC3NextHashedOwnerName |
|     | &nbsp;                     |  |
| 928 | dnsHitCount                | DEPRECATED, merged into smDedupHitCount(929) |
|     | &nbsp;                     |  |
| 226 | dnsID                      | dnsId |
|     | &nbsp;                     |  |
| 235 | dnsIterations              | DEPRECATED, replaced with |
| 437 | NEW                        | dnsNSEC3Iterations |
| 443 | NEW                        | dnsNSEC3PARAMIterations |
|     | &nbsp;                     |  |
| 228 | dnsKeyTag                  | DEPRECATED, replaced with |
| 434 | NEW                        | dnsDSKeyTag |
| 448 | NEW                        | dnsRRSIGKeyTag |
|     | &nbsp;                     |  |
| 304 | DNSKEY\_ProtocolIdentifier | dnsDNSKEYProtocol |
| 239 | dnsLabels                  | dnsRRSIGLabels |
| 177 | dnsNXDomain                | dnsResponseCode |
| 232 | dnsPublicKey               | dnsDNSKEYPublicKey |
| 179 | dnsQName                   | dnsName |
| 175 | dnsQRType                  | dnsRRType |
| 927 | dnsRName                   | smDNSData |
| 178 | dnsRRSection               | dnsSection |
|     | &nbsp;                     |  |
| 233 | dnsSalt                    | DEPRECATED, replaced with |
| 439 | NEW                        | dnsNSEC3Salt |
| 444 | NEW                        | dnsNSEC3PARAMSalt |
|     | &nbsp;                     |  |
| 230 | dnsSignature               | dnsRRSIGSignature |
| 236 | dnsSignatureExpiration     | dnsRRSIGSignatureExpiration |
| 237 | dnsSignatureInception      | dnsRRSIGSignatureInception |
| 229 | dnsSigner                  | dnsRRSIGSigner |
| 240 | dnsTypeCovered             | dnsRRSIGTypeCovered |
| 306 | DNS\_AAAA\_Record          | pipelineDNSAAAARecord |
| 305 | DNS\_A\_Record             | pipelineDNSARecord |
| 307 | DNS\_RESOURCE\_RECORD      | pipelineDNSResourceRecord |
| 286 | ethernetIPData             | enipData |
| 100 | expiredFragmentCount       | yafExpiredFragmentCount |
| 551 | exporterConfiguredId       | certToolExporterConfiguredId |
| 552 | exporterUniqueId           | certToolExporterUniqueId |
| 104 | flowTableFlushEventCount   | yafFlowTableFlushEventCount |
| 105 | flowTablePeakCount         | yafFlowTablePeakCount |
| 274 | httpX-DeviceID             | httpXDeviceId |
| 254 | httpX-Forwarded-For        | httpXForwardedFor |
| 272 | httpX-Forwarded-Host       | httpXForwardedHost |
| 271 | httpX-Forwarded-Proto      | httpXForwardedProto |
| 273 | httpX-Forwarded-Server     | httpXForwardedServer |
| 275 | httpX-Profile              | httpXProfile |
| 280 | httpX-UA-Compatible        | httpXUaCompatible |
| 102 | meanFlowRate               | yafMeanFlowRate |
| 103 | meanPacketRate             | yafMeanPacketRate |
| 292 | mptcpAddressID             | mptcpAddressId |
| 300 | nDPIL7Protocol             | ndpiL7Protocol |
| 301 | nDPIL7SubProtocol          | ndpiL7SubProtocol |
| 930 | observedData               | smDedupData |
| 929 | observedDataTotalCount     | smDedupHitCount |
| 107 | osFingerPrint              | osFingerprint |
| 302 | rrIPv4                     | dnsA |
| 303 | rrIPv6                     | dnsAAAA |
| 205 | sslCertSubCommonName       | sslCertSubjectCommonName |
| 200 | sslCertSubCountryName      | sslCertSubjectCountryName |
| 315 | sslCertSubDomainComponent  | sslCertSubjectDomainComponent |
| 313 | sslCertSubEmailAddress     | sslCertSubjectEmailAddress |
| 206 | sslCertSubLocalityName     | sslCertSubjectLocalityName |
| 311 | sslCertSubName             | sslCertSubjectName |
| 201 | sslCertSubOrgName          | sslCertSubjectOrgName |
| 202 | sslCertSubOrgUnitName      | sslCertSubjectOrgUnitName |
| 204 | sslCertSubState            | sslCertSubjectState |
| 207 | sslCertSubStreetAddress    | sslCertSubjectStreetAddress |
| 309 | sslCertSubTitle            | sslCertSubjectTitle |
| 203 | sslCertSubZipCode          | sslCertSubjectZipCode |
| 296 | sslCertificate             | sslBinaryCertificate |
| 554 | tombstoneAccessList        | certToolTombstoneAccessList |
| 550 | tombstoneId                | certToolTombstoneId |
|     | &nbsp;                     |  |
| 449 | NEW [split from dnsTTL]    | dnsRRSIGOriginalTTL |
| 446 | NEW                        | dnsNSECTypeBitMaps |
| 440 | NEW                        | dnsNSEC3TypeBitMaps |
| 436 | NEW                        | dnsNSEC3Flags |
| 442 | NEW                        | dnsNSEC3PARAMFlags |


[lua]:         https://www.lua.org/
[PCRE]:        http://www.pcre.org/
[PCREdoc]:     http://www.pcre.org/original/doc/html/pcrepattern.html

[certipfix]:            /cert-ipfix-registry/cert_ipfix_formatted.html

[applabeling]:          applabeling.html
[deeppacketinspection]: deeppacketinspection.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
