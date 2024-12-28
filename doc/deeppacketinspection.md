% YAF: Deep Packet Inspection

# [Introduction](#introduction) {#introduction}

With Deep Packet Inspection (DPI) enabled, **yaf** can examine packet
payloads, capture useful information for a specific protocol, and export it
in a protocol-specific IPFIX template. DPI in **yaf** is directly related to
[application labeling][applabeling] as it will only perform DPI if a match
was found during the application labeling phase, and it will only execute an
inspection specific to the protocol denoted by the application label
(applabel).

> **Note:** The DPI support in YAF 3 differs greatly from that in prior
> releases. If using a previous release of **yaf**, please consult the
> manual pages for your installation.

### [Required build time options: --enable-applabel --enable-dpi](#build-time) {#build-time}

Deep packet inspection support is not included in **yaf** by default; the
**--enable-applabel** and **--enable-dpi** options must be passed to
`configure`.

To check whether your **yaf** installation has DPI enabled, run **yaf**
**--version** and check the setting of "Deep Packet Inspection Support".

### [Minimum required run time options: --dpi --max-payload](#runtime) {#runtime}

Deep packet inspection always requires payload capture to be enabled with
the **--max-payload** option. Since DPI requires application labeling, the
**--dpi** option will enable both features.

A minimum payload capture length of 2048 bytes is recommended, but 4096
bytes is ideal for best results (including capture of full certificate
chains):

    yaf --daemonize --live pcap --in eth0               \
        --out localhost --ipfix-port=18000 --ipfix tcp  \
        --dpi --max-payload=4096

DPI is enabled for all supported protocols by default, but you can also
specify the **dpi-select** option to select on which protocols to perform
DPI. The below command will perform DPI for only SMTP, DNS, and HTTP labeled
flows:

    yaf --daemonize --live pcap --in eth0               \
        --out localhost --ipfix-port=18000 --ipfix tcp  \
        --dpi --dpi-select=25,53,80 --max-payload=4096

DPI rules, or where to find them, are taken from a configuration file read
by **yaf** at startup time. This is the same configuration file that **yaf**
[application labeling][applabeling] uses and is written in [Lua][]. The rule
file can be given on the command line with the **--dpi-rules-file** option,
or **yaf** will try to read it from the default location of
`/usr/local/etc/yafDPIRules.conf.` (The location may be different depending
on how your **yaf** installation was built.)

    yaf --daemonize --live pcap --in eth0               \
        --out localhost --ipfix-port=18000 --ipfix tcp  \
        --dpi --dpi-rules-file=*FILE* --max-payload=4096

### [Additional DNS Build Time Options](#dns-build) {#dns-build}

The default behavior of the **yaf**'s DNS DPI support is to capture and
export all DNS responses.  One or both of the following options may be given
to `configure` to limit which DNS responses **yaf** is capable of exporting.

**Once built, yaf only supports these DNS responses. It will be necesssary
to recompile and reinstall yaf to change its behavior.**

When these build-time options are used, **yaf** still requires the **--dpi**
and **--max-payload** options to export the DNS elements.

-   **--enable-exportDNSAuth** enables export of DNS Authoritative Responses
    *only*. May be paired with the following option.

-   **--enable-exportDNSNXDomain** enables export of DNS NXDomain Responses
    *only*. May be paired with the previous option.

# [Configuration File](#configuration-file) {#configuration-file}

While both applabel and DPI-related configuration options are in the
configuration file, here we are focusing only on options relevant to DPI.
The syntax for application labeling is described [here][applabeling].

The configuration file is written in [Lua][]. For specifics of the Lua
language, see http://www.lua.org/manual/5.3/manual.html.

Comments in Lua start with double hyphens (`--`) and continue to the end of
the line.

## [DPI-Related Settings](#dpi-related) {#dpi-related}

The file has some DPI-specific variables that may be set:

-   **per\_field\_limit** sets the number of bytes **yaf** will export for
    any given DPI field. This does not affect DNS DPI or SSL/TLS Certificate
    Capture. For DNS, a domain name can have a maximum of 255 characters, so
    the limit is not configurable. Maximum value is 65535 with anything
    larger reverting this setting back to its default value. Default is 200
    bytes.

-   **per\_record\_limit** sets the total number of bytes **yaf** may export
    from DPI. No matter what this is set to, this number will not be larger
    than the --max-payload value **yaf** is given at run time. Maximum value
    is 65535 with anything larger reverting this setting back to its default
    value. Default is 1000 bytes.

Currently the per\_field\_limit and per\_record\_limit are global settings
and apply to all protocols. In a future release, we may allow configuration
of these limits per protocol.

-   **cert_export_enabled**, when set to `true`, tells **yaf** to export the
    full X.509 certificate to **sslCertificate** and disable the normal
    X.509 certificate decode and export. This is a useful option to offload
    certificate processing to a downstream tool, such as [Super
    Mediator][super_mediator], which can perform the extraction of relevant
    fields as is typically done by **yaf**, plus it provides the option to
    perform SHA-1 or MD5 hashing of the certificate. Default is false.

[//]: # (COMMENT: May be a good use case/tutorial to actually walk through how to do this with Super Mediator)

-   **cert_hash_enabled**, when set to `true`, has **yaf** export the hash
    of the X.509 certificate as found in the certificate to
    **sslCertificateHash**. This is typically the SHA-256 hash of the binary
    certificate but it can vary on the hashing algorithm used. The hashing
    algorithm can be identified by the **sslCertSignature** field. If both
    **cert_export_enabled** and **cert_hash_enabled** are set to true,
    **yaf** will export both the full X.509 certificate and perform the
    normal decode and export of the X.509 certificate. It is not recommended
    to do both. Default is false.

-   **dnssec_enabled** has **yaf** perform and export DPI on DNSSEC Resource
    Records, if set to true. Default is false.

## [Rule Format](#rule-format) {#rule-format}

DPI related rule entries are ultimately optional and are only given after
required applabel keys within an applabel rule if **yaf** supports DPI for
the associated protocol.

[//]: # (COMMENT: Since an applabel rule is a keyed dictionary, the order is irrelevant.)

The file must define a variable named `applabels` which is an array of
applabel tables. Each applabel table defines a rule that tells **yaf** how
to assign an applabel, what information elements to create when doing DPI,
and how to assign values to those elements.

An applabel rule has the form

     {label=<APP>,
      label_type="<LABEL_TYPE>",
      value=[=[<EXPRESSION>]=],
      ports={<PORTS>},
      protocol=<PROTO>,
      active=<true|false>,
      <DPI-RELATED-ENTRIES>}

Here, we expand on the available options which may be given for
**\<DPI-RELATED-ENTRIES\>**. (See [application labeling][applabeling] for a
desciption of the other key-value pairs.)

If **yaf** supports DPI for a given protocol, the associated applabel
rule will include at least the following:

    dpi_type="<DPI_TYPE>"

where \<DPI_TYPE\> is how to perform DPI. The value is a string, and the
recognized values are: **none**, **regex**, **plugin, and **regex-plugin**.
If `dpi_type` is not present or has the value "none", no DPI is performed.
More details are in the "Assigning..." sections below.

### [Assigning DPI Using Regular Expressions](#dpi-regex) {#dpi-regex}

A "regex" dpi\_type is typically used with label\_type="regex" rules and has
the following form:

     {label=<APP>,
      label_type="regex",
      active=true,
      protocol=<PROTO>,
      value=[=[<APP_PCRE_REGEX>]=],
      dpi_type="regex",
      dpi_template_id=<TID>,
      dpi_name="<NAME>",
      dpi_rules={
          {elem_name="<ELEMENT>",
           active=<true|false>,
           regex=[=[DPI_PCRE_REGEX]=]},
          ...
      }}

where the following additional key-value pairs are required or strongly
recommended:

-   **dpi\_template\_id** is the template ID to assign to the template
    holding this information. The ID must be a value between 256 and 65535
    and it must not match any other template ID used by yaf. If this element
    is not present or 0, an arbitrary ID is assigned. This template will
    hold one or more information elements of type basicList.

-   **dpi\_name** is a name to assign to the template; this name is exported
    as part of the template metadata. If not present, a name is generated.

-   **dpi\_rules** is an array of tables, where each table describes one
    information element to appear in the template and a regular expression
    to extract the data for that element from the payload. The tables in
    dpi\_rules must have the following entries:

    -   **elem\_name** is the name of the information element to use for
        each value found by the regex. This must name an existing element.

    -   **regex** is a [PCRE][] regular expression that is used to examine
        the payload. Each time it matches, a new elem\_name item is created.
        All the elements are stored in a basicList that is itself added to
        the template specified by dpi\_template\_id.

        If capturing parantheses are used in the regex, only the text
        captured by the first set of parantheses is exported. If no
        capturing parantheses are used, the entire match is exported.

    -   **active** is an optional boolean value. If present and `false` the
        entry is ignored.

When creating the template that holds the basicLists, YAF first checks for
an information element of whose name is elem\_name+"List" and whose type is
basicList. If found, that element is used, otherwise the generic basicList
element is used.

### [Assigning DPI Using A Plugin](#dpi-plugin) {#dpi-plugin}

Rules with label\_type="plugin" may have a dpi\_type of either "plugin" or
"regex-plugin". The latter is rarely used; see the DNP 3.0, Modbus, and
Ethernet/IP rules for examples.

Typically, a "plugin" dpi\_type is used with label\_type="plugin" rules and
the same \<LIBRARY\> is used to perform DPI. In this case, no additional
key-value pairs are required and the rule has the following form:

    {label=<APP>,
     label_type="plugin",
     active=true,
     value=[=[<LIBRARY>]=],
     args={[[ARG1]], [[ARG2]], ...},
     dpi_type="plugin"}

## [Creating New Information Elements](#new-ie) {#new-ie}

The variable `elements` may be used to define new information elements
within the CERT private enterprise domain (Private Enterprise Number (PEN)
6871). If defined, it must be an array of tables, where each table
represents an element:

    elements = {
      {name="<NAME>", id=<NUM>, is_string=<true|false>},
      ...
    }

Each table in `elements` must contain the keys `name` and `id`, where
\<NAME\> is the name of the element and \<NUM\> is its ID. \<NAME\> must be
an unused name and \<NUM\> must be an unused ID between 1 and 16383
inclusive. If you attempt to use an existing name or ID, **yaf** exists with
an error message. To find an unused name and ID, consult the [CERT IPFIX
Registry][certipfix] for the defined elements.

The key `is_string` accepts a boolean; if present and true, the type of the
new element is set to `string`, otherwise the new element's type is
`octetArray`. Typically `string` should be `true` unless the object contains
binary data.

[//]: # (COMMENT: OK, but how do I use this, find an unused ID, when to choose to use a string or not, reference it in a rule, view it in output ... may be a good use case/tutorial.)

Keep in mind that user defined information elements may be added for any
"regex" dpi\_type, but there is a total limit of 40 regexes per protocol.

To find out if **yaf** accepted your elements, run **yaf** with
**--verbose** and review the terminal output or log file.

Upon **yaf** startup and capture, you will be able to see if the rule files
and their regular expressions were accepted.

    [2021-10-15 17:20:14] DPI Running for ALL Protocols
    [2021-10-15 17:20:14] Reading packets from packets.pcap
    [2021-10-15 17:20:14] Initializing Rules from DPI File /usr/local/etc/yafDPIRules.conf
    [2021-10-15 17:20:14] DPI rule scanner accepted 63 rules from the DPI Rule File

An unacceptable regular expression will be brought to your attention with
the above statements. If you choose certain protocols for inspection using
the **--dpi-select** option, only the appropriate rule statements will be
loaded into the DPI Rule Scanner.

# [DPI Data Export](#dpi-data-export) {#dpi-data-export}

**yaf**'s output consists of an IPFIX message stream. **yaf** uses a variety
of templates for IPFIX data records; As of **yaf** 3.0, DPI information is
now housed in its own named subTemplateList: **yafDPIList**. Rather than the
previous subTemplateMultiList which could have a variety of nested templates
for each record, the **yafDPIList** will only use one template per record,
corresponding to the DPI for the protocol specified in the **silkAppLabel**
field.

Below are the templates that may appear depending on the application label
of the flow. For more information on **yaf** information elements see
*[\<todo link to basic flow record\>]{.underline}*. For more information on
IPFIX Structured lists, see [Export of Structured Data in IPFIX, RFC
6313][rfc6313].

Most of the values are exported as a basicList, which represents a list of
zero or more instances of any Information Element. In YAF 3, there is a
specific element of type basicList that holds a single type of element. For
example, the HTTP GET DPI is exported in the httpGetList element, which is a
basicList that holds zero or more httpGet elements.

[//]: # (COMMENT: See navigation note on the original page.)

## [HTTP](#http) {#http}

Hypertext Transfer Protocol (HTTP) Deep Packet Inspection is based on [RFC
2616][rfc2616].

- **httpServerStringList** CERT (PEN 6871) IE 338, variable length,
  basicList of **httpServerString** CERT (PEN 6871) IE 110, variable length,
  string

  HTTP Server Response-header field. Contains information about the software
  used to handle the HTTP Request.

- **httpUserAgentList** CERT (PEN 6871) IE 339, variable length, basicList
  of **httpUserAgent** CERT (PEN 6871) IE 111, variable length, string

  HTTP User-Agent Request-header field. Contains information about the user
  agent originating the request.

- **httpGetList** CERT (PEN 6871) IE 340, variable length, basicList of
  **httpGet** CERT (PEN 6871) IE 112, variable length, string

  HTTP Method Command. Retrieves information identified by the following
  Request-URI.

- **httpConnectionList** CERT (PEN 6871) IE 341, variable length, basicList
  of **httpConnection** CERT (PEN 6871) IE 113, variable length, string

  HTTP Connection header fields. Contains options that are desired for a
  particular connection.

- **httpRefererList** CERT (PEN 6871) IE 343, variable length, basicList of
  **httpReferer** CERT (PEN 6871) IE 115, variable length, string

  HTTP Referer request-header field. Address (URI) of the resource which the
  Request-URI was obtained.

- **httpLocationList** CERT (PEN 6871) IE 344, variable length, basicList of
  **httpLocation** CERT (PEN 6871) IE 116, variable length, string

  HTTP Location response-header field. Used to redirect the recipient to a
  location to complete a request or identify a new resource.

- **httpHostList** CERT (PEN 6871) IE 345, variable length, basicList of
  **httpHost** CERT (PEN 6871) IE 117, variable length, string

  HTTP Host Request-header. The Internet host and port number of the
  resource being requested.

- **httpContentLengthList** CERT (PEN 6871) IE 346, variable length,
  basicList of **httpContentLength** CERT (PEN 6871) IE 118, variable
  length, string

  HTTP Content-Length header. Indicates the size of the entity-body.

- **httpAgeList** CERT (PEN 6871) IE 347, variable length, basicList of
  **httpAge** CERT (PEN 6871) IE 119, variable length, string

  HTTP Age response-header. Argument is the sender's estimate of the time
  elapsed since the response.

- **httpResponseList** CERT (PEN 6871) IE 351, variable length, basicList of
  **httpResponse** CERT (PEN 6871) IE 123, variable length, string

  HTTP Response Status Code. Usually a three-digit number followed by text.

- **httpAcceptLanguageList** CERT (PEN 6871) IE 349, variable length,
  basicList of **httpAcceptLanguage** CERT (PEN 6871) IE 121, variable
  length, string

  HTTP Accept-Language Request-Header field. Restricts the set of natural
  languages that preferred.

- **httpAcceptList** CERT (PEN 6871) IE 348, variable length, basicList of
  **httpAccept** CERT (PEN 6871) IE 120, variable length, string

  HTTP Accept request-header field. Used to specify certain media types that
  are acceptable for the response.

- **httpContentTypeList** CERT (PEN 6871) IE 350, variable length, basicList
  of **httpContentType** CERT (PEN 6871) IE 122, variable length, string

  HTTP Content Type entity-header field. Indicates the media type of the
  entity-body.

- **httpVersionList** CERT (PEN 6871) IE 342, variable length, basicList of
  **httpVersion** CERT (PEN 6871) IE 114, variable length, string

  HTTP Version Number.

- **httpCookieList** CERT (PEN 6871) IE 390, variable length, basicList of
  **httpCookie** CERT (PEN 6871) IE 220, variable length, string

  HTTP Cookie Header Field.

- **httpSetCookieList** CERT (PEN 6871) IE 391, variable length, basicList
  of **httpSetCookie** CERT (PEN 6871) IE 221, variable length, string

  HTTP Set Cookie Header Field.

- **httpAuthorizationList** CERT (PEN 6871) IE 392, variable length,
  basicList of **httpAuthorization** CERT (PEN 6871) IE 252, variable
  length, string

  HTTP Authorization Header Field.

- **httpViaList** CERT (PEN 6871) IE 393, variable length, basicList of
  **httpVia** CERT (PEN 6871) IE 253, variable length, string

  HTTP Via Header Field.

- **httpXForwardedForList** CERT (PEN 6871) IE 394, variable length,
  basicList of **httpXForwardedFor** CERT (PEN 6871) IE 254, variable
  length, string

  HTTP X-Forwarded-For Header Field.

- **httpRefreshList** CERT (PEN 6871) IE 396, variable length, basicList of
  **httpRefresh** CERT (PEN 6871) IE 256, variable length, string

  HTTP Refresh Header Field.

### [Optional HTTP Elements](#optional-http) {#optional-http}

The following information elements are defined but not enabled by default.
To enable any of the following fields individually, set the field's `active`
key to `true` in the yafDPIRules.conf file.

#### [HTTP Mobile Fields](#http-mobile) {#http-mobile}

These fields may be enabled all together by setting the **http_mobile**
variable to `true` in the yafDPIRules.conf file.

- **httpIMEIList** CERT (PEN 6871) IE 397, variable length, basicList of
  **httpIMEI** CERT (PEN 6871) IE 257, variable length, string

  HTTP International Mobile Station Equipment Identity ID.

- **httpIMSIList** CERT (PEN 6871) IE 398, variable length, basicList of
  **httpIMSI** CERT (PEN 6871) IE 258, variable length, string

  HTTP International Mobile Subscriber Identity

- **httpMSISDNList** CERT (PEN 6871) IE 399, variable length, basicList of
  **httpMSISDN** CERT (PEN 6871) IE 259, variable length, string

  HTTP MSISDN number, a telephone number for the SIM card in a
  mobile/cellular phone.

- **httpSubscriberList** CERT (PEN 6871) IE 400, variable length, basicList
  of **httpSubscriber** CERT (PEN 6871) IE 260, variable length, string

  HTTP Mobile Subscriber Information

#### [HTTP Extra Fields](#http-extra) {#http-extra}

These fields may be enabled all together by setting the **http_extra**
variable to `true` in the yafDPIRules.conf file.

- **httpExpiresList** CERT (PEN 6871) IE 395, variable length, basicList of
  **httpExpires** CERT (PEN 6871) IE 255, variable length, string

  HTTP Expires Header Field.

- **httpAcceptCharsetList** CERT (PEN 6871) IE 401, variable length,
  basicList of **httpAcceptCharset** CERT (PEN 6871) IE 261, variable
  length, string

  HTTP Accept Charset Header Field.

- **httpAllowList** CERT (PEN 6871) IE 402, variable length, basicList of
  **httpAllow** CERT (PEN 6871) IE 263, variable length, string

  HTTP Accept Encoding Header Field.

- **httpDateList** CERT (PEN 6871) IE 403, variable length, basicList of
  **httpDate** CERT (PEN 6871) IE 264, variable length, string

  HTTP Date Header Field.

- **httpExpectList** CERT (PEN 6871) IE 404, variable length, basicList of
  **httpExpect** CERT (PEN 6871) IE 265, variable length, string

  HTTP Expect Header Field.

- **httpFromList** CERT (PEN 6871) IE 405, variable length, basicList of
  **httpFrom** CERT (PEN 6871) IE 266, variable length, string

  HTTP From Header Field.

- **httpProxyAuthenticationList** CERT (PEN 6871) IE 406, variable length,
  basicList of **httpProxyAuthentication** CERT (PEN 6871) IE 267, variable
  length, string

  HTTP Proxy Authentication Field.

- **httpUpgradeList** CERT (PEN 6871) IE 407, variable length, basicList of
  **httpUpgrade** CERT (PEN 6871) IE 268, variable length, string

  HTTP Upgrade Header Field.

- **httpWarningList** CERT (PEN 6871) IE 408, variable length, basicList of
  **httpWarning** CERT (PEN 6871) IE 269, variable length, string

  HTTP Warning Header Field.

- **httpDNTList** CERT (PEN 6871) IE 409, variable length, basicList of
  **httpDNT** CERT (PEN 6871) IE 270, variable length, string

  HTTP DNT Header Field.

- **httpXForwardedProtoList** CERT (PEN 6871) IE 410, variable length,
  basicList of **httpXForwardedProto** CERT (PEN 6871) IE 271, variable
  length, string

  HTTP X-Forwarded-Proto Header Field.

- **httpXForwardedHostList** CERT (PEN 6871) IE 411, variable length,
  basicList of **httpXForwardedHost** CERT (PEN 6871) IE 272, variable
  length, string

  HTTP X-Forwarded-Host Header Field.

- **httpXForwardedServerList** CERT (PEN 6871) IE 412, variable length,
  basicList of **httpXForwardedServer** CERT (PEN 6871) IE 273, variable
  length, string

  HTTP X-Forwarded-Server Header Field.

- **httpXDeviceIdList** CERT (PEN 6871) IE 413, variable length, basicList
  of **httpXDeviceId** CERT (PEN 6871) IE 274, variable length, string

  HTTP X-Device ID Header Field.

- **httpXProfileList** CERT (PEN 6871) IE 414, variable length, basicList of
  **httpXProfile** CERT (PEN 6871) IE 275, variable length, string

  HTTP X-Profile Header Field.

- **httpLastModifiedList** CERT (PEN 6871) IE 415, variable length,
  basicList of **httpLastModified** CERT (PEN 6871) IE 276, variable length,
  string

  HTTP Last Modified Header Field.

- **httpContentEncodingList** CERT (PEN 6871) IE 416, variable length,
  basicList of **httpContentEncoding** CERT (PEN 6871) IE 277, variable
  length, string

  HTTP Content Encoding Header Field.

- **httpContentLanguageList** CERT (PEN 6871) IE 417, variable length,
  basicList of **httpContentLanguage** CERT (PEN 6871) IE 278, variable
  length, string

  HTTP Content Language Header Field.

- **httpContentLocationList** CERT (PEN 6871) IE 418, variable length,
  basicList of **httpContentLocation** CERT (PEN 6871) IE 279, variable
  length, string

  HTTP Content Location Header Field.

- **httpXUaCompatibleList** CERT (PEN 6871) IE 419, variable length,
  basicList of **httpXUaCompatible** CERT (PEN 6871) IE 280, variable
  length, string

  HTTP X-UA-Compatible Header Field.

## [SSH](#ssh) {#ssh}

Secure Shell (SSH) Deep Packet Inspection is based on [RFC 4253][rfc4253].

- **sshVersion** CERT (PEN 6871) IE 171, variable length, string

  SSH Version Number of the client.

- **sshServerVersion** CERT (PEN 6871) IE 472, variable length, string

  The version string from an SSH server.

- **sshKeyExchangeAlgorithm** CERT (PEN 6871) IE 476, variable length, string 

  The negotiated key exchange algorithm used for an SSH session.

- **sshHostKeyAlgorithm** CERT (PEN 6871) IE 477, variable length, string

  The negotiated host key algorithm used for an SSH session.

- **sshServerHostKey** CERT (PEN 6871) IE 478, variable length, octetarray

  The MD5 hash of the public key of the SSH server.

- **sshCipher** CERT (PEN 6871) IE 473, variable length, string

  The negotiated symmetric encryption algorithm used for an SSH session.

- **sshMacAlgorithm** CERT (PEN 6871) IE 474, variable length, string

  The negotiated MAC algorithm used for an SSH session.

- **sshCompressionMethod** CERT (PEN 6871) IE 475, variable length, string

  The negotiated compression algorithm used for an SSH session.

- **sshHassh** CERT (PEN 6871) IE 468, variable length, octetarray

  The client HASSH MD5 hash of the sshHasshAlgorithms (CERT/469) fingerprint for an SSH client.

- **sshServerHassh** CERT (PEN 6871) IE 470, variable length, octetarray

  The server HASSH MD5 hash (hasshServer) of the sshServerHasshAlgorithms (CERT/471) fingerprint for an SSH server.  

- **sshHasshAlgorithms** CERT (PEN 6871) IE 469, variable length, string

  The SSH client hasshAlgorithms: the concatenated name-lists of the client-to-server algorithms delimited by a semicolon. Element sshHassh (CERT/468) holds the MD5 of this.

- **sshServerHasshAlgorithms** CERT (PEN 6871) IE 471, variable length, string 

  The SSH server hasshServerAlgoritms: the concatenated name-lists of the server-to-client algorithms delimited by a semicolon. Element sshServerHassh (CERT/470) holds the MD5 of this.

## [SMTP](#smtp) {#smtp}

Simple Mail Transfer Protocol (SMTP) Deep Packet Inspection is based on [RFC
2821][rfc2821].

As of YAF 2.12, the SMTP DPI data is represented as a hierarchy. The outer
layer captures the SMTP connection information. For each message sent during
the connection, a separate sub-record is created. Within the subrecord,
another subrecord exists that contains the header fields found in the DATA
section exported as key-value pairs.

- **smtpHello** CERT (PEN 6871) IE 162, variable length, string

  SMTP Hello or Extend Hello command. Captures the command and the
  domain name or IP of the SMTP client.

- **smtpResponseList** CERT (PEN 6871) IE 331, variable length, basicList
  of **smtpResponse** CERT (PEN 6871) IE 169, variable length, string

  SMTP Replies. Each smtpResponse contains of a three digit number followed
  by text.

- **smtpMessageList** CERT (PEN 6871) IE 336, variable length,
  subTemplateList

  A subTemplateList containing zero (but usually at least one) or more
  records where each record represents a single email message sent during
  the SMTP conversation. That template contains the following elements:

  - **smtpSubject** CERT (PEN 6871) IE 166, variable length, string

    The subject of the message.

  - **smtpToList** CERT (PEN 6871) IE 332, variable length, basicList of
    **smtpTo** CERT (PEN 6871) IE 164, variable length, string

    The SMTP Recipient (RCPT) Command. Each smtpTo captures the forward-path
    of the recipient of the mail data.

  - **smtpFromList** CERT (PEN 6871) IE 333, variable length, basicList
    of **smtpFrom** CERT (PEN 6871) IE 163, variable length, string

    SMTP Mail Command. Each stmpFrom contains the reverse-path of the sender
    mailbox. A successful message has a single `MAIL FROM`, but the sender
    may provide multiple if `RCPT TO` is rejected and the sender RSETs or if
    they are testing/probing the server.

  - **smtpFilenameList** CERT (PEN 6871) IE 334, variable length, basicList
    of **smtpFilename** CERT (PEN 6871) IE 167, variable length, string

    SMTP Filename. Each smtpFilename contains the name of a file attached to
    the mail message, if any.

  - **smtpURLList** CERT (PEN 6871) IE 335, variable length, basicList of
    **smtpURL** CERT (PEN 6871) IE 329, variable length, string

    SMTP URL. Each smtpURL contains a URL captured in the SMTP message body,
    if any.

  - **smtpHeaderList** CERT (PEN 6871) IE 337, variable length,
    subTemplateList

    A subTemplateList containing zero or more records describing the message
    headers. Each record represents a single header (SMTP field name and
    body) in the email DATA. That template contains the following elements:

    - **smtpKey** CERT (PEN 6871) IE 327, variable length, string

      SMTP Header key string. The name of the header (for example, \"To\",
      \"From\").

    - **smtpValue** CERT (PEN 6871) IE 328, variable length, string

      SMTP Header value string. The value of that header.

  - **smtpMessageSize** CERT (PEN 6871) IE 330, 4 octets, unsigned

    SMTP Size Header Field, optionally given by the client following a MAIL
    FROM command. Contains the size in bytes of the mail data.

- **smtpStartTLS** CERT (PEN 6871) IE 326, 1 octet, unsigned

  Indicates whether or not the SMTP session sent the STARTTLS command.

## [DNS](#dns) {#dns}

Domain Name System (DNS) Deep Packet Inspection is based on [RFC
1035][rfc1035].

DNS information is exported in the **yafDPIList** as zero or more DNS
Resource Record Templates. Each Resource Record (RR) entry contains generic
RR information such as type, TTL, and name. There is also a subTemplateList
element, **dnsDetailRecordList**, that contains RR specific information
based on the type of RR (A Record vs NS Record, for example). The main
subTemplateList contains one entry for each RR in the flow.

The following elements are contained in the DNS Resource Record Template.

- **dnsQueryResponse** CERT (PEN 6871) IE 174, 1 octet, unsigned

  DNS Query/Response header field. This corresponds with the DNS header one
  bit field, QR, indicating whether the record is a query (0) or a response
  (1).

- **dnsRRType** CERT (PEN 6871) IE 175, 2 octets, unsigned

  DNS Query/Response Type. This corresponds with the QTYPE field in the DNS
  Question Section or the TYPE field in the DNS Resource Record Section.
  This field determines the template used by the **dnsDetailRecordList**
  subTemplateList found in this record.

- **dnsAuthoritative** CERT (PEN 6871) IE 176, 1 octet, unsigned

  DNS Authoritative header field. This corresponds with the DNS header one
  bit field, AA. This bit is only valid in responses (when
  **dnsQueryResponse** is 1), and specifies that the responding name server
  is an authority for the domain name in the question section.

- **dnsResponseCode** CERT (PEN 6871) IE 177, 1 octet, unsigned

  This corresponds with the DNS RCODE header field. This field is set
  to 0 for No Error, 1 for a Format Error, 2 for a Server Failure, and 3 for
  a Name Error. See <http://www.iana.org/assignments/dns-parameters> for
  other valid values.

- **dnsSection** CERT (PEN 6871) IE 178, 1 octet, unsigned

  DNS Resource Record Section Field. This field is set to 0 if the
  information is from the Question Section, 1 for the Answer Section, 2 for
  the Name Server Section, and 3 for the Additional Section.

- **dnsName** CERT (PEN 6871) IE 179, variable length, string

  A DNS Query or Response Name. This field corresponds with the QNAME field
  in the DNS Question Section or the NAME field in the DNS Resource Record
  Section.

- **dnsTTL** CERT (PEN 6871) IE 199, 4 octets, unsigned

  DNS Time To Live. This is an unsigned integer that specifies the time
  interval, in seconds, that the resource record may be cached for. This
  contains a value of zero for DNS Queries.

- **dnsId** CERT (PEN 6871) IE 226, 2 octets, unsigned

  DNS Transaction ID. This identifier is used by the requester to match
  replies to outstanding queries.

- **dnsDetailRecordList** CERT (PEN 6871) IE 431, variable length, subTemplateList

  An IPFIX subTemplateList. This list contains a "DNS Resource Record Type"
  Template, whose type depends on the type (**dnsRRType**) of resource
  record, as described in the next subsection.

### [DNS Resource Record Types](#dns-rr-types) {#dns-rr-types}

This section describes the templates that may be used in the
**dnsDetailRecordList** according to the type of resource record (the
**dnsRRType**).

- DNS A (Address) Resource Record

  This entry exists if **dnsRRType** is 1 and the A Record contains an IP
  address.

  - **dnsA** CERT (PEN 6871) IE 302, 4 octets, ipv4Address

     The IPv4 address of the host.

- DNS NS (Name Server) Resource Record

  This entry will exist if **dnsRRType** is 2 and the NS Record contains an
  NSDNAME.

  - **dnsNSDName** CERT (PEN 6871) IE 183, variable length, string

    An authoritative name server domain-name.

- DNS CNAME (Canonical Name) Resource Record

  This entry will exist if **dnsRRType** is 5 and the CNAME Record contains
  a CNAME.

  - **dnsCNAME** CERT (PEN 6871) IE 180, variable length, string

    A domain-name which specifies the canonical or primary name for the
    owner.

- DNS SOA (Start of Authority) Resource Record

  This entry will exist if **dnsRRType** is 6 and the SOA Record contains at
  least 1 of the following elements (all element are always present in the
  template):

  - **dnsSOAMName** CERT (PEN 6871) IE 214, variable length, string

    Corresponds to DNS SOA MNAME Field.

  - **dnsSOARName** CERT (PEN 6871) IE 215, variable length, string

    Corresponds to DNS SOA RNAME Field.

  - **dnsSOASerial** CERT (PEN 6871) IE 209, 4 octets, unsigned

    Corresponds to DNS SOA SERIAL Field.

  - **dnsSOARefresh** CERT (PEN 6871) IE 210, 4 octets, unsigned

    Corresponds to DNS SOA REFRESH Field.

  - **dnsSOARetry** CERT (PEN 6871) IE 211, 4 octets, unsigned

    Corresponds to DNS SOA RETRY Field.

  - **dnsSOAExpire** CERT (PEN 6871) IE 212, 4 octets, unsigned

    Corresponds to DNS SOA EXPIRE Field.

  - **dnsSOAMinimum** CERT (PEN 6871) IE 213, 4 octets, unsigned

    Corresponds to DNS SOA MINIMUM Field.

- DNS PTR (Domain Name Pointer) Resource Record

  This entry will exist if **dnsRRType** is set to 12 and PTRDNAME exists.

  - **dnsPTRDName** CERT (PEN 6871) IE 184, variable length, string

    Corresponds to DNS PTR PTRDNAME Field.

- DNS MX (Mail Exchange) Resource Record

  This entry will exist if **dnsRRType** is set to 15 and MXExchange exists

  - **dnsMXExchange** CERT (PEN 6871) IE 182, variable length, string

    Corresponds to the DNS MX Exchange field.

  - **dnsMXPreference** CERT (PEN 6871) IE 181, 2 octets, unsigned

    Corresponds to the DNS MX Preference field.

- DNS TXT (Text) Resource Record

  This entry will exist if **dnsRRType** is set to 16 and TXT-DATA exists.

  - **dnsTXTData** CERT (PEN 6871) IE 208, variable length, string

    Corresponds to DNS TXT TXT-DATA field.

- DNS AAAA (IPv6 Address) Record

  This entry will exist if **dnsRRType** is set to 28 and the IPv6 Address
  exists. See [RFC 3596][rfc3596].

  - **dnsAAAA** CERT (PEN 6871) IE 303, 16 octets, ipv6Address

    An IPv6 Address found in the data portion of an AAAA Resource Record.

- DNS SRV (Server Locator) Record

  This entry will exist if **dnsRRType** is set to 33 and at least 1 of the
  following elements exist (all element are always present in the template).
  See [RFC 2782][rfc2782].

  - **dnsSRVTarget** CERT (PEN 6871) IE 219, variable length, string

    Corresponds to the Target Field in the DNS SRV Resource Record.

  - **dnsSRVPriority** CERT (PEN 6871) IE 216, 2 octets, unsigned

    Corresponds to the Priority Field in the DNS SRV Resource Record.

  - **dnsSRVWeight** CERT (PEN 6871) IE 217, 2 octets, unsigned

    Corresponds to the Weight Field in the DNS SRV Resource Record.

  - **dnsSRVPort** CERT (PEN 6871) IE 218, 2 octets, unsigned

    Corresponds to the Port Field in the DNS SRV Resource Record.

### [DNSSEC Resource Record Types](#dnssec-rr-types) {#dnssec-rr-types}

DNSSEC information is not exported by default. To export DNSSEC information,
set **dnssec_enabled** to true in the yafDPIRules.conf file. DNSSEC DPI is
based on [RFC 4034, Resource Records for the DNS Security
Extensions][rfc4034] and, for NSEC3, [RFC 5155, DNS Security (DNSSEC) Hashed
Authenticated Denial of Existence][rfc5155].

- DNSSEC DNSKEY (DNS Key) Record

  This entry will exist if **dnsRRType** is set to 48 and at least 1 of the
  following elements exist (all element are always present in the template).

  - **dnsDNSKEYPublicKey** CERT (PEN 6871) IE 232, variable length, octetArray

    DNSSEC uses public key cryptography to sign and authenticate DNS
    resource record sets. This field holds the public key. The format
    depends on the algorithm of the key.

  - **dnsDNSKEYFlags** CERT (PEN 6871) IE 241, 2 octets, unsigned

    The flags field in the DNSKey Resource Record. Certain bits determine if
    the key is a zone key or should be used for a secure entry point.

  - **dnsDNSKEYProtocol** CERT (PEN 6871) IE 304, 1 octet, unsigned

    The protocol field in the DNSKEY RR. This should be 3 or treated as
    invalid.

  - **dnsDNSKEYAlgorithm** CERT (PEN 6871) IE 423, 1 octet, unsigned

    Identifies the public key's cryptographic algorithm, which determines
    its format.

- DNSSEC DS (Delegation Signer) Record

  This entry will exist if **dnsRRType** is set to 43 and at least 1 of the
  following elements exist (all element are always present in the template).

  - **dnsDSDigest** CERT (PEN 6871) IE 231, variable length, octetArray

    The digest of the DNSKEY RR.

  - **dnsDSKeyTag** CERT (PEN 6871) IE 434, 2 octets, unsigned

    The Key Tag field in the DS RR.

  - **dnsDSAlgorithm** CERT (PEN 6871) IE 433, 1 octet, unsigned

    The Algorithm number of the DNSKEY RR referred to by the DS Record.

  - **dnsDSDigestType** CERT (PEN 6871) IE 238, 1 octet, unsigned

    The Digest Type field which identifies the algorithm used to construct
    the digest.

- DNSSEC RRSIG (DNSSEC Signature) Record

  This entry will exist if **dnsRRType** is set to 46 and at least one of
  the following fields exists (all element are always present in the
  template).

  - **dnsRRSIGSigner** CERT (PEN 6871) IE 229, variable length, string

    The Signer's Name field in the RRSIG RR.

  - **dnsRRSIGSignature** CERT (PEN 6871) IE 230, variable length, octetArray

    The Signature field in the RRSIG RR. Contains the cryptographic
    signature that covers the dnsName field.

  - **dnsRRSIGSignatureInception** CERT (PEN 6871) IE 237, 4 octets, unsigned

    The Signature Inception field in a RRSIG RR. The Expiration and
    Inception fields specify a validity period for the signature.

  - **dnsRRSIGSignatureExpiration** CERT (PEN 6871) IE 236, 4 octets, unsigned

    The Signature Expiration field in a RRSIG RR. The Expiration and
    Inception fields specify a validity period for the signature.

  - **dnsRRSIGOriginalTTL** CERT (PEN 6871) IE 449, 4 octets, unsigned

    The Original TTL Field in the RRSIG RR.

  - **dnsRRSIGKeyTag** CERT (PEN 6871) IE 448, 2 octets, unsigned

    The Key Tag field in a RRSIG RR.

  - **dnsRRSIGTypeCovered** CERT (PEN 6871) IE 240, 2 octets, unsigned

    The Type Covered field in a RRSIG RR.

  - **dnsRRSIGAlgorithm** CERT (PEN 6871) IE 447, 1 octet, unsigned

    The Algorithm Number field in a RRSIG RR. Identifies the algorithm used
    to create the signature.

  - **dnsRRSIGLabels** CERT (PEN 6871) IE 239, 1 octet, unsigned

    The Labels field in a RRSIG RR. Specifies the number of labels in the
    original RRSIG resource record owner name.

- DNSSEC NSEC (Next Secure) Record

  This entry will exist if **dnsRRType** is set to 47 and the
  dnsNSECNextDomainName field exists.

  - **dnsNSECNextDomainName** CERT (PEN 6871) IE 445, variable length, octetArray

    This item contains the Next Domain Name in the NSEC RR.

  - **dnsNSECTypeBitMaps** CERT (PEN 6871) IE 446, variable length, octetArray

    The Type Bit Maps field in a DNS NSEC RR.

- DNSSEC NSEC3 (Next Secure version 3) Record

  This entry will exist if **dnsRRType** is set to 50 and at least one of
  the following fields exists.

  - **dnsNSEC3Salt** CERT (PEN 6871) IE 439, variable length, octetArray

    The Salt Field in the DNSSEC NSEC3 RR.

  - **dnsNSEC3NextHashedOwnerName** CERT (PEN 6871) IE 438, variable length, octetArray

    The Next Hashed Owner Name in the DNSSEC NSEC3 RR.

  - **dnsNSEC3TypeBitMaps** CERT (PEN 6871) IE 440, variable length, octetArray

    The Type Bit Maps field in a DNS NSEC3 RR.

  - **dnsNSEC3Iterations** CERT (PEN 6871) IE 437, 2 octets, unsigned

    The Iterations field in the DNSSEC NSEC3 RR.

  - **dnsNSEC3Algorithm** CERT (PEN 6871) IE 435, 1 octet, unsigned

    The Hash Algorithm field in the DNSSEC NSEC3 RR. Values are described in
    RFC 5155.

  - **dnsNSEC3Flags** CERT (PEN 6871) IE 436, 1 octet, unsigned

    The Flags field in a DNS NSEC3 RR.

- DNSSEC NSEC3PARAM (NSEC3 Parameters) Record

  This entry will exist if **dnsRRType** is set to 51 and at least one of
  the following fields exists.

  - **dnsNSEC3PARAMSalt** CERT (PEN 6871) IE 444, variable length, octetArray

    The Salt Field in the DNSSEC NSEC3PARAM RR.

  - **dnsNSEC3PARAMIterations** CERT (PEN 6871) IE 443, 2 octets, unsigned

    The Iterations field in the DNSSEC NSEC3PARAM RR.

  - **dnsNSEC3PARAMAlgorithm** CERT (PEN 6871) IE 441, 1 octet, unsigned

    The Hash Algorithm field in the DNSSEC NSEC3PARAM RR. Values are
    described in RFC 5155.

  - **dnsNSEC3PARAMFlags** CERT (PEN 6871) IE 442, 1 octet, unsigned

    The Flags field in a DNS NSEC3PARAM RR.

## [FTP](#ftp) {#ftp}

File Transfer Protocol (FTP) Deep Packet Inspection is based on [RFC
959][rfc959].

- **ftpReturnList** CERT (PEN 6871) IE 355, variable length, basicList of
  **ftpReturn** CERT (PEN 6871) IE 131, variable length, string

  FTP Commands issued by the client.

- **ftpUserList** CERT (PEN 6871) IE 356, variable length, basicList of
  **ftpUser** CERT (PEN 6871) IE 132, variable length, string

  FTP User Command Argument. This command will normally be the first
  command transmitted by the user.

- **ftpPassList** CERT (PEN 6871) IE 357, variable length, basicList of
  **ftpPass** CERT (PEN 6871) IE 133, variable length, string

  FTP Password Command Argument. This command must be preceded by the
  user name command, and is usually required to complete authentication.

- **ftpTypeList** CERT (PEN 6871) IE 358, variable length, basicList of
  **ftpType** CERT (PEN 6871) IE 134, variable length, string

  FTP Data Representation Type.

- **ftpRespCodeList** CERT (PEN 6871) IE 359, variable length, basicList of
  **ftpRespCode** CERT (PEN 6871) IE 135, variable length, string

  FTP Replies from the server. This consists of a three digit number
  followed by some text.

## [TLS/SSL](#tlsssl) {#tlsssl}

Transport Layer Security (TLS)/Secure Socket Layer (SSL) Deep Packet
Inspection can identify and export handshake and certificate information if
it is contained in the payload of the flow. The TLS/SSL DPI is presented in
a nested structure, detailed in this section. At the top level are the TLS
handshake-related elements.

Each certificate identified by **yaf** is exported as an entry in the
**sslCertList** subTemplateList or/and the **sslBinaryCertificateList**
basicList. **sslCertList** is used when the yafDPIRules.conf file has
**cert_export_enabled** set to `false` (the default) or
**cert_hash_enabled** set to `true` (`false` is the default).
**sslBinaryCertificateList** is used when **cert_export_enabled** is `true`.
(To get both lists, set both those variable to `true`.)

An entry in **sslCertList** contains basic certificate elements such as
serial numbers, validity timestamps, and optionally the certificate's hash
when **cert_hash_enabled** is set to `true`. **sslCertList** also contains
three nested subTemplateLists: **sslIssuerFieldList** for Issuer fields,
**sslSubjectFieldList** for Subject fields, and **sslExtensionFieldList**
for Extension fields. Each of these subTemplateLists contains an ID and it
associated value, where the IDs correspond to the attributes associated with
X.509 Certificates, object identifiers id-ce and id-at. See below.

**sslBinaryCertificateList** is a basicList of **sslBinaryCertificate**
entries, where each entry hold an entire binary certificate.

Note that most certificate chains are about 3000 bytes. In order to capture
the entire certificate chain, the **--max-payload** option to **yaf** should
be set appropriately.

### [TLS/SSL Handshake-related Elements](#tlsssl-handshake) {#tlsssl-handshake}

- **sslServerName** CERT (PEN 6871) IE 294, variable length, string

  The server name from the SSL/TLS Client Hello. This is typically the
  name of the server that the client is connecting to.

- **sslCipherList** CERT (PEN 6871) IE 389, variable length, basicList of
  **sslCipher** CERT (PEN 6871) IE 185, 4 octets, unsigned

  The list of CipherSuites suggested by the client in the ClientHello
  Message.

- **sslServerCipher** CERT (PEN 6871) IE 187, 4 octets, unsigned

  The CipherSuite chosen by the server in the ServerHello message.

- **sslClientVersion** CERT (PEN 6871) IE 186, 1 octet, unsigned

  The version contained in the initial ClientHello message.

- **sslCompressionMethod** CERT (PEN 6871) IE 188, 1 octet, unsigned

  The compression method chosen by the server in the ServerHello
  message.

- **sslRecordVersion** CERT (PEN 6871) IE 288, 2 octets, unsigned

  The version of SSL or TLS that was used in the flow.

- **sslClientJA3** CERT (PEN 6871) IE 463, variable length, octetarray

  The JA3 MD5 hash of the sslClientJA3Fingerprint (CERT/464) calculated on the client-side TLS/SSL fingerprint string.

- **sslClientJA3Fingerprint** CERT (PEN 6871) IE 464, variable length, string

  The JA3 fingerprint string enumerated from the TLS/SSL ClientHello packet. Element sslClientJA3 (CERT/463) holds the MD5 of this.

- **sslServerJA3S** CERT (PEN 6871) IE 465, variable length, octetarray

  The JA3S MD5 hash of the sslServerJA3SFingerprint (CERT/466) calculated on the server-side TLS/SSL fingerprint string.

- **sslServerJA3SFingerprint** CERT (PEN 6871) IE 466, variable length, string

  The JA3S fingerprint string enumerated from the TLS/SSL ServerHello packet. Element sslServerJA3S (CERT/465) holds the MD5 of this. 


### [TLS/SSL X.509 Certificate-related Elements](#tlsssl-x509) {#tlsssl-x509}

When **cert_export_enabled** is `false` or **cert_hash_enabled** is `true`,
the top-level TLS/SSL record contains:

- **sslCertList** CERT (PEN 6871) IE 425, variable length, subTemplateList

  This list contains 0 or more X.509 Certificates as available in the
  captured payload. Each entry in the **sslCertList** contains these
  elements:

  - **sslCertVersion** CERT (PEN 6871) IE 189, 1 octet, unsigned

    The Certificate Version. This is the value contained in the certificate
    v1(0), v2(1), v3(2).

  - **sslCertSerialNumber** CERT (PEN 6871) IE 244, variable length,
    octetArray

    The Serial Number from the X.509 certificate.

  - **sslCertValidityNotBefore** CERT (PEN 6871) IE 247, variable length,
    string

    The notBefore field in the Validity Sequence of the X.509 Certificate.

  - **sslCertValidityNotAfter** CERT (PEN 6871) IE 248, variable length,
    string

    The notAfter field in the Validity Sequence of the X.509 Certificate.

  - **sslPublicKeyAlgorithm** CERT (PEN 6871) IE 249, variable length,
    octetArray

    The algorithm, encoded in ASN.1, in the SubjectPublicKeyInfo Sequence of
    the X.509 Certificate.

  - **sslPublicKeyLength** CERT (PEN 6871) IE 250, 2 octets, unsigned

    The length of the public key in the X.509 Certificate.

  - **sslCertSignature** CERT (PEN 6871) IE 190, variable length, octetArray

    The signature contained in the X.509 certificate. This is typically the
    hashing algorithm identifier.

  - **sslCertificateHash** CERT (PEN 6871) IE 295, variable length,
    octetArray

    The hash of the X.509 certificate as found in the certificate. This
    field is only populated if **cert_hash_enabled** is set to `true` in the
    yafDPIRules.conf file, otherwise it is present but empty.

  - **sslIssuerFieldList** CERT (PEN 6871) IE 426, variable length,
    subTemplateList

    The Issuer field identifies the entity that has signed and issued the
    certificate. See below for its contents.

  - **sslSubjectFieldList** CERT (PEN 6871) IE 427, variable length,
    subTemplateList

    The Subject field identifies the entity associated with the public key
    stored in the subject public key field. See below for its contents.

  - **sslExtensionFieldList** CERT (PEN 6871) IE 428, variable length,
    subTemplateList

    Extensions are only defined for X.509 v3 certificates and provide
    methods for associating additional attributes with the Issuer and
    Subject information. See below for its contents.

### [TLS/SSL Issuer and Subject Field Lists](#tlsssl-issuer) {#tlsssl-issuer}

The **sslIssuerFieldList** and **sslSubjectFieldList** are encoded as a
sequence of Relative Distinguished Names, which are basically type-value
pairs. These lists contain zero or more occurrences of the
RelativeDistinguishedName id-value pairs pulled from the X.509 Certificate.
**sslIssuerFieldList** entries are pulled from the Issuer RDNSequence, and
**sslIssuerFieldList** entries from the Subject RDNSequence. There is one
entry in the list for each pair. Each entry contains:

- **sslObjectValue** CERT (PEN 6871) IE 246, variable length, octetArray

  The bit strings associated with the below attribute types.

- **sslObjectType** CERT (PEN 6871) IE 245, 1 octet, unsigned

  The member ID of the RDN identifier. **yaf** only parses RDNSequence
  objects that are members of the id-at arc {joint-iso-itu-t(2) ds(5)
  attributeType(4)}, pkcs-9 {iso(1) member-body (2) us(840) rsadsi(113459)
  pkcs(1) 9}, and LDAP dc 0.9.2342.19200300.100.1.25. This field does not
  contain the full object identifier, it only contains the member id. For
  example, for an issuer common name, sslObjectType will contain 3.

  Below is a list of common objects in an X.509 RelativeDistinguishedName
  Sequence for X.509 Certificates:
  
  | sslObjectType | ID                               | Reference |
  | ------------: | -------------------------------- | :-------- |
  |             1 | **pkcs-9-emailAddress**          | pkcs-9 1  |
  |             3 | **id-at-commonName**             | id-at 3   |
  |             6 | **id-at-countryName**            | id-at 6   |
  |             7 | **id-at-localityName**           | id-at 7   |
  |             8 | **id-at-stateOrProvinceName**    | id-at 8   |
  |             9 | **id-at-streetAddress**          | id-at 9   |
  |            10 | **id-at-organizationName**       | id-at 10  |
  |            11 | **id-at-organizationalUnitName** | id-at 11  |
  |            12 | **id-at-title**                  | id-at 12  |
  |            17 | **id-at-postalCode**             | id-at 17  |
  |            25 | **0.9.2342.19200300.100.1.25**   | dc 25     |
  |            41 | **id-at-name**                   | id-at 41  |

### [TLS/SSL Extension Field List](#tlsssl-extension) {#tlsssl-extension}

Extensions are only defined for X.509 v3 certificates and provide methods
for associating additional attributes with the Issuer and Subject
information. The **sslExtensionFieldList** contains zero or more occurrences
of the following element pair:

- **sslObjectValue** CERT (PEN 6871) IE 246, variable length, octetArray

  The ASN.1 structure associated with the below attribute types. **yaf**
  does not parse the ASN.1 values for the string objects; it includes the
  entire ASN.1 structure in the this field.

- **sslObjectType** CERT (PEN 6871) IE 245, 1 octet, unsigned

  An identifier for the extension, but not the entire extension ID. **yaf**
  only parses extensions that are members of the id-ce arc
  {joint-iso-itu-t(2) ds(5) certificateExtension(29)} and only exports
  information about the following objects. The leading number will appear in
  this field.

  | sslObjectType | ID                               | Reference |
  | ------------: | -------------------------------- | :-------- |
  |            14 | **id-ce-subjectKeyIdentifier**   | id-ce 14  |
  |            15 | **id-ce-keyUsage**               | id-ce 15  |
  |            16 | **id-ce-privateKeyUsagePeriod**  | id-ce 16  |
  |            17 | **id-ce-subjectAltName**         | id-ce 17  |
  |            18 | **id-ce-issuerAltName**          | id-ce 18  |
  |            29 | **id-ce-certificateIssuer**      | id-ce 29  |
  |            31 | **id-ce-cRLDistributionPoints**  | id-ce 31  |
  |            32 | **id-ce-certificatePolicies**    | id-ce 32  |
  |            35 | **id-ce-authorityKeyIdentifier** | id-ce 35  |
  |            37 | **id-ce-extKeyUsage**            | id-ce 37  |

  > **Note:** Although **sslExtensionFieldList** has the same structure as
  > **sslIssuerFieldList** and **sslSubjectFieldList**, the values used in
  > the extension list map to different values.

### [Full Certificate Export Template](#full-cert-export) {#full-cert-export}

When **cert_export_enabled** is `true`, the top-level TLS/SSL record
contains:

- **sslBinaryCertificateList** CERT (PEN 6871) IE 429, variable length,
  basicList of **sslBinaryCertificate** CERT (PEN 6871) IE 296, variable
  length, octetArray

  The complete X.509 certificates. There will be one entry for each
  certificate that **yaf** observes in the captured payload.

## [SLP](#slp) {#slp}

Service Location Protocol (SLP) Deep Packet Inspection is based on [RFC
2608][rfc2608].

- **slpStringList** CERT (PEN 6871) IE 354, variable length, basicList of
  **slpString** CERT (PEN 6871) IE 130, variable length, string

  Contains the text elements found in an SLP Service Request.

- **slpVersion** CERT (PEN 6871) IE 128, 1 octet, unsigned

  SLP Version Number.

- **slpMessageType** CERT (PEN 6871) IE 129, 1 octet, unsigned

  SLP Message Type. This value should be between 1 and 11 and describes the
  type of SLP message.

## [IMAP](#imap) {#imap}

Internet Message Access Protocol (IMAP) Deep Packet Inspection is based on
[RFC 3501][rfc3501].

- **imapCapabilityList** CERT (PEN 6871) IE 360, variable length, basicList
  of **imapCapability** CERT (PEN 6871) IE 136, variable length, string

  IMAP Capability Command and Response. Captures the listing of capabilities
  that the server supports.

- **imapLoginList** CERT (PEN 6871) IE 361, variable length, basicList of
  **imapLogin** CERT (PEN 6871) IE 137, variable length, string

  IMAP Login Command. Arguments are user name and password.

- **imapStartTLSList** CERT (PEN 6871) IE 362, variable length, basicList of
  **imapStartTLS** CERT (PEN 6871) IE 138, variable length, string

  IMAP STARTTLS Command. Captures this command only as no arguments or
  responses are related.

- **imapAuthenticateList** CERT (PEN 6871) IE 363, variable length,
  basicList of **imapAuthenticate** CERT (PEN 6871) IE 139, variable length,
  string

  IMAP Authenticate Command. Captures the authentication mechanism name of
  the server following this command.

- **imapCommandList** CERT (PEN 6871) IE 364, variable length, basicList of
  **imapCommand** CERT (PEN 6871) IE 140, variable length, string

  Captures a variety of IMAP Commands and their arguments.

- **imapExistsList** CERT (PEN 6871) IE 365, variable length, basicList of
  **imapExists** CERT (PEN 6871) IE 141, variable length, string

  IMAP Exists Response. Reports the number of messages in the mailbox.

- **imapRecentList** CERT (PEN 6871) IE 366, variable length, basicList of
  **imapRecent** CERT (PEN 6871) IE 142, variable length, string

  IMAP Recent Response. Reports the number of message with the Recent flag
  set.

## [IRC](#irc) {#irc}

Internet Relay Chat (IRC) Deep Packet Inspection is based on [RFC
2812][rfc2812].

- **ircTextMessageList** CERT (PEN 6871) IE 353, variable length, basicList
  of **ircTextMessage** CERT (PEN 6871) IE 125, variable length, string

  IRC Chat or Join Message. This field contains any IRC Command and the
  following arguments.

## [RTSP](#rtsp) {#rtsp}

Real Time Streaming Protocol (RTSP) Deep Packet Inspection is based on [RFC
2326][rfc2326].

- **rtspURLList** CERT (PEN 6871) IE 367, variable length, basicList of
  **rtspURL** CERT (PEN 6871) IE 143, variable length, string

  RTSP URL. Captures the address of the network resources requested.

- **rtspVersionList** CERT (PEN 6871) IE 368, variable length, basicList of
  **rtspVersion** CERT (PEN 6871) IE 144, variable length, string

  RTSP Version Number.

- **rtspReturnCodeList** CERT (PEN 6871) IE 369, variable length, basicList
  of **rtspReturnCode** CERT (PEN 6871) IE 145, variable length, string

  RTSP Status-Line. Captures the RTSP Protocol version, numeric status code,
  and the textual phrase associated with the numeric code.

- **rtspContentLengthList** CERT (PEN 6871) IE 370, variable length,
  basicList of **rtspContentLength** CERT (PEN 6871) IE 146, variable
  length, string

  RTSP Content-Length Header Field. Contains the length of the content of
  the method.

- **rtspCommandList** CERT (PEN 6871) IE 371, variable length, basicList of
  **rtspCommand** CERT (PEN 6871) IE 147, variable length, string

  RTSP Command. Captures the method to be performed and the Request-URI
  associated with the method.

- **rtspContentTypeList** CERT (PEN 6871) IE 372, variable length, basicList
  of **rtspContentType** CERT (PEN 6871) IE 148, variable length, string

  RTSP Content Type.

- **rtspTransportList** CERT (PEN 6871) IE 373, variable length, basicList
  of **rtspTransport** CERT (PEN 6871) IE 149, variable length, string

  RTSP Transport request header field. Captures the transport protocol used
  and the parameters that follow.

- **rtspCSeqList** CERT (PEN 6871) IE 374, variable length, basicList of
  **rtspCSeq** CERT (PEN 6871) IE 150, variable length, string

  RTSP CSeq field. Contains the sequence number for an RTSP request-response
  pair.

- **rtspLocationList** CERT (PEN 6871) IE 375, variable length, basicList of
  **rtspLocation** CERT (PEN 6871) IE 151, variable length, string

  RTSP Location header field.

- **rtspPacketsReceivedList** CERT (PEN 6871) IE 376, variable length,
  basicList of **rtspPacketsReceived** CERT (PEN 6871) IE 152, variable
  length, string

  RTSP Packets Received header field.

- **rtspUserAgentList** CERT (PEN 6871) IE 377, variable length, basicList
  of **rtspUserAgent** CERT (PEN 6871) IE 153, variable length, string

  RTSP User Agent field. Contains information about the user agent
  originating the request.

- **rtspJitterList** CERT (PEN 6871) IE 378, variable length, basicList of
  **rtspJitter** CERT (PEN 6871) IE 154, variable length, string

  RTSP Jitter Value.

## [SIP](#sip) {#sip}

Session Initiation Protocol (SIP) Deep Packet Inspection is based on [RFC
3261][rfc3261].

- **sipInviteList** CERT (PEN 6871) IE 379, variable length, basicList of
  **sipInvite** CERT (PEN 6871) IE 155, variable length, string

  SIP Invite Method. Contains the SIP address and SIP Version Number.

- **sipCommandList** CERT (PEN 6871) IE 380, variable length, basicList of
  **sipCommand** CERT (PEN 6871) IE 156, variable length, string

  SIP Command. Contains a SIP Method, SIP address, and SIP Version Number.

- **sipViaList** CERT (PEN 6871) IE 381, variable length, basicList of
  **sipVia** CERT (PEN 6871) IE 157, variable length, string

  SIP Via contains the SIP Version Number and the address the sender is
  expecting to receive responses.

- **sipMaxForwardsList** CERT (PEN 6871) IE 382, variable length, basicList
  of **sipMaxForwards** CERT (PEN 6871) IE 158, variable length, string

  SIP Max Forwards contains the limit of number of hops a request can make
  on the way to its destination.

- **sipAddressList** CERT (PEN 6871) IE 383, variable length, basicList of
  **sipAddress** CERT (PEN 6871) IE 159, variable length, string

  SIP Address contains the argument of the To, From, or Contact Header
  Fields.

- **sipContentLengthList** CERT (PEN 6871) IE 384, variable length,
  basicList of **sipContentLength** CERT (PEN 6871) IE 160, variable length,
  string

  SIP Content Length header field. Contains the byte count of the message
  byte.

- **sipUserAgentList** CERT (PEN 6871) IE 385, variable length, basicList of
  **sipUserAgent** CERT (PEN 6871) IE 161, variable length, string

  SIP User Agent Header Field. Contains information about the User Agent
  Client originating the request.

## [NNTP](#nntp) {#nntp}

Network News Transfer Protocol (NNTP) Deep Packet Inspection is based on
[RFC 977][rfc977].

- **nntpResponseList** CERT (PEN 6871) IE 387, variable length, basicList of
  **nntpResponse** CERT (PEN 6871) IE 172, variable length, string

  NNTP Reply. This consists of a three digit status code and text
  message.

- **nntpCommandList** CERT (PEN 6871) IE 388, variable length, basicList of
  **nntpCommand** CERT (PEN 6871) IE 173, variable length, string

  NNTP Command. Contains an NNTP Command and following argument(s).

## [TFTP](#tftp) {#tftp}

Trivial File Transfer Protocol (TFTP) Deep Packet Inspection is based on
[RFC 1350][rfc1350].

- **tftpFilename** CERT (PEN 6871) IE 126, variable length, string

  TFTP Name of File being transferred.

- **tftpMode** CERT (PEN 6871) IE 127, variable length, string

  Contains the mode of transfer. (Currently supported: netascii, octet,
  mail).

## [MySQL](#mysql) {#mysql}

MySQL Deep Packet Inspection is based on information found in the [MYSQL
Developer
Documentation](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html).

- **mysqlUsername** CERT (PEN 6871) IE 223, variable length, string

  MySQL Login User Name.

- **mysqlCommandTextCodeList** CERT (PEN 6871) IE 424, variable length,
  subTemplateList

  A list of MySQL Command Code, Command Text Pairs. There will be one entry
  in the list for each MySQL Command found.

  - **mysqlCommandText** CERT (PEN 6871) IE 225, variable length, string

    MySQL Command Text. For example, this can be a SELECT, INSERT, DELETE
    statement.

  - **mysqlCommandCode** CERT (PEN 6871) IE 224, 1 octet, unsigned

    MySQL Command Code. This number should be between 0 and 28.

## [POP3](#pop3) {#pop3}

Post Office Protocol 3 (POP3) Deep Packet Inspection is based on [RFC
1939][rfc1939].

- **pop3TextMessageList** CERT (PEN 6871) IE 352, variable length, basicList
  of **pop3TextMessage** CERT (PEN 6871) IE 124, variable length, string

  POP3 Command and Replies. Contains any command or reply message found in
  POP3 payload data.

## [RTP](#rtp) {#rtp}

Real-time Transport Protocol (RTP) Deep Packet Inspection is based on [RFC
3550][rfc3550]. The Payload Type indicates the format of the payload and how
it should be interpreted by the receiving application.

- **rtpPayloadType** CERT (PEN 6871) IE 287, 1 octet, unsigned

  The payload type in the RTP header of the first payload in the forward
  direction.

- **reverseRtpPayloadType** CERT (PEN 6871) IE 16671, 1 octet, unsigned

  The payload type in the RTP header of the first payload in the reverse
  direction.

## [DNP3](#dnp3) {#dnp3}

Distributed Network Protocol 3 (DNP3) Deep Packet Inspection is slightly
different than other plugin-based protocols, operating as a
"regex-plugin" dpi\_type. YAF will export the following information if
the yafDPIRules.conf contain regular expressions under the label ID
20000. The regular expressions are compared against the payload of DNP3
packets starting with the function code in the DNP Application Layer header.
YAF will loop through all the the available DNP3 packets contained in the
captured payload. For each packet that matches one of the regular
expressions listed in yafDPIRules.conf, YAF will include an entry in the
exported subTemplateList. The DNP3 DPI is disabled by default. To enable it,
uncomment the DPI-related entries in the DNP3 rule in the yafDPIRules.conf
file.

- **subTemplateList** IE 292, variable length

  An IPFIX SubTemplateList. There will be one element in the list for
  each DNP3 packet that matches one of the DNP3 regular expressions
  found in the yafDPIRules.conf file.

- **dnp3SourceAddress** CERT (PEN 6871) IE 281, 2 octets, unsigned

  The DNP3 Source Address found in the Data Link Layer of the DNP
  Header.

- **dnp3DestinationAddress** CERT (PEN 6871) IE 282, 2 octets, unsigned

  The DNP3 Destination Address found in the Data Link Layer of the DNP
  Header.

- **dnp3Function** CERT (PEN 6871) IE 283, 1 octet, unsigned

  The DNP3 Function Code found in the first byte of the Application
  Layer.

- **dnp3ObjectData** CERT (PEN 6871) IE 284, variable length, octetArray

  The pattern captured from the DNP3 regular expression in
  yafDPIRules.conf

## [Modbus](#modbus) {#modbus}

Modbus DPI is similar to DNP3 DPI. YAF will export any patterns matched by
the regular expressions labeled with the ID 502 found in the
yafDPIRules.conf file. The regular expressions are compared against the
payload of all valid Modbus packets starting right after the MBAP header
(offset 7), beginning with the Modbus function code. The Modbus DPI is
disabled by default. To enable it, uncomment the DPI-related entries in the
Modbus rule in the yafDPIRules.conf file.

- **modbusDataList** CERT (PEN 6871) IE 420, variable length, basicList of
  **modbusData** CERT (PEN 6871) IE 285, variable length, octetArray

  Any patterns captured from the Modbus regular expressions in
  yafDPIRules.conf

## [Ethernet/IP](#ethernetip) {#ethernetip}

Ethernet/IP DPI is similar to DNP3 and Modbus DPI. YAF will export any
patterns matched by the regular expressions labeled with the ID 44818 in the
yafDPIRules.conf file. The regular expressions are compared against the
start of the payload of all valid Ethernet/IP packets (Command in the
Encapsulation Header is the first byte). The Ethernet/IP DPI is disabled by
default. To enable it, uncomment the DPI-related entries in the Ethernet/IP
rule in the yafDPIRules.conf file.

- **enipDataList** CERT (PEN 6871) IE 421, variable length, basicList of
  **enipData** CERT (PEN 6871) IE 286, variable length, octetArray

  The pattern captured from the Ethernet/IP regular expressions in
  yafDPIRules.conf


[Lua]:            https://www.lua.org/
[PCRE]:           https://www.pcre.org/
[rfc959]:         https://datatracker.ietf.org/doc/html/rfc959.html
[rfc977]:         https://datatracker.ietf.org/doc/html/rfc977.html
[rfc1035]:        https://datatracker.ietf.org/doc/html/rfc1035.html
[rfc1350]:        https://datatracker.ietf.org/doc/html/rfc1350.html
[rfc1939]:        https://datatracker.ietf.org/doc/html/rfc1939.html
[rfc2326]:        https://datatracker.ietf.org/doc/html/rfc2326.html
[rfc2608]:        https://datatracker.ietf.org/doc/html/rfc2608.html
[rfc2616]:        https://datatracker.ietf.org/doc/html/rfc2616.html
[rfc2782]:        https://datatracker.ietf.org/doc/html/rfc2782.html
[rfc2812]:        https://datatracker.ietf.org/doc/html/rfc2812.html
[rfc2821]:        https://datatracker.ietf.org/doc/html/rfc2821.html
[rfc3261]:        https://datatracker.ietf.org/doc/html/rfc3261.html
[rfc3501]:        https://datatracker.ietf.org/doc/html/rfc3501.html
[rfc3550]:        https://datatracker.ietf.org/doc/html/rfc3550.html
[rfc3596]:        https://datatracker.ietf.org/doc/html/rfc3596.html
[rfc4034]:        https://datatracker.ietf.org/doc/html/rfc4034.html
[rfc4253]:        https://datatracker.ietf.org/doc/html/rfc4253.html
[rfc5155]:        https://datatracker.ietf.org/doc/html/rfc5155.html
[rfc6313]:        https://datatracker.ietf.org/doc/html/rfc6313.html

[certipfix]:      /cert-ipfix-registry/index.html
[super_mediator]: /super_mediator/index.html

[applabeling]:    applabeling.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
