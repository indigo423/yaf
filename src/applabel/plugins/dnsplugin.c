/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file dnsplugin.c
 *
 *  provides a plugin to the ipfix payload classifier to attempt to determine
 *  if a packet payload is a DNS packet (see RFC 1035)
 *
 *  @note defining PAYLOAD_INSPECTION at compile time will attempt to better
 *  inspection of the packet payload at a cost of deeper inspection;  even with
 *  PAYLOAD_INSPECTION enabled, it is possible that this may not be 100%
 *  correct in ID'ing the packets
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 3.0.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS – Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2317
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */
#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>

#include <yaf/yafDPIPlugin.h>
#ifdef YAF_ENABLE_DPI

/**
 *  Pulls (reads) an integer from a data buffer at an offset and advances the
 *  offset pointer.  Sets the offset to the data length when there is not
 *  enough data (or offset already excceds the data length).  Does not modify
 *  the destination when there is not enough data available.
 *
 *  @param r_type the type of integer to read (uint8_t, uint16_t, etc)
 *  @param r_swap macro to swap network/host endian
 *  @param r_dst  where to put the value, a pointer
 *  @param r_off  the offset, a pointer
 *  @param r_data the data buffer to pull the value from
 *  @param r_len  the length of the data buffer
 */
#define READ_TYPE_INC(r_type, r_swap, r_dst, r_off, r_data, r_len) \
    if ((size_t)(*(r_off)) + sizeof(r_type) <= (r_len)) {          \
        *(r_dst) = r_swap(*((r_type *)((r_data) + *(r_off))));     \
        *(r_off) += sizeof(r_type);                                \
    } else {                                                       \
        *(r_off) = (r_len);                                        \
    }

/**
 *  Pull (read) a uint8_t from the data buffer `r_data` of length `r_len` at
 *  the offset `r_off` (a pointer), store the value at `r_dst` (a pointer),
 *  and advance the offset pointer.
 */
#define READ_U8_INC(r_dst, r_off, r_data, r_len) \
    READ_TYPE_INC(uint8_t, , r_dst, r_off, r_data, r_len)

/**
 *  Pull (read) a uint16_t from the data buffer `r_data` of length `r_len` at
 *  the offset `r_off` (a pointer), store the value at `r_dst` (a pointer),
 *  and advance the offset pointer.
 */
#define READ_U16_INC(r_dst, r_off, r_data, r_len) \
    READ_TYPE_INC(uint16_t, ntohs, r_dst, r_off, r_data, r_len)

/**
 *  Pull (read) a uint32_t from the data buffer `r_data` of length `r_len` at
 *  the offset `r_off` (a pointer), store the value at `r_dst` (a pointer),
 *  and advance the offset pointer.
 */
#define READ_U32_INC(r_dst, r_off, r_data, r_len) \
    READ_TYPE_INC(uint32_t, ntohl, r_dst, r_off, r_data, r_len)



/* DNS QR. Level 1 #1 */
#define YAF_DNS_RR_TID              0xCF00
#define YAF_DNS_RR_NAME             "yaf_dns_rr"
#define YAF_DNS_RR_DESC             NULL

/* DNS A. Level 2 #1 */
#define YAF_DNS_A_TID               0xCE01
#define YAF_DNS_A_NAME              "yaf_dns_a"
#define YAF_DNS_A_DESC              NULL

/* DNS AAAA. Level 2 #2 */
#define YAF_DNS_AAAA_TID            0xCE02
#define YAF_DNS_AAAA_NAME           "yaf_dns_aaaa"
#define YAF_DNS_AAAA_DESC           NULL

/* DNS CNAME. Level 2 #3 */
#define YAF_DNS_CNAME_TID           0xCE03
#define YAF_DNS_CNAME_NAME          "yaf_dns_cname"
#define YAF_DNS_CNAME_DESC          NULL

/* DNS MX. Level 2 #4 */
#define YAF_DNS_MX_TID              0xCE04
#define YAF_DNS_MX_NAME             "yaf_dns_mx"
#define YAF_DNS_MX_DESC             NULL

/* DNS NS. Level 2 #5 */
#define YAF_DNS_NS_TID              0xCE05
#define YAF_DNS_NS_NAME             "yaf_dns_ns"
#define YAF_DNS_NS_DESC             NULL

/* DNS PTR. Level 2 #6 */
#define YAF_DNS_PTR_TID             0xCE06
#define YAF_DNS_PTR_NAME            "yaf_dns_ptr"
#define YAF_DNS_PTR_DESC            NULL

/* DNS TXT. Level 2 #7 */
#define YAF_DNS_TXT_TID             0xCE07
#define YAF_DNS_TXT_NAME            "yaf_dns_txt"
#define YAF_DNS_TXT_DESC            NULL

/* DNS SRV. Level 2 #8 */
#define YAF_DNS_SRV_TID             0xCE08
#define YAF_DNS_SRV_NAME            "yaf_dns_srv"
#define YAF_DNS_SRV_DESC            NULL

/* DNS SOA. Level 2 #9 */
#define YAF_DNS_SOA_TID             0xCE09
#define YAF_DNS_SOA_NAME            "yaf_dns_soa"
#define YAF_DNS_SOA_DESC            NULL

/* DNS DS. Level 2 #10 */
#define YAF_DNS_DS_TID              0xCE0E
#define YAF_DNS_DS_NAME             "yaf_dns_ds"
#define YAF_DNS_DS_DESC             NULL

/* DNS RRSIG. Level 2 #11*/
#define YAF_DNS_RRSIG_TID           0xCE0F
#define YAF_DNS_RRSIG_NAME          "yaf_dns_rrsig"
#define YAF_DNS_RRSIG_DESC          NULL

/* DNS NSEC. Level 2 #12 */
#define YAF_DNS_NSEC_TID            0xCE11
#define YAF_DNS_NSEC_NAME           "yaf_dns_nsec"
#define YAF_DNS_NSEC_DESC           NULL

/* DNS KEY. Level 2 #13 */
#define YAF_DNS_DNSKEY_TID          0xCE12
#define YAF_DNS_DNSKEY_NAME         "yaf_dns_dnskey"
#define YAF_DNS_DNSKEY_DESC         NULL

/* DNS NSEC3. Level 2 #14 */
#define YAF_DNS_NSEC3_TID           0xCE13
#define YAF_DNS_NSEC3_NAME          "yaf_dns_nsec3"
#define YAF_DNS_NSEC3_DESC          NULL

/* DNS NSEC3PARM. Level 2 #15 */
#define YAF_DNS_NSEC3PARAM_TID      0xCE15
#define YAF_DNS_NSEC3PARAM_NAME     "yaf_dns_nsec3param"
#define YAF_DNS_NSEC3PARAM_DESC     NULL


/* SM has an Exact Match version. Changes won't break, but sync is good */
static fbInfoElementSpec_t yaf_dns_rr_spec[] = {
    /* based on type of RR */
    {"dnsDetailRecordList",     FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    /* used by SM to label DNS Resource Record */
    {"dnsName",                 FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsTTL",                  4, YAF_DISABLE_IE_FLAG },
    /* used by SM to label DNS Resource Record */
    {"dnsRRType",               2, YAF_DISABLE_IE_FLAG },
    /* Q(0) or R(1) - uint8*/
    {"dnsQueryResponse",        1, YAF_DISABLE_IE_FLAG },
    /* authoritative response (1)*/
    {"dnsAuthoritative",        1, YAF_DISABLE_IE_FLAG },
    /* nxdomain (1) */
    {"dnsResponseCode",         1, YAF_DISABLE_IE_FLAG },
    /* 0, 1, 2, 3 (q, ans, auth, add'l) */
    {"dnsSection",              1, YAF_DISABLE_IE_FLAG },
    {"dnsId",                   2, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",           4, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_rr_st {
    fbSubTemplateList_t   dnsRRList;
    fbVarfield_t          dnsName;
    uint32_t              dnsTTL;
    uint16_t              dnsRRType;
    uint8_t               dnsQueryResponse;
    uint8_t               dnsAuthoritative;
    uint8_t               dnsResponseCode;
    uint8_t               dnsSection;
    uint16_t              dnsId;
    uint8_t               padding[4];
} yaf_dns_rr_t;


static fbInfoElementSpec_t yaf_dns_a_spec[] = {
    {"dnsA",         4, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_a_st {
    uint32_t   dnsA;
} yaf_dns_a_t;

static fbInfoElementSpec_t yaf_dns_aaaa_spec[] = {
    {"dnsAAAA",         16, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_aaaa_st {
    uint8_t   dnsAAAA[16];
} yaf_dns_aaaa_t;

static fbInfoElementSpec_t yaf_dns_cname_spec[] = {
    {"dnsCNAME",                  FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_cname_st {
    fbVarfield_t   dnsCNAME;
} yaf_dns_cname_t;

static fbInfoElementSpec_t yaf_dns_mx_spec[] = {
    {"dnsMXExchange",             FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsMXPreference",           2, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",             6, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_mx_st {
    fbVarfield_t   dnsMXExchange;
    uint16_t       dnsMXPreference;
    uint8_t        padding[6];
} yaf_dns_mx_t;

static fbInfoElementSpec_t yaf_dns_ns_spec[] = {
    {"dnsNSDName",                FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_ns_st {
    fbVarfield_t   dnsNSDName;
} yaf_dns_ns_t;

static fbInfoElementSpec_t yaf_dns_ptr_spec[] = {
    {"dnsPTRDName",               FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_ptr_st {
    fbVarfield_t   dnsPTRDName;
} yaf_dns_ptr_t;

static fbInfoElementSpec_t yaf_dns_txt_spec[] = {
    {"dnsTXTData",                FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_txt_st {
    fbVarfield_t   dnsTXTData;
} yaf_dns_txt_t;

static fbInfoElementSpec_t yaf_dns_srv_spec[] = {
    {"dnsSRVTarget",              FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsSRVPriority",            2, YAF_DISABLE_IE_FLAG },
    {"dnsSRVWeight",              2, YAF_DISABLE_IE_FLAG },
    {"dnsSRVPort",                2, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",             2, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_srv_st {
    fbVarfield_t   dnsSRVTarget;
    uint16_t       dnsSRVPriority;
    uint16_t       dnsSRVWeight;
    uint16_t       dnsSRVPort;
    uint8_t        padding[2];
} yaf_dns_srv_t;

static fbInfoElementSpec_t yaf_dns_soa_spec[] = {
    {"dnsSOAMName",               FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsSOARName",               FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsSOASerial",              4, YAF_DISABLE_IE_FLAG },
    {"dnsSOARefresh",             4, YAF_DISABLE_IE_FLAG },
    {"dnsSOARetry",               4, YAF_DISABLE_IE_FLAG },
    {"dnsSOAExpire",              4, YAF_DISABLE_IE_FLAG },
    {"dnsSOAMinimum",             4, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",             4, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_soa_st {
    fbVarfield_t   dnsSOAMName;
    fbVarfield_t   dnsSOARName;
    uint32_t       dnsSOASerial;
    uint32_t       dnsSOARefresh;
    uint32_t       dnsSOARetry;
    uint32_t       dnsSOAExpire;
    uint32_t       dnsSOAMinimum;
    uint8_t        padding[4];
} yaf_dns_soa_t;

static fbInfoElementSpec_t yaf_dns_ds_spec[] = {
    {"dnsDSDigest",               FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsDSKeyTag",               2, YAF_DISABLE_IE_FLAG },
    {"dnsDSAlgorithm",            1, YAF_DISABLE_IE_FLAG },
    {"dnsDSDigestType",           1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",             4, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_ds_st {
    fbVarfield_t   dnsDSDigest;
    uint16_t       dnsDSKeyTag;
    uint8_t        dnsDSAlgorithm;
    uint8_t        dnsDSDigestType;
    uint8_t        padding[4];
} yaf_dns_ds_t;


static fbInfoElementSpec_t yaf_dns_rrsig_spec[] = {
    {"dnsRRSIGSigner",              FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsRRSIGSignature",           FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsRRSIGSignatureInception",  4, YAF_DISABLE_IE_FLAG },
    {"dnsRRSIGSignatureExpiration", 4, YAF_DISABLE_IE_FLAG },
    {"dnsRRSIGOriginalTTL",         4, YAF_DISABLE_IE_FLAG },
    {"dnsRRSIGKeyTag",              2, YAF_DISABLE_IE_FLAG },
    {"dnsRRSIGTypeCovered",         2, YAF_DISABLE_IE_FLAG },
    {"dnsRRSIGAlgorithm",           1, YAF_DISABLE_IE_FLAG },
    {"dnsRRSIGLabels",              1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",               6, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_rrsig_st {
    fbVarfield_t   dnsRRSIGSigner;
    fbVarfield_t   dnsRRSIGSignature;
    uint32_t       dnsRRSIGSignatureInception;
    uint32_t       dnsRRSIGSignatureExpiration;
    uint32_t       dnsRRSIGOriginalTTL;
    uint16_t       dnsRRSIGKeyTag;
    uint16_t       dnsRRSIGTypeCovered;
    uint8_t        dnsRRSIGAlgorithm;
    uint8_t        dnsRRSIGLabels;
    uint8_t        padding[6];
} yaf_dns_rrsig_t;

static fbInfoElementSpec_t yaf_dns_nsec_spec[] = {
    {"dnsNSECNextDomainName",     FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsNSECTypeBitMaps",        FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_nsec_st {
    fbVarfield_t   dnsNSECNextDomainName;
    fbVarfield_t   dnsNSECTypeBitMaps;
} yaf_dns_nsec_t;

static fbInfoElementSpec_t yaf_dns_dnskey_spec[] = {
    {"dnsDNSKEYPublicKey",        FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsDNSKEYFlags",            2, YAF_DISABLE_IE_FLAG },
    {"dnsDNSKEYProtocol",         1, YAF_DISABLE_IE_FLAG },
    {"dnsDNSKEYAlgorithm",        1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",             4, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_dnskey_st {
    fbVarfield_t   dnsDNSKEYPublicKey;
    uint16_t       dnsDNSKEYFlags;
    uint8_t        dnsDNSKEYProtocol;
    uint8_t        dnsDNSKEYAlgorithm;
    uint8_t        padding[4];
} yaf_dns_dnskey_t;

static fbInfoElementSpec_t yaf_dns_nsec3_spec[] = {
    {"dnsNSEC3Salt",                FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsNSEC3NextHashedOwnerName", FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsNSEC3TypeBitMaps",         FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsNSEC3Iterations",          2, YAF_DISABLE_IE_FLAG },
    {"dnsNSEC3Algorithm",           1, YAF_DISABLE_IE_FLAG },
    {"dnsNSEC3Flags",               1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",               4, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_nsec3_st {
    fbVarfield_t   dnsNSEC3Salt;
    fbVarfield_t   dnsNSEC3NextHashedOwnerName;
    fbVarfield_t   dnsNSEC3TypeBitMaps;
    uint16_t       dnsNSEC3Iterations;
    uint8_t        dnsNSEC3Algorithm;
    uint8_t        dnsNSEC3Flags;
    uint8_t        padding[4];
} yaf_dns_nsec3_t;


static fbInfoElementSpec_t yaf_dns_nsec3param_spec[] = {
    {"dnsNSEC3PARAMSalt",         FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnsNSEC3PARAMIterations",   2, YAF_DISABLE_IE_FLAG },
    {"dnsNSEC3PARAMAlgorithm",    1, YAF_DISABLE_IE_FLAG },
    {"dnsNSEC3PARAMFlags",        1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",             4, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dns_nsec3param_st {
    fbVarfield_t   dnsNSEC3PARAMSalt;
    uint16_t       dnsNSEC3PARAMIterations;
    uint8_t        dnsNSEC3PARAMAlgorithm;
    uint8_t        dnsNSEC3PARAMFlags;
    uint8_t        padding[4];
} yaf_dns_nsec3param_t;

static fbTemplate_t *yaf_dns_rr_tmpl;
static fbTemplate_t *yaf_dns_a_tmpl;
static fbTemplate_t *yaf_dns_aaaa_tmpl;
static fbTemplate_t *yaf_dns_cname_tmpl;
static fbTemplate_t *yaf_dns_mx_tmpl;
static fbTemplate_t *yaf_dns_ns_tmpl;
static fbTemplate_t *yaf_dns_ptr_tmpl;
static fbTemplate_t *yaf_dns_txt_tmpl;
static fbTemplate_t *yaf_dns_srv_tmpl;
static fbTemplate_t *yaf_dns_soa_tmpl;
static fbTemplate_t *yaf_dns_ds_tmpl;
static fbTemplate_t *yaf_dns_nsec_tmpl;
static fbTemplate_t *yaf_dns_nsec3_tmpl;
static fbTemplate_t *yaf_dns_nsec3param_tmpl;
static fbTemplate_t *yaf_dns_rrsig_tmpl;
static fbTemplate_t *yaf_dns_dnskey_tmpl;

static gboolean      dnssec_global = FALSE;
#endif  /* YAF_ENABLE_DPI */

typedef struct ycDnsScanMessageHeader_st {
    uint16_t   id;

    uint16_t   qr     : 1;
    uint16_t   opcode : 4;
    uint16_t   aa     : 1;
    uint16_t   tc     : 1;
    uint16_t   rd     : 1;
    uint16_t   ra     : 1;
    uint16_t   z      : 1;
    uint16_t   ad     : 1;
    uint16_t   cd     : 1;
    uint16_t   rcode  : 4;

    uint16_t   qdcount;
    uint16_t   ancount;
    uint16_t   nscount;
    uint16_t   arcount;
} ycDnsScanMessageHeader_t;

#define DNS_LABEL_TYPE_MASK 0xC0
#define DNS_LABEL_TYPE_STANDARD 0x00
#define DNS_LABEL_TYPE_COMPRESSED 0xC0
#define DNS_LABEL_TYPE_EXTENDED 0x40
#define DNS_LABEL_OFFSET_MASK 0x3FFF

#define DNS_PORT_NUMBER 53

/* DNS record types */
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_SRV 33
#define DNS_TYPE_DS 43
#define DNS_TYPE_RRSIG 46
#define DNS_TYPE_NSEC 47
#define DNS_TYPE_DNSKEY 48
#define DNS_TYPE_NSEC3 50
#define DNS_TYPE_NSEC3PARAM 51

/* The EDNS option pseudo-type--used to ignore these */
#define DNS_TYPE_OPT 41

/* DNS class NONE--used to check for valid class */
#define DNS_CLASS_NONE 254

/* DNS Max Name length */
#define DNS_MAX_NAME_LENGTH     255

/** this field defines the number of octects we fuzz the size of the
 *  DNS to the IP+TCP+payload size with; we don't record any TCP
 *  options, so it is possible to have a few extra bytes in the
 *  calculation, and we won't say that's bad until that is larger
 *  than the following constant */
#define DNS_TCP_FLAG_SLACK 8

/** Since NETBIOS looks A LOT like DNS, there's no need to create
 *  a separate plugin for it - if we think it's NETBIOS we will
 *  return NETBIOS_PORT */
#define NETBIOS_PORT 137

#define PAYLOAD_INSPECTION 1

/**
 * local prototypes
 *
 */

#ifdef PAYLOAD_INSPECTION
static uint16_t
ycDnsScanCheckResourceRecord(
    const uint8_t  *payload,
    uint32_t       *offset,
    unsigned int    payloadSize);

#endif /* ifdef PAYLOAD_INSPECTION */

#ifdef YAF_ENABLE_DPI
static void
ypDnsParser(
    yaf_dns_rr_t **dnsRecord,
    yfFlow_t      *flow,
    yfFlowVal_t   *val,
    uint8_t       *buf,
    uint32_t      *bufLen,
    uint8_t        recordCount,
    uint16_t       export_limit);

static uint16_t
ypDnsScanResourceRecord(
    yaf_dns_rr_t  **dnsRecord,
    const uint8_t  *payload,
    unsigned int    payloadSize,
    uint32_t       *offset,
    uint8_t        *buf,
    uint32_t       *bufLen,
    uint16_t        export_limit);

static unsigned int
ypDnsEscapeValue(
    uint8_t       *dst,
    unsigned int   dst_size,
    const uint8_t *src,
    unsigned int   src_size,
    gboolean       escape_dots);

static unsigned int
ypDnsGetName(
    uint8_t        *export_buffer,
    uint32_t        export_offset,
    const uint8_t  *payload,
    unsigned int    payload_size,
    uint32_t       *payload_offset,
    uint16_t        export_limit);

/* For DNS binary octet escaping */
static const uint8_t hex_digits[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};
#endif  /* YAF_ENABLE_DPI */

static void
ycDnsScanRebuildHeader(
    const uint8_t             *payload,
    ycDnsScanMessageHeader_t  *header);


/**
 * ydpScanPayload
 *
 * scans a payload to determine if the payload is a dns request/reply.
 * It checks the structure for self referential integrity, but it can't
 * guarantee that the payload is actually DNS, it could be
 * some degenerate random data
 *
 * name abomination has been achieved by combining multiple naming standards
 * until the prefix to
 * the function name is dnsplugin_LTX_ycDnsScan --- it's a feature
 *
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match DNS_PORT_NUMBER (53) for a match
 *
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    unsigned int loop = 0;
    uint16_t     msglen;
    uint32_t     firstpkt = payloadSize;
    ycDnsScanMessageHeader_t header;
    gboolean     netbios = FALSE;
    uint32_t     offset;
    uint16_t     qtype = 0;
#ifdef YAF_ENABLE_DPI
    unsigned int recordCount = 0;
    uint16_t     direction;
#endif

    if (payloadSize < sizeof(ycDnsScanMessageHeader_t)) {
        /*fprintf(stderr, " <dns exit 1> ");
         * g_debug("returning at line 118");*/
        return 0;
    }

    if (flow->key.proto == YF_PROTO_TCP) {
        while (loop < val->pkt && loop < YAF_MAX_PKT_BOUNDARY) {
            if (val->paybounds[loop] == 0) {
                loop++;
            } else {
                firstpkt = val->paybounds[loop];
                break;
            }
        }
        msglen = ntohs(*((uint16_t *)(payload)));
        if ((uint32_t)(msglen + 2) == firstpkt) {
            /* this is the weird message length in TCP */
            payload += sizeof(uint16_t);
            payloadSize -= sizeof(uint16_t);
        }
    }

    ycDnsScanRebuildHeader(payload, &header);

    /* Treat OpCodes 0-2,4-5 as DNS; treat OpCodes 6-8 as NetBIOS; reject
     * OpCodes 3,>=9 */
    if (header.opcode >= 6) {
        if (header.opcode >= 9) {
            return 0;
        }
        netbios = TRUE;
    } else if (header.opcode == 3) {
        return 0;
    }
    /* else DNS */

    /* rfc 2136 updates rfc 1035 */
    /* 16-22 are DNSSEC rcodes*/
    if ((header.rcode > 10) && (1 == header.qr)) {
        if ((header.rcode < 16) || (header.rcode > 22)) {
            /*g_debug("returning at line 197 %d", header.rcode);*/
            return 0;
        }
    }

    /* rfc states that Z is reserved for future use and must be zero */
    if (0 != header.z) {
        /*g_debug("returning at line 141");*/
        return 0;
    }

    /* check to make sure resource records are not empty -
     * gets rid of all 0's payloads */
    if (header.qdcount == 0 && header.ancount == 0 && header.nscount == 0
        && header.arcount == 0)
    {
        if (!(header.rcode > 0 && header.qr == 1)) {
            /* DNS responses that are not errors will have something in them*/
            return 0;
        }
    }

    /* query validation */
    if (header.qr == 0) {
        if ((header.rcode > 0 || header.aa != 0 || header.ra != 0 ||
             header.ad != 0))
        {
            /* queries should not have an rcode, an authoritative answer,
             * recursion available, or authenticated data */
            return 0;
        }
        if (!(header.qdcount > 0)) {
            /* queries should have at least one question */
            return 0;
        }
    }

#ifdef PAYLOAD_INSPECTION
    /* parse through the rest of the DNS message, only the header is fixed
     * in size */
    offset = sizeof(ycDnsScanMessageHeader_t);
    /* the the query entries */

    if (offset >= payloadSize) {
        return 0;
    }
    /*fprintf(stderr,"dns qdcount %d, ancount %d, nscount %d, arcount
     * %d\n",header.qdcount,header.ancount,header.nscount, header.arcount);*/

    for (loop = 0; loop < header.qdcount; loop++) {
        uint8_t  sizeOct = *(payload + offset);
        uint16_t qclass;
        uint8_t  comp = 0;            /* turn on if something is compressed */

        while (0 != sizeOct && offset < payloadSize) {
            if (DNS_LABEL_TYPE_COMPRESSED == (sizeOct & DNS_LABEL_TYPE_MASK)) {
                offset += sizeof(uint16_t);
                /* compression happened so we don't need add 1 later */
                comp = 1;
            } else {
                offset += sizeOct + 1;
            }
            if (offset >= payloadSize) {
                return 0;
            }
            sizeOct = *(payload + offset);
        }

        if (offset >= payloadSize) {
            /* this is either a DNS fragment, or a malformed DNS */
            /*fprintf(stderr, " <dns exit 5> ");*/
            return 0;
        }

        /* get past the terminating 0 length in the name if NO COMPRESSION*/
        if (!comp) {
            offset++;
        }

        if ((offset + 2) > payloadSize) {
            return 0;
        }

        /* check the query type */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
        qtype = ((*(payload + offset)) << 8) |
            ((*(payload + offset + 1)) );

        qtype = ntohs(qtype);
#else /* ifdef HAVE_ALIGNED_ACCESS_REQUIRED */
        qtype = ntohs(*((uint16_t *)(payload + offset)));
#endif /* ifdef HAVE_ALIGNED_ACCESS_REQUIRED */
        if (qtype == 0) {
            return 0;
        } else if (qtype > 52) {
            if ((qtype < 249) || (qtype > 253)) {
                if ((qtype != 32769) && (qtype != 32768) && (qtype != 99)) {
                    return 0;
                }
            }
        }

        if (qtype == 32) {
            netbios = TRUE;
        } else if (qtype == 33 && (flow->key.sp == NETBIOS_PORT ||
                                   flow->key.dp == NETBIOS_PORT))
        {
            netbios = TRUE;
        }

        offset += sizeof(uint16_t);

        if ((offset + 2) > payloadSize) {
            return 0;
        }

        /* check the class code */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
        qclass = ((*(payload + offset)) << 8) |
            ((*(payload + offset + 1)) );
        qclass = ntohs(qclass);
#else
        qclass = ntohs(*((uint16_t *)(payload + offset)));
#endif /* ifdef HAVE_ALIGNED_ACCESS_REQUIRED */

        if (qclass > 4 && qclass != 255) {
            /*fprintf(stderr, " <dns exit 7, qclass = %d> ", qclass);*/
            return 0;
        }

        if (netbios) {
            if (qclass != 1) {
                return 0;
            }
        }

        offset += sizeof(uint16_t);

        if (offset > payloadSize) {
            return 0;
        }
    }

    /* check each record for the answer record count */
    for (loop = 0; loop < header.ancount; loop++) {
        uint16_t rc;

        rc = ycDnsScanCheckResourceRecord(payload, &offset,
                                          payloadSize);
        if (0 == rc) {
            return rc;
        }

        if (netbios && (rc != 1 && rc != 2 && rc != 10 && rc != 32 &&
                        rc != 33))
        {
            return 0;
        } else if (rc == 32) {
            netbios = TRUE;
        } else if (rc == 33 && header.qdcount == 0) {
            netbios = TRUE;
        }

#ifdef YAF_ENABLE_DPI
        if (rc != DNS_TYPE_OPT) {
            recordCount++;
        }
#endif
    }

    /* check each record for the name server resource record count */
    for (loop = 0; loop < header.nscount; loop++) {
        uint16_t rc;
        rc = ycDnsScanCheckResourceRecord(payload, &offset,
                                          payloadSize);
        if (0 == rc) {
            return 0;
        }

        if (netbios && (rc != 1 && rc != 2 && rc != 10 && rc != 32 &&
                        rc != 33))
        {
            return 0;
        } else if (rc == 2 && header.qdcount == 0) {
            netbios = TRUE;
        }

#ifdef YAF_ENABLE_DPI
        if (rc != DNS_TYPE_OPT) {
            recordCount++;
        }
#endif
    }
    /* check each record for the additional record count */
    for (loop = 0; loop < header.arcount; loop++) {
        uint16_t rc;
        rc = ycDnsScanCheckResourceRecord(payload, &offset,
                                          payloadSize);
        if (0 == rc) {
            return 0;
        }

        if (netbios && (rc != 1 && rc != 2 && rc != 10 && rc != 32 &&
                        rc != 33))
        {
            return 0;
        }

#ifdef YAF_ENABLE_DPI
        if (rc != DNS_TYPE_OPT) {
            recordCount++;
        }
#endif
    }

    if (netbios) {
        return NETBIOS_PORT;
    }

#ifdef YAF_ENABLE_DPI
    if (val == &flow->val) {
        direction = 0;
    } else {
        direction = 1;
    }

#if defined(YAF_ENABLE_DNSAUTH) && defined(YAF_ENABLE_DNSNXDOMAIN)
    if ((header.aa == 1) || (header.rcode == 3)) {
        if (recordCount + header.qdcount) {
            ydRunPluginRegex(flow, payload, 0, NULL,
                             (recordCount + header.qdcount), direction,
                             DNS_PORT_NUMBER);
        }
    }
#elif defined(YAF_ENABLE_DNSAUTH) && !defined(YAF_ENABLE_DNSNXDOMAIN)
    if (header.aa == 1) {
        if (recordCount + header.qdcount) {
            ydRunPluginRegex(flow, payload, 0, NULL,
                             (recordCount + header.qdcount),
                             direction, DNS_PORT_NUMBER);
        }
    }
#elif defined(YAF_ENABLE_DNSNXDOMAIN) && !defined(YAF_ENABLE_DNSAUTH)
    if (header.rcode == 3) {
        if (recordCount + header.qdcount) {
            ydRunPluginRegex(flow, payload, 0, NULL,
                             (recordCount + header.qdcount), direction,
                             DNS_PORT_NUMBER);
        }
    }
#else /* if defined(YAF_ENABLE_DNSAUTH) && defined(YAF_ENABLE_DNSNXDOMAIN) */
    if (header.qr && !(header.rcode)) {
        if (recordCount) {
            ydRunPluginRegex(flow, payload, 0, NULL, recordCount, direction,
                             DNS_PORT_NUMBER);
        }
    } else {
        if (recordCount + header.qdcount) {
            ydRunPluginRegex(flow, payload, 0, NULL,
                             (recordCount + header.qdcount),
                             direction, DNS_PORT_NUMBER);
        }
    }
#endif /* if defined(YAF_ENABLE_DNSAUTH) && defined(YAF_ENABLE_DNSNXDOMAIN) */
#endif /* ifdef YAF_ENABLE_DPI */

#endif /* ifdef PAYLOAD_INSPECTION */

    /* this is the DNS port code */
    /* fprintf(stderr, " <dns exit 11 match> ");*/
    return DNS_PORT_NUMBER;
}


#ifdef YAF_ENABLE_DPI
void *
ydpProcessDPI(
    ypDPIFlowCtx_t       *flowContext,
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    uint8_t               fwdcap,
    uint8_t               totalcap)
{
    yfDPIData_t  *dpi         = flowContext->dpi;
    yaf_dns_rr_t *dnsRecord   = NULL;
    uint8_t       recCountFwd = 0;
    uint8_t       recCountRev = 0;
    uint32_t      buflen      = 0;
    int           loop;

    flowContext->exbuf = g_slice_alloc0(flowContext->yfctx->dpi_total_limit);

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for (loop = flowContext->startOffset; loop < totalcap; ++loop) {
        if (dpi[loop].dpacketID == 0) {
            recCountFwd += dpi[loop].dpacketCapt;
        } else if (dpi[loop].dpacketID == 1) {
            recCountRev += dpi[loop].dpacketCapt;
        }
    }

    dnsRecord = (yaf_dns_rr_t *)fbSubTemplateListInit(
        stl, 3, YAF_DNS_RR_TID, yaf_dns_rr_tmpl, recCountFwd + recCountRev);
    if (!dnsRecord) {
        g_debug("Error initializing SubTemplateList for DNS Resource "
                "Record with %d Templates", recCountFwd + recCountRev);
        return NULL;
    }

    if (flow->val.payload && recCountFwd) {
        ypDnsParser(&dnsRecord, flow, &flow->val,
                    flowContext->exbuf, &buflen, recCountFwd,
                    flowContext->yfctx->dpi_total_limit);
    }

    if (recCountRev) {
        if (recCountFwd) {
            if (!(dnsRecord = fbSubTemplateListGetNextPtr(stl, dnsRecord))) {
                return (void *)stl;
            }
        }
        if (!flow->rval.payload) {
            /* Uniflow */
            ypDnsParser(&dnsRecord, flow, &flow->val,
                        flowContext->exbuf, &buflen, recCountRev,
                        flowContext->yfctx->dpi_total_limit);
        } else {
            ypDnsParser(&dnsRecord, flow, &flow->rval,
                        flowContext->exbuf, &buflen, recCountRev,
                        flowContext->yfctx->dpi_total_limit);
        }
    }

    return (void *)stl;
}

gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t *mdInfo;

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_RR_NAME, YAF_DNS_RR_DESC,
                       DNS_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    if (!ydInitTemplate(&yaf_dns_rr_tmpl, session, yaf_dns_rr_spec,
                        mdInfo, YAF_DNS_RR_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_A_NAME, YAF_DNS_A_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_a_tmpl, session, yaf_dns_a_spec,
                        mdInfo, YAF_DNS_A_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_AAAA_NAME, YAF_DNS_AAAA_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_aaaa_tmpl, session, yaf_dns_aaaa_spec,
                        mdInfo, YAF_DNS_AAAA_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_CNAME_NAME, YAF_DNS_CNAME_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_cname_tmpl, session, yaf_dns_cname_spec,
                        mdInfo, YAF_DNS_CNAME_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_MX_NAME, YAF_DNS_MX_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_mx_tmpl, session, yaf_dns_mx_spec,
                        mdInfo, YAF_DNS_MX_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_NS_NAME, YAF_DNS_NS_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_ns_tmpl, session, yaf_dns_ns_spec,
                        mdInfo, YAF_DNS_NS_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_PTR_NAME, YAF_DNS_PTR_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_ptr_tmpl, session, yaf_dns_ptr_spec,
                        mdInfo, YAF_DNS_PTR_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_TXT_NAME, YAF_DNS_TXT_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_txt_tmpl, session, yaf_dns_txt_spec,
                        mdInfo, YAF_DNS_TXT_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_SOA_NAME, YAF_DNS_SOA_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_soa_tmpl, session, yaf_dns_soa_spec,
                        mdInfo, YAF_DNS_SOA_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNS_SRV_NAME, YAF_DNS_SRV_DESC,
                       DNS_PORT_NUMBER, YAF_DNS_RR_TID);

    if (!ydInitTemplate(&yaf_dns_srv_tmpl, session, yaf_dns_srv_spec,
                        mdInfo, YAF_DNS_SRV_TID, 0, err))
    {
        return FALSE;
    }

    if (dnssec_global) {
        mdInfo = fbTemplateInfoAlloc();
        fbTemplateInfoInit(mdInfo, YAF_DNS_DS_NAME, YAF_DNS_DS_DESC,
                           DNS_PORT_NUMBER, YAF_DNS_RR_TID);

        if (!ydInitTemplate(&yaf_dns_ds_tmpl, session, yaf_dns_ds_spec,
                            mdInfo, YAF_DNS_DS_TID, 0, err))
        {
            return FALSE;
        }

        mdInfo = fbTemplateInfoAlloc();
        fbTemplateInfoInit(mdInfo, YAF_DNS_RRSIG_NAME, YAF_DNS_RRSIG_DESC,
                           DNS_PORT_NUMBER, YAF_DNS_RR_TID);

        if (!ydInitTemplate(&yaf_dns_rrsig_tmpl, session, yaf_dns_rrsig_spec,
                            mdInfo, YAF_DNS_RRSIG_TID, 0, err))
        {
            return FALSE;
        }

        mdInfo = fbTemplateInfoAlloc();
        fbTemplateInfoInit(mdInfo, YAF_DNS_NSEC_NAME, YAF_DNS_NSEC_DESC,
                           DNS_PORT_NUMBER, YAF_DNS_RR_TID);

        if (!ydInitTemplate(&yaf_dns_nsec_tmpl, session, yaf_dns_nsec_spec,
                            mdInfo, YAF_DNS_NSEC_TID, 0, err))
        {
            return FALSE;
        }

        mdInfo = fbTemplateInfoAlloc();
        fbTemplateInfoInit(mdInfo, YAF_DNS_NSEC3_NAME, YAF_DNS_NSEC3_DESC,
                           DNS_PORT_NUMBER, YAF_DNS_RR_TID);

        if (!ydInitTemplate(&yaf_dns_nsec3_tmpl, session, yaf_dns_nsec3_spec,
                            mdInfo, YAF_DNS_NSEC3_TID, 0, err))
        {
            return FALSE;
        }

        mdInfo = fbTemplateInfoAlloc();
        fbTemplateInfoInit(
            mdInfo, YAF_DNS_NSEC3PARAM_NAME, YAF_DNS_NSEC3PARAM_DESC,
            DNS_PORT_NUMBER, YAF_DNS_RR_TID);

        if (!ydInitTemplate(
                &yaf_dns_nsec3param_tmpl, session, yaf_dns_nsec3param_spec,
                mdInfo, YAF_DNS_NSEC3PARAM_TID, 0, err))
        {
            return FALSE;
        }

        mdInfo = fbTemplateInfoAlloc();
        fbTemplateInfoInit(mdInfo, YAF_DNS_DNSKEY_NAME, YAF_DNS_DNSKEY_DESC,
                           DNS_PORT_NUMBER, YAF_DNS_RR_TID);

        if (!ydInitTemplate(&yaf_dns_dnskey_tmpl, session, yaf_dns_dnskey_spec,
                            mdInfo, YAF_DNS_DNSKEY_TID, 0, err))
        {
            return FALSE;
        }
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_dns_rr_t        *dns = NULL;
    fbSubTemplateList_t *stl = (fbSubTemplateList_t *)flowContext->rec;

    if (!stl) {
        return;
    }

    while ((dns = fbSubTemplateListGetNextPtr(stl, dns))) {
        fbSubTemplateListClear(&dns->dnsRRList);
    }
}
#endif  /* YAF_ENABLE_DPI */


#ifdef PAYLOAD_INSPECTION
/**
 * ycDnsScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octect stream directly into the DNS structure
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated dns message
 *        header structure
 *
 *
 */
static void
ycDnsScanRebuildHeader(
    const uint8_t             *payload,
    ycDnsScanMessageHeader_t  *header)
{
    uint16_t    *tempArray = (uint16_t *)header;
    uint16_t     bitmasks = ntohs(*((uint16_t *)(payload + 2)));
    unsigned int loop;

    memcpy(tempArray, payload, sizeof(ycDnsScanMessageHeader_t));
    for (loop = 0; loop < sizeof(ycDnsScanMessageHeader_t) / sizeof(uint16_t);
         loop++)
    {
        *(tempArray + loop) = ntohs(*(tempArray + loop));
    }

    header->qr = bitmasks & 0x8000 ? 1 : 0;
    header->opcode = (bitmasks & 0x7800) >> 11;
    header->aa = bitmasks & 0x0400 ? 1 : 0;
    header->tc = bitmasks & 0x0200 ? 1 : 0;
    header->rd = bitmasks & 0x0100 ? 1 : 0;
    header->ra = bitmasks & 0x0080 ? 1 : 0;
    header->z = bitmasks & 0x0040 ? 1 : 0;
    /* don't think we care about these
     * header->ad = bitmasks & 0x0020 ? 1 : 0;
     * header->cd = bitmasks & 0x0010 ? 1 : 0; */
    header->rcode = bitmasks & 0x000f;
/*
 *  g_debug("header->qr %d", header->qr);
 *  g_debug("header->opcode %d", header->opcode);
 *  g_debug("header->aa %d", header->aa);
 *  g_debug("header->tc %d", header->tc);
 *  g_debug("header->rd %d", header->rd);
 *  g_debug("header->ra %d", header->ra);
 *  g_debug("header->z %d", header->z);
 *  g_debug("header->rcode %d", header->rcode);
 */
}

static
uint16_t
ycDnsScanCheckResourceRecord(
    const uint8_t  *payload,
    uint32_t       *offset,
    unsigned int    payloadSize)
{
    uint16_t nameSize;
    uint16_t rrType;
    uint16_t rrClass;
    uint16_t rdLength;
    gboolean compress_flag = FALSE;

    if (*offset >= payloadSize) {
        return 0;
    }

    nameSize  = *(payload + (*offset));

    while ((0 != nameSize) && (*offset < payloadSize)) {
        if (DNS_LABEL_TYPE_COMPRESSED == (nameSize & DNS_LABEL_TYPE_MASK)) {
            *offset += sizeof(uint16_t);
            if (!compress_flag) {
                compress_flag = TRUE;
            }
        } else {
            *offset += nameSize + 1;
        }
        if (*offset >= payloadSize) {
            return 0;
        }
        nameSize = *(payload + (*offset));
    }

    if (!compress_flag) {
        *offset += 1;
    }

    if ((*offset + 2) > payloadSize) {
        return 0;
    }

    /* check the type */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
    rrType = ((*(payload + (*offset))) << 8) |
        ((*(payload + (*offset) + 1)) );
    rrType = ntohs(rrType);
#else
    rrType = ntohs(*(uint16_t *)(payload + (*offset)));
#endif /* ifdef HAVE_ALIGNED_ACCESS_REQUIRED */
    *offset += sizeof(uint16_t);

    if (rrType == 0) {
        return 0;
    } else if (rrType > 52) {
        if ((rrType < 249) || (rrType > 253)) {
            if ((rrType != 32769) && (rrType != 32768) && (rrType != 99)) {
                return 0;
            }
        }
    }

    if ((*offset + 2) > payloadSize) {
        return 0;
    }

    /* check the class */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
    rrClass = ((*(payload + (*offset))) << 8) |
        ((*(payload + (*offset) + 1)) );
    rrClass = ntohs(rrClass);
#else
    rrClass = ntohs(*(uint16_t *)(payload + (*offset)));
#endif /* ifdef HAVE_ALIGNED_ACCESS_REQUIRED */
    *offset += sizeof(uint16_t);
    /* OPT Records use class field as UDP payload size */
    /* Otherwise, only 0-4 and 254 (NONE) are valid for RRs */
    if (rrClass > 4 && rrType != DNS_TYPE_OPT) {
        /* rfc 2136 */
        if (rrClass != DNS_CLASS_NONE) {
            return 0;
        }
    }
    /* skip past the time to live */
    *offset += sizeof(uint32_t);

    if ((*offset + 2) > payloadSize) {
        return 0;
    }

    /* get the record data length, (so we can skip ahead the right amount) */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
    rdLength = ((*(payload + (*offset))) << 8) |
        ((*(payload + (*offset) + 1)) );
    rdLength = ntohs(rdLength);
#else
    rdLength = ntohs(*(uint16_t *)(payload + (*offset)));
#endif /* ifdef HAVE_ALIGNED_ACCESS_REQUIRED */
    *offset += sizeof(uint16_t);

    /* not going to try to parse the data record, what's in there depends on
     * the class and type fields, but the rdlength field always tells us how
     * many bytes are in it */
    *offset += rdLength;

    if (*offset > payloadSize) {
        return 0;
    }/* the record seems intact enough */
    return rrType;
}


#ifdef YAF_ENABLE_DPI
/*
 * Decodes a DNS name, including uncompressing compressed  names by
 * following poitners and escaping non-ASCII characters. Returns the
 * length of the escaped name added to the export buffer. Updates
 * payload_offset to increase it by the amount consumed (or to
 * payload_size in case of an error.
 */
static unsigned int
ypDnsGetName(
    uint8_t        *export_buffer,
    uint32_t        export_offset,
    const uint8_t  *payload,
    unsigned int    payload_size,
    uint32_t       *payload_offset,
    uint16_t        export_limit)
{
    /*
     * Pointer to the offset currently being updated. Starts as the
     * offset that was passed in, then switches to &nested_offset when
     * name compression is encountered.
     */
    uint32_t *working_offset = payload_offset;
    /* Local offset once we've followed a poitner to previous labels. */
    uint32_t nested_offset = *payload_offset;

    /*
     * The payload size limit currently in effect. Starts as the
     * passed-in payload size, then switches to just before the current
     * label when name compression is encountered. Prevents loops.
     */
    unsigned int working_size = payload_size;

    /* How much has been written directly to the export_buffer. */
    unsigned int escaped_size = 0;
    /* How big is the unescaped name, to check DNS protocol limits. */
    unsigned int unescaped_size = 0;

    /* Size of the current label, and calculation space for pointer offset. */
    unsigned int label_size;
    /* Size of last escaped label written into the export buffer. */
    unsigned int escaped_label_size;

    while (*working_offset < working_size) {
        label_size = payload[*working_offset];
        *working_offset += 1;
        switch (label_size & DNS_LABEL_TYPE_MASK) {

          case DNS_LABEL_TYPE_STANDARD:
            if (0 == label_size) {
                /* Empty label, end of name or root domain. */
                if (0 == unescaped_size) {
                    /*
                     * If the output is zero-length, use a single "." to
                     * represent the root domain.
                     */
                    if (export_offset + 1 > export_limit) {
                        /* No room for "." root domain */
                        goto err;
                    }
                    export_buffer[export_offset] = '.';
                    escaped_size = 1;
                    unescaped_size = 1;
                }
                return escaped_size;
            } else {
                if (label_size + unescaped_size + 1 > DNS_MAX_NAME_LENGTH) {
                    /* Unescaped DNS name is longer than spec allows. */
                    goto err;
                }
                if (*working_offset + label_size >= working_size) {
                    /* Label text passes end of allowed payload. */
                    goto err;
                }
                escaped_label_size = ypDnsEscapeValue(
                    &export_buffer[export_offset + escaped_size],
                    export_limit - export_offset - escaped_size,
                    &payload[*working_offset], label_size,
                    TRUE);
                if ((export_offset + escaped_size + escaped_label_size + 1)
                      > export_limit)
                {
                    /* Added escaped label and dot don't fit. */
                    goto err;
                }
                escaped_size += escaped_label_size;
                export_buffer[export_offset + escaped_size] = '.';
                escaped_size += 1;
                *working_offset += label_size;
                unescaped_size += label_size + 1;
            }
            continue;

          case DNS_LABEL_TYPE_COMPRESSED:
            if (*working_offset >= working_size) {
                /* Encoded offset passes end of allowed payload. */
                goto err;
            }
            /* Combine parts of compressed name offset and mask them. */
            label_size = (label_size << 8) | payload[*working_offset];
            label_size &= DNS_LABEL_OFFSET_MASK;
            *working_offset += 1;
            /*
             * Payload from the start of this compressed name offset is
             * no longer allowed, to prevent cycles or forward pointing
             * compressed names. Forward pointers will be caught by the
             * next loop iteration.
             */
            working_size = *working_offset - 2;
            nested_offset = label_size;
            working_offset = &nested_offset;
            continue;

          case DNS_LABEL_TYPE_EXTENDED:
            /*
             * See RFC6891, Extension Mechanisms for DNS (EDNS(0)),
             * which obsoletes RFC2671, RFC2673.
             */
            /* YAF does not support this. */
#if 0
            g_debug("Extended DNS label types (%#04x) are not supported",
                    label_size);
#endif /* 0 */
            goto err;

          default:
            g_assert(0x80 == (label_size & DNS_LABEL_TYPE_MASK));
#if 0
            g_debug("Unknown DNS label type %#04x", label_size);
#endif /* 0 */
            goto err;
        }
    }

  err:
    /*
     * Set payload_offset to payload_size to "consume" everything and
     * prevent further processing.
     */
     *payload_offset = payload_size;
     return 0;
}

/*
 * Processes a DNS text value (either a name label or a TXT record
 * value) which may contain binary data, and escapes the content.
 * Backslashes are escaped as "\\", newlines as "\n", and byte values
 * outside of 32-126 as "\xHH" where HH is a pair of hexadecimal digits.
 *
 * In addition, if escape_dots is true, then dots are encoded as "\.",
 * for internal dots in DNS name labels.
 *
 * Returns the length encoded into the destination buffer. Returns zero
 * and zeroes out the destination if the result did not fit in the
 * buffer.
 */
static unsigned int
ypDnsEscapeValue(
    uint8_t       *dst,
    unsigned int   dst_size,
    const uint8_t *src,
    unsigned int   src_size,
    gboolean       escape_dots)
{
    unsigned int i;
    uint8_t b;
    unsigned int escaped_size = 0;
    for (i = 0; i < src_size; i++) {
        b = src[i];
        switch (b) {
          case '\\':
            if (escaped_size + 2 > dst_size) goto err;
            dst[escaped_size] = '\\';
            dst[escaped_size + 1] = '\\';
            escaped_size += 2;
            continue;
          case '\n':
            if (escaped_size + 2 > dst_size) goto err;
            dst[escaped_size] = '\\';
            dst[escaped_size + 1] = 'n';
            escaped_size += 2;
            continue;
          case '.':
            if (escape_dots) {
                if (escaped_size + 2 > dst_size) goto err;
                dst[escaped_size] = '\\';
                dst[escaped_size + 1] = '.';
                escaped_size += 2;
                continue;
            }
            /* fall through to default case if not escaping dots */
            /* FALLTHROUGH */

          default:
            if (b < 32 || b > 126) {
                /* control characters and special whitespace */
                if (escaped_size + 4 > dst_size) goto err;
                dst[escaped_size] = '\\';
                dst[escaped_size + 1] = 'x';
                dst[escaped_size + 2] = hex_digits[0x0f & (b >> 4)];
                dst[escaped_size + 3] = hex_digits[0x0f & b];
                escaped_size += 4;
            } else {
                /* normal ASCII characters */
                if (escaped_size + 1 > dst_size) goto err;
                dst[escaped_size] = b;
                escaped_size += 1;
                continue;
            }
        }
    }

    /* success, return the escaped length of the value. */
    return escaped_size;

  err:
    /* clear out anything that was written before returning. */
    memset(dst, 0, escaped_size);
    return 0;
}

static void
ypDnsParser(
    yaf_dns_rr_t **dnsRecord,
    yfFlow_t      *flow,
    yfFlowVal_t   *val,
    uint8_t       *buf,
    uint32_t      *bufLen,
    uint8_t        recordCount,
    uint16_t       export_limit)
{
    ycDnsScanMessageHeader_t header;
    uint32_t       offset = sizeof(ycDnsScanMessageHeader_t);
    uint32_t       firstpkt = val->paylen;
    uint16_t       msglen;
    size_t         nameLen;
    uint8_t        nxdomain = 0;
    uint32_t       bufSize = (*bufLen);
    uint16_t       rrType;
    unsigned int   loop = 0;
    const uint8_t *payload = val->payload;
    unsigned int   payloadSize = val->paylen;

    if (flow->key.proto == YF_PROTO_TCP) {
        while (loop < val->pkt && loop < YAF_MAX_PKT_BOUNDARY) {
            if (val->paybounds[loop] == 0) {
                loop++;
            } else {
                firstpkt = val->paybounds[loop];
                break;
            }
        }
        msglen = ntohs(*((uint16_t *)(payload)));
        if ((uint32_t)(msglen + 2) == firstpkt) {
            /* this is the weird message length in TCP */
            payload += sizeof(uint16_t);
            payloadSize -= sizeof(uint16_t);
        }
    }

    ycDnsScanRebuildHeader(payload, &header);

    if (header.rcode != 0) {
        nxdomain = 1;
    }

#if defined(YAF_ENABLE_DNSAUTH)
    if (header.aa) {
        /* get the query part if authoritative */
        nxdomain = 1;
    }
#endif /* if defined(YAF_ENABLE_DNSAUTH) */
    for (loop = 0; loop < header.qdcount && offset < payloadSize; loop++) {
        nameLen = ypDnsGetName(buf, bufSize, payload, payloadSize,
                               &offset, export_limit);
        if ((!header.qr || nxdomain)) {
            fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
            (*dnsRecord)->dnsName.len = nameLen;
            (*dnsRecord)->dnsName.buf = buf + bufSize;
            bufSize += (*dnsRecord)->dnsName.len;
            (*dnsRecord)->dnsAuthoritative = header.aa;
            (*dnsRecord)->dnsResponseCode = header.rcode;
            (*dnsRecord)->dnsSection = 0;
            (*dnsRecord)->dnsQueryResponse = header.qr;
            (*dnsRecord)->dnsId = header.id;
            if (((size_t)offset + 2) < payloadSize) {
                (*dnsRecord)->dnsRRType =
                    ntohs(*((uint16_t *)(payload + offset)));
            }

            recordCount--;
            if (recordCount) {
                (*dnsRecord)++;
            } else {
                goto cleanup;
            }
        }

        offset += (sizeof(uint16_t) * 2);
        /* skip over class */
        if (offset > payloadSize) {
            goto cleanup;
        }
    }
    if ( loop < header.qdcount ) {
        /* Not all questions processed. */
        goto cleanup;
    }

    for (loop = 0; loop < header.ancount && offset < payloadSize; loop++) {
        (*dnsRecord)->dnsSection = 1;
        (*dnsRecord)->dnsAuthoritative = header.aa;
        (*dnsRecord)->dnsResponseCode = header.rcode;
        (*dnsRecord)->dnsQueryResponse = 1;
        (*dnsRecord)->dnsId = header.id;
        rrType = ypDnsScanResourceRecord(dnsRecord, payload, payloadSize,
                                         &offset, buf, &bufSize,
                                         export_limit);
        if (rrType != DNS_TYPE_OPT) {
            recordCount--;
            if (recordCount) {
                (*dnsRecord)++;
            } else {
                goto cleanup;
            }
        }

        if (offset > payloadSize) {
            goto cleanup;
        }

        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto cleanup;
        }
    }
    if ( loop < header.ancount ) {
        /* Not all answer records processed. */
        goto cleanup;
    }

    for (loop = 0; loop < header.nscount && offset < payloadSize; loop++) {
        (*dnsRecord)->dnsSection = 2;
        (*dnsRecord)->dnsAuthoritative = header.aa;
        (*dnsRecord)->dnsResponseCode = header.rcode;
        (*dnsRecord)->dnsQueryResponse = 1;
        (*dnsRecord)->dnsId = header.id;
        rrType = ypDnsScanResourceRecord(dnsRecord, payload, payloadSize,
                                         &offset, buf, &bufSize,
                                         export_limit);
        if (rrType != DNS_TYPE_OPT) {
            recordCount--;
            if (recordCount) {
                (*dnsRecord)++;
            } else {
                goto cleanup;
            }
        }

        if (offset > payloadSize) {
            goto cleanup;
        }

        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto cleanup;
        }
    }
    if ( loop < header.nscount ) {
        /* Not all authority records processed. */
        goto cleanup;
    }


    for (loop = 0; loop < header.arcount && offset < payloadSize; loop++) {
        (*dnsRecord)->dnsSection = 3;
        (*dnsRecord)->dnsAuthoritative = header.aa;
        (*dnsRecord)->dnsResponseCode = header.rcode;
        (*dnsRecord)->dnsQueryResponse = 1;
        (*dnsRecord)->dnsId = header.id;
        rrType = ypDnsScanResourceRecord(dnsRecord, payload, payloadSize,
                                         &offset, buf, &bufSize,
                                         export_limit);
        if (rrType != DNS_TYPE_OPT) {
            recordCount--;
            if (recordCount) {
                (*dnsRecord)++;
            } else {
                goto cleanup;
            }
        }

        if (offset > payloadSize) {
            goto cleanup;
        }

        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto cleanup;
        }
    }
    if ( loop < header.arcount ) {
        /* Not all additional records processed. */
        goto cleanup;
    }

  cleanup:
    /* Make sure to pass export buffer usage back up to the caller */
    *bufLen = bufSize;
    /*
     * If something went wrong so we need to pad the rest of the STL
     * with NULLs. This would most likely mean we ran out of space in
     * the DNS Export Buffer.
     */
    while (recordCount) {
        fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 3,
                              YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        recordCount--;
        if (recordCount) {
            (*dnsRecord)++;
        }
    }
}


static uint16_t
ypDnsScanResourceRecord(
    yaf_dns_rr_t  **dnsRecord,
    const uint8_t  *payload,
    unsigned int    payloadSize,
    uint32_t       *offset,
    uint8_t        *buf,
    uint32_t       *bufLen,
    uint16_t        export_limit)
{
    uint16_t rrLen = 0;
    uint16_t rrType = 0;
    uint32_t temp_size;
    uint32_t temp_offset;
    uint32_t bufSize = *bufLen;

    (*dnsRecord)->dnsName.len = ypDnsGetName(
        buf, bufSize, payload, payloadSize, offset, export_limit);
    (*dnsRecord)->dnsName.buf = buf + bufSize;
    bufSize += (*dnsRecord)->dnsName.len;

    /* rrType */
    READ_U16_INC(&((*dnsRecord)->dnsRRType), offset, payload, payloadSize);
    rrType = (*dnsRecord)->dnsRRType;
    /* ignore class */
    *offset += sizeof(uint16_t);
    /* time to live */
    READ_U32_INC(&((*dnsRecord)->dnsTTL), offset, payload, payloadSize);
    /* length */
    READ_U16_INC(&rrLen, offset, payload, payloadSize);

    if (*offset + rrLen > payloadSize) {
        /* If the stated RR length goes past what's captured, move along. */
        *offset = payloadSize;
        fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 3,
                              YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        goto cleanup;
    }

    temp_offset = (*offset);
    temp_size = temp_offset + rrLen;

    switch (rrType) {
      case DNS_TYPE_A:
        {
            yaf_dns_a_t *arecord = (yaf_dns_a_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_A_TID, yaf_dns_a_tmpl, 1);
            READ_U32_INC(&arecord->dnsA, &temp_offset, payload, temp_size);
        }
        break;

      case DNS_TYPE_NS:
        {
            yaf_dns_ns_t *nsrecord = (yaf_dns_ns_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_NS_TID, yaf_dns_ns_tmpl, 1);
            nsrecord->dnsNSDName.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            nsrecord->dnsNSDName.buf = buf + bufSize;
            bufSize += nsrecord->dnsNSDName.len;
        }
        break;

      case DNS_TYPE_CNAME:
        {
            yaf_dns_cname_t *cname = (yaf_dns_cname_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_CNAME_TID, yaf_dns_cname_tmpl, 1);
            cname->dnsCNAME.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            cname->dnsCNAME.buf = buf + bufSize;
            bufSize += cname->dnsCNAME.len;
        }
        break;

      case DNS_TYPE_SOA:
        {
            yaf_dns_soa_t *soa = (yaf_dns_soa_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_SOA_TID, yaf_dns_soa_tmpl, 1);
            soa->dnsSOAMName.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            soa->dnsSOAMName.buf = buf + bufSize;
            bufSize += soa->dnsSOAMName.len;
            if (temp_offset >= temp_size) {
                break;
            }
            soa->dnsSOARName.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            soa->dnsSOARName.buf = buf + bufSize;
            bufSize += soa->dnsSOARName.len;
            if (temp_offset >= temp_size) {
                break;
            }
            READ_U32_INC(&soa->dnsSOASerial, &temp_offset,
                         payload, temp_size);
            READ_U32_INC(&soa->dnsSOARefresh, &temp_offset,
                         payload, temp_size);
            READ_U32_INC(&soa->dnsSOARetry, &temp_offset,
                         payload, temp_size);
            READ_U32_INC(&soa->dnsSOAExpire, &temp_offset,
                         payload, temp_size);
            READ_U32_INC(&soa->dnsSOAMinimum, &temp_offset,
                         payload, temp_size);
        }
        break;

      case DNS_TYPE_PTR:
        {
            yaf_dns_ptr_t *ptr = (yaf_dns_ptr_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_PTR_TID, yaf_dns_ptr_tmpl, 1);
            ptr->dnsPTRDName.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            ptr->dnsPTRDName.buf = buf + bufSize;
            bufSize += ptr->dnsPTRDName.len;
        }
        break;

      case DNS_TYPE_MX:
        {
            yaf_dns_mx_t *mx = (yaf_dns_mx_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_MX_TID, yaf_dns_mx_tmpl, 1);
            READ_U16_INC(&mx->dnsMXPreference, &temp_offset,
                         payload, temp_size);
            mx->dnsMXExchange.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            mx->dnsMXExchange.buf = buf + bufSize;
            bufSize += mx->dnsMXExchange.len;
        }
        break;

      case DNS_TYPE_TXT:
        {
            yaf_dns_txt_t *txt = (yaf_dns_txt_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_TXT_TID, yaf_dns_txt_tmpl, 1);
            uint8_t unescaped_TXT_length = 0;
            READ_U8_INC(&unescaped_TXT_length, &temp_offset,
                        payload, temp_size);
            if (unescaped_TXT_length + temp_offset > temp_size) {
                txt->dnsTXTData.len = 0;
            } else {
                txt->dnsTXTData.len = ypDnsEscapeValue(
                    &buf[bufSize], export_limit - bufSize,
                    &payload[temp_offset], unescaped_TXT_length,
                    FALSE);
                if (txt->dnsTXTData.len > 0) {
                    txt->dnsTXTData.buf = &buf[bufSize];
                    bufSize += txt->dnsTXTData.len;
                }
                temp_offset += unescaped_TXT_length;
            }
        }
        break;

      case DNS_TYPE_AAAA:
        {
            yaf_dns_aaaa_t *aa = (yaf_dns_aaaa_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_AAAA_TID, yaf_dns_aaaa_tmpl, 1);
            if ( temp_offset + sizeof(aa->dnsAAAA) > temp_size ) {
                memset(aa->dnsAAAA, 0, sizeof(aa->dnsAAAA));
            } else {
                memcpy(aa->dnsAAAA, (payload + temp_offset), sizeof(aa->dnsAAAA));
            }
        }
        break;

      case DNS_TYPE_SRV:
        {
            yaf_dns_srv_t *srv = (yaf_dns_srv_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_SRV_TID, yaf_dns_srv_tmpl, 1);
            READ_U16_INC(&srv->dnsSRVPriority, &temp_offset,
                         payload, temp_size);
            READ_U16_INC(&srv->dnsSRVWeight, &temp_offset,
                         payload, temp_size);
            READ_U16_INC(&srv->dnsSRVPort, &temp_offset,
                         payload, temp_size);
            srv->dnsSRVTarget.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            srv->dnsSRVTarget.buf = buf + bufSize;
            bufSize += srv->dnsSRVTarget.len;
        }
        break;

      case DNS_TYPE_DS:
        if (!dnssec_global) {
            fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 3,
                                  YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        } else {
            yaf_dns_ds_t *ds = (yaf_dns_ds_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_DS_TID, yaf_dns_ds_tmpl, 1);
            READ_U16_INC(&ds->dnsDSKeyTag, &temp_offset,
                         payload, temp_size);
            READ_U8_INC(&ds->dnsDSAlgorithm, &temp_offset,
                        payload, temp_size);
            READ_U8_INC(&ds->dnsDSDigestType, &temp_offset,
                        payload, temp_size);

            /* length of rrdata is rrLen - we know these 3 fields */
            /* should add up to 4 - so rest is digest */
            if ((size_t)rrLen + *offset > temp_size) {
                break;
            }
            ds->dnsDSDigest.buf = (uint8_t *)payload + temp_offset;
            ds->dnsDSDigest.len = rrLen - 4;
            /* not storing in exbuf, but it counts against export_limit */
            bufSize += ds->dnsDSDigest.len;
        }
        break;

      case DNS_TYPE_RRSIG:
        if (!dnssec_global) {
            fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 3,
                                  YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        } else {
            yaf_dns_rrsig_t *rrsig = (yaf_dns_rrsig_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_RRSIG_TID, yaf_dns_rrsig_tmpl, 1);

            READ_U16_INC(&rrsig->dnsRRSIGTypeCovered, &temp_offset,
                         payload, temp_size);
            READ_U8_INC(&rrsig->dnsRRSIGAlgorithm, &temp_offset,
                        payload, temp_size);
            READ_U8_INC(&rrsig->dnsRRSIGLabels, &temp_offset,
                        payload, temp_size);
            READ_U32_INC(&rrsig->dnsRRSIGOriginalTTL, &temp_offset,
                         payload, temp_size);
            READ_U32_INC(&rrsig->dnsRRSIGSignatureExpiration, &temp_offset,
                         payload, temp_size);
            READ_U32_INC(&rrsig->dnsRRSIGSignatureInception, &temp_offset,
                         payload, temp_size);
            READ_U16_INC(&rrsig->dnsRRSIGKeyTag, &temp_offset,
                         payload, temp_size);

            rrsig->dnsRRSIGSigner.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            rrsig->dnsRRSIGSigner.buf = buf + bufSize;
            bufSize += rrsig->dnsRRSIGSigner.len;

            /* we are (temp_offset - *offset) into the rrdata; the remainder
             * is the signature */
            if ((size_t)rrLen + *offset > temp_size) {
                break;
            }
            rrsig->dnsRRSIGSignature.buf = (uint8_t *)payload + temp_offset;
            rrsig->dnsRRSIGSignature.len = rrLen - (temp_offset - *offset);
            bufSize += rrsig->dnsRRSIGSignature.len;
        }
        break;

      case DNS_TYPE_NSEC:
        if (!dnssec_global) {
            fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 3,
                                  YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        } else {
            yaf_dns_nsec_t *nsec = (yaf_dns_nsec_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_NSEC_TID, yaf_dns_nsec_tmpl, 1);

            nsec->dnsNSECNextDomainName.len = ypDnsGetName(
                buf, bufSize, payload, temp_size, &temp_offset, export_limit);
            nsec->dnsNSECNextDomainName.buf = buf + bufSize;
            bufSize += nsec->dnsNSECNextDomainName.len;

            /* we are (temp_offset - *offset) into the rrdata; the remainder
             * is the TypeBitMaps */
            if ((size_t)rrLen + *offset > temp_size) {
                break;
            }
            nsec->dnsNSECTypeBitMaps.buf = (uint8_t *)payload + temp_offset;
            nsec->dnsNSECTypeBitMaps.len = rrLen - (temp_offset - *offset);
            bufSize += nsec->dnsNSECTypeBitMaps.len;
        }
        break;

      case DNS_TYPE_DNSKEY:
        if (!dnssec_global) {
            fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 0,
                                  YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        } else {
            yaf_dns_dnskey_t *dnskey;
            dnskey = (yaf_dns_dnskey_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_DNSKEY_TID, yaf_dns_dnskey_tmpl, 1);

            READ_U16_INC(&dnskey->dnsDNSKEYFlags, &temp_offset,
                         payload, temp_size);
            READ_U8_INC(&dnskey->dnsDNSKEYProtocol, &temp_offset,
                        payload, temp_size);
            READ_U8_INC(&dnskey->dnsDNSKEYAlgorithm, &temp_offset,
                        payload, temp_size);

            if ((size_t)rrLen + *offset > temp_size) {
                break;
            }
            dnskey->dnsDNSKEYPublicKey.buf = (uint8_t *)payload + temp_offset;
            dnskey->dnsDNSKEYPublicKey.len = rrLen - 4;
            bufSize += dnskey->dnsDNSKEYPublicKey.len;
        }
        break;

      case DNS_TYPE_NSEC3:
        if (!dnssec_global) {
            fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 0,
                                  YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        } else {
            yaf_dns_nsec3_t *nsec3 = (yaf_dns_nsec3_t *)fbSubTemplateListInit(
                &((*dnsRecord)->dnsRRList), 3,
                YAF_DNS_NSEC3_TID, yaf_dns_nsec3_tmpl, 1);

            READ_U8_INC(&nsec3->dnsNSEC3Algorithm, &temp_offset,
                        payload, temp_size);
            READ_U8_INC(&nsec3->dnsNSEC3Flags, &temp_offset,
                        payload, temp_size);
            READ_U16_INC(&nsec3->dnsNSEC3Iterations, &temp_offset,
                         payload, temp_size);

            READ_U8_INC(&nsec3->dnsNSEC3Salt.len, &temp_offset,
                        payload, temp_size);
            if (nsec3->dnsNSEC3Salt.len + temp_offset > temp_size) {
                nsec3->dnsNSEC3Salt.len = 0;
                break;
            }
            nsec3->dnsNSEC3Salt.buf = (uint8_t *)payload + temp_offset;
            bufSize += nsec3->dnsNSEC3Salt.len;
            if (bufSize > export_limit) {
                break;
            }
            temp_offset += nsec3->dnsNSEC3Salt.len;

            READ_U8_INC(&nsec3->dnsNSEC3NextHashedOwnerName.len,
                        &temp_offset, payload, temp_size);
            if (nsec3->dnsNSEC3NextHashedOwnerName.len + temp_offset >
                temp_size)
            {
                nsec3->dnsNSEC3NextHashedOwnerName.len = 0;
                break;
            }
            nsec3->dnsNSEC3NextHashedOwnerName.buf =
                (uint8_t *)payload + temp_offset;
            bufSize += nsec3->dnsNSEC3NextHashedOwnerName.len;
            if (bufSize > export_limit) {
                break;
            }
            temp_offset += nsec3->dnsNSEC3NextHashedOwnerName.len;

            /* we have moved (temp_offset - *offset) bytes into the record;
             * subtract that from rrLen to get length of TypeBitMaps */
            if ((size_t)rrLen + *offset > temp_size) {
                break;
            }
            nsec3->dnsNSEC3TypeBitMaps.buf = (uint8_t *)payload + temp_offset;
            nsec3->dnsNSEC3TypeBitMaps.len = rrLen - (temp_offset - *offset);
            bufSize += nsec3->dnsNSEC3TypeBitMaps.len;
        }
        break;

      case DNS_TYPE_NSEC3PARAM:
        if (!dnssec_global) {
            fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 0,
                                  YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        } else {
            yaf_dns_nsec3param_t *nsec3param =
                (yaf_dns_nsec3param_t *)fbSubTemplateListInit(
                    &((*dnsRecord)->dnsRRList), 3,
                    YAF_DNS_NSEC3PARAM_TID, yaf_dns_nsec3param_tmpl, 1);

            READ_U8_INC(&nsec3param->dnsNSEC3PARAMAlgorithm, &temp_offset,
                        payload, temp_size);
            READ_U8_INC(&nsec3param->dnsNSEC3PARAMFlags, &temp_offset,
                        payload, temp_size);
            READ_U16_INC(&nsec3param->dnsNSEC3PARAMIterations, &temp_offset,
                         payload, temp_size);

            READ_U8_INC(&nsec3param->dnsNSEC3PARAMSalt.len, &temp_offset,
                        payload, temp_size);
            if (nsec3param->dnsNSEC3PARAMSalt.len + temp_offset > temp_size) {
                nsec3param->dnsNSEC3PARAMSalt.len = 0;
                break;
            }
            nsec3param->dnsNSEC3PARAMSalt.buf
                = (uint8_t *)payload + temp_offset;
            bufSize += nsec3param->dnsNSEC3PARAMSalt.len;
        }
        break;
      default:
        fbSubTemplateListInit(&((*dnsRecord)->dnsRRList), 3,
                              YAF_DNS_A_TID, yaf_dns_a_tmpl, 0);
        break;
    }

  cleanup:
    *offset += rrLen;
    if (*offset > payloadSize) {
        *offset = payloadSize;
    }
    *bufLen = bufSize;
    return rrType;
}
#endif  /* YAF_ENABLE_DPI */
#endif /* ifdef PAYLOAD_INSPECTION */


/**
 * ydpInitialize
 *
 * Processes the plugin's arguments to determine whether to enable dnssec
 * export and enables DPI Information Elements.
 *
 */
int
ydpInitialize(
    int        argc,
    char      *argv[],
    uint16_t   applabel,
    gboolean   applabelOnly,
    void      *extra,
    GError   **err)
{
#ifdef YAF_ENABLE_DPI
    /* first argument determines whether to enable dnssec export */
    if (!applabelOnly && argc >= 2) {
        if (0 == strcmp("true", argv[1])) {
            dnssec_global = TRUE;
            g_debug("DNSSEC export enabled.");
        }
    }

    pluginExtras_t *pluginExtras = (pluginExtras_t *)extra;
    GArray         *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;

    YC_ENABLE_ELEMENTS(yaf_dns_rr, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_a, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_aaaa, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_cname, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_mx, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_ns, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_ptr, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_txt, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_soa, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_srv, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_ds, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_rrsig, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_nsec, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_dnskey, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_nsec3, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dns_nsec3param, pluginTemplates);
#endif /* ifdef YAF_ENABLE_DPI */
    return 1;
}
