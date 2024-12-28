/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file tlsplugin.c
 *
 *
 *  This recognizes SSL & TLS packets
 *
 *  Remember to update proxyplugin.c with any changes.
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio, Emily Sarneso
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

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif
#endif  /* HAVE_OPENSSL */

typedef struct yf_asn_tlv_st {
    uint8_t   class : 2;
    uint8_t   p_c   : 1;
    uint8_t   tag   : 5;
} yf_asn_tlv_t;


#ifdef YAF_ENABLE_DPI
#define SSL_CERT_EXPORT_FLAG    0x02

/* YAF_SSL_TID, yaf_ssl_spec, yaf_ssl_t, yaf_ssl_tmpl, "yaf_ssl" */
#define YAF_SSL_TID      0xCA0A
#define YAF_SSL_NAME     "yaf_ssl"
#define YAF_SSL_DESC     NULL

/* YAF_SSL_CERT_TID, yaf_ssl_cert_spec, yaf_ssl_cert_t, yaf_ssl_cert_tmpl,
 * "yaf_ssl_cert" */
#define YAF_SSL_CERT_TID 0xCA0B
#define YAF_SSL_CERT_NAME "yaf_ssl_cert"
#define YAF_SSL_CERT_DESC NULL

/* YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_spec, yaf_ssl_subcert_t,
 * yaf_ssl_subcert_tmpl, "yaf_ssl_subcert" */
#define YAF_SSL_SUBCERT_TID 0xCE14
#define YAF_SSL_SUBCERT_NAME "yaf_ssl_subcert"
#define YAF_SSL_SUBCERT_DESC NULL

/* YAF_SSL_TID, yaf_ssl_spec, yaf_ssl_t, yaf_ssl_tmpl, "yaf_ssl" */
static fbInfoElementSpec_t yaf_ssl_spec[] = {
    /* List of ciphers, each is 32bit */
    {"sslCipherList",             FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    /* List of complete binary certificates, added by request */
    {"sslBinaryCertificateList",  FB_IE_VARLEN, SSL_CERT_EXPORT_FLAG },
    /* Server name from client hello */
    /* Used by SM to label SSL DPI Level 1 */
    {"sslServerName",             FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    /* List of certs */
    {"sslCertList",               FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    /* Cipher suite in server hello */
    /* Used by SM to label SSL DPI Level 1 */
    {"sslServerCipher",           4, YAF_DISABLE_IE_FLAG },
    /* Protocol version, 2==ssl, 3==tls */
    {"sslClientVersion",          1, YAF_DISABLE_IE_FLAG },
    /* Compression method in server hello */
    {"sslCompressionMethod",      1, YAF_DISABLE_IE_FLAG },
    /* Message version */
    {"sslRecordVersion",          2, YAF_DISABLE_IE_FLAG },
    /* Client JA3 Hash (MD5 of sslClientJA3Fingerprint) */
    {"sslClientJA3",              16, YAF_DISABLE_IE_FLAG },
    /* Server JA3 Hash (MD5 of sslServerJA3Fingerprint) */
    {"sslServerJA3S",             16, YAF_DISABLE_IE_FLAG },
    /* Client JA3 String */
    {"sslClientJA3Fingerprint",   FB_IE_VARLEN, YAF_DISABLE_IE_FLAG},
    /* Server JA3S String */
    {"sslServerJA3SFingerprint",  FB_IE_VARLEN, YAF_DISABLE_IE_FLAG},
    FB_IESPEC_NULL
};

/* YAF_SSL_TID, yaf_ssl_spec, yaf_ssl_t, yaf_ssl_tmpl, "yaf_ssl" */
typedef struct yaf_ssl_st {
    fbBasicList_t         sslCipherList;
    fbBasicList_t         sslBinaryCertificateList;
    fbVarfield_t          sslServerName;
    fbSubTemplateList_t   sslCertList;
    uint32_t              sslServerCipher;
    uint8_t               sslClientVersion;
    uint8_t               sslCompressionMethod;
    uint16_t              sslRecordVersion;
    uint8_t               sslClientJA3[16];
    uint8_t               sslServerJA3S[16];
    fbVarfield_t          sslClientJA3Fingerprint;
    fbVarfield_t          sslServerJA3SFingerprint;
} yaf_ssl_t;


/* YAF_SSL_CERT_TID, yaf_ssl_cert_spec, yaf_ssl_cert_t, yaf_ssl_cert_tmpl,
 * "yaf_ssl_cert" */
static fbInfoElementSpec_t yaf_ssl_cert_spec[] = {
    {"sslIssuerFieldList",          FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sslSubjectFieldList",         FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sslExtensionFieldList",       FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    /* used by SM to label SSL DPI Level 2 */
    {"sslCertSignature",            FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    /* used by SM to label SSL DPI Level 2 */
    {"sslCertSerialNumber",         FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sslCertValidityNotBefore",    FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sslCertValidityNotAfter",     FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sslPublicKeyAlgorithm",       FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sslPublicKeyLength",          2, YAF_DISABLE_IE_FLAG },
    /* used by SM to label SSL DPI Level 2 */
    {"sslCertVersion",              1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",               5, 0 },
    /* TODO: re-enable when downstream is ready */
    {"sslCertificateHash",          FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

/* YAF_SSL_CERT_TID, yaf_ssl_cert_spec, yaf_ssl_cert_t, yaf_ssl_cert_tmpl,
 * "yaf_ssl_cert" */
typedef struct yaf_ssl_cert_st {
    fbSubTemplateList_t   sslIssuerFieldList;
    fbSubTemplateList_t   sslSubjectFieldList;
    fbSubTemplateList_t   sslExtensionFieldList;
    fbVarfield_t          sslCertSignature;
    fbVarfield_t          sslCertSerialNumber;
    fbVarfield_t          sslCertValidityNotBefore;
    fbVarfield_t          sslCertValidityNotAfter;
    fbVarfield_t          sslPublicKeyAlgorithm;
    uint16_t              sslPublicKeyLength;
    uint8_t               sslCertVersion;
    uint8_t               padding[5];
    fbVarfield_t          sslCertificateHash;
} yaf_ssl_cert_t;

/* YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_spec, yaf_ssl_subcert_t,
 * yaf_ssl_subcert_tmpl, "yaf_ssl_subcert" */
static fbInfoElementSpec_t yaf_ssl_subcert_spec[] = {
    {"sslObjectValue",              FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sslObjectType",               1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",               7, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

/* YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_spec, yaf_ssl_subcert_t,
 * yaf_ssl_subcert_tmpl, "yaf_ssl_subcert" */
typedef struct yaf_ssl_subcert_st {
    fbVarfield_t   sslObjectValue;
    uint8_t        sslObjectType;
    uint8_t        padding[7];
} yaf_ssl_subcert_t;

/* YAF_SSL_TID, yaf_ssl_spec, yaf_ssl_t, yaf_ssl_tmpl, "yaf_ssl" */
static fbTemplate_t *yaf_ssl_tmpl;

/* YAF_SSL_CERT_TID, yaf_ssl_cert_spec, yaf_ssl_cert_t, yaf_ssl_cert_tmpl,
 * "yaf_ssl_cert" */
static fbTemplate_t *yaf_ssl_cert_tmpl;

/* YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_spec, yaf_ssl_subcert_t,
 * yaf_ssl_subcert_tmpl, "yaf_ssl_subcert" */
static fbTemplate_t *yaf_ssl_subcert_tmpl;

/* When TRUE, causes the complete binary X.509 certificate to be exported.
 * Set by the arguments to ydpInitialize(). */
static gboolean full_cert_export = FALSE;

/* When TRUE, causes the hash of the X.509 certificate to be exported.  Set by
 * the arguments to ydpInitialize(). */
static gboolean cert_hash_export = FALSE;

/* When TRUE, turns off the default DPI processing of the certificates.  Set
 * by the arguments to ydpInitialize(). */
static gboolean ssl_dpi_off = FALSE;

/* IDs used by yfDPIData_t->dpacketID */
/* sslClientVersion */
#define YF_SSL_CLIENT_VERSION   88
/* sslServerCipher */
#define YF_SSL_SERVER_CIPHER    89
/* sslCompressionMethod */
#define YF_SSL_COMPRESSION      90
/* sslCipherList */
#define YF_SSL_CIPHER_LIST      91
/* sslCipherList in SSL v2 */
#define YF_SSL_V2_CIPHER_LIST   92
/* offset of the start of a certificate */
#define YF_SSL_CERT_START       93
/* sslRecordVersion */
#define YF_SSL_RECORD_VERSION   94
/* sslServerName */
#define YF_SSL_SERVER_NAME      95
/* location of eliptic curve values */
#define YF_SSL_ELIPTIC_CURVE    96
/* location of eliptic curve point format list */
#define YF_SSL_ELIPTIC_FORMAT   97
/* ssl version? */
#define YF_SSL_VERSION          99
/* location of the client extension list */
#define YF_SSL_CLIENT_EXTENSION 100
/* location of the server extension list */
#define YF_SSL_SERVER_EXTENSION 101
/* the server version */
#define YF_SSL_SERVER_VERSION   102

#endif  /* YAF_ENABLE_DPI */

/*
 *  ASN.1 Tag Numbers (for SSL)
 *
 *  A Layman's Guide to a Subset of ASN.1, BER, and DER
 *  An RSA Laboratories Technical Note
 *  Burton S. Kaliski Jr.
 *  Revised November 1, 1993
 *
 *  https://luca.ntop.org/Teaching/Appunti/asn1.html
 *
 *  Not all these tags are used in the code but having them here is useful.
 */
#define CERT_BOOL               0x01
/* Integer */
#define CERT_INT                0x02
/* Bit String */
#define CERT_BITSTR             0x03
/* Octet String */
#define CERT_OCTSTR             0x04
#define CERT_NULL               0x05
/* Object Identifer */
#define CERT_OID                0x06
/* UTF8 String */
#define CERT_UTF8STR            0x0C
/* Start of Sequence */
#define CERT_SEQ                0x10
/* Start of Set */
#define CERT_SET                0x11
/* Printable String */
#define CERT_PRINT              0x13
/* 8-bit (T.61) Char String */
#define CERT_T61STR             0x14
/* ASCII String */
#define CERT_IA5STR             0x16
/* UTC Time */
#define CERT_TIME               0x17
/* Generalized Time */
#define CERT_GENRLTIME          0x18
#define CERT_EXPLICIT           0xa0
/* ASN.1 P/C Bit (primitive, constucted) */
#define CERT_PRIM               0x00
#define CERT_CONST              0x01
/* ASN.1 Length 0x81 is length follows in 1 byte */
#define CERT_1BYTE              0x81
/* ASN.1 Length 0x82 is length follows in 2 bytes */
#define CERT_2BYTE              0x82

/*
 *  BER encoding of object ids (OID): First byte is (40 * value1 + value2).
 *  Remaining bytes are in base-128 with the MSB high in all bytes except the
 *  last.  To compute the BER value in reverse order:
 *
 *  1. Mask value by 0x7f to get final byte
 *  2. Shift value right by 7.
 *  3. Stop if value is 0.
 *  4. Compute (0x80 | (0x7f & value)) to get the previous byte.
 *  5. Goto 2.
 *
 *  113549 ->
 *    final byte: (113549 & 0x7f) = 13 (0x0d)
 *    shift: 113549 >> 7 = 887, not zero
 *    next to last: (0x80 | (0x7f & 887)) = (0x80 | 119) = 0xf7
 *    shift: 887 >> 7 = 6, not zero
 *    second to last: (0x80 | (0x7f & 6)) = (0x80 | 6) = 0x86
 *    shift: 6 >> 7 = 0, end
 *    result: 0x86 0xf7 0x0d
 */

/*
 *  id-ce: {joint-iso-itu-t(2) ds(5) certificateExtension(29)}
 *
 *  http://oid-info.com/cgi-bin/display?tree=2.5.29
 *
 *  bytes: (40 * 2 + 5), base128(29) ==> (55, 1D)
 */
#define CERT_IDCE               0x551D

/*
 *  id-at: {joint-iso-itu-t(2) ds(5) attributeType(4)}
 *
 *  http://oid-info.com/cgi-bin/display?tree=2.5.4.45#focus
 *
 *  bytes: (40 * 2 + 5), base128(4) ==> (55, 04)
 */
#define CERT_IDAT               0x5504

/*
 *  pkcs-9: {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9}
 *
 *  http://oid-info.com/cgi-bin/display?tree=1.2.840.113549.1.9#focus
 *
 *  bytes: (40 * 1 + 2), base128(840), base128(113549), base128(1), base128(9)
 *  ==> (2A, 86 48, 86 f7 0d, 01, 09)
 */
static const uint8_t CERT_PKCS[] = {
    0x2A, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09
};

/*
 *  ldap-domainComponent: {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100)
 *  pilotAttributeType(1) domainComponent(25)}
 *
 *  bytes (40 * 0 + 9), base128(2342), base128(19200300), base128(100),
 *  base128(1), base128(25) ==> (09, 92 26, 89, 93 f2 2c, 64, 01, 19)
 */
static const uint8_t CERT_DC[] = {
    0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19
};


/* this might be more - but I have to have a limit somewhere */
#define MAX_CERTS 10

/** defining the header structure for SSLv2 is pointless, because the
 *  first field of the record is variable length, either 2 or 3 bytes
 *  meaning that the first step has to be to figure out how far offset
 *  all of the other fields are.  Further, the client can send a v2
 *  client_hello stating that it is v3/TLS 1.0 capable, and the server
 *  can respond with v3/TLS 1.0 record formats
 */


/** this defines the record header for SSL V3 negotiations,
 *  it also works for TLS 1.0 */
typedef struct sslv3RecordHeader_st {
    uint8_t    contentType;
    uint8_t    protocolMajor;
    uint8_t    protocolMinor;
    uint16_t   length;
} sslv3RecordHeader_t;

static gboolean
decodeSSLv2(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint8_t         datalength);

static gboolean
decodeTLSv1(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint8_t         datalength,
    uint8_t         type);

#ifdef YAF_ENABLE_DPI
static void
sslServerJA3S(
    uint16_t       scipher,
    uint16_t       sversion,
    char          *ser_extension,
    uint8_t       *smd5,
    fbVarfield_t  *string);

static void
sslClientJA3(
    fbBasicList_t  *ciphers,
    char           *ser_extension,
    uint16_t       *elliptic_curve,
    char           *elliptic_format,
    uint16_t        version,
    int             ellip_curve_len,
    uint8_t        *md5,
    fbVarfield_t   *string);

#ifdef HAVE_OPENSSL
static void
computeMD5(
    const char  *string,
    int          len,
    uint8_t     *mdbuff);
#else  /* HAVE_OPENSSL */
#define computeMD5(_s, _l, _buf)   memset(_buf, 0, 16)
#endif  /* HAVE_OPENSSL */

static gboolean
greaseTableCheck(
    uint16_t   value);

static char *
storeExtension(
    const uint8_t  *payload);
#endif  /* YAF_ENABLE_DPI */

#define TLS_PORT_NUMBER  443

/* The two-byte version number is treated as one 16-bit number in SSLv2 and as
 * two 8-bit numbers (major,minor) in SSLv3 & TLS */

#define TLS_VERSION_10   0x0301
#define TLS_VERSION_11   0x0302
#define TLS_VERSION_12   0x0303

#define SSL_VERSION_2    0x0002

/* This is not correct but "fixing" it seems to break things. Not certain what
 * is going on here.... */
#define SSL_VERSION_3    0x0003


/**
 * SSL CERT Parsing
 *
 */

#ifdef YAF_ENABLE_DPI
static gboolean
ypDecodeSSLCertificate(
    yfDPIContext_t  *ctx,
    yaf_ssl_cert_t **sslCert,
    const uint8_t   *payload,
    unsigned int     payloadSize,
    yfFlow_t        *flow,
    uint32_t         offset);
#endif  /* YAF_ENABLE_DPI */

/**
 * ydpScanPayload
 *
 * the scanner for recognizing SSL/TLS packets
 *
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return TLS_PORT_NUMBER
 *         otherwise 0
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint8_t  ssl_length;
    uint8_t  ssl_msgtype;
    uint16_t tls_version;
    uint32_t offset = 0;

    /* every SSL/TLS header has to be at least 2 bytes long... */
    /* we need 5 to determine message type and version */
    if (payloadSize < 5) {
        return 0;
    }

    /* FIXME: Change this function to check TLS first and then fallback to
     * SSLv2 if TLS check fails. */

    /*understanding how to determine between SSLv2 and SSLv3/TLS is "borrowed"
     * from OpenSSL payload byte 0 for v2 is the start of the length field, but
     * its MSb is always reserved to tell us how long the length field is, and
     * in some cases, the second MSb is reserved as well */

    /* when length is 2 bytes in size (MSb == 1), and the message type code is
     * 0x01 (client_hello) we know we're doing SSL v2 */
    if ((payload[0] & 0x80) && (0x01 == payload[2])) {
        ssl_length = ((payload[0] & 0x7F) << 8) | payload[1];

        if (ssl_length < 2) {
            return 0;
        }

        ssl_msgtype = 1;
        offset += 3;

        /* this is the version from the handshake message */
        tls_version = ntohs(*(uint16_t *)(payload + offset));
        offset += 2;
        if (tls_version == TLS_VERSION_10 || tls_version == SSL_VERSION_2 ||
            tls_version == SSL_VERSION_3)
        {
            if (!decodeSSLv2(payload, payloadSize, flow, offset, ssl_length)) {
                return 0;
            }
        } else {
            return 0;
        }

        /* SSLv2 (client_hello) */
#ifdef YAF_ENABLE_DPI
        ydRunPluginRegex(flow, payload, 1, NULL, 2,
                         YF_SSL_CLIENT_VERSION, TLS_PORT_NUMBER);
        ydRunPluginRegex(flow, payload, 2, NULL, tls_version,
                         YF_SSL_RECORD_VERSION, TLS_PORT_NUMBER);
#endif /* ifdef YAF_ENABLE_DPI */
        return TLS_PORT_NUMBER;
    } else {
        if ((0x00 == (payload[0] & 0x80)) && (0x00 == (payload[0] & 0x40))
            && (0x01 == payload[3]))
        {
            /* this is ssl v2 but with a 3-byte header */
            /* the second MSb means the record is a data record */
            /* the fourth byte should be 1 for client hello */
            if ((payload[0] == 0x16) && (payload[1] == 0x03)) {
                /* this is most likely tls, not sslv2 */
                goto tls;
            }

            ssl_length = ((payload[0] * 0x3F) << 8) | payload[1];

            if (ssl_length < 3) {
                return 0;
            }
            offset += 4;

            if ((offset + 2) < payloadSize) {
                tls_version = ntohs(*(uint16_t *)(payload + offset));
                offset += 2;

                if (tls_version == TLS_VERSION_10 ||
                    tls_version == SSL_VERSION_2 ||
                    tls_version == SSL_VERSION_3)
                {
                    if (!decodeSSLv2(payload, payloadSize, flow, offset,
                                     ssl_length))
                    {
                        return 0;
                    }
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
#ifdef YAF_ENABLE_DPI
            ydRunPluginRegex(flow, payload, 1, NULL, 2,
                             YF_SSL_CLIENT_VERSION, TLS_PORT_NUMBER);
            ydRunPluginRegex(flow, payload, 2, NULL, tls_version,
                             YF_SSL_RECORD_VERSION, TLS_PORT_NUMBER);
#endif /* ifdef YAF_ENABLE_DPI */
            return TLS_PORT_NUMBER;
        }

      tls:
        if (payloadSize >= 10) {
            /* payload[0] is handshake request [0x16]
             * payload[1] is ssl major version, sslv3 & tls is 3
             * payload[5] is handshake command, 1=client_hello,2=server_hello
             * payload[3,4] is length
             * payload[9] is the version from the record */
            if ((payload[0] == 0x16) && (payload[1] == 0x03) &&
                ((payload[5] == 0x01) || (payload[5] == 0x02)) &&
                (((payload[3] == 0) && (payload[4] < 5)) ||
                 (payload[9] == payload[1])))
            {
                ssl_msgtype = payload[5];
                ssl_length = payload[4];
                tls_version = ntohs(*(uint16_t *)(payload + 1));
                /* 1 for content type, 2 for version, 2 for length,
                 * 1 for handshake type*/
                offset += 6;
                /* now we should be at record length */
                if (!decodeTLSv1(payload, payloadSize, flow, offset,
                                 ssl_length, ssl_msgtype))
                {
                    return 0;
                }

                /* SSLv3 / TLS */
#ifdef YAF_ENABLE_DPI
                ydRunPluginRegex(flow, payload, 1, NULL, 3,
                                 YF_SSL_CLIENT_VERSION, TLS_PORT_NUMBER);
                ydRunPluginRegex(flow, payload, 2, NULL, tls_version,
                                 YF_SSL_RECORD_VERSION, TLS_PORT_NUMBER);
#endif /* ifdef YAF_ENABLE_DPI */
                return TLS_PORT_NUMBER;
            }
        }
    }

    return 0;
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
    yfDPIData_t    *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    yaf_ssl_t      *rec = NULL;
    yaf_ssl_cert_t *sslcert = NULL;
    fbInfoModel_t  *model = ydGetDPIInfoModel();
    int             count = flowContext->startOffset;
    int             total_certs = 0;
    uint32_t       *sslCiphers;
    const uint8_t  *payload = NULL;
    size_t          paySize = 0;
    uint8_t         totalIndex[YAF_MAX_CAPTURE_FIELDS];
    gboolean        ciphertrue = FALSE;
    int             i;
    fbVarfield_t   *sslfull = NULL;
    const fbInfoElement_t *sslCipherIE;
    const fbInfoElement_t *sslCertificateIE;
    uint16_t        version = 0;
    uint16_t        sversion = 0;
    uint16_t       *elliptic_curve = NULL;
    char           *elliptic_format = NULL;
    char           *extension = NULL;
    char           *ser_extension = NULL;
    int             ellip_curve_len = 0;

    rec = (yaf_ssl_t *)fbSubTemplateListInit(stl, 3, YAF_SSL_TID,
                                             yaf_ssl_tmpl, 1);
    sslCipherIE = fbInfoModelGetElementByName(model, "sslCipher");
    sslCertificateIE = fbInfoModelGetElementByName(model,
                                                   "sslBinaryCertificate");

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for ( ; count < totalcap; ++count) {
        if (count < fwdcap) {
            payload = flow->val.payload;
            paySize = flow->val.paylen;
        } else if (flow->rval.payload) {
            payload = flow->rval.payload;
            paySize = flow->rval.paylen;
        } else {
            continue;
        }

        switch (dpi[count].dpacketID) {
          case YF_SSL_CIPHER_LIST:
            /* uses 2 bytes for each cipher */
            sslCiphers = (uint32_t *)fbBasicListInit(
                &rec->sslCipherList, 3, sslCipherIE,
                dpi[count].dpacketCaptLen / 2);
            for (i = 0; i < dpi[count].dpacketCaptLen && sslCiphers; i += 2) {
                *sslCiphers = (uint32_t)ntohs(
                    *(uint16_t *)(payload + dpi[count].dpacketCapt + i));
                sslCiphers = fbBasicListGetNextPtr(&rec->sslCipherList,
                                                   sslCiphers);
            }
            ciphertrue = TRUE;
            break;

          case YF_SSL_COMPRESSION:
            rec->sslCompressionMethod = *(payload + dpi[count].dpacketCapt);
            break;

          case YF_SSL_CLIENT_VERSION:
            /* major version */
            if (!rec->sslClientVersion) {
                rec->sslClientVersion = dpi[count].dpacketCapt;
            }
            break;

          case YF_SSL_RECORD_VERSION:
            /* record version */
            rec->sslRecordVersion = dpi[count].dpacketCapt;
            break;

          case YF_SSL_SERVER_CIPHER:
            rec->sslServerCipher =
                ntohs(*(uint16_t *)(payload + dpi[count].dpacketCapt));
            break;

          case YF_SSL_V2_CIPHER_LIST:
            /* uses 3 bytes for each cipher */
            sslCiphers = (uint32_t *)fbBasicListInit(
                &rec->sslCipherList, 3, sslCipherIE,
                dpi[count].dpacketCaptLen / 3);
            for (i = 0; i < dpi[count].dpacketCaptLen && sslCiphers; i += 3) {
                *sslCiphers =
                    (ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt + i))
                     & 0xFFFFFF00) >> 8;
                sslCiphers = fbBasicListGetNextPtr(&rec->sslCipherList,
                                                   sslCiphers);
            }
            ciphertrue = TRUE;
            break;

          case YF_SSL_CERT_START:
            /* cache location to examine the certificates below */
            totalIndex[total_certs] = count;
            total_certs++;
            break;

          case YF_SSL_SERVER_NAME:
            /* server Name */
            rec->sslServerName.buf =
                (uint8_t *)payload + dpi[count].dpacketCapt;
            rec->sslServerName.len = dpi[count].dpacketCaptLen;
            break;

          case YF_SSL_VERSION:
            version = ntohs(*(uint16_t *)(payload + dpi[count].dpacketCapt));
            break;

          case YF_SSL_ELIPTIC_CURVE:
            ellip_curve_len = dpi[count].dpacketCaptLen / 2;
            elliptic_curve = g_new0(uint16_t, ellip_curve_len);
            for (i = 0; i < ellip_curve_len; i++) {
                elliptic_curve[i] = ntohs(
                    *(uint16_t *)(payload + dpi[count].dpacketCapt + (i * 2)));
            }
            break;

          case YF_SSL_ELIPTIC_FORMAT:
            {
                /* join elliptic curve formats with hyphens */
                GString *str =
                    g_string_sized_new(1 + 4 * dpi[count].dpacketCaptLen);
                for (i = 0; i < dpi[count].dpacketCaptLen; i++) {
                    g_string_append_printf(
                        str, "%u-", *(payload + dpi[count].dpacketCapt + i));
                }
                if (str->len > 1 && '-' == str->str[str->len - 1]) {
                    g_string_truncate(str, str->len - 1);
                }
                elliptic_format = g_string_free(str, FALSE);
            }
            break;

          case YF_SSL_CLIENT_EXTENSION:
            extension = storeExtension(payload + dpi[count].dpacketCapt);
            break;

          case YF_SSL_SERVER_EXTENSION:
            ser_extension = storeExtension(payload + dpi[count].dpacketCapt);
            break;

          case YF_SSL_SERVER_VERSION:
            sversion = ntohs(*(uint16_t *)(payload + dpi[count].dpacketCapt));
            break;

          default:
            g_debug("TLS DPI capture position %u has unexpected value %u"
                    " (len = %u)",
                    count, dpi[count].dpacketID, dpi[count].dpacketCapt);
            break;
        }
    }
    sslClientJA3( &rec->sslCipherList, extension, elliptic_curve,
                  elliptic_format, version, ellip_curve_len, rec->sslClientJA3,
                  &rec->sslClientJA3Fingerprint);
    sslServerJA3S(rec->sslServerCipher, sversion, ser_extension,
                  rec->sslServerJA3S, &rec->sslServerJA3SFingerprint);

    if (!ciphertrue) {
        fbBasicListInit(&rec->sslCipherList, 3, sslCipherIE, 0);
    }

    if (ssl_dpi_off) {
        /* empty since we're doing full cert export */
        sslcert = (yaf_ssl_cert_t *)fbSubTemplateListInit(
            &rec->sslCertList, 3, YAF_SSL_CERT_TID, yaf_ssl_cert_tmpl, 0);
    } else {
        /* use the cached locations of YF_SSL_CERT_START and parse the
         * certificates */
        sslcert = ((yaf_ssl_cert_t *)fbSubTemplateListInit(
                       &rec->sslCertList, 3,
                       YAF_SSL_CERT_TID, yaf_ssl_cert_tmpl, total_certs));
        for (i = 0; i < total_certs; i++) {
            if (totalIndex[i] < fwdcap) {
                payload = flow->val.payload;
                paySize = flow->val.paylen;
            } else if (flow->rval.payload) {
                payload = flow->rval.payload;
                paySize = flow->rval.paylen;
            }
            if (!ypDecodeSSLCertificate(ctx, &sslcert, payload, paySize, flow,
                                        dpi[totalIndex[i]].dpacketCapt))
            {
                if (sslcert->sslIssuerFieldList.tmpl == NULL) {
                    fbSubTemplateListInit(
                        &sslcert->sslIssuerFieldList, 3,
                        YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_tmpl, 0);
                }
                if (sslcert->sslSubjectFieldList.tmpl == NULL) {
                    fbSubTemplateListInit(
                        &sslcert->sslSubjectFieldList, 3,
                        YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_tmpl, 0);
                }
                if (sslcert->sslExtensionFieldList.tmpl == NULL) {
                    fbSubTemplateListInit(
                        &sslcert->sslExtensionFieldList, 3,
                        YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_tmpl, 0);
                }
            }

            if (!(sslcert =
                      fbSubTemplateListGetNextPtr(&rec->sslCertList,
                                                  sslcert)))
            {
                break;
            }
        }
    }

    if (full_cert_export) {
        uint32_t sub_cert_len;
        uint32_t tot_bl_len = 0;
        uint32_t doffset;
        sslfull = (fbVarfield_t *)fbBasicListInit(
            &rec->sslBinaryCertificateList, 3, sslCertificateIE, total_certs);
        for (i = 0; i < total_certs; i++) {
            if (totalIndex[i] < fwdcap) {
                payload = flow->val.payload;
                paySize = flow->val.paylen;
            } else if (flow->rval.payload) {
                payload = flow->rval.payload;
                paySize = flow->rval.paylen;
            }
            doffset = dpi[totalIndex[i]].dpacketCapt;
            if (doffset + 4 > paySize) {
                sslfull->len = 0;
                sslfull->buf = NULL;
                sslfull = (fbVarfield_t *)fbBasicListGetNextPtr(
                    &rec->sslBinaryCertificateList, sslfull);
                continue;
            }
            sub_cert_len =
                (ntohl(*(uint32_t *)(payload + doffset)) & 0xFFFFFF00) >> 8;

            /* only continue if we have enough payload for the whole cert */
            if (doffset + sub_cert_len > paySize) {
                sslfull->len = 0;
                sslfull->buf = NULL;
                sslfull = (fbVarfield_t *)fbBasicListGetNextPtr(
                    &rec->sslBinaryCertificateList, sslfull);
                continue;
            }

            sslfull->buf = (uint8_t *)payload + doffset + 3;
            sslfull->len = sub_cert_len;
            tot_bl_len += sub_cert_len;
            sslfull = (fbVarfield_t *)fbBasicListGetNextPtr(
                &rec->sslBinaryCertificateList, sslfull);
        }

        if (!tot_bl_len) {
            fbBasicListClear(&rec->sslBinaryCertificateList);
            sslfull = (fbVarfield_t *)fbBasicListInit(
                &rec->sslBinaryCertificateList, 3, sslCertificateIE, 0);
        }
    }

    return (void *)rec;
}

gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t      *mdInfo;
    const fbInfoElement_t *bl_element;

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(
        mdInfo, YAF_SSL_NAME, YAF_SSL_DESC, TLS_PORT_NUMBER,
        FB_TMPL_MD_LEVEL_1);
    /* sslCipher */
    bl_element = ydLookupNamedBlByID(CERT_PEN, 185);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, 185);
    }

    if (full_cert_export) {
        /* sslBinaryCertificate */
        bl_element = ydLookupNamedBlByID(CERT_PEN, 296);
        if (bl_element) {
            fbTemplateInfoAddBasicList(mdInfo, bl_element->ent,
                                       bl_element->num, CERT_PEN, 296);
        }

        if (!ydInitTemplate(&yaf_ssl_tmpl, session, yaf_ssl_spec,
                            mdInfo, YAF_SSL_TID, SSL_CERT_EXPORT_FLAG,
                            err))
        {
            return FALSE;
        }
    } else {
        if (!ydInitTemplate(&yaf_ssl_tmpl, session, yaf_ssl_spec,
                            mdInfo, YAF_SSL_TID, 0, err))
        {
            return FALSE;
        }
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(
        mdInfo, YAF_SSL_CERT_NAME, YAF_SSL_CERT_DESC, TLS_PORT_NUMBER,
        YAF_SSL_TID);

    if (!ydInitTemplate(&yaf_ssl_cert_tmpl, session, yaf_ssl_cert_spec,
                        mdInfo, YAF_SSL_CERT_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(
        mdInfo, YAF_SSL_SUBCERT_NAME, YAF_SSL_SUBCERT_DESC, TLS_PORT_NUMBER,
        YAF_SSL_CERT_TID);

    if (!ydInitTemplate(&yaf_ssl_subcert_tmpl, session, yaf_ssl_subcert_spec,
                        mdInfo, YAF_SSL_SUBCERT_TID, 0, err))
    {
        return FALSE;
    }

    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_ssl_t      *rec = (yaf_ssl_t *)flowContext->rec;
    yaf_ssl_cert_t *cert = NULL;

    while ((cert = fbSubTemplateListGetNextPtr(&rec->sslCertList, cert))) {
        fbSubTemplateListClear(&cert->sslIssuerFieldList);
        fbSubTemplateListClear(&cert->sslSubjectFieldList);
        fbSubTemplateListClear(&cert->sslExtensionFieldList);
    }

    fbSubTemplateListClear(&rec->sslCertList);

    fbBasicListClear(&rec->sslCipherList);

    g_free(rec->sslClientJA3Fingerprint.buf);
    g_free(rec->sslServerJA3SFingerprint.buf);

    if (full_cert_export) {
        fbBasicListClear(&rec->sslBinaryCertificateList);
    }
}
#endif  /* YAF_ENABLE_DPI */

static gboolean
decodeTLSv1(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint8_t         datalength,
    uint8_t         type)
{
    uint32_t record_len;
    uint32_t header_len = offset - 1;
    uint32_t cert_len, sub_cert_len;
    uint16_t cert_version;
    int      cert_count = 0;
    uint16_t ciphers = 0;
    uint16_t cipher_suite_len;
    uint8_t  session_len;
    uint8_t  compression_len;
    uint16_t version;

    /* Both Client and Server Hello's start off the same way */
    /* 3 for Length, 2 for Version, 32 for Random, 1 for session ID Len*/
    if ((size_t)offset + 39 > payloadSize) {
        return FALSE;
    }

    record_len = (ntohl(*(uint32_t *)(payload + offset)) & 0xFFFFFF00) >> 8;
    offset += 3;

    cert_version = ntohs(*(uint16_t *)(payload + offset));

    version = offset;
    offset += 34; /* skip version and random */

    session_len = *(payload + offset);
    offset += session_len + 1;

    if ((size_t)offset + 2 > payloadSize) {
        return FALSE;
    }

    if (type == 1) {
        /* Client Hello */

        /* number of ciphers is len divided by 2 */
        cipher_suite_len = ntohs(*(uint16_t *)(payload + offset));
        offset += 2;

        if ((size_t)offset + cipher_suite_len > payloadSize) {
            return FALSE;
        }

        /* ciphers are here */
        ciphers = offset;

        offset += cipher_suite_len;
        if ((size_t)offset + 1 > payloadSize) {
            return FALSE;
        }

        compression_len = *(payload + offset);
        offset += compression_len + 1;

#ifdef YAF_ENABLE_DPI
        ydRunPluginRegex(flow, payload, 2, NULL, cert_version,
                         YF_SSL_RECORD_VERSION, TLS_PORT_NUMBER);
        ydRunPluginRegex(flow, payload, cipher_suite_len, NULL, ciphers,
                         YF_SSL_CIPHER_LIST, TLS_PORT_NUMBER);
        ydRunPluginRegex(flow, payload, 2, NULL, version,
                         YF_SSL_VERSION, TLS_PORT_NUMBER);
#endif /* ifdef YAF_ENABLE_DPI */
    } else if (type == 2) {
        /* Server Hello */
        if ((size_t)offset + 3 > payloadSize) {
            return FALSE;
        }
        /* cipher is here */
#ifdef YAF_ENABLE_DPI
        ydRunPluginRegex(flow, payload, 2, NULL, offset,
                         YF_SSL_SERVER_CIPHER, TLS_PORT_NUMBER);
#endif
        offset += 2;
        /* compression method */
#ifdef YAF_ENABLE_DPI
        ydRunPluginRegex(flow, payload, 2, NULL, cert_version,
                         YF_SSL_RECORD_VERSION, TLS_PORT_NUMBER);
        ydRunPluginRegex(flow, payload, 1, NULL, offset,
                         YF_SSL_COMPRESSION, TLS_PORT_NUMBER);
        ydRunPluginRegex(flow, payload, 2, NULL, version,
                         YF_SSL_SERVER_VERSION, TLS_PORT_NUMBER);
#endif /* ifdef YAF_ENABLE_DPI */
        offset++;
    }

    if (((size_t)offset - header_len) < record_len) {
        /* extensions? */

        const uint16_t ext_len = ntohs(*(uint16_t *)(payload + offset));
#ifdef YAF_ENABLE_DPI
        uint32_t       ext_ptr = offset;
#endif

        offset += 2 + ext_len;

#ifdef YAF_ENABLE_DPI
        if (type == 1) {
            ydRunPluginRegex(flow, payload, 2, NULL, ext_ptr,
                             YF_SSL_CLIENT_EXTENSION, TLS_PORT_NUMBER);
        } else if (type == 2) {
            ydRunPluginRegex(flow, payload, 2, NULL, ext_ptr,
                             YF_SSL_SERVER_EXTENSION, TLS_PORT_NUMBER);
        }
        ext_ptr += 2;

        if (type == 1) {
            uint16_t sub_ext_len;
            uint16_t sub_ext_type;
            uint32_t tot_ext = 0;
            uint32_t ext_ptr2;
            uint16_t eli_curv_len;
            uint8_t  eli_form_len;

            while ((ext_ptr < payloadSize) && (tot_ext < ext_len)) {
                sub_ext_type = ntohs(*(uint16_t *)(payload + ext_ptr));
                ext_ptr += 2;
                sub_ext_len = ntohs(*(uint16_t *)(payload + ext_ptr));
                ext_ptr += 2;
                tot_ext += sizeof(uint16_t) + sizeof(uint16_t) + sub_ext_len;
                ext_ptr2 = ext_ptr;
                ext_ptr += sub_ext_len;

                switch (sub_ext_type) {
                  case 0:
                    /* server name */
                    /* jump past list length and type to get name length and
                     * name */
                    ext_ptr2 += 3; /* 2 for length, 1 for type */
                    sub_ext_len = ntohs(*(uint16_t *)(payload + ext_ptr2));
                    ext_ptr2 += 2;
                    if ((ext_ptr2 + sub_ext_len) < payloadSize) {
                        ydRunPluginRegex(
                            flow, payload, sub_ext_len, NULL, ext_ptr2,
                            YF_SSL_SERVER_NAME, TLS_PORT_NUMBER);
                    }
                    break;

                  case 10:
                    /* elliptic curve list */
                    /* After grabing the length jump past it and grab the
                     * desired list */
                    eli_curv_len = ntohs(*(uint16_t *)(payload + ext_ptr2));
                    ext_ptr2 += 2;
                    if ((ext_ptr2 + eli_curv_len) < payloadSize) {
                        ydRunPluginRegex(
                            flow, payload, eli_curv_len, NULL, ext_ptr2,
                            YF_SSL_ELIPTIC_CURVE, TLS_PORT_NUMBER);
                    }
                    break;

                  case 11:
                    /* elliptic curve point format list */
                    /* After grabing the length jump past it and grab the
                     * desired list */
                    eli_form_len = *(payload + ext_ptr2);
                    ext_ptr2 += 1;
                    if ((ext_ptr2 + eli_form_len) < payloadSize) {
                        ydRunPluginRegex(
                            flow, payload, eli_form_len, NULL, ext_ptr2,
                            YF_SSL_ELIPTIC_FORMAT, TLS_PORT_NUMBER);
                    }
                    break;
                }
            }
        }
#endif /* ifdef YAF_ENABLE_DPI */
    }

    while (payloadSize > offset) {
        switch (*(payload + offset)) {
          case 11:
            /* certificate */
            if ((size_t)offset + 7 > payloadSize) {
                return TRUE; /* prob should be false */
            }
            offset++;
            record_len = (ntohl(*(uint32_t *)(payload + offset)) &
                          0xFFFFFF00) >> 8;
            offset += 3;

            /* Total Cert Length */
            cert_len = (ntohl(*(uint32_t *)(payload + offset)) &
                        0xFFFFFF00) >> 8;
            offset += 3;

            while (payloadSize > (offset + 4)) {
                sub_cert_len = (ntohl(*(uint32_t *)(payload + offset)) &
                                0xFFFFFF00) >> 8;

                if ((sub_cert_len > cert_len) || (sub_cert_len < 2)) {
                    /* it's at least got to have a version number */
                    return TRUE; /* prob should be false */
                } else if (sub_cert_len > payloadSize) {
                    /* just not enough room */
                    return TRUE;
                }

                /* offset of certificate */
                if (cert_count >= MAX_CERTS) {
                    return TRUE;
                }
#ifdef YAF_ENABLE_DPI
                if (((size_t)offset + sub_cert_len + 3) <= payloadSize) {
                    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                                     YF_SSL_CERT_START, TLS_PORT_NUMBER);
                }
#endif /* ifdef YAF_ENABLE_DPI */
                cert_count++;
                offset += 3 + sub_cert_len;
            }
            break;

          case 22:
            /* 1 for type, 2 for version, 2 for length - we know it's long */
            offset += 5;
            break;

          case 20:
          case 21:
          case 23:
            offset += 3; /* 1 for type, 2 for version */
            if (((size_t)offset + 2) > payloadSize) {
                return TRUE; /* prob should be false */
            }
            record_len = ntohs(*(uint16_t *)(payload + offset));
            if (record_len > payloadSize) {
                return TRUE;
            }
            offset += record_len + 2;
            break;

          default:
            return TRUE;
        }
    }

    return TRUE;
}


static gboolean
decodeSSLv2(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint8_t         datalength)
{
    uint32_t record_len;
    uint16_t cipher_spec_length;
    uint16_t challenge_length;
    uint32_t cert_len, sub_cert_len;
    int      cert_count = 0;

    if ((size_t)offset + 6 > payloadSize) {
        return FALSE;
    }

    cipher_spec_length = ntohs(*(uint16_t *)(payload + offset));

    /* cipher_spec_length */
    /* session length */

    offset += 4;

    /* challenge length */
    challenge_length = ntohs(*(uint16_t *)(payload + offset));

    offset += 2;

    if ((size_t)offset + cipher_spec_length > payloadSize) {
        return FALSE;
    }

    if (cipher_spec_length > payloadSize) {
        return FALSE;
    }

#ifdef YAF_ENABLE_DPI
    ydRunPluginRegex(flow, payload, cipher_spec_length, NULL, offset,
                     YF_SSL_V2_CIPHER_LIST, TLS_PORT_NUMBER);
#endif
    offset += cipher_spec_length + challenge_length;

    while (payloadSize > offset) {
        switch (*(payload + offset)) {
          case 11:
            /* certificate */
            if (offset + 7 > payloadSize) {
                return TRUE; /* prob should be false */
            }

            offset++;
            record_len = (ntohl(*(uint32_t *)(payload + offset)) &
                          0xFFFFFF00) >> 8;
            offset += 3;

            /* Total Cert Length */
            cert_len = (ntohl(*(uint32_t *)(payload + offset)) &
                        0xFFFFFF00) >> 8;
            offset += 3;

            while (payloadSize > ((size_t)offset + 4)) {
                sub_cert_len = (ntohl(*(uint32_t *)(payload + offset)) &
                                0xFFFFFF00) >> 8;

                if ((sub_cert_len > cert_len) || (sub_cert_len < 2)) {
                    /* it's at least got to have a version number */
                    return TRUE; /* prob should be false */
                } else if (sub_cert_len > payloadSize) {
                    /* just not enough room */
                    return TRUE;
                }

                /* offset of certificate */
                if (cert_count >= MAX_CERTS) {
                    return TRUE;
                }
#ifdef YAF_ENABLE_DPI
                if (((size_t)offset + sub_cert_len + 3) < payloadSize) {
                    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                                     YF_SSL_CERT_START, TLS_PORT_NUMBER);
                }
#endif /* ifdef YAF_ENABLE_DPI */
                cert_count++;
                offset += 3 + sub_cert_len;
            }
            break;

          case 22:
            /* 1 for type, 2 for version, 2 for length - we know it's long */
            offset += 5;
            break;

          case 20:
          case 21:
          case 23:
            offset += 3; /* 1 for type, 2 for version */
            if (((size_t)offset + 2) > payloadSize) {
                return TRUE; /* prob should be false */
            }
            record_len = ntohs(*(uint16_t *)(payload + offset));
            if (record_len > payloadSize) {
                return TRUE;
            }
            offset += record_len + 2;
            break;

          default:
            return TRUE;
        }
    }

    return TRUE;
}


#ifdef YAF_ENABLE_DPI
/*
 *  Decodes the length in `payload` at the current `offset`, sets the referent
 *  of `offset` to the octet AFTER the length, and returns the length.
 *  `payload_size` is the maximum number of octets to read.
 *
 *  If there are too few bytes to read the length, sets the referent of
 *  `offset` to one more than `payload_size` and returns UINT16_MAX.
 */
static uint16_t
ypDecodeLength(
    const uint8_t  *payload,
    uint32_t        payload_size,
    uint32_t       *offset)
{
    uint16_t obj_len;
    uint8_t  len8;

    /*
     *  When the high bit of the byte at `offset` is not set, that single byte
     *  is the length (0--127).  When the high bit is set, the remaining bits
     *  are the length of length (either 1 byte (0x81) (128--255) or 2 bytes
     *  (0x82) (256--65535) in practice).
     */

    if (*offset + 4 <= payload_size) {
        obj_len = *(payload + *offset);
        ++*offset;
        if (obj_len == CERT_1BYTE) {
            obj_len = *(payload + *offset);
            ++*offset;
        } else if (obj_len == CERT_2BYTE) {
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
            memcpy(&obj_len, (payload + offset), sizeof(uint16_t));
            obj_len = ntohs(obj_len);
#else
            obj_len = ntohs(*(uint16_t *)(payload + *offset));
#endif  /* HAVE_ALIGNED_ACCESS_REQUIRED */
            *offset += 2;
        }

        return obj_len;
    }

    /*
     *  Calling the yfUnpackU*() function-like-macros multiple times is fine
     *  since they won't read data (and they set the referent of their first
     *  argument to 0) when (*offset >= payload_size).
     */

    yfUnpackU8(&len8, payload, offset, payload_size);
    if (len8 == CERT_1BYTE) {
        yfUnpackU8(&len8, payload, offset, payload_size);
        obj_len = len8;
    } else if (len8 == CERT_2BYTE) {
        yfUnpackU16(&obj_len, payload, offset, payload_size);
    } else {
        obj_len = len8;
    }
    if (*offset > payload_size) {
        return UINT16_MAX;
    }

    return obj_len;
}


/*
 *  Decodes the type of value in `payload` at `offset`, fills `tlv` with the
 *  type, moves `offset` to the first octet AFTER the length (that is, to the
 *  first octet of the item the tag describes), and returns the length.
 *  `payload_size` is the maximum number of octets to read.
 *
 *  If the tag is an ASN.1 NULL value (CERT_NULL), continues reading tags
 *  until a non-NULL tag is found or `payload_size` is reached.
 *
 *  If `payload_size` is reached, sets the referent of `offset` to
 *  `payload_size` and returns UINT16_MAX.
 */
static uint16_t
ypDecodeTLV(
    yf_asn_tlv_t   *tlv,
    const uint8_t  *payload,
    uint32_t        payload_size,
    uint32_t       *offset)
{
    uint8_t  val;
    uint16_t obj_len;

    while (*offset < payload_size) {
        val = *(payload + *offset);

        tlv->class = (val & 0xD0) >> 6;
        tlv->p_c = (val & 0x20) >> 5;
        tlv->tag = (val & 0x1F);
        ++*offset;

        obj_len = ypDecodeLength(payload, payload_size, offset);
        if (UINT16_MAX == obj_len || *offset > payload_size) {
            break;
        }
        if (tlv->tag != CERT_NULL) {
            return obj_len;
        }

        *offset += obj_len;
    }

    /* We have run out of bytes */
    *offset = payload_size;
    return UINT16_MAX;
}

/**
 *    Check whether the OID having length `obj_len` and starting at position
 *    *`offset` in `payload` is one that we want to capture.  If so, position
 *    `offset` on the final octet of the OID and return TRUE.  Otherwise leave
 *    `offset` unchanged and return FALSE.
 */
static gboolean
ypDecodeOID(
    const uint8_t  *payload,
    uint32_t       *offset,
    uint8_t         obj_len)
{
    uint32_t tmp_off;
    uint16_t id_at;

#if 0
    /* to print to OID */
    GString *str = g_string_sized_new(3 * obj_len);
    g_string_printf(str, "%02x", *(payload + *offset));
    for (uint32_t i = 1; i < obj_len; ++i) {
        g_string_append_printf(str, " %02x", *(payload + *offset + i));
    }
    g_debug("OID = [%s]", str->str);
    g_string_free(str, TRUE);
#endif  /* 0 */

    /*
     * To check for a child OID (having a value <= 127) one level below id-at
     * or pkcs-9, check that the obj_len is one more than the BER encoding of
     * the parent and move the offset to the child.
     *
     * To check exactly for ldap-domainComponent, check that the length
     * matches exactly, but return an offset one less for consistency with the
     * others.
     */
    switch (obj_len) {
      case 3:
        /* Check for OID under id-at */
        tmp_off = 0;
        yfUnpackU16(&id_at, payload + *offset, &tmp_off, obj_len);
        if (CERT_IDAT == id_at) {
            *offset += 2;
            return TRUE;
        }
        break;
      case 9:
        /* Check for OID under pkcs-9 */
        if (0 == memcmp(payload + *offset, CERT_PKCS, sizeof(CERT_PKCS))) {
            *offset += sizeof(CERT_PKCS);
            return TRUE;
        }
        break;
      case 10:
        /* Check for exactly ldap-domainComponent */
        if (0 == memcmp(payload + *offset, CERT_DC, sizeof(CERT_DC))) {
            *offset += sizeof(CERT_DC) - 1;
            return TRUE;
        }
        break;
    }

    /* this is not the usual id-at, pkcs, or dc - so ignore it */
    return FALSE;
}


/**
 *    Returns the number of sequential CERT_SET objects found in the first
 *    `seq_len` octets of `payload`.  Includes only SETs that are entirely
 *    within `seq_len`.
 */
static uint8_t
ypGetSequenceCount(
    const uint8_t  *payload,
    uint16_t        seq_len)
{
    uint32_t     offset = 0;
    uint16_t     obj_len;
    uint8_t      count = 0;
    yf_asn_tlv_t tlv;

    for (;;) {
        obj_len = ypDecodeTLV(&tlv, payload, seq_len, &offset);
        if (UINT16_MAX == obj_len || offset >= seq_len) {
            return count;
        }
        offset += obj_len;
        if (tlv.tag != CERT_SET || offset > seq_len) {
            return count;
        }
        count++;
    }
}


/**
 *    Loops over the first `ext_len` octets of `payload` which is expected to
 *    contain sequences (CERT_SEQ).  For each sequence, checks whether the
 *    first item is an OID where the OID is 3 octets long, its first two
 *    octets are certificateExtension (CERT_IDCE), and its final octet is a
 *    particular value of interest.
 *
 *    Returns the number of items found.  Includes only items that are
 *    entirely contained within ext_len.
 */
static uint8_t
ypGetExtensionCount(
    const uint8_t  *payload,
    uint16_t        ext_len)
{
    /* When checking whether the ObjectID is under certificateExtension, we
     * read 4 octets into a uint32_t.  The first should be CERT_OID, the
     * second (length) must be 3, and the lower two must those for a
     * certificate extension, CERT_IDCE. */
    const uint32_t  wanted = ((CERT_OID << 24) | 0x030000 | CERT_IDCE);
    uint32_t        oid_len_id_ce;
    uint32_t        offset = 0;
    uint32_t        next_item;
    yf_asn_tlv_t    tlv;
    uint16_t        obj_len = 0;
    uint8_t         count = 0;

    for (;;) {
        obj_len = ypDecodeTLV(&tlv, payload, ext_len, &offset);
        next_item = offset + obj_len;
        if (tlv.tag != CERT_SEQ || next_item > ext_len) {
            return count;
        }

        yfUnpackU32(&oid_len_id_ce, payload, &offset, ext_len);
        if (0 == oid_len_id_ce) {
            return count;
        }
        if (oid_len_id_ce == wanted) {
            switch (*(payload + offset)) {
              case 14:
                /* subject key identifier */
              case 15:
                /* key usage */
              case 16:
                /* private key usage period */
              case 17:
                /* alternative name */
              case 18:
                /* alternative name */
              case 29:
                /* authority key identifier */
              case 31:
                /* CRL dist points */
              case 32:
                /* Cert Policy ID */
              case 35:
                /* Authority Key ID */
              case 37:
                count++;
                break;
            }
        }

        offset = next_item;
    }
}


/**
 *    Processes the Issuer or Subject data at `seq_payload`, having length
 *    `seq_len`, initializes the subTemplateList `subCertSTL`, and adds
 *    `yaf_ssl_subcert_tmpl` records containing sslObjectType and
 *    sslObjectValue pairs to the `subCertSTL`.
 *
 *    Returns FALSE on error.
 */
static gboolean
ypDecodeIssuerSubject(
    fbSubTemplateList_t  *subCertSTL,
    const uint8_t        *seq_payload,
    unsigned int          seq_len)
{
    yaf_ssl_subcert_t *sslObject = NULL;
    yf_asn_tlv_t       tlv = {0, 0, 0};
    uint32_t           offset = 0;
    uint8_t            seq_count;
    uint16_t           obj_len = 0;
    uint32_t           set_end;

    /* Each item is CERT_SET containing a CERT_SEQ which contains a CERT_OID
     * to label the data and the data itself (typically one of the string
     * types) */

    seq_count = ypGetSequenceCount(seq_payload, seq_len);
    sslObject = (yaf_ssl_subcert_t *)fbSubTemplateListInit(
        subCertSTL, 3, YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_tmpl, seq_count);

    for ( ; seq_count && sslObject; --seq_count, ++sslObject) {
        obj_len = ypDecodeTLV(&tlv, seq_payload, seq_len, &offset);
        /* note offset for the end of this set */
        set_end = offset + obj_len;
        if (set_end > seq_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SET) {
            break;
        }

        obj_len = ypDecodeTLV(&tlv, seq_payload, seq_len, &offset);
        if (offset + obj_len > seq_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            break;
        }

        obj_len = ypDecodeTLV(&tlv, seq_payload, seq_len, &offset);
        if (offset + obj_len > seq_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_OID) {
            break;
        }

        if (!ypDecodeOID(seq_payload, &offset, obj_len)) {
            offset = set_end;
            continue;
        }

        /*
         *  ypDecodeOID() leaves `offset` on final octet of the OID which we
         *  use as the type.  The +2 moves us to the length of the data (we
         *  skip the ASN.1 type octet since we don't care about it).
         */

        sslObject->sslObjectType = *(seq_payload + offset);
        offset += 2;
        obj_len = ypDecodeLength(seq_payload, seq_len, &offset);
        if (offset + obj_len > seq_len) {
            sslObject->sslObjectType = 0;
            return FALSE;
        }

        /* OBJ VALUE */
        sslObject->sslObjectValue.buf = (uint8_t *)seq_payload + offset;
        sslObject->sslObjectValue.len = obj_len;
        offset += obj_len;
    }

#if 0
    /* The while() should take us the the end of the sequence, but we could
     * "break" out early for an unexpected case. */
    if (offset != seq_len) {
        g_debug("Issuer/Subject: offset is %u but expected to be at %u."
                "  Most recent tag was %#04x having length %u",
                offset, seq_len, tlv.tag, obj_len);
    }
#endif  /* 0 */

    return TRUE;
}


/**
 *  Called to parse one certificate whose starting-offset was captured while
 *  scanning the payload (YF_SSL_CERT_START).
 *
 *  @param ctx          DPI Context (unused)
 *  @param sslCert      the record within an STL to fill
 *  @param payload      all of the captured payload (either forward/reverse)
 *  @param payloadSize  the size of the payload
 *  @param flow         the current (top-level) flow record (unused)
 *  @param offset       the offset of the certificate's start within `paylaod`
 */
static gboolean
ypDecodeSSLCertificate(
    yfDPIContext_t  *ctx,
    yaf_ssl_cert_t **sslCert,
    const uint8_t   *payload,
    unsigned int     payloadSize,
    yfFlow_t        *flow,
    uint32_t         offset)
{
    yaf_ssl_subcert_t *sslObject = NULL;
    yf_asn_tlv_t       tlv;
    uint32_t           sub_cert_len;
    uint32_t           ext_end_offset;
    uint8_t            seq_count;
    uint16_t           obj_len;
    uint16_t           tmp16;

    (*sslCert)->sslCertificateHash.len = 0;

    /*
     *  Notes:
     *
     *  The certificate is represented as sequence containing two objects:
     *  Another sequence for the certificate's details and a sequence for the
     *  signature.
     *
     *  The ASN.1 sequences (0x10) in the certificate have the contructed bit
     *  set (bit-6, 0x20), resulting in 0x30 when examining the raw octets.
     *  Similarly, a raw octet for an ASN.1 set (0x11) appears as 0x31.
     *
     *  In much of the following, it would be more correct to use the length
     *  of the inner-most containing sequence as the upper limit instead of
     *  `sub_cert_len`.
     */

    /* we start with the length of inner cert; `sub_cert_len` does not include
     * the bytes that hold the length. */
    yfUnpackU32(&sub_cert_len, payload, &offset, payloadSize);
    if (0 == sub_cert_len || offset >= payloadSize) {
        /* not enough payload to read the length */
        return FALSE;
    }

    /* The length is only 3 octets but yfUnpackU32() moved 4 octets, so
     * decrement `offset` and adjust `sub_cert_len` */
    --offset;
    sub_cert_len = sub_cert_len >> 8;

    /* only continue if we have enough payload for the whole cert */
    if (offset + sub_cert_len > payloadSize) {
        return FALSE;
    }

    /* use local values for the payload and offset so we can ensure `cert_off`
     * never exceeds `sub_cert_len` */
    const uint8_t *cert_pay = payload + offset;
    uint32_t cert_off = 0;

    /* We expect a sequence (0x30) where the length is specified in two bytes
     * (CERT_2BYTE) [0x30 0x82] */
    yfUnpackU16(&tmp16, cert_pay, &cert_off, sub_cert_len);
    if (tmp16 != 0x3082) {
        return FALSE;
    }

    /* yfUnpackU16() moved forward 2.  The following moves forward over the 2
     * bytes holding the sequence's length, over the tag for the inner
     * sequence (0x3082 again (+2)), and over its length (+2). */
    cert_off += 6;
    if (cert_off >= sub_cert_len) {
        return FALSE;
    }

    /* the version is next unless this is version 1 certificate (1988).  The
     * version is denoted by CERT_EXPLICIT (0xA0), where the following octet
     * is its length (expected to be 0x03), followed by an object type
     * (CERT_INT == 0x02), the length of the integer (expected to be 0x01),
     * and finally the version number. */
    if (*(cert_pay + cert_off) == CERT_EXPLICIT) {
        cert_off += 4;
        yfUnpackU8(&((*sslCert)->sslCertVersion),
                   cert_pay, &cert_off, sub_cert_len);
        if (cert_off > sub_cert_len) {
            return FALSE;
        }
    } else {
        /* default version is version 1 [0] */
        (*sslCert)->sslCertVersion = 0;
    }

    /* serial number */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len > sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag == CERT_INT) {
        (*sslCert)->sslCertSerialNumber.buf = (uint8_t *)cert_pay + cert_off;
        (*sslCert)->sslCertSerialNumber.len = obj_len;
    }
    cert_off += obj_len;

    /* signature algorithm */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len > sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        cert_off += obj_len;
    } else {
        obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
        if (cert_off + obj_len > sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag == CERT_OID) {
            (*sslCert)->sslCertSignature.buf = (uint8_t *)cert_pay + cert_off;
            (*sslCert)->sslCertSignature.len = obj_len;
        }
        cert_off += obj_len;
    }


    /* ISSUER - sequence */

    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len > sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        return FALSE;
    }
    if (!ypDecodeIssuerSubject(
            &(*sslCert)->sslIssuerFieldList, cert_pay + cert_off, obj_len))
    {
        return FALSE;
    }
    cert_off += obj_len;

    /* VALIDITY is a sequence of times */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        return FALSE;
    }

    /* notBefore time */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_TIME) {
        return FALSE;
    }
    (*sslCert)->sslCertValidityNotBefore.buf = (uint8_t *)cert_pay + cert_off;
    (*sslCert)->sslCertValidityNotBefore.len = obj_len;

    cert_off += obj_len;

    /* not After time */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_TIME) {
        return FALSE;
    }
    (*sslCert)->sslCertValidityNotAfter.buf = (uint8_t *)cert_pay + cert_off;
    (*sslCert)->sslCertValidityNotAfter.len = obj_len;

    cert_off += obj_len;

    /* SUBJECT - sequence */

    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        return FALSE;
    }
    if (!ypDecodeIssuerSubject(
            &(*sslCert)->sslSubjectFieldList, cert_pay + cert_off, obj_len))
    {
        return FALSE;
    }
    cert_off += obj_len;

    /* subject public key info */
    /* this is a sequence of a sequence of algorithms and public key */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        cert_off += obj_len;
    } else {
        /* this is also a seq */
        obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
        if (cert_off + obj_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            cert_off += obj_len;
        } else {
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (cert_off + obj_len >= sub_cert_len) {
                return FALSE;
            }
            /* this is the algorithm id */
            if (tlv.tag == CERT_OID) {
                (*sslCert)->sslPublicKeyAlgorithm.buf =
                    (uint8_t *)cert_pay + cert_off;
                (*sslCert)->sslPublicKeyAlgorithm.len = obj_len;
            }
            cert_off += obj_len;
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (cert_off + obj_len >= sub_cert_len) {
                return FALSE;
            }
            /* this is the actual public key */
            if (tlv.tag == CERT_BITSTR) {
                (*sslCert)->sslPublicKeyLength = obj_len;
            }
            cert_off += obj_len;
        }
    }

    /* EXTENSIONS! - ONLY AVAILABLE FOR VERSION 3 */
    /* since it's optional - it has a tag if it's here */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }

    if ((tlv.class != 2) || ((*sslCert)->sslCertVersion != 2)) {
        /* no extensions */
        ext_end_offset = cert_off;
        fbSubTemplateListInit(&(*sslCert)->sslExtensionFieldList, 3,
                              YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_tmpl, 0);
    } else {
        obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
        /* note offset after all extensions */
        ext_end_offset = cert_off + obj_len;
        if (ext_end_offset >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            return FALSE;
        }

        /* extensions */
        seq_count = ypGetExtensionCount((cert_pay + cert_off), obj_len);
        sslObject = (yaf_ssl_subcert_t *)fbSubTemplateListInit(
            &(*sslCert)->sslExtensionFieldList, 3,
            YAF_SSL_SUBCERT_TID, yaf_ssl_subcert_tmpl, seq_count);

        /* exts is a sequence of a sequence of {id, critical flag, value} */
        while (seq_count && sslObject) {
            /* the offset at the end of the current extension */
            uint32_t cur_ext_end;
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            cur_ext_end = cert_off + obj_len;
            if (cur_ext_end >= sub_cert_len) {
                return FALSE;
            }
            if (tlv.tag != CERT_SEQ) {
                return FALSE;
            }

            /* get the object ID and see if it is one we want */
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (cert_off + obj_len >= cur_ext_end) {
                return FALSE;
            }
            if (tlv.tag != CERT_OID) {
                return FALSE;
            }
            if (obj_len != 3) {
                /* ignore this object */
                cert_off = cur_ext_end;
                continue;
            }
            yfUnpackU16(&tmp16, cert_pay, &cert_off, sub_cert_len);
            if (tmp16 != CERT_IDCE) {
                /* ignore this object */
                cert_off = cur_ext_end;
                continue;
            }

            /* keep this switch() in sync with ypGetExtensionCount() */
            switch (*(cert_pay + cert_off)) {
              case 14:
                /* subject key identifier */
              case 15:
                /* key usage */
              case 16:
                /* private key usage period */
              case 17:
                /* alternative name */
              case 18:
                /* alternative name */
              case 29:
                /* authority key identifier */
              case 31:
                /* CRL dist points */
              case 32:
                /* Cert Policy ID */
              case 35:
                /* Authority Key ID */
              case 37:
                /* ext. key usage */
                break;
              default:
                /* ignore it; go to the next one */
                cert_off = cur_ext_end;
                continue;
            }

            /* wanted; decode the rest of this extension */
            sslObject->sslObjectType = *(cert_pay + cert_off);
            ++cert_off;

            /* read the next tag, which may give the type and length of the
             * data or indicate an optional CRITICAL flag if it is a
             * boolean */
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (cert_off + obj_len > cur_ext_end) {
                sslObject->sslObjectType = 0;
                return FALSE;
            }
            if (tlv.tag == CERT_BOOL) {
                cert_off += obj_len;
                /* this should be the object's data type and length */
                obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
                if (cert_off + obj_len > cur_ext_end) {
                    sslObject->sslObjectType = 0;
                    return FALSE;
                }
            }

            sslObject->sslObjectValue.len = obj_len;
            sslObject->sslObjectValue.buf = (uint8_t *)cert_pay + cert_off;
            cert_off += obj_len;
            seq_count--;
            sslObject++;
        }
    }

    if (cert_hash_export) {
        /* The signaure is represented by a sequence containing an OID which
         * is signing algorithm (a repeat of what we saw above) and the
         * signature bitstring */

        cert_off = ext_end_offset;
        if (cert_off >= sub_cert_len) {
            return TRUE;
        }

        obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
        if (cert_off + obj_len > sub_cert_len) {
            return TRUE;
        }

        if (tlv.tag == CERT_SEQ) {
            /* skip the OID */
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (tlv.tag != CERT_OID) {
                return TRUE;
            }
            cert_off += obj_len;
            if (cert_off >= sub_cert_len) {
                return TRUE;
            }

            /* read the bitstring */
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (tlv.tag != CERT_BITSTR) {
                return TRUE;
            }
            if (cert_off + obj_len > sub_cert_len) {
                return TRUE;
            }

            /* there is one octet of padding; ignore it */
            cert_off++;
            obj_len -= 1;

            /* must be a multiple of 16 */
            if (obj_len & 0xF) {
                return TRUE;
            }
            (*sslCert)->sslCertificateHash.len = obj_len;
            (*sslCert)->sslCertificateHash.buf = (uint8_t *)cert_pay + cert_off;
        }
    }

    return TRUE;
}
#endif  /* YAF_ENABLE_DPI */


/**
 * ydpInitialize
 *
 * Processes the plugin's arguments to determine whether to enable (1)full
 * certificate export and (2)certifcate hash export and enables DPI Information
 * Elements.
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
    if (!applabelOnly) {
        /* the first argument is the plugin's name */

        /* the second argument determines whether to enable export of the
         * complete binary X.509 certificate instead of DPI processing */
        if (argc > 1 && (0 == strcmp("true", argv[1]))) {
            full_cert_export = TRUE;
            ssl_dpi_off = TRUE;
            g_debug("SSL [Full] Certificate Export Enabled.");
        }

        /* the third argument determines whether to enable export of the
         * certificate's hash; if set, re-enables DPI export if
         * full_cert_export disabled it */
        if (argc > 2 && (0 == strcmp("true", argv[2]))) {
            cert_hash_export = TRUE;
            ssl_dpi_off = FALSE;
            g_debug("SSL Certificate Hash Export Enabled.");
        }
    }
    pluginExtras_t *pluginExtras = (pluginExtras_t *)extra;
    GArray         *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;

    YC_ENABLE_ELEMENTS(yaf_ssl, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_ssl_cert, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_ssl_subcert, pluginTemplates);
#endif /* ifdef YAF_ENABLE_DPI */

    return 1;
}

#ifdef YAF_ENABLE_DPI
/**
 * sslServerJA3
 *
 * Processes the plugin's arguments to create a string that will be used to
 * generate an MD5 Hash of a server response
 */
static void
sslServerJA3S(
    uint16_t       scipher,
    uint16_t       sversion,
    char          *ser_extension,
    uint8_t       *smd5,
    fbVarfield_t  *string)
{
    GString *str = g_string_sized_new(500);

    if (sversion != 0) {
        g_string_append_printf(str, "%hu,", sversion);
        g_string_append_printf(str, "%hu,", scipher);
    } else {
        g_string_append(str, ",,");
    }

    if (ser_extension != NULL) {
        g_string_append_printf(str, "%s", ser_extension);
    }

    g_free(ser_extension);
    computeMD5(str->str, str->len, smd5);
    string->len = str->len;
    string->buf = (uint8_t *)g_string_free(str, FALSE);
}

/**
 * sslClientJA3
 *
 * Processes the plugin's arguments to create a string that will be used to
 * generate an MD5 Hash of a client response.
 */
static void
sslClientJA3(
    fbBasicList_t  *ciphers,
    char           *extension,
    uint16_t       *elliptic_curve,
    char           *elliptic_format,
    uint16_t        version,
    int             ellip_curve_len,
    uint8_t        *md5,
    fbVarfield_t   *string)
{
    GString  *str = g_string_sized_new(500);
    int       i;
    uint16_t *cipher;

    /*The version is added to the string*/
    if (version != 0) {
        g_string_append_printf(str, "%hu,", version);
    } else {
        g_string_append(str, ",,");
    }
    /*The ciphers are beinf added to the string*/
    for (i = 0; (cipher = (uint16_t *)fbBasicListGetIndexedDataPtr(ciphers, i));
         i++)
    {
        if (!greaseTableCheck(*cipher)) {
            g_string_append_printf(str, "%hu-", *cipher);
        }
    }
    if (str->str[str->len - 1] == '-') {
        g_string_truncate(str, str->len - 1);
        g_string_append(str, ",");
    }

    /*Extensions are added at this point*/
    if (extension != NULL) {
        g_string_append_printf(str, "%s,", extension);
        /*The eliptical curve is added to string*/
        if (elliptic_curve != NULL) {
            for (i = 0; i < ellip_curve_len; i++) {
                if (!greaseTableCheck(elliptic_curve[i])) {
                    g_string_append_printf(str, "%hu-", elliptic_curve[i]);
                }
            }
            if (str->str[str->len - 1] == '-') {
                g_string_truncate(str, str->len - 1);
                g_string_append(str, ",");
            }
        } else {
            g_string_append(str, ",");
        }
        /*The elliptical format is added to the string*/
        if (elliptic_format != NULL) {
            g_string_append_printf(str, "%s", elliptic_format);
        }
    } else {
        g_string_append(str, ",,");
    }

    g_free(elliptic_curve);
    g_free(elliptic_format);
    g_free(extension);
    computeMD5(str->str, str->len, md5);
    string->len = str->len;
    string->buf = (uint8_t *)g_string_free(str, FALSE);
}

/**
 * computeMD5
 *
 * Processes the plugin's arguments to generate an MD5 Hash
 *
 */
#ifdef HAVE_OPENSSL
static void
computeMD5(
    const char  *string,
    int          len,
    uint8_t     *mdbuff)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000
    MD5((const unsigned char *)string, len, mdbuff);
#else
    EVP_MD_CTX   *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char md_size[EVP_MAX_MD_SIZE];
    unsigned int  md_len;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, string, len);
    EVP_DigestFinal_ex(mdctx, md_size, &md_len);
    EVP_MD_CTX_free(mdctx);

    memcpy(mdbuff, md_size, 16);
#endif /* if OPENSSL_VERSION_NUMBER < 0x30000000 */
}
#endif /* ifdef HAVE_OPENSSL */

/**
 * sslClientJA3
 *
 * Processes the plugin's argument to verify if an extension is equal to a
 * grease table value
 */
static gboolean
greaseTableCheck(
    uint16_t   value)
{
    uint16_t greaseTable[] = {
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
        35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250
    };

    for (size_t i = 0; i < sizeof(greaseTable) / sizeof(greaseTable[0]); i++) {
        if (greaseTable[i] == value) {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 *  Takes the position in the payload where the extension list begins
 *  (specifically on the length of the extension list) and returns a newly
 *  allocated string containing the extension types joined by a hyphen.
 *
 *  The caller must g_free() the string when no longer required.
 */
static char *
storeExtension(
    const uint8_t  *payload)
{
    uint16_t total_count = ntohs(*(uint16_t *)payload);
    uint16_t ext_type = 0;
    uint16_t ext_len = 0;
    uint32_t offset = 0;
    uint32_t total_ext = 0;

    GString *str = g_string_sized_new(500);

    offset += 2;

    while (total_ext + 4 < total_count) {
        ext_type = ntohs(*(uint16_t *)(payload + offset));
        offset += 2;
        ext_len = ntohs(*(uint16_t *)(payload + offset));
        offset += 2;
        total_ext += sizeof(uint16_t) + sizeof(uint16_t) + ext_len;
        if (!greaseTableCheck(ext_type)) {
            g_string_append_printf(str, "%hu-", ext_type);
        }
        offset += ext_len;
    }
    if (str->len > 0 && str->str[str->len - 1] == '-') {
        g_string_truncate(str, str->len - 1);
    }
    return g_string_free(str, FALSE);
}
#endif  /* YAF_ENABLE_DPI */
