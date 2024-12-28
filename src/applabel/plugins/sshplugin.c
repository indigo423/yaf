/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file sshplugin.c
 *
 *
 *  This recognizes SSH packets
 *
 *  Remember to update proxyplugin.c with any changes.
 *  ------------------------------------------------------------------------
 *  Authors: Steven Ibarra
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

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif
#endif  /* HAVE_OPENSSL */

#define YAF_SSH_TID   0xCC01
#define YAF_SSH_NAME  "yaf_ssh"
#define YAF_SSH_DESC  NULL

static fbInfoElementSpec_t yaf_ssh_spec[] = {
    {"sshVersion",               FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sshServerVersion",         FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sshKeyExchangeAlgorithm",  FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sshHostKeyAlgorithm",      FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sshServerHostKey",         16,           YAF_DISABLE_IE_FLAG },
    {"sshCipher",                FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sshMacAlgorithm",          FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sshCompressionMethod",     FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sshHassh",                 16,           YAF_DISABLE_IE_FLAG },
    {"sshServerHassh",           16,           YAF_DISABLE_IE_FLAG },
    {"sshHasshAlgorithms",       FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"sshServerHasshAlgorithms", FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_ssh_st {
    fbVarfield_t   sshVersion;
    fbVarfield_t   sshServerVersion;
    fbVarfield_t   sshKeyExchangeAlgorithm;
    fbVarfield_t   sshHostKeyAlgorithm;
    uint8_t        sshServerHostKey[16];
    fbVarfield_t   sshCipher;
    fbVarfield_t   sshMacAlgorithm;
    fbVarfield_t   sshCompressionMethod;
    uint8_t        sshHassh[16];
    uint8_t        sshServerHassh[16];
    fbVarfield_t   sshHasshAlgorithms;
    fbVarfield_t   sshServerHasshAlgorithms;
} yaf_ssh_t;

static fbTemplate_t *yaf_ssh_tmpl;


/* IDs used by yfDPIData_t->dpacketID */
/* SSH List of Key Exchange Algorithms */
#define YF_SSH_KEX_ALGO                 20
/* SSH List of Host Key Algorithms */
#define YF_SSH_SERVER_HOST_KEY_ALGO     21
/* SSH List of Encryption Algorithms Client to Server */
#define YF_SSH_ENCRYPTION_ALGO_CLI_SRV  22
/* SSH List of MAC Algorithms Client to Server */
#define YF_SSH_MAC_ALGO_CLI_SRV         23
/* SSH List of Compression Algorithms Client to Server */
#define YF_SSH_COMPRESS_ALGO_CLI_SRV    24
/* SSH List of Encryption Algorithms Server to Client */
#define YF_SSH_ENCRYPTION_ALGO_SRV_CLI  25
/* SSH List of MAC Algorithms Server to Client */
#define YF_SSH_MAC_ALGO_SRV_CLI         26
/* SSH List of Compression Algorithms Server to Client */
#define YF_SSH_COMPRESS_ALGO_SRV_CLI    27
/* SSH Host Key */
#define YF_SSH_HOST_KEY                 28
/* SSH Version reported in initial packet */
#define YF_SSH_VERSION                  29
/* Client's KEX Request value */
#define YF_SSH_CLIENT_KEX_REQUEST       30


/* Values defined in the SSH RFCs. For a complete list:
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml */

/* Values between 1 and 19 are transport layer messages */
#define SSH_MSG_DISCONNECT              1

/* Key exchange initialization */
#define SSH2_MSG_KEXINIT                20
#define SSH2_MSG_NEWKEYS                21

/*
 * To find the message containing the host key, examine the message from the
 * client after the KEXINIT message.  Per RFC 4253 Section 8, if the client
 * sends KEXDH_INIT (or ECDH_INIT), the server sends the host key in the
 * KEXDH_REPLY (or ECDH_REPLY) message.  Per RFC 4419, if the client sends
 * group exchange init (KEX_DH_GEX_REQUEST), the server responds with
 * KEX_DH_GEX_GROUP, the client responds with MSG_KEX_DH_GEX_INIT (32), and
 * the server responds with KEX_DH_GEX_REPLY which contains the host key.
 */
#define SSH_MSG_KEXDH_INIT          30
#define SSH_MSG_KEXDH_REPLY         31
#define SSH2_MSG_KEX_ECDH_INIT      30
#define SSH2_MSG_KEX_ECDH_REPLY     31
#define SSH_MSG_KEX_DH_GEX_REQUEST  34
#define SSH_MSG_KEX_DH_GEX_GROUP    31
#define SSH_MSG_KEX_DH_GEX_REPLY    33

#endif  /* YAF_ENABLE_DPI */

#define SSH_PORT_NUMBER 22

/*
 * the compiled regular expressions
 */
static pcre *sshVersionRegex = NULL;


#ifdef YAF_ENABLE_DPI
static void
ssh_HASSH(
    GString       *kex,
    const gchar   *encryp,
    const gchar   *mac,
    const gchar   *compression,
    uint8_t       *md5,
    fbVarfield_t  *string);

#ifdef HAVE_OPENSSL
static void
compute_MD5(
    const char  *string,
    int          len,
    uint8_t     *mdbuff);
#else  /* HAVE_OPENSSL */
#define compute_MD5(_s, _l, _buf)   memset(_buf, 0, 16)
#endif  /* HAVE_OPENSSL */

static void
algo_Compare(
    const GString *str,
    const GString *str2,
    fbVarfield_t  *str3);
#endif  /* YAF_ENABLE_DPI */


/**
 * ydpScanPayload
 *
 * scans a given payload to see if it conforms to our idea of what SSH traffic
 * looks like.
 *
 *
 *
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match SSH_PORT_NUMBER (22) for a match
 *
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#define NUM_CAPT_VECTS 60
    int vects[NUM_CAPT_VECTS];
    int rc;

    rc = pcre_exec(sshVersionRegex, NULL, (char *)payload, payloadSize, 0,
                   0, vects, NUM_CAPT_VECTS);
    if (rc <= 0) {
        return 0;
    }

#ifdef YAF_ENABLE_DPI
    uint32_t offset = 0;
    uint8_t  message_code = 0;
    uint32_t algo_length = 0;
    uint32_t packet_length = 0;
    uint32_t available_bytes = 0;
    uint32_t host_key_length = 0;
    uint32_t host_key_offset = 0;
    gboolean host_key_found = FALSE;

    if (rc == 2) {
        /* Server and Client*/
        ydRunPluginRegex(flow, payload, payloadSize, sshVersionRegex, 0,
                         YF_SSH_VERSION, SSH_PORT_NUMBER);
    }

    /*
     * Use the offset of the end of the regex to determine the start of the
     * Binary Protocol (RFC4253 Section 6)
     */
    offset = vects[1];

    /* Look for KEXINIT message, ignoring transport messages (2-19) */
    for (;;) {
        packet_length = ntohl(*(uint32_t *)(payload + offset));
        if ((packet_length + offset) >= payloadSize) {
            return SSH_PORT_NUMBER;
        }
        available_bytes = packet_length;

        /* Move the offset over Packet Length(4) and Padding Length(1);
         * subtract the Padding Length from available_bytes */
        offset += 5; available_bytes -= 1;

        /* We are expecting a Key Exchange Init Message (RFC 4253 Section 7) */
        message_code = *(payload + offset);
        if (message_code == SSH2_MSG_KEXINIT) {
            break;
        }
        if (message_code > SSH2_MSG_KEXINIT ||
            message_code == SSH_MSG_DISCONNECT ||
            message_code == 0)
        {
            return SSH_PORT_NUMBER;
        }
        /* Go to next packet for a message_code < 20 */
        offset += available_bytes;
    }

    /* Skip the KEXINIT mesage code(1) and the cookie (16 random bytes) */
    offset += 17; available_bytes -= 17;

    /* Note: We store the locations of algorithms' lengths in the
     * flowContext->dpi[] array since storing the entire text exceeds the
     * length that YAF permits DPI code to store. */

    /* Kex algorithms */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                     YF_SSH_KEX_ALGO, SSH_PORT_NUMBER);
    /* End of Algorith String */
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Server host key algorithms */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                     YF_SSH_SERVER_HOST_KEY_ALGO, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Encryption algorithms client to server */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                     YF_SSH_ENCRYPTION_ALGO_CLI_SRV, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Encryption algorithms for the server to client response */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                     YF_SSH_ENCRYPTION_ALGO_SRV_CLI, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* MAC algorithms client to server */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                     YF_SSH_MAC_ALGO_CLI_SRV, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* MAC algorithms server to client */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                     YF_SSH_MAC_ALGO_SRV_CLI, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Compression algorithms client to server */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                     YF_SSH_COMPRESS_ALGO_CLI_SRV, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Compression algorithms server to client */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    ydRunPluginRegex(flow, payload, 1, NULL, offset,
                     YF_SSH_COMPRESS_ALGO_SRV_CLI, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Finished with KEXINIT packet; move to next packet start */
    offset += available_bytes;

    /* Look for the key exchange messages, codes 30--34 */
    while (!host_key_found) {
        packet_length = ntohl(*(uint32_t *)(payload + offset));
        if ((packet_length + offset) >= payloadSize) {
            return SSH_PORT_NUMBER;
        }
        available_bytes = packet_length;
        offset += 5; available_bytes -= 1;

        /* Check for key exchange messages */
        message_code = *(payload + offset);
        switch (message_code) {
          case SSH_MSG_KEXDH_INIT:
          case SSH_MSG_KEX_DH_GEX_REQUEST:
            /* Client side messages; store the code in the offset location and
             * return */
            ydRunPluginRegex(flow, payload, 1, NULL, message_code,
                             YF_SSH_CLIENT_KEX_REQUEST, SSH_PORT_NUMBER);
            return SSH_PORT_NUMBER;

          case SSH_MSG_KEX_DH_GEX_REPLY:
            /* Server side that definitely holds the host key */
            host_key_found = TRUE;
            /* FALLTHROUGH */
          case SSH_MSG_KEX_DH_GEX_GROUP:
            /* Server side that may hold the host key; cache the location.
             * Note that the offset is on the message_code so its value can be
             * checked by ydpProcessDPI(). */
            host_key_offset = offset;
            offset += 1; available_bytes -= 1;
            host_key_length = ntohl(*(uint32_t *)(payload + offset));
            if (host_key_length > available_bytes) {
                return SSH_PORT_NUMBER;
            }
            break;

          case 0:
          case SSH_MSG_DISCONNECT:
            /* give up */
            return SSH_PORT_NUMBER;

          case SSH2_MSG_NEWKEYS:
            /* stop looking */
            host_key_found = TRUE;
            break;

          default:
            if (message_code >= SSH2_MSG_KEXINIT) {
                /* stop looking */
                host_key_found = TRUE;
            }
            /* else ignore any message that uses codes 2-19 */
            break;
        }

        /* move to the next packet */
        offset += available_bytes;
    }

    if (host_key_offset) {
        ydRunPluginRegex(flow, payload, 1, NULL, host_key_offset,
                         YF_SSH_HOST_KEY, SSH_PORT_NUMBER);
    }
#endif  /* YAF_ENABLE_DPI */

    return SSH_PORT_NUMBER;
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
    yfDPIData_t   *dpi = flowContext->dpi;
    int            count = flowContext->startOffset;
    const uint8_t *payload = NULL;
    yaf_ssh_t     *rec = NULL;
    uint8_t        client_kex_request = 0;
    uint8_t        server_kex_reply = 0;
    uint32_t       server_kex_offset = 0;

    /* True if it is a client response */
    gboolean       client;
    GString       *kex_algo =                g_string_sized_new(500);
    GString       *server_host =             g_string_sized_new(500);
    GString       *encryptio_algo =          g_string_sized_new(500);
    GString       *mac_algo =                g_string_sized_new(500);
    GString       *compression_algo =        g_string_sized_new(500);
    GString       *kex_algo_server =         g_string_sized_new(500);
    GString       *encryptio_algo_server =   g_string_sized_new(500);
    GString       *mac_algo_server =         g_string_sized_new(500);
    GString       *compression_algo_server = g_string_sized_new(500);
    GString       *server_host_server =      g_string_sized_new(500);
    GString       *server_host_key    =      g_string_sized_new(500);

    rec = (yaf_ssh_t *)fbSubTemplateListInit(stl, 3, YAF_SSH_TID,
                                             yaf_ssh_tmpl, 1);

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    payload = flow->val.payload;
    client = TRUE;

    for (count = flowContext->startOffset; count < totalcap; ++count) {
        if (count == fwdcap) {
            payload = flow->rval.payload;
            client = FALSE;
        }

        switch (dpi[count].dpacketID) {
          case YF_SSH_KEX_ALGO:
            if (client) {
                g_string_append_len(
                    kex_algo,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            } else {
                g_string_append_len(
                    kex_algo_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_SERVER_HOST_KEY_ALGO:
            if (client) {
                g_string_append_len(
                    server_host,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            } else {
                g_string_append_len(
                    server_host_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_ENCRYPTION_ALGO_CLI_SRV:
            if (client) {
                g_string_append_len(
                    encryptio_algo,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_MAC_ALGO_CLI_SRV:
            if (client) {
                g_string_append_len(
                    mac_algo,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_COMPRESS_ALGO_CLI_SRV:
            if (client) {
                g_string_append_len(
                    compression_algo,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_ENCRYPTION_ALGO_SRV_CLI:
            if (!client) {
                g_string_append_len(
                    encryptio_algo_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_MAC_ALGO_SRV_CLI:
            if (!client) {
                g_string_append_len(
                    mac_algo_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_COMPRESS_ALGO_SRV_CLI:
            if (!client) {
                g_string_append_len(
                    compression_algo_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_CLIENT_KEX_REQUEST:
            if (client) {
                client_kex_request = dpi[count].dpacketCapt;
            }
            break;

          case YF_SSH_HOST_KEY:
            if (server_host_server->len > 0) {
                server_kex_reply = *(payload + dpi[count].dpacketCapt);
                server_kex_offset = dpi[count].dpacketCapt + 1;
            }
            break;

          case YF_SSH_VERSION:
            if (client) {
                rec->sshVersion.buf =
                    (uint8_t *)payload + dpi[count].dpacketCapt;
                rec->sshVersion.len = dpi[count].dpacketCaptLen;
            } else {
                rec->sshServerVersion.buf =
                    (uint8_t *)payload + dpi[count].dpacketCapt;
                rec->sshServerVersion.len = dpi[count].dpacketCaptLen;
            }
            break;
        }
    }

    if ((client_kex_request == SSH_MSG_KEXDH_INIT &&
         server_kex_reply == SSH_MSG_KEXDH_REPLY) ||
        (client_kex_request == SSH_MSG_KEX_DH_GEX_REQUEST &&
         server_kex_reply == SSH_MSG_KEX_DH_GEX_REPLY))
    {
        g_string_append_len(
            server_host_key,
            (const char *)(payload + server_kex_offset + 4),
            ntohl(*(uint32_t *)(payload + server_kex_offset)));
        compute_MD5(server_host_key->str, server_host_key->len,
                    rec->sshServerHostKey);
    }

    algo_Compare(kex_algo, kex_algo_server, &rec->sshKeyExchangeAlgorithm);
    algo_Compare(server_host, server_host_server, &rec->sshHostKeyAlgorithm);
    algo_Compare(encryptio_algo, encryptio_algo_server, &rec->sshCipher);
    /* Implicit is declared for the mac address when ever a cipher is used
     * that has a domain */
    if ((rec->sshCipher.buf != NULL) &&
        strchr((const char *)rec->sshCipher.buf, '@') != NULL)
    {
        rec->sshMacAlgorithm.len = strlen("implicit");
        rec->sshMacAlgorithm.buf = (uint8_t *)g_strdup("implicit");
    } else {
        algo_Compare(mac_algo, mac_algo_server, &rec->sshMacAlgorithm);
    }
    algo_Compare(compression_algo, compression_algo_server,
                 &rec->sshCompressionMethod);

    if (kex_algo->len > 0) {
        ssh_HASSH(kex_algo, encryptio_algo->str, mac_algo->str,
                  compression_algo->str, rec->sshHassh,
                  &rec->sshHasshAlgorithms);
    }
    if (kex_algo_server->len > 0) {
        ssh_HASSH(kex_algo_server, encryptio_algo_server->str,
                  mac_algo_server->str, compression_algo_server->str,
                  rec->sshServerHassh, &rec->sshServerHasshAlgorithms);
    }

    g_string_free(encryptio_algo, TRUE);
    g_string_free(server_host, TRUE);
    g_string_free(server_host_server, TRUE);
    g_string_free(encryptio_algo_server, TRUE);
    g_string_free(mac_algo, TRUE);
    g_string_free(mac_algo_server, TRUE);
    g_string_free(compression_algo, TRUE);
    g_string_free(compression_algo_server, TRUE);
    g_string_free(server_host_key, TRUE);

    return (void *)rec;
}

gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t *mdInfo;

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(
        mdInfo, YAF_SSH_NAME, YAF_SSH_DESC, SSH_PORT_NUMBER,
        FB_TMPL_MD_LEVEL_1);

    if (!ydInitTemplate(&yaf_ssh_tmpl, session, yaf_ssh_spec,
                        mdInfo, YAF_SSH_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_ssh_t *rec = (yaf_ssh_t *)flowContext->rec;

    g_free(rec->sshKeyExchangeAlgorithm.buf);
    g_free(rec->sshHasshAlgorithms.buf);
    g_free(rec->sshServerHasshAlgorithms.buf);
    g_free(rec->sshHostKeyAlgorithm.buf);
    g_free(rec->sshCipher.buf);
    g_free(rec->sshMacAlgorithm.buf);
    g_free(rec->sshCompressionMethod.buf);

    (void)rec;
}
#endif  /* YAF_ENABLE_DPI */

/**
 * ydpInitialize
 *
 * this finds and initializes the PCRE expressions needed to search the payload
 * for SSH
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is completed correctly, 0 on warn, -1 on error
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
    pluginExtras_t *pluginExtras = (pluginExtras_t *)extra;
    GArray         *pluginRegexes = (GArray *)pluginExtras->pluginRegexes;

    /* used to determine if this connection looks like SSH; capture the
     * response from server and client  */
    sshVersionRegex = ycFindCompilePluginRegex(pluginRegexes, "sshVersionRegex",
                                               0, err);
    if (!sshVersionRegex) {
        g_prefix_error(err, "In SSH plugin: ");
        return -1;
    }

#ifdef YAF_ENABLE_DPI
    GArray *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;

    YC_ENABLE_ELEMENTS(yaf_ssh, pluginTemplates);
#endif

    return 1;
}

#ifdef YAF_ENABLE_DPI
/**
 * Concatenate algorith strings to create HASSH string.
 * MD5 HASSH string to create HASSH hash.
 */
static void
ssh_HASSH(
    GString       *kex,
    const gchar   *encryp,
    const gchar   *mac,
    const gchar   *compression,
    uint8_t       *md5,
    fbVarfield_t  *string)
{
    g_string_append_printf(kex, ";%s;%s;%s", encryp, mac, compression);

    compute_MD5(kex->str, kex->len, md5);
    string->len =  kex->len;
    string->buf = (uint8_t *)g_string_free(kex, FALSE);
}

/**
 * compute_MD5
 *
 * Processes the plugin's arguments to generate an MD5 Hash
 *
 */
#ifdef HAVE_OPENSSL
static void
compute_MD5(
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
 * algo_Compare
 *
 * Compare the client `str1` and server `str2` algorithm strings
 * Split the given strings into tokens and compare first token
 * of the client & server string
 *
 */
static void
algo_Compare(
    const GString *str1,
    const GString *str2,
    fbVarfield_t  *str3)
{
    if (strchr(str1->str, ',') != NULL) {
        gchar  **tokens1 = g_strsplit(str1->str, ",", -1);
        gchar  **tokens2 = g_strsplit(str2->str, ",", -1);
        gboolean algo_match = FALSE;
        for (unsigned int i = 0; i < g_strv_length(tokens1); i++) {
            for (unsigned int j = 0; j < g_strv_length(tokens2); j++) {
                if (strcmp(tokens2[j], tokens1[i]) == 0) {
                    str3->len = strlen(tokens1[i]);
                    str3->buf = (unsigned char *)g_strdup(tokens1[i]);
                    algo_match = TRUE;
                    break;
                }
            }
            if (algo_match == TRUE) {
                break;
            }
        }
        g_strfreev(tokens1);
        g_strfreev(tokens2);
    } else {
        str3->len = str1->len;
        str3->buf = (uint8_t *)g_strdup(str1->str);
    }
}
#endif  /* YAF_ENABLE_DPI */
