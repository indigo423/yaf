/*
 *  Copyright 2017-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file ntpplugin.c
 *
 *  Attempts to identify NTP traffic.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Matt Coates
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

static uint16_t
validate_NTP(
    const uint8_t  *payload,
    unsigned int    payloadSize)
{
    uint8_t      ntp_version;
    uint8_t      ntp_mode;
    uint32_t     consumed = 0;
    uint16_t     data_item_size;
    uint16_t     data_item_count;
    uint16_t     extension_field_len;

#if 0
    char         hexbuf[21];
    int          mfci;
    for (mfci = 0; mfci < 10; mfci++) {
        sprintf(&(hexbuf[mfci * 2]), "%02x", payload[mfci]);
    }
    hexbuf[20] = '\0';
    g_debug("NTP payload: %s", hexbuf);
    g_debug("NTP: payload size: 0x%x", payloadSize);
#endif /* 0 */

    /* minimum NTP size = 48 bytes */
    if (payload == NULL || payloadSize < 48) {
        return 0;
    }

    ntp_version = (payload[0] & (uint8_t)0x38) >> 3;
    ntp_mode = (payload[0] & (uint8_t)0x7);
    /* g_debug("NTP version %d, mode %d",ntp_version,ntp_mode); */
    if (ntp_version == 0 || ntp_version > 4) { /* NTP is at version 4 */
        return 0;
    }

    /* // nevermind: 0-6 are valid, and 7 is reserved
     * unsigned short ntp_mode = flow->val.payload[0] & 0x07;
     */

    /* standard size w/o key/MAC and extension fields for all versions */
    if (payloadSize == 48) {
        return 1;
    }

    /* 20 bytes for key and MAC (optional) */
    if (ntp_version >= 3 && payloadSize == 68) {
        return 1;
    }

    /* 12 bytes for Authenticator (optional) */
    if (ntp_version == 2 && payloadSize == 60) {
        return 1;
    }

    if (ntp_mode == 7) {
        /* uint8_t ntp_response = payload[0] & (uint8_t)0x80 ? 1:0; */
        uint8_t ntp_authenticated = payload[1] & 0x80 ? 1 : 0;
        uint8_t ntp_request_code = (uint8_t)payload[3];
        /* g_debug("NTP mode 7 with request code %d",ntp_request_code); */

        if (ntp_request_code == 42) {
            consumed = 8;
            /* payload[4] to [5] */
            data_item_count = g_ntohs(*(uint16_t *)(payload + 4));
            /* payload[6] to [7] */
            data_item_size = g_ntohs(*(uint16_t *)(payload + 6));
            /* g_debug("NTP mode 7 request 42 with %d data items, size: 0x%x",
             *         data_item_count,data_item_size); */
            if (data_item_size > 500) {
                /* cannot exceede 500 bytes */
                return 0;
            }
            consumed += (data_item_count * data_item_size);
            if (ntp_authenticated) {
                consumed += 20;
            }
            /* g_debug("consumed: 0x%x, size: 0x%x\n",consumed,payloadSize); */
        }
    }

    consumed = 48;
    if (ntp_version == 4) {
        while (consumed < (payloadSize - 20)) {
            /*  we have extension fields */
            /* payload[consumed+2] to [consumed+3] */
            extension_field_len =
                g_ntohs(*(uint16_t *)(payload + consumed + 2));
            /* g_debug("Extension field length: 0x%x starting at * 0x%x",
             *         extension_field_len,consumed); */
            if (extension_field_len < 16 || extension_field_len % 4 != 0 ||
                ((extension_field_len + consumed) > (payloadSize - 20)))
            {
                /* g_debug("Invalid extension field length."); */
                return 0;
            }
            consumed += extension_field_len;
        }

        /* we saw extension fields, which mandate the key id and MAC */
        /* ensure there is enough bytes remaining in the packet to hold
         * them. */
        if (payloadSize - consumed == 20) {
            return 1;
        } else {
            /* g_debug("Not enough space for key and MAC (0x%x bytes), invalid
             * NTP.",payloadSize-consumed); */
        }
    }
    return 0;
}


/**
 * ydpScanPayload
 *
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 1 if this is an NTP packet
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    if (flow->key.proto != YF_PROTO_UDP) { /*  must be UDP */
        return 0;
    }
    return validate_NTP(payload, payloadSize);
#if 0
    /* Not ready yet */
    int      packet_n = 0;
    size_t   packet_payload_len;
    uint8_t *end_payload = payload + payloadSize;

    g_debug("checking NTP packet count: %d, payload size: %d",
            val->pkt, payloadSize);
    while (packet_n < val->pkt && packet_n < YAF_MAX_PKT_BOUNDARY
           && payload < end_payload)
    {
        packet_payload_len = val->paybounds[packet_n];
        g_debug(" packet %d len: %d", packet_n, packet_payload_len);
        if (packet_payload_len != 0) {
            if (validate_NTP(payload, packet_payload_len)) {
                return 1;
            }
        }
        payload += packet_payload_len;
        packet_n++;
    }
#endif /* 0 */
}
