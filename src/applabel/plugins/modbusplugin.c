/*
 *  Copyright 2014-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file modbusplugin.c
 *
 *  This tries to recognize the Modbus protocol, a SCADA protocol.
 *  Decoder based on reference:
 *  http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso
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

#define IE_NUM_modbusData   285


#define YAF_MODBUS_TID   0xC204
#define YAF_MODBUS_NAME  "yaf_modbus"
#define YAF_MODBUS_DESC  NULL

static fbInfoElementSpec_t yaf_modbus_spec[] = {
    {"modbusDataList",      FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_modbus_st {
    /* basicList of modbusData */
    fbBasicList_t   modbusDataList;
} yaf_modbus_t;

static fbTemplate_t *yaf_modbus_tmpl;
#endif /* ifdef YAF_ENABLE_DPI */

#define MODBUS_PORT_NUMBER 502
#define MODBUS_OBJECT 285
#define MODBUS_EXCEPTION 0x80

typedef struct ycMBAPMessageHeader_st {
    uint16_t   trans_id;
    uint16_t   protocol;
    uint16_t   length;
    uint8_t    unit_id;
} ycMBAPMessageHeader_t;


/* Local Prototypes */
static void
ycMBAPScanRebuildHeader(
    const uint8_t          *payload,
    ycMBAPMessageHeader_t  *header);

/**
 * ydpScanPayload
 *
 * the scanner for recognizing modbus packets
 *
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return dnp_port_number
 *         otherwise 0
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t     offset = 0, total_offset = 0;
    uint64_t     num_packets = val->pkt;
    uint8_t      function, exception;
    unsigned int packets = 0;
    unsigned int i;
    size_t       pkt_length = 0;
    ycMBAPMessageHeader_t header;

    /* must be TCP */
    if (flow->key.proto != 6) {
        return 0;
    }

    /* must have MBAP Header and function and data */
    if (payloadSize < 9) {
        return 0;
    }

    if (num_packets > YAF_MAX_PKT_BOUNDARY) {
        num_packets = YAF_MAX_PKT_BOUNDARY;
    }

    for (i = 0; i < num_packets; ++i) {
        if (val->paybounds[i]) {
            pkt_length = val->paybounds[i];
            if (pkt_length > payloadSize) {
                pkt_length = payloadSize;
            }
            break;
        }
    }

    if (pkt_length > 260) {
        /* max pkt length of a MODBUS PDU is 260 bytes */
        return 0;
    }

    while (offset < payloadSize) {
        exception = 0;
#ifndef YAF_ENABLE_DPI
        if (packets > 0) {
            goto end;
        }
#endif
        offset = total_offset;

        if (((size_t)offset + 9) > payloadSize) {
            goto end;
        }

        /* check for MBAP (Modbus Application Protocol) header */
        ycMBAPScanRebuildHeader((payload + offset), &header);

        if (header.trans_id == pkt_length) {
            /* this is prob Oracle TNS protocol - first 2 bytes are length */
            return 0;
        }

        if (!packets) {
            if ((header.trans_id & 0xFF80) == 0x3080) {
                unsigned int len_octets = header.trans_id & 0x7F;
                /* this might be LDAP (ASN.1 SEQUENCE) long form */
                if ((len_octets + 2) < payloadSize) {
                    if (*(payload + len_octets + 2) == 0x02) {
                        /* INTEGER TAG NUMBER FOR RESPONSE/msgID */
                        return 0;
                    }
                }
            }
        }

        offset += 7;

        /* protocol is always 0 */

        if (header.protocol != 0) {
            goto end;
        }

        if (header.length < 3) {
            goto end;
        }

        if (((size_t)offset + header.length - 1) > payloadSize) {
            goto end;
        }

        if (!packets && (((size_t)header.length + 6) != pkt_length)) {
            /* 6 byte header + length */
            return 0;
        }

        function = *(payload + offset);

        /* 1-65, 72-100, 110-127 are public codes, rest are user-defined */
        if (function > 127) {
            exception = *(payload + offset + 1);
            /* is this is an exception to the query? */
            if (exception == 0 || exception > 12) {
                goto end;
            }
        }

#ifdef YAF_ENABLE_DPI
        ydRunPluginRegex(flow, payload, (offset + header.length - 1), NULL,
                         offset, MODBUS_OBJECT, MODBUS_PORT_NUMBER);
#endif
        /* length plus transaction id, protocol id, and length field */
        total_offset += header.length + 6;
        packets++;
    }

  end:

    if (packets) {
        return MODBUS_PORT_NUMBER;
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
    return ydProcessGenericPlugin(flowContext, stl, flow, fwdcap, totalcap,
                                  YAF_MODBUS_TID, yaf_modbus_tmpl,
                                  "modbusData");
}

gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t      *mdInfo;
    const fbInfoElement_t *bl_element;

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_MODBUS_NAME, YAF_MODBUS_DESC,
                       MODBUS_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    bl_element = ydLookupNamedBlByID(CERT_PEN, IE_NUM_modbusData);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, IE_NUM_modbusData);
    }

    if (!ydInitTemplate(&yaf_modbus_tmpl, session, yaf_modbus_spec,
                        mdInfo, YAF_MODBUS_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_modbus_t *rec = (yaf_modbus_t *)flowContext->rec;

    fbBasicListClear(&rec->modbusDataList);
}
#endif  /* YAF_ENABLE_DPI */

/**
 * ycMBAPScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octet stream directly into the MBAP header
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated dnp message
 *        header structure
 *
 *
 */
static
void
ycMBAPScanRebuildHeader(
    const uint8_t          *payload,
    ycMBAPMessageHeader_t  *header)
{
    uint32_t offset = 0;

    header->trans_id = ntohs(*((uint16_t *)(payload)));
    offset += 2;
    header->protocol = ntohs(*((uint16_t *)(payload + offset)));
    offset += 2;
    header->length = ntohs(*((uint16_t *)(payload + offset)));
    offset += 2;
    header->unit_id = *(payload + offset);

    /*    g_debug("header->trans_id %d", header->trans_id);
     * g_debug("header->proto_id %d", header->protocol);
     * g_debug("header->length %d", header->length);
     * g_debug("header->unit_id %d", header->unit_id);*/
}

/**
 * ydpInitialize
 *
 * enables DPI Information Elements.
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
    pluginExtras_t *pluginExtras = (pluginExtras_t *)extra;
    GArray         *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;
    YC_ENABLE_ELEMENTS(yaf_modbus, pluginTemplates);
#endif /* ifdef YAF_ENABLE_DPI */
    return 1;
}
