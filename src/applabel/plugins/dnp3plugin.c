/*
 *  Copyright 2015-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file dnp3plugin.c
 *
 *  This tries to recognize the DNP3 protocol, a SCADA protocol.
 *  Decoder based on reference:
 *  http://www05.abb.com/global/scot/scot229.nsf/veritydisplay/\
 *  65b4a3780db3b3f3c2256e68003dffe6/$file/rec523_dnpprotmanend.pdf
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

#define YAF_DNP3_TID     0xC202
#define YAF_DNP3_NAME    "yaf_dnp"
#define YAF_DNP3_DESC    NULL

#define YAF_DNP3_REC_TID 0xC203
#define YAF_DNP3_REC_NAME "yaf_dnp_rec"
#define YAF_DNP3_REC_DESC NULL

typedef struct yaf_dnp3_st {
    /* STL of yaf_dnp3_rec */
    fbSubTemplateList_t   dnp3RecordList;
} yaf_dnp3_t;

static fbInfoElementSpec_t yaf_dnp3_spec[] = {
    {"dnp3RecordList",      FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_dnp3_rec_st {
    fbVarfield_t   dnp3ObjectData;
    uint16_t       dnp3SourceAddress;
    uint16_t       dnp3DestinationAddress;
    uint8_t        dnp3Function;
} yaf_dnp3_rec_t;

static fbInfoElementSpec_t yaf_dnp3_rec_spec[] = {
    {"dnp3ObjectData",           FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"dnp3SourceAddress",        2, YAF_DISABLE_IE_FLAG },
    {"dnp3DestinationAddress",   2, YAF_DISABLE_IE_FLAG },
    {"dnp3Function",             1, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

static fbTemplate_t       *yaf_dnp3_tmpl;
static fbTemplate_t       *yaf_dnp3_rec_tmpl;
#endif  /* YAF_ENABLE_DPI */

#define DNP_PORT_NUMBER 20000
#define DNP_START_BYTES 0x0564
#define DNP3_OBJ_QUAL_INDEX(x) ((x & 0x70) >> 4)
#define DNP3_OBJ_QUAL_CODE(x) (x & 0x0F)
#define DNP3_DLL_FUNCTION(x) (x & 0x0F)
#define DNP_BLOCK_SIZE 16
#define DNP_CLIENT 0
#define DNP_SERVER 1

#define DNP3_NO_INDEX       0x00
#define DNP3_1OCT_INDEX     0x01
#define DNP3_2OCT_INDEX     0x02
#define DNP3_4OCT_INDEX     0x03
#define DNP3_1SZ_INDEX      0x04
#define DNP3_2SZ_INDEX      0x05
#define DNP3_4SZ_INDEX      0x06
#define DNP3_INDEX_RESERVED 0x07

/* Qualifier codes */
#define DNP3_8BIT_IND       0x00
#define DNP3_16BIT_IND      0x01
#define DNP3_32BIT_IND      0x02
#define DNP3_8BIT_ADDRESS   0x03
#define DNP3_16BIT_ADDRESS  0x04
#define DNP3_32BIT_ADDRESS  0x05
#define DNP3_NO_RANGE       0x06
#define DNP3_8BIT_FIELD     0x07
#define DNP3_16BIT_FIELD    0x08
#define DNP3_32BIT_FIELD    0x09
#define DNP3_VARIABLE       0x0B

/* IDs used by yfDPIData_t->dpacketID */
#define DNP_SRC_ADDRESS     281
#define DNP_DEST_ADDRESS    282
#define DNP_FUNCTION        283
#define DNP_OBJECT_DATA     284
#define DNP_PLACEHOLDER     15

typedef struct ycDNPMessageHeader_st {
    /* Data Link Layer */
    uint16_t   start_bytes;    /*0x0564*/
    uint8_t    length;
    /* control */
    uint8_t    dir     : 1;
    uint8_t    prm     : 1;
    uint8_t    fcb     : 1;
    uint8_t    fcv     : 1;
    uint8_t    control : 4;
    uint16_t   destination;
    uint16_t   source;
    uint16_t   crc;

    /* Transport Layer */
    uint8_t    transport;
    /* Application Layer */
    uint8_t    app_control;
    uint8_t    app_function;
    /* responses only */
    uint16_t   indications;
} ycDNPMessageHeader_t;



/* Local Prototypes */
static void
ycDNPScanRebuildHeader(
    const uint8_t         *payload,
    ycDNPMessageHeader_t  *header);

#ifdef YAF_ENABLE_DPI
/**
 *
 * yfRemoveCRC
 *
 *
 * This function removes the Cyclic Redundancy Check codes
 * from a payload, in order to do DPI.
 *
 * @param start start of payload that contains CRCs
 * @param length length of payload that contains CRCs
 * @param dst destination buffer to copy payload without CRCs
 * @param dst_length length of destination buffer
 * @param block_size size of blocks of data
 * @param crc_length size of crc codes
 *
 *
 */
static void
yfRemoveCRC(
    const uint8_t  *start,
    size_t          length,
    uint8_t        *dst,
    size_t         *dst_length,
    unsigned int    block_size,
    unsigned int    crc_length);
#endif  /* YAF_ENABLE_DPI */

/**
 * ydpScanPayload
 *
 * the scanner for recognizing DNP3 packets
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
    ycDNPMessageHeader_t header;
    /* int                  direction; */
    uint32_t             offset = 0, function_offset = 0;
    uint32_t             total_offset = 0;
    uint8_t              function = 0;
    /* uint8_t              group, variation, prefix, qual_code; */
    int     app_header_len = 0, packets = 0;
    int     packet_len, packet_rem;
    /*    uint32_t            quantity = 0;*/
#ifdef YAF_ENABLE_DPI
    /* The DNP3 length in the header is a single byte but that length does not
     * include the CRCs. However, crc_buf holds the data once the CRCs have
     * been removed, so we can safely use a max of 255. (Actual data max is
     * 250 since the header length includes the link control (1 byte) and
     * destination and source addresses (each 2 bytes)). */
    uint8_t crc_buf[255];
    size_t  crc_buf_len;
#endif  /* #ifdef YAF_ENABLE_DPI */

    /* direction is determined by TCP session */
    /* There is a direction and primary bit in the Control flags but
     * it does not determine request vs response */
    if (val == &flow->val) {
        /* direction = DNP_CLIENT; */
        app_header_len = 2;
    } else {
        /* direction = DNP_SERVER; */
        app_header_len = 4;
    }

    while (offset < payloadSize) {
        /* only go around once for just applabeling */
#ifndef YAF_ENABLE_DPI
        if (packets > 0) {
            goto end;
        }
#endif

        offset = total_offset;

        /*must have start(2),length(1), control(1), dest(2), src(2), crc(2)*/
        if (((size_t)offset + 10) > payloadSize) {
            goto end;
        }

        ycDNPScanRebuildHeader((payload + offset), &header);

        header.start_bytes = ntohs(*((uint16_t *)(payload + offset)));

        /* DNP starts with 0x0564 */
        if (header.start_bytes != DNP_START_BYTES) {
            goto end;
        }

        if (header.prm) {
            if (header.control > 4 && header.control != 9) {
                goto end;
            }
        } else {
            if (header.control > 1) {
                if ((header.control != 11) &&
                    (header.control != 14) && (header.control != 15))
                {
                    goto end;
                }
            }
        }

        /* min length is 5 which indicates there is only a header
         * which includes control, dest, and src. CRC fields are
         * not included in the count */
        if (header.length < 5) {
            goto end;
        }

        /* Length only counts non-CRC octets. Each CRC is 2 octets.
         * There is one after the header and then one for each 16 octets
         * of user data, plus a CRC for the extra */
        packet_len = header.length + 4;

        /* get past the header */
        offset += 10;
        packet_rem = packet_len - 10;

        if (packet_rem <= 0) {
            packets++;
            total_offset += packet_len + 1;
            continue;
        }

        /* have room for transport and application layer headers?
         * if it's the first packet we should and if for some reason we don't,
         * it's not DNP */
        if ( ((size_t)total_offset + offset + packet_rem) > payloadSize) {
            goto end;
        }

        /* transport layer */
        header.transport = *(payload + offset);

        packet_rem--;

        if (packet_rem <= 0) {
            packets++;
            total_offset += packet_len + 1;
            continue;
        }

        /* skip past transport & application control */
        offset += 2;

        function_offset = offset;
        function = *(payload + offset);

        if (function > 23) {
            if (function != 129 && function != 130) {
                goto end;
            }
        } else if (function > 6 && (function < 13)) {
            goto end;
        }

        /* REGULAR EXPRESSIONS START HERE! */

        offset += app_header_len - 1; /* -1 for application control */
        packet_rem -= app_header_len;

        /* now we're at Data Link Layer which contains objects.
         * object is a 2 octet field that identifies the
         * class and variation of object */

        if (packet_rem <= 0) {
            packets++;
            /* 2 for CRC, 1 to move to next packet */
            total_offset += packet_len + 3;
            continue;
        }

        /* group = *(payload + offset); */
        /* variation = *(payload + offset + 1); */

        offset += 2;

        /* The Qualifier field specifies the Range field */
        /* prefix = DNP3_OBJ_QUAL_INDEX(*(payload + offset)); */
        /* qual_code = DNP3_OBJ_QUAL_CODE(*(payload + offset)); */

        offset++;

        /* For a Request, The Index (prefix) bit are only valid when Qualifier
         * Code (qual_code) is 11.  These bits indicate the size, in
         * octets, of each entry in the Range Field. */

        /*
         * if (direction == DNP_CLIENT && qual_code == 11) {
         *
         *  switch (prefix) {
         *    case DNP3_NO_INDEX:
         *      index = 0;
         *      return 0;
         *    case DNP3_1OCT_INDEX:
         *      index = 1;
         *      offset++;
         *      break;
         *    case DNP3_2OCT_INDEX:
         *      index = 2;
         *      offset+=2;
         *      break;
         *    case DNP3_4OCT_INDEX:
         *      index = 4;
         *      offset+=4;
         *      break;
         *    default:
         *      return 0;
         *  }
         *
         * } else {
         *  switch (prefix) {
         *    case DNP3_NO_INDEX:
         *      index = 0;
         *      break;
         *    case DNP3_1OCT_INDEX:
         *    case DNP3_1SZ_INDEX:
         *      index = 1;
         *      offset++;
         *      break;
         *    case DNP3_2OCT_INDEX:
         *    case DNP3_2SZ_INDEX:
         *      index = 2;
         *      offset+=2;
         *      break;
         *    case DNP3_4OCT_INDEX:
         *    case DNP3_4SZ_INDEX:
         *      index = 4;
         *      offset+=4;
         *      break;
         *    default:
         *      return 0;
         *  }
         * } */
        /*  * 0 - 5 describes points in sequence *
         *  * 7 - 9 describe unrelated points *
         *  * 11 describes points that need an object identifier */
        /*
         * switch(qual_code) {
         * case DNP3_8BIT_IND:
         * case DNP3_8BIT_ADDRESS:
         *  offset+=2;
         *  break;
         * case DNP3_16BIT_ADDRESS:
         * case DNP3_16BIT_IND:
         *  offset+=4;
         *  break;
         * case DNP3_32BIT_IND:
         * case DNP3_32BIT_ADDRESS:
         *  offset += 8;
         *  break;
         * case DNP3_NO_RANGE:
         *  break;
         * case DNP3_8BIT_FIELD:
         *  {
         *      quantity = *(payload + offset);
         *      offset += 1 + (index * quantity);
         *      break;
         *  }
         * case DNP3_16BIT_FIELD:
         *  {
         *      quantity = ntohs(*((uint16_t *)(payload + offset)));
         *      offset += 2 + (index * quantity);
         *      break;
         *  }
         * case DNP3_32BIT_FIELD:
         *  {
         *      quantity = ntohl(*((uint32_t *)(payload + offset)));
         *      offset += 4 + (index * quantity);
         *      break;
         *  }
         * case DNP3_VARIABLE:
         *  {
         *      if (index == 1) {
         *          uint8_t size = *(payload + offset + 1);
         *          quantity = *(payload + offset);
         *          offset += 2 + (quantity * size);
         *      } else if (index == 2) {
         *          uint16_t size=ntohs(*((uint16_t *)(payload + offset + 2)));
         *          quantity = ntohs(*((uint16_t *)(payload + offset)));
         *          offset += 4 + (quantity * size);
         *      } else {
         *          uint32_t size=ntohl(*((uint32_t *)(payload + offset + 4)));
         *          quantity = ntohl(*((uint32_t *)(payload + offset)));
         *          offset += 8 + (quantity * size);
         *      }
         *      break;
         *  }
         * default:
         *  return 0;
         * }
         */
        /* Figure out how much to account for CRCs and add it to the total
         * packet length */
        packet_len += ((packet_rem / 16) * 2) + 2;

#ifdef YAF_ENABLE_DPI
        /* 3 for DLL header  - is there any user data? */
        if (packet_rem > 3) {
            ydRunPluginRegex(flow, payload, 2, NULL, 4,
                             DNP_DEST_ADDRESS, DNP_PORT_NUMBER);
            ydRunPluginRegex(flow, payload, 2, NULL, 6,
                             DNP_SRC_ADDRESS, DNP_PORT_NUMBER);
            ydRunPluginRegex(flow, payload, 1, NULL, function_offset,
                             DNP_FUNCTION, DNP_PORT_NUMBER);
            ydRunPluginRegex(flow, payload, (packet_len - 10), NULL,
                             (total_offset + 10), DNP_PLACEHOLDER,
                             DNP_PORT_NUMBER);
            crc_buf_len = sizeof(crc_buf);
            yfRemoveCRC((payload + total_offset + 10), (packet_len - 10),
                        crc_buf, &crc_buf_len, DNP_BLOCK_SIZE, 2);
            /* offset is 2, past transport & application control */
            ydRunPluginRegex(flow, crc_buf, crc_buf_len, NULL,
                             2, DNP_OBJECT_DATA, DNP_PORT_NUMBER);
        }
#endif /* ifdef YAF_ENABLE_DPI */
        total_offset += packet_len + 1;
        packets++;
    }

  end:
    if (packets) {
        return DNP_PORT_NUMBER;
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
    yaf_dnp3_t     *rec = (yaf_dnp3_t *)flowContext->rec;
    yaf_dnp3_rec_t *dnp = NULL;
    uint8_t         count;
    uint8_t         start = flowContext->startOffset;
    uint8_t        *crc_ptr;
    size_t          crc_len = 0;
    int             total = 0;
    size_t          total_len = 0;

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    count = start;
    while (count < totalcap) {
        if (dpi[count].dpacketID == DNP_OBJECT_DATA) {
            total++;
        }
        count++;
    }

    if (total == 0) {
        rec = (yaf_dnp3_t *)fbSubTemplateListInit(stl, 3, YAF_DNP3_TID,
                                                  yaf_dnp3_tmpl, 0);
        flowContext->dpinum = 0;
        return (void *)rec;
    }

    flowContext->exbuf = g_slice_alloc0(flowContext->yfctx->dpi_total_limit);
    crc_ptr = flowContext->exbuf;

    rec = (yaf_dnp3_t *)fbSubTemplateListInit(stl, 3, YAF_DNP3_TID,
                                              yaf_dnp3_tmpl, 1);
    dnp = (yaf_dnp3_rec_t *)fbSubTemplateListInit(
        &rec->dnp3RecordList, 3, YAF_DNP3_REC_TID, yaf_dnp3_rec_tmpl, total);
    count = start;
    while (count < fwdcap && dnp) {
        switch (dpi[count].dpacketID) {
          case DNP_OBJECT_DATA:
            if (dpi[count].dpacketCaptLen <= crc_len) {
                dnp->dnp3ObjectData.buf = crc_ptr + dpi[count].dpacketCapt;
                dnp->dnp3ObjectData.len = dpi[count].dpacketCaptLen;
                crc_ptr += crc_len;
                total_len += crc_len;
                /* FIXME: the reverse code is identical except it
                 * includes the following statement here.  why?
                 *
                 * crc_len = ctx->dpi_total_limit - total_len;
                 */
            }
            dnp = fbSubTemplateListGetNextPtr(&rec->dnp3RecordList, dnp);
            break;
          case DNP_SRC_ADDRESS:
            dnp->dnp3SourceAddress =
                *((uint16_t *)(flow->val.payload + dpi[count].dpacketCapt));
            break;
          case DNP_DEST_ADDRESS:
            dnp->dnp3DestinationAddress =
                *((uint16_t *)(flow->val.payload + dpi[count].dpacketCapt));
            break;
          case DNP_FUNCTION:
            dnp->dnp3Function = *(flow->val.payload + dpi[count].dpacketCapt);
            break;
          case DNP_PLACEHOLDER:
            crc_len = ctx->dpi_total_limit - total_len;
            yfRemoveCRC((flow->val.payload + dpi[count].dpacketCapt),
                        dpi[count].dpacketCaptLen,
                        crc_ptr, &crc_len, DNP_BLOCK_SIZE, 2);
            break;
          default:
            g_debug("Unexpected dpacketID %d in %s plugin",
                    dpi[count].dpacketID, __FILE__);
            break;
        }
        count++;
    }

    while (count < totalcap && dnp && flow->rval.payload) {
        switch (dpi[count].dpacketID) {
          case DNP_OBJECT_DATA:
            if (dpi[count].dpacketCaptLen <= crc_len) {
                dnp->dnp3ObjectData.buf = crc_ptr + dpi[count].dpacketCapt;
                dnp->dnp3ObjectData.len = dpi[count].dpacketCaptLen;
                crc_ptr += crc_len;
                total_len += crc_len;
                /* FIXME: why is this only in the reverse code? */
                crc_len = ctx->dpi_total_limit - total_len;
            }
            dnp = fbSubTemplateListGetNextPtr(&rec->dnp3RecordList, dnp);
            break;
          case DNP_SRC_ADDRESS:
            dnp->dnp3SourceAddress =
                *((uint16_t *)(flow->rval.payload + dpi[count].dpacketCapt));
            break;
          case DNP_DEST_ADDRESS:
            dnp->dnp3DestinationAddress =
                *((uint16_t *)(flow->rval.payload + dpi[count].dpacketCapt));
            break;
          case DNP_FUNCTION:
            dnp->dnp3Function = *(flow->rval.payload + dpi[count].dpacketCapt);
            break;
          case DNP_PLACEHOLDER:
            crc_len = ctx->dpi_total_limit - total_len;
            yfRemoveCRC((flow->rval.payload + dpi[count].dpacketCapt),
                        dpi[count].dpacketCaptLen, crc_ptr,
                        &crc_len, DNP_BLOCK_SIZE, 2);
            break;
          default:
            g_debug("Unexpected dpacketID %d in %s plugin",
                    dpi[count].dpacketID, __FILE__);
            break;
        }
        count++;
    }

    return (void *)rec;
}

gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t *mdInfo;

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNP3_NAME, YAF_DNP3_DESC,
                       DNP_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    if (!ydInitTemplate(&yaf_dnp3_tmpl, session, yaf_dnp3_spec,
                        mdInfo, YAF_DNP3_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DNP3_REC_NAME, YAF_DNP3_REC_DESC,
                       DNP_PORT_NUMBER, YAF_DNP3_TID);

    if (!ydInitTemplate(&yaf_dnp3_rec_tmpl, session, yaf_dnp3_rec_spec,
                        mdInfo, YAF_DNP3_REC_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_dnp3_t *dnp = (yaf_dnp3_t *)flowContext->rec;

    if (flowContext->dpinum) {
        fbSubTemplateListClear(&dnp->dnp3RecordList);
    }
}
#endif  /* YAF_ENABLE_DPI */


/**
 * ycDNPScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octet stream directly into the DNP structure
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated dnp message
 *        header structure
 *
 *
 */
static
void
ycDNPScanRebuildHeader(
    const uint8_t         *payload,
    ycDNPMessageHeader_t  *header)
{
    uint8_t bitmasks = *(payload + 3);

    header->start_bytes = ntohs(*((uint16_t *)(payload)));
    header->length = *(payload + 2);
    header->dir = (bitmasks & 0xE0) ? 1 : 0;
    header->prm = (bitmasks & 0xD0) ? 1 : 0;
    header->fcb = (bitmasks & 0xB0) ? 1 : 0;
    header->fcv = (bitmasks & 0x70) ? 1 : 0;

    header->control = (bitmasks & 0x0F);

    header->destination = *((uint16_t *)(payload + 4));
    header->source = *((uint16_t *)(payload + 6));

    /*    g_debug("header->start_bytes %d", header->start_bytes);
     * g_debug("header->length %d", header->length);
     * g_debug("header->dir %d", header->dir);
     * g_debug("header->prm %d", header->prm);
     * g_debug("header->fcb %d", header->fcb);
     * g_debug("header->fcv %d", header->fcv);
     * g_debug("header->control %d", header->control);
     * g_debug("header->destination %d", header->destination);
     * g_debug("header->source %d", header->source);*/
}

#ifdef YAF_ENABLE_DPI
/**
 *
 * yfRemoveCRC
 *
 *
 * This function removes the Cyclic Redundancy Check codes
 * from a payload, in order to do DPI.
 *
 * @param start start of payload that contains CRCs
 * @param length length of payload that contains CRCs
 * @param dst destination buffer to copy payload without CRCs
 * @param dst_length length of destination buffer
 * @param block_size size of blocks of data
 * @param crc_length size of crc codes
 *
 *
 */
static void
yfRemoveCRC(
    const uint8_t  *start,
    size_t          length,
    uint8_t        *dst,
    size_t         *dst_length,
    unsigned int    block_size,
    unsigned int    crc_length)
{
    uint32_t offset = 0;
    size_t   curlen = 0;

    while ((length > (block_size + crc_length)) &&
           (curlen + block_size < *dst_length))
    {
        memcpy((dst + curlen), start + offset, block_size);
        curlen += block_size;
        offset += block_size + crc_length;
        length -= block_size + crc_length;
    }

    if ((length > crc_length) && (curlen + length < *dst_length)) {
        memcpy((dst + curlen), (start + offset), (length - crc_length));
        curlen += length - crc_length;
        offset += length;
    }

    *dst_length = curlen;
}
#endif  /* YAF_ENABLE_DPI */

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
    YC_ENABLE_ELEMENTS(yaf_dnp3, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_dnp3_rec, pluginTemplates);
#endif /* ifdef YAF_ENABLE_DPI */
    return 1;
}
