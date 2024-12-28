/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file slpplugin.c
 *
 *  @brief this is a protocol classifier for the service location protocol
 *  (SLP)
 *
 *  SLP is a protocol to find well known protocol/services on a local area
 *  network.  It can scale from small scale networks to large lan networks.
 *  For small scale networks, it uses multicasting in order to ask all
 *  machines for a service.  In larger networks it uses Directory Agents
 *  in order to centralize management of service information and increase
 *  scaling by decreasing network load.
 *
 *  @sa rfc 2608  href="http://www.ietf.org/rfc/rfc2608.txt"
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

/* IDs used by yfDPIData_t->dpacketID */
/* slpVersion */
#define YF_SLP_VERSION  90
/* slpMessageType */
#define YF_SLP_MSG_TYPE 91
/* slpString -- this value or greater */
#define YF_SLP_STRING   92

/* slpString */
#define IE_NUM_slpString  130

#define YAF_SLP_TID    0xC500
#define YAF_SLP_NAME   "yaf_slp"
#define YAF_SLP_DESC   NULL

static fbInfoElementSpec_t yaf_slp_spec[] = {
    {"slpStringList",         FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"slpVersion",            1, YAF_DISABLE_IE_FLAG },
    {"slpMessageType",        1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",         6, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_slp_st {
    /* basicList of slpString */
    fbBasicList_t   slpStringList;
    uint8_t         slpVersion;
    uint8_t         slpMessageType;
    uint8_t         padding[6];
} yaf_slp_t;

static fbTemplate_t *yaf_slp_tmpl;
#endif /* ifdef YAF_ENABLE_DPI */

#include <arpa/inet.h>


typedef struct __attribute__((__packed__)) srcLocProtoHeader_v1_st {
    uint8_t  version;
    uint8_t  function;
    uint16_t length;

    uint8_t  overflow    : 1;
    uint8_t  monolingual : 1;
    uint8_t  urlAuth     : 1;
    uint8_t  attribAuth  : 1;
    uint8_t  srvcAck     : 1;
    uint8_t  reserved    : 3;

    uint8_t  dialect;
    uint16_t langCode;
    uint16_t charEncoding;
    uint16_t xid;
} srcLocProtoHeader_v1_t;


/** this structure does not match (bit-for-bit anyway)  the
 *  on the wire protocol.  Machines without native 24-bit
 *  int types (darn near everything except some DSPs & older
 *  video chips maybe) will not be able to pack it correctly
 *  to match the wire */
typedef struct srcLocProtoHeader_v2_st {
    uint8_t    version;
    uint8_t    function;

    /* this is really a 24-bit value */
    uint32_t   length;

    uint8_t    overflow : 1;
    uint8_t    fresh    : 1;
    uint8_t    reqMcast : 1;
    uint16_t   reserved : 13;

    /* this is really a 24-bit value */
    uint32_t   nextExtensionOffset;

    uint16_t   xid;

    uint16_t   langTagLength;
    uint8_t    langCode;                /* there is at least 1 char here, and
                                         * up to 8 */
} srcLocProtoHeader_v2_t;

/* this is the size of the V2 header up to and including the language
 * tag length in uint8_t/octects/bytes */
#define SLP_V2_HEADER_SIZE 14

typedef enum slpFunction_et {
    SrvReq = 1,
    SrvRply = 2,
    SrvReg = 3,
    SrvDereg = 4,
    SrvAck = 5,
    AttrRqst = 6,
    AttrRply = 7,
    DAAdvert = 8,
    SrvTypeRqst = 9,
    SrvTypeReply = 10,
    SAAdvert = 11
} slpFunction_t;


#define SLP_PORT_NUMBER 427


/*
 * File local functions
 *
 */
static unsigned int
ycPopulateSLPV2Header(
    const uint8_t           *payload,
    unsigned int             payloadSize,
    srcLocProtoHeader_v2_t  *header);


/**
 * ydpScanPayload
 *
 * returns SLP_PORT_NUMBER if the passed in payload matches a service location
 * protocol packet
 *
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return 0 if not a match, if it is SLP, returns the version of the protocol
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint8_t      version;
    srcLocProtoHeader_v1_t *slpHeader;
    unsigned int loop;

#ifdef YAF_ENABLE_DPI
    gboolean     slpStringFound = FALSE;
    uint16_t     slplength[5];
    uint32_t     slpoffset[5];
    for (loop = 0; loop < 5; loop++) {
        slplength[loop] = 0;
        slpoffset[loop] = 0;
    }
#endif /* ifdef YAF_ENABLE_DPI */

    if (payloadSize < 2) {
        return 0;
    }

    /* map the payload into an SLP structure */
    slpHeader = (srcLocProtoHeader_v1_t *)payload;
    version = slpHeader->version;

    if (1 == version) {
        if (payloadSize < sizeof(srcLocProtoHeader_v1_t)) {
            return 0;
        }

        /* check the reserved fields first, they are required to be zero */
        if ((0 != slpHeader->reserved) || (0 != slpHeader->dialect)) {
            return 0;
        }

        /* check for a valid function code */
        if ((slpHeader->function < SrvReq)
            || (slpHeader->function > SrvTypeReply))
        {
            return 0;
        }

#ifdef YAF_ENABLE_DPI
        /* /\* version *\/ */
        /* ydRunPluginRegex(flow, payload, sizeof(uint8_t), NULL, 0, */
        /*                   YF_SLP_VERSION, SLP_PORT_NUMBER); */
        /* /\* msg type *\/ */
        /* ydRunPluginRegex(flow, payload, sizeof(uint8_t), NULL, 1, */
        /*                   YF_SLP_MSG_TYPE, SLP_PORT_NUMBER); */

        /* /\*Nothing valuable for now*\/ */
        /* offset = 13; */
        /* for (loop = 0; loop < 2; loop++){ */
        /*     ydRunPluginRegex(flow, payload, *(payload+offset), */
        /*                      NULL, (offset + sizeof(uint16_t)), */
        /*                      YF_SLP_STRING + loop, SLP_PORT_NUMBER); */
        /*     offset += *(payload+offset) + sizeof(uint16_t); */
        /* } */
#endif /* ifdef YAF_ENABLE_DPI */

        /* seems likely that this might be a service location protocol, let's
         * run with that as the answer */
        return 1;
    } else if (2 == version) {
        srcLocProtoHeader_v2_t slpHeader2;
        uint32_t offset;

        if (payloadSize < sizeof(srcLocProtoHeader_v2_t)) {
            return 0;
        }

        if (0 == ycPopulateSLPV2Header(payload, payloadSize, &slpHeader2)) {
            return 0;
        }

        /* make sure the reserved field is set to zero, as required */
        if (0 != slpHeader2.reserved) {
            return 0;
        }

        /* check for a valid function code */
        if ((slpHeader2.function < SrvReq) ||
            (slpHeader2.function > SAAdvert))
        {
            return 0;
        }

        /* check the length of the language tag field */
        if (slpHeader2.langTagLength < 1 || slpHeader2.langTagLength > 8) {
            /* this is an invalid language length */
            return 0;
        }

        /* substract the size of the single langCode, but then we need to add
         * the length of the language string */
        offset = SLP_V2_HEADER_SIZE + slpHeader2.langTagLength;

        if (offset > payloadSize) {
            return 0;
        }

        /* five string fields are defined for a request */
        if (slpHeader2.function == SrvReq) {
            uint16_t stringLength;

            for (loop = 0; loop < 5; loop++) {
                if (((size_t)offset + 2) > payloadSize) {
                    return 0;
                }
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
                stringLength = ((*(payload + offset)) << 8) |
                    ((*(payload + offset + 1)) );
                stringLength = ntohs(stringLength);
#ifdef YAF_ENABLE_DPI
                slplength[loop] = stringLength;
#endif
#else /* ifdef HAVE_ALIGNED_ACCESS_REQUIRED */
                stringLength = ntohs(*(uint16_t *)(payload + offset));
#ifdef YAF_ENABLE_DPI
                slplength[loop] = stringLength;
#endif
#endif /* ifdef HAVE_ALIGNED_ACCESS_REQUIRED */
                /* we could get a string out here, but what would we do with
                 * it? */
#ifdef YAF_ENABLE_DPI
                slpoffset[loop] = offset + sizeof(uint16_t);
#endif

                offset += sizeof(uint16_t) + stringLength;
            }

            if (offset > payloadSize) {
                return 0;
            }
        }

        /* seems likely that this might be a service location protocol, let's
         * run with that as the answer */
#ifdef YAF_ENABLE_DPI
        for (loop = 0; loop < 5; loop++) {
            if ((slplength[loop] > 0) && (slplength[loop] < payloadSize)
                && (slpoffset[loop] < payloadSize))
            {
                slpStringFound = TRUE;
                ydRunPluginRegex(flow, payload, slplength[loop], NULL,
                                 slpoffset[loop],
                                 YF_SLP_STRING + loop, SLP_PORT_NUMBER);
            }
        }
        /* only record version and type if we have some data */
        if (slpStringFound) {
            /* version */
            ydRunPluginRegex(flow, payload, sizeof(uint8_t), NULL, 0,
                             YF_SLP_VERSION, SLP_PORT_NUMBER);
            /* message type */
            ydRunPluginRegex(flow, payload, sizeof(uint8_t), NULL, 1,
                             YF_SLP_MSG_TYPE, SLP_PORT_NUMBER);
        }
#endif /* ifdef YAF_ENABLE_DPI */

        return 1;
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
    yfDPIData_t   *dpi = flowContext->dpi;
    yaf_slp_t     *rec = NULL;
    fbInfoModel_t *model = ydGetDPIInfoModel();
    int            loop;
    int            total = 0;
    int            count = flowContext->startOffset;
    fbVarfield_t  *slpVar = NULL;
    const fbInfoElement_t *slpString;
    yfFlowVal_t   *val;

    g_assert(fwdcap <= totalcap);
    rec = (yaf_slp_t *)fbSubTemplateListInit(stl, 3, YAF_SLP_TID,
                                             yaf_slp_tmpl, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for (loop = count; loop < totalcap; loop++) {
        if (dpi[loop].dpacketID >= YF_SLP_STRING) {
            total++;
        }
    }
    slpString = fbInfoModelGetElementByName(model, "slpString");
    slpVar = (fbVarfield_t *)fbBasicListInit(
        &rec->slpStringList, 3, slpString, total);

    val = &flow->val;
    for ( ; count < totalcap; ++count) {
        if (count == fwdcap) {
            val = &flow->rval;
        }
        if (dpi[count].dpacketID == YF_SLP_VERSION) {
            rec->slpVersion = (uint8_t)*(val->payload +
                                         dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == YF_SLP_MSG_TYPE) {
            rec->slpMessageType = (uint8_t)*(val->payload +
                                             dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID >= YF_SLP_STRING && slpVar) {
            slpVar->buf = val->payload + dpi[count].dpacketCapt;
            slpVar->len = dpi[count].dpacketCaptLen;
            slpVar = fbBasicListGetNextPtr(&rec->slpStringList, slpVar);
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
    fbTemplateInfoInit(mdInfo, YAF_SLP_NAME, YAF_SLP_DESC,
                       SLP_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    /* ruleset does not contain IE information, add metadata manually */
    bl_element = ydLookupNamedBlByID(CERT_PEN, IE_NUM_slpString);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, IE_NUM_slpString);
    }

    if (!ydInitTemplate(&yaf_slp_tmpl, session, yaf_slp_spec,
                        mdInfo, YAF_SLP_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_slp_t *rec = (yaf_slp_t *)flowContext->rec;

    fbBasicListClear(&rec->slpStringList);
}
#endif  /* YAF_ENABLE_DPI */


/**
 * ycPopulateSLPV2Header
 *
 * reads bytes from a stream (byte-by-byte) to fill in a structure for the V2
 * SLP header
 *
 * @note it doesn't attempt to fill in the langcode field
 *
 * @param payload pointer to the payload bytes as captured from the wire
 * @param payloadSize the size of the payload array
 * @param a pointer to a srcLocProtoHeader_V2_t to populate from parsing the
 * capture array
 *
 *
 * @return 0 on failure, non-zero on success
 */
static
unsigned int
ycPopulateSLPV2Header(
    const uint8_t           *payload,
    unsigned int             payloadSize,
    srcLocProtoHeader_v2_t  *header)
{
    uint32_t     offset = 0;
    uint8_t      readValue;
    uint8_t      readValue2;
    unsigned int loop;

    readValue = *(payload + offset);
    offset++;
    header->version = readValue;

    if (offset > payloadSize) {
        return 0;
    }

    readValue = *(payload + offset);
    offset++;
    header->function = readValue;

    header->length = 0;
    for (loop = 0; loop < 3; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->length = (header->length << 8) | readValue;
    }

    if (offset > payloadSize) {
        return 0;
    }

    readValue = *(payload + offset);
    offset++;
    header->overflow = (readValue & 0x80) >> 7;
    header->fresh = (readValue & 0x40) >> 6;
    header->reqMcast = (readValue & 0x20) >> 5;

    if (offset > payloadSize) {
        return 0;
    }
    readValue2 = *(payload + offset);
    offset++;
    header->reserved = ((readValue & 0x1f) << 8) | (readValue2);

    header->nextExtensionOffset = 0;
    for (loop = 0; loop < 3; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->nextExtensionOffset =
            (header->nextExtensionOffset << 8) | readValue;
    }

    header->xid = 0;
    for (loop = 0; loop < 2; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->xid = (header->xid << 8) | readValue;
    }

    header->langTagLength = 0;
    for (loop = 0; loop < 2; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->langTagLength = (header->langTagLength << 8) | readValue;
    }

    return offset;
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
    YC_ENABLE_ELEMENTS(yaf_slp, pluginTemplates);
    /* printSpec(yaf_slp_spec, ""); */
#endif /* ifdef YAF_ENABLE_DPI */
    return 1;
}
