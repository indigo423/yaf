/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file nntpplugin.c
 *
 *  this provides NNTP payload packet recognition for use within YAF
 *  It is based on RFC 977 and some random limited packet capture.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Ecoff
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

/* nntpResponse */
#define IE_NUM_nntpResponse  172
/* nntpCommand */
#define IE_NUM_nntpCommand   173

#define YAF_NNTP_TID   0xCD00
#define YAF_NNTP_NAME  "yaf_nntp"
#define YAF_NNTP_DESC  NULL

static fbInfoElementSpec_t yaf_nntp_spec[] = {
    {"nntpResponseList",    FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"nntpCommandList",     FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_nntp_st {
    /* basicList of nntpResponse */
    fbBasicList_t   nntpResponseList;
    /* basicList of nntpCommand */
    fbBasicList_t   nntpCommandList;
} yaf_nntp_t;

static fbTemplate_t *yaf_nntp_tmpl;
#endif /* ifdef YAF_ENABLE_DPI */

#define NNTP_PORT_NUMBER 119

/**
 * the compiled regular expressions, and related
 * flags
 *
 */
static pcre *nntpCommandRegex = NULL;
static pcre *nntpResponseRegex = NULL;


/*static int ycDebugBinPrintf(uint8_t *data, uint16_t size);*/

#ifdef YAF_ENABLE_DPI
static void
nntpFillBasicList(
    yfFlow_t      *flow,
    yfDPIData_t   *dpi,
    uint8_t        totalCaptures,
    uint8_t        forwardCaptures,
    fbVarfield_t **varField,
    uint8_t       *indexArray)
{
    yfFlowVal_t *val;
    unsigned int i;

    if (!(*varField)) {
        return;
    }
    for (i = 0; i < totalCaptures; i++) {
        val = (indexArray[i] < forwardCaptures) ? &flow->val : &flow->rval;
        if (dpi[indexArray[i]].dpacketCapt + dpi[indexArray[i]].dpacketCaptLen
            > val->paylen)
        {
            continue;
        }
        if (val->payload) {
            (*varField)->buf = val->payload + dpi[indexArray[i]].dpacketCapt;
            (*varField)->len = dpi[indexArray[i]].dpacketCaptLen;
        }
        if (i + 1 < totalCaptures) {
            (*varField)++;
        }
    }
}
#endif  /* YAF_ENABLE_DPI */


/**
 * ydpScanPayload
 *
 * scans a given payload to see if it conforms to our idea of what NNTP traffic
 * looks like.
 *
 *
 *
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match NNTP_PORT_NUMBER (119) for a match
 *
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    int rc;
#   define NUM_CAPT_VECTS 60
    int vects[NUM_CAPT_VECTS];

    rc = pcre_exec(nntpCommandRegex, NULL, (char *)payload, payloadSize,
                   0, 0, vects, NUM_CAPT_VECTS);

    if (rc <= 0) {
        rc = pcre_exec(nntpResponseRegex, NULL, (char *)payload,
                       payloadSize, 0, 0, vects, NUM_CAPT_VECTS);
    }

    /** at some point in the future, this is the place to extract protocol
     *  information like message targets and join targets, etc.*/
#ifdef YAF_ENABLE_DPI
    if (rc > 0) {
        ydRunPluginRegex(flow, payload, payloadSize, nntpCommandRegex, 0,
                         IE_NUM_nntpCommand, NNTP_PORT_NUMBER);
        ydRunPluginRegex(flow, payload, payloadSize, nntpResponseRegex, 0,
                         IE_NUM_nntpResponse, NNTP_PORT_NUMBER);
    }
#endif /* ifdef YAF_ENABLE_DPI */

    if (rc > 0) {
        return NNTP_PORT_NUMBER;
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
    yaf_nntp_t    *rec = NULL;
    fbInfoModel_t *model = ydGetDPIInfoModel();
    uint8_t        count;
    uint8_t        start = flowContext->startOffset;
    int            total = 0;
    fbVarfield_t  *nntpVar = NULL;
    uint8_t        totalIndex[YAF_MAX_CAPTURE_FIELDS];
    const fbInfoElement_t *nntpResponse;
    const fbInfoElement_t *nntpCommand;

    rec = (yaf_nntp_t *)fbSubTemplateListInit(stl, 3, YAF_NNTP_TID,
                                              yaf_nntp_tmpl, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    /* nntp Response */
    for (count = start; count < totalcap; count++) {
        if (dpi[count].dpacketID == IE_NUM_nntpResponse) {
            totalIndex[total] = count;
            total++;
        }
    }

    nntpResponse = fbInfoModelGetElementByName(model, "nntpResponse");
    nntpVar = (fbVarfield_t *)fbBasicListInit(
        &rec->nntpResponseList, 3, nntpResponse, total);

    nntpFillBasicList(flow, dpi, total, fwdcap, &nntpVar, totalIndex);

    total = 0;
    nntpVar = NULL;
    /* nntp Command */
    for (count = start; count < totalcap; count++) {
        if (dpi[count].dpacketID == IE_NUM_nntpCommand) {
            totalIndex[total] = count;
            total++;
        }
    }

    nntpCommand = fbInfoModelGetElementByName(model, "nntpCommand");
    nntpVar = (fbVarfield_t *)fbBasicListInit(
        &rec->nntpCommandList, 3, nntpCommand, total);

    nntpFillBasicList(flow, dpi, total, fwdcap, &nntpVar, totalIndex);

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
    fbTemplateInfoInit(mdInfo, YAF_NNTP_NAME, YAF_NNTP_DESC,
                       NNTP_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    /* ruleset does not contain IE information, add metadata manually */
    bl_element = ydLookupNamedBlByID(CERT_PEN, IE_NUM_nntpResponse);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, IE_NUM_nntpResponse);
    }
    bl_element = ydLookupNamedBlByID(CERT_PEN, IE_NUM_nntpCommand);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, IE_NUM_nntpCommand);
    }

    if (!ydInitTemplate(&yaf_nntp_tmpl, session, yaf_nntp_spec,
                        mdInfo, YAF_NNTP_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_nntp_t *rec = (yaf_nntp_t *)flowContext->rec;

    fbBasicListClear(&rec->nntpResponseList);
    fbBasicListClear(&rec->nntpCommandList);
}
#endif  /* YAF_ENABLE_DPI */

/**
 * ydpInitialize
 *
 * this initializes the PCRE expressions needed to search the payload for
 * NNTP and enables DPI Information Elements.
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is completed correctly, 0 on warning, -1 on
 * error.
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

    nntpCommandRegex = ycFindCompilePluginRegex(
        pluginRegexes, "nntpCommandRegex", 0, err);
    nntpResponseRegex = ycFindCompilePluginRegex(
        pluginRegexes, "nntpResponseRegex", PCRE_EXTENDED | PCRE_ANCHORED, err);

    if (!nntpCommandRegex || !nntpResponseRegex) {
        g_prefix_error(err, "In NNTP plugin: ");
        return -1;
    }
#ifdef YAF_ENABLE_DPI
    GArray *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;
    YC_ENABLE_ELEMENTS(yaf_nntp, pluginTemplates);
#endif
    return 1;
}


#if 0
static int
ycDebugBinPrintf(
    uint8_t   *data,
    uint16_t   size)
{
    uint16_t loop;
    int      numPrinted = 0;

    for (loop = 0; loop < size; loop++) {
        if (isprint(*(data + loop)) && !iscntrl(*(data + loop))) {
            printf("%c", *(data + loop));
        } else {
            printf(".");
        }
        if ('\n' == *(data + loop) || '\r' == *(data + loop)
            || '\0' == (data + loop))
        {
            break;
        }
        numPrinted++;
    }

    return numPrinted;
}
#endif /* 0 */
