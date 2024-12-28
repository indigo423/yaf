/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @INTERNAL
 *
 *  @file pop3plugin.c
 *
 *  this provides POP3 payload packet recognition for use within YAF
 *  It is based on RFC 1939 and some random limited packet capture.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Dan Ruef, Emily Ecoff
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

#define YAF_POP3_TID   0xC300
#define YAF_POP3_NAME  "yaf_pop3"
#define YAF_POP3_DESC  NULL

/* pop3TextMessage */
#define IE_NUM_pop3TextMessage  124

static fbInfoElementSpec_t yaf_pop3_spec[] = {
    {"pop3TextMessageList", FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_pop3_st {
    /* basicList of pop3TextMessage */
    fbBasicList_t   pop3TextMessageList;
} yaf_pop3_t;

static fbTemplate_t *yaf_pop3_tmpl;
#endif  /* YAF_ENABLE_DPI */

#define POP3DEBUG 0
#define POP3_PORT_NUMBER 110

/**
 * the compiled regular expressions, and related
 * flags
 *
 */
static pcre *pop3RegexApplabel = NULL;
#ifdef YAF_ENABLE_DPI
static pcre *pop3RegexRequest  = NULL;
static pcre *pop3RegexResponse = NULL;
#endif


/**
 * static local functions
 *
 */

#if POP3DEBUG
static int
ycDebugBinPrintf(
    uint8_t   *data,
    uint16_t   size);
#endif /* if POP3DEBUG */

/**
 * ydpScanPayload
 *
 * scans a given payload to see if it conforms to our idea of what POP3 traffic
 * looks like.
 *
 *
 *
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match POP3_PORT_NUMBER (110) for a match
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

    rc = pcre_exec(pop3RegexApplabel, NULL, (char *)payload, payloadSize, 0,
                   0, vects, NUM_CAPT_VECTS);
    if (rc <= 0) {
        return 0;
    }

#ifdef YAF_ENABLE_DPI
    if (rc == 2) {
        /* server side */
        ydRunPluginRegex(flow, payload, payloadSize, pop3RegexResponse, 0,
                         111, POP3_PORT_NUMBER);
    } else {
        /* client side */
        ydRunPluginRegex(flow, payload, payloadSize, pop3RegexRequest, 0,
                         110, POP3_PORT_NUMBER);
    }
#endif /* ifdef YAF_ENABLE_DPI */

    return POP3_PORT_NUMBER;
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
                                  YAF_POP3_TID, yaf_pop3_tmpl,
                                  "pop3TextMessage");
}

gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t      *mdInfo;
    const fbInfoElement_t *bl_element;

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_POP3_NAME, YAF_POP3_DESC,
                       POP3_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    /* ruleset does not contain IE information, add metadata manually */
    bl_element = ydLookupNamedBlByID(CERT_PEN, IE_NUM_pop3TextMessage);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, IE_NUM_pop3TextMessage);
    }

    if (!ydInitTemplate(&yaf_pop3_tmpl, session, yaf_pop3_spec,
                        mdInfo, YAF_POP3_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_pop3_t *rec = (yaf_pop3_t *)flowContext->rec;

    fbBasicListClear(&rec->pop3TextMessageList);
}
#endif  /* YAF_ENABLE_DPI */

/**
 * ydpInitialize
 *
 * this finds and initializes the PCRE expressions needed to search the payload
 * for POP3 and enables DPI Information Elements.
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

    /* used to determine if this connection looks like POP3; capture the
     * response to distinguish the server from the client */
    pop3RegexApplabel = ycFindCompilePluginRegex(
        pluginRegexes, "pop3RegexApplabel", 0, err);
#ifdef YAF_ENABLE_DPI
    /* capture everything the client says */
    pop3RegexRequest = ycFindCompilePluginRegex(
        pluginRegexes, "pop3RegexRequest", 0, err);

    /* capture the first line of each response */
    pop3RegexResponse = ycFindCompilePluginRegex(
        pluginRegexes, "pop3RegexResponse", 0, err);

    if (!pop3RegexApplabel || !pop3RegexRequest || !pop3RegexResponse) {
        g_prefix_error(err, "In POP3 plugin: ");
        return -1;
    }
    GArray *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;
    YC_ENABLE_ELEMENTS(yaf_pop3, pluginTemplates);
#endif  /* YAF_ENABLE_DPI */
    return 1;
}



#if POP3DEBUG
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
            || '\0' == *(data + loop))
        {
            break;
        }
        numPrinted++;
    }

    return numPrinted;
}
#endif /* if POP3DEBUG */
