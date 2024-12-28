/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file ircplugin.c
 *
 *  this provides IRC payload packet recognition for use within YAF
 *  It is based on RFC 2812 and some random limited packet capture.
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

#define IE_NUM_ircTextMessage   125

/* IDs used by yfDPIData_t->dpacketID */
#define YF_IRC_TEXT_MESSAGE     202

#define YAF_IRC_TID    0xC200
#define YAF_IRC_NAME   "yaf_irc"
#define YAF_IRC_DESC   NULL

static fbInfoElementSpec_t yaf_irc_spec[] = {
    {"ircTextMessageList",  FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_irc_st {
    /* basicList of ircTextMessage */
    fbBasicList_t   ircTextMessageList;
} yaf_irc_t;

static fbTemplate_t *yaf_irc_tmpl;
#endif  /* YAF_ENABLE_DPI */

#define IRCDEBUG 0
#define IRC_PORT_NUMBER 194

/**
 * the compiled regular expressions, and related
 * flags
 *
 */
static pcre *ircMsgRegex = NULL;
/*static pcre *ircJoinRegex = NULL;*/
static pcre *ircRegex = NULL;
#ifdef YAF_ENABLE_DPI
static pcre *ircDPIRegex = NULL;
#endif


/**
 * static local functions
 *
 */
#if IRCDEBUG
static int
ycDebugBinPrintf(
    uint8_t   *data,
    uint16_t   size);
#endif /* if IRCDEBUG */

/**
 * ydpScanPayload
 *
 * scans a given payload to see if it conforms to our idea of what IRC traffic
 * looks like.
 *
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match IRC_PORT_NUMBER (194) for a match
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

    rc = pcre_exec(ircMsgRegex, NULL, (char *)payload, payloadSize,
                   0, 0, vects, NUM_CAPT_VECTS);

    /*if (rc <= 0) {
     *  rc = pcre_exec(ircJoinRegex, NULL, (char *)payload, payloadSize,
     *                 0, 0, vects, NUM_CAPT_VECTS);
     *                 }*/
    if (rc <= 0) {
        rc = pcre_exec(ircRegex, NULL, (char *)payload, payloadSize,
                       0, 0, vects, NUM_CAPT_VECTS);
    }

    /*  at some point in the future, this is the place to extract protocol
     *  information like message targets and join targets, etc. */

#ifdef YAF_ENABLE_DPI
    if (rc > 0) {
        /* single basicList so value used for 7th arg does not matter */
        ydRunPluginRegex(flow, payload, payloadSize, ircDPIRegex, 0,
                         YF_IRC_TEXT_MESSAGE, IRC_PORT_NUMBER);
    }
#endif /* ifdef YAF_ENABLE_DPI */

    if (rc > 0) {
        return IRC_PORT_NUMBER;
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
                                  YAF_IRC_TID, yaf_irc_tmpl,
                                  "ircTextMessage");
}

gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t      *mdInfo;
    const fbInfoElement_t *bl_element;

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_IRC_NAME, YAF_IRC_DESC,
                       IRC_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    /* ruleset does not contain IE information, add metadata manually */
    /*fbTemplateInfoAddBasicList(mdInfo, IANA_ENT, IANA_BASICLIST_IE,
     * CERT_PEN, 125); */
    bl_element = ydLookupNamedBlByID(CERT_PEN, IE_NUM_ircTextMessage);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, IE_NUM_ircTextMessage);
    }

    if (!ydInitTemplate(&yaf_irc_tmpl, session, yaf_irc_spec,
                        mdInfo, YAF_IRC_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_irc_t *rec = (yaf_irc_t *)flowContext->rec;
    fbBasicListClear(&rec->ircTextMessageList);
}
#endif  /* YAF_ENABLE_DPI */


/**
 * ydpInitialize
 *
 * this initializes the PCRE expressions needed to search the payload for
 * IRC and enables DPI Information Elements.
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

    ircRegex = ycFindCompilePluginRegex(
        pluginRegexes, "ircRegex", PCRE_EXTENDED | PCRE_ANCHORED, err);
    ircMsgRegex = ycFindCompilePluginRegex(
        pluginRegexes, "ircMsgRegex", PCRE_EXTENDED | PCRE_ANCHORED, err);

    if (!ircRegex || !ircMsgRegex) {
        g_prefix_error(err, "In IRC plugin: ");
        return -1;
    }

#ifdef YAF_ENABLE_DPI
    ircDPIRegex = ycFindCompilePluginRegex(
        pluginRegexes, "ircDPIRegex", PCRE_MULTILINE, err);
    if (!ircDPIRegex) {
        g_prefix_error(err, "In IRC plugin: ");
        return -1;
    }
    GArray *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;
    YC_ENABLE_ELEMENTS(yaf_irc, pluginTemplates);
#endif /* ifdef YAF_ENABLE_DPI */
    return 1;
}


#if IRCDEBUG
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
#endif /* if IRCDEBUG */
