/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file smtpplugin.c
 *
 *  @brief this is a protocol classifier for the simple mail transport
 *  protocol (SMTP)
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

#define YAF_SMTP_TID            0xCB01
#define YAF_SMTP_NAME           "yaf_smtp"
#define YAF_SMTP_DESC           NULL

#define YAF_SMTP_MESSAGE_TID    0xCB02
#define YAF_SMTP_MESSAGE_NAME   "yaf_smtp_message"
#define YAF_SMTP_MESSAGE_DESC   NULL

#define YAF_SMTP_HEADER_TID     0xCB03
#define YAF_SMTP_HEADER_NAME    "yaf_smtp_header"
#define YAF_SMTP_HEADER_DESC    NULL

/* top level SMTP DPI subrecord */
static fbInfoElementSpec_t yaf_smtp_spec[] = {
    {"smtpHello",         FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpResponseList",  FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpMessageList",   FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpStartTLS",      1, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_smtp_st {
    fbVarfield_t          smtpHello;
    /* basicList of smtpResponse */
    fbBasicList_t         smtpResponseList;
    fbSubTemplateList_t   smtpMessageList;
    uint8_t               smtpStartTLS;
} yaf_smtp_t;

static fbInfoElementSpec_t yaf_smtp_message_spec[] = {
    {"smtpSubject",       FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpToList",        FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpFromList",      FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpFilenameList",  FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpURLList",       FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpHeaderList",    FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpMessageSize",   4,            YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_smtp_message_st {
    fbVarfield_t          smtpSubject;
    fbBasicList_t         smtpToList;
    fbBasicList_t         smtpFromList;
    fbBasicList_t         smtpFilenameList;
    fbBasicList_t         smtpURLList;
    fbSubTemplateList_t   smtpHeaderList;
    uint32_t              smtpSize;
} yaf_smtp_message_t;

static fbInfoElementSpec_t yaf_smtp_header_spec[] = {
    {"smtpKey",           FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"smtpValue",         FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_smtp_header_st {
    fbVarfield_t   smtpKey;
    fbVarfield_t   smtpValue;
} yaf_smtp_header_t;

static fbTemplate_t *yaf_smtp_tmpl;
static fbTemplate_t *yaf_smtp_message_tmpl;
static fbTemplate_t *yaf_smtp_header_tmpl;


/*  Max number of separate emails; note that these fill space in the DPI
 *  array that could be used by other DPI info. */
#define SMTP_MAX_EMAILS 5

/*  If the <CRLF>.<CRLF> to close a message is within this number of bytes of
 *  the payloadSize, assume the only remaining SMTP command from the client is
 *  "QUIT<CRLF>". */
#define YF_BYTES_AFTER_DOT  12

/* IDs used by yfDPIData_t->dpacketID */
/* HELO/EHLO */
#define YF_SMTP_HELO      26
/* SIZE following MAIL FROM */
#define YF_SMTP_SIZE      28
/* STARTTLS */
#define YF_SMTP_STARTTLS  29
/* Response messages/codes */
#define YF_SMTP_RESPONSE  30
/* Text following Subject: */
#define YF_SMTP_SUBJECT   31
/* RCTP TO */
#define YF_SMTP_TO        32
/* MAIL FROM */
#define YF_SMTP_FROM      33
/* filename in Content-Disposition */
#define YF_SMTP_FILENAME  34
/* any URL */
#define YF_SMTP_URL       35
/* Generic header */
#define YF_SMTP_HEADER    36
/* End of one message / Start of another */
#define YF_SMTP_MSGBOUND  38

#endif  /* YAF_ENABLE_DPI */

#define SMTP_PORT_NUMBER 25

/*  Size for PCRE capture vector. */
#define NUM_CAPT_VECTS 60

static pcre *smtpRegexApplabel = NULL;

#ifdef YAF_ENABLE_DPI
static pcre *smtpRegexBdatLast = NULL;
static pcre *smtpRegexBlankLine = NULL;
static pcre *smtpRegexDataBdat = NULL;
static pcre *smtpRegexEndData = NULL;

static pcre *smtpRegexFilename = NULL;
static pcre *smtpRegexFrom = NULL;
static pcre *smtpRegexHeader = NULL;
static pcre *smtpRegexHello = NULL;
static pcre *smtpRegexResponse = NULL;
static pcre *smtpRegexSize = NULL;
static pcre *smtpRegexStartTLS = NULL;
static pcre *smtpRegexSubject = NULL;
static pcre *smtpRegexTo = NULL;
static pcre *smtpRegexURL = NULL;

static const fbInfoElement_t *smtpElemFilename = NULL;
static const fbInfoElement_t *smtpElemFrom = NULL;
static const fbInfoElement_t *smtpElemResponse = NULL;
static const fbInfoElement_t *smtpElemTo = NULL;
static const fbInfoElement_t *smtpElemURL = NULL;
#endif  /* YAF_ENABLE_DPI */


#ifndef YFP_DEBUG
#define YFP_DEBUG 0
#endif

#if !YFP_DEBUG
#define YFP_DEBUG_STORE_COUNT(count_, flowctx_)
#define YFP_DEBUG_LOG_NEW(count_, flowctx_, what_)
#else

#define YFP_DEBUG_STORE_COUNT(count_, flowctx_) \
    do { *(count_) = (flowctx_)->dpinum; } while (0)

#define YFP_DEBUG_LOG_NEW(count_, flowctx_, what_)          \
    do {                                                    \
        g_debug("SMTP %s check matched %u locations",       \
                what_, (flowctx_)->dpinum - *(count_));     \
        while (*(count_) < (flowctx_)->dpinum) {            \
            ydpPayloadPrinter(                              \
                payload, payloadSize,                       \
                (flowctx_)->dpi[*(count_)].dpacketCapt,     \
                (flowctx_)->dpi[*(count_)].dpacketCaptLen,  \
                "    offset %u, len %u, data",              \
                (flowctx_)->dpi[*(count_)].dpacketCapt,     \
                (flowctx_)->dpi[*(count_)].dpacketCaptLen); \
            ++*(count_);                                    \
        }                                                   \
    } while (0)



/**
 *  Print `numPrint` octets of data contained in `payloadData` starting at
 *  octet position `offset`.  `payloadSize` is the size of `payloadData`.  The
 *  output is prefixed with text created by applying `format` to the remaining
 *  arguments, followed by ": ".
 */
static void
ydpPayloadPrinter(
    const uint8_t  *payloadData,
    unsigned int    payloadSize,
    unsigned int    offset,
    unsigned int    numPrint,
    const char     *format,
    ...)
{
#define PAYLOAD_PRINTER_ARRAY_LENGTH 4096
    unsigned int loop;
    char         dumpArray[PAYLOAD_PRINTER_ARRAY_LENGTH];
    char         prefixString[PAYLOAD_PRINTER_ARRAY_LENGTH];
    va_list      args;

    va_start(args, format);
    vsnprintf(prefixString, sizeof(prefixString), format, args);
    va_end(args);

    if (NULL == payloadData) {
        numPrint = 0;
    } else {
        if (offset >= payloadSize) {
            numPrint = 0;
        } else {
            payloadSize -= offset;
            payloadData += offset;
        }
        if (numPrint > payloadSize) {
            numPrint = payloadSize;
        }
        if (numPrint > PAYLOAD_PRINTER_ARRAY_LENGTH) {
            numPrint = PAYLOAD_PRINTER_ARRAY_LENGTH;
        }
    }
    for (loop = 0; loop < numPrint; ++loop) {
        if (isprint(*(payloadData + loop)) &&
            !iscntrl(*(payloadData + loop)))
        {
            dumpArray[loop] = (char)(*(payloadData + loop));
        } else {
            dumpArray[loop] = '.';
        }
    }
    dumpArray[loop] = '\0';

    g_debug("%s: \"%s\"", prefixString, dumpArray);
}
#endif /* if YFP_DEBUG */


#ifdef YAF_ENABLE_DPI
/**
 * @brief Create a regex string that excludes some headers
 * The caller is responsible for freeing the returned string
 *
 * @param excludedHeaders A list of headers to exclude.
 * @param len The length/number of excludedHeaders
 * @param regexString The original regex string to change
 * @return GString* The new regex string
 */
static GString *
excludeRegexes(
    char  *excludedHeaders[],
    int    len,
    char  *regexString)
{
    /* builds:
     * (?im)^<exclude>:(*SKIP)(*F)|^<exclude>:(*SKIP)(*F)|<smtpRegexHeader> */

    const char *mlm = "(?im)"; /* case insensitive multiline mode */
    const char *newline = "^"; /*newline caret */
    const char *skipfail = ":(*SKIP)(*F)|"; /* PCRE Regex magic */

    GString    *newRegexString = g_string_new(regexString);

    /* prepend the excluded terms and extra stuff into a new regex string;
     * since we prepend, work backward through the headers to maintain the
     * user's order---helpful if an error message is generated */
    while (len > 0) {
        --len;
        g_string_insert(newRegexString, 0, skipfail);
        g_string_insert(newRegexString, 0, excludedHeaders[len]);
        g_string_insert(newRegexString, 0, newline);
    }
    g_string_insert(newRegexString, 0, mlm);

    return newRegexString;
}
#endif  /* YAF_ENABLE_DPI */

/**
 * ydpScanPayload
 *
 * returns SMTP_PORT_NUMBER if the passed in payload matches a service location
 * protocol packet
 *
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return SMTP_PORT_NUMBER otherwise 0
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#if YFP_DEBUG && YAF_ENABLE_DPI
    const ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)(flow->dpictx);
    unsigned int          prev;
#endif
    int rc;
    int vects[NUM_CAPT_VECTS];

#if YFP_DEBUG
    g_debug("smtpplugin scanning payload of flow %p\n", flow);
#endif

    rc = pcre_exec(smtpRegexApplabel, NULL, (char *)payload, payloadSize,
                   0, 0, vects, NUM_CAPT_VECTS);
#if YFP_DEBUG
    ydpPayloadPrinter(payload, payloadSize, 0, 512,
                      "SMTP applabel check returned %d", rc);
#endif

#ifdef YAF_ENABLE_DPI
    /* If pcre_exec() returns 1 this is the client-side of the conversation
     * and if 2 it is the server-side. */
    if (rc == 1) {
        /*
         * To limit the regexes to searching only the relative parts of the
         * payload, we first find the positions of those relative parts, while
         * being aware multiple messages may be sent during a single
         * connection.
         *
         * msgSplits[i] is start of the area where STMP commands are allowed
         * and also marks the end of message i-1.
         * msgData[i] is boundary between STMP commands and the message.
         * msgBegin[i] equals msgData[i] unless DATA/BDAT was not seen, in
         * which case it equals msgSplit[i].
         * hdrEnd[i] is the blank line beween the msg's header and body.
         */
        uint32_t msgSplits[1 + SMTP_MAX_EMAILS];
        uint32_t msgData[SMTP_MAX_EMAILS];
        uint32_t msgBegin[SMTP_MAX_EMAILS];
        uint32_t hdrEnd[SMTP_MAX_EMAILS];
        int msgIndex = 0;
        int tmprc;
        int i;

        msgSplits[0] = 0;

        for (;;) {
            /* look for DATA or BDAT */
            tmprc = pcre_exec(smtpRegexDataBdat, NULL, (char *)payload,
                              payloadSize, msgSplits[msgIndex],
                              0, vects, NUM_CAPT_VECTS);
#if YFP_DEBUG
            switch (tmprc) {
              case 1:
                ydpPayloadPrinter(
                    payload, payloadSize, vects[0], (1 + vects[1] - vects[0]),
                    ("SMTP data/bdat check returned %d at offset %d"
                     "; vects %d,%d; data"),
                    tmprc, msgSplits[msgIndex], vects[0], vects[1]);
                break;
              case 2:
                ydpPayloadPrinter(
                    payload, payloadSize, vects[0], (1 + vects[1] - vects[0]),
                    ("SMTP data/bdat check returned %d at offset %d"
                     "; vects %d,%d %d,%d; data"),
                    tmprc, msgSplits[msgIndex], vects[0], vects[1],
                    vects[2], vects[3]);
                break;
              default:
                ydpPayloadPrinter(
                    payload, payloadSize, MAX(0, msgSplits[msgIndex] - 10),
                    64, "SMTP data/bdat check returned %d at offset %d; data",
                    tmprc, msgSplits[msgIndex]);
                break;
            }
#endif  /* YFP_DEBUG */

            if (tmprc <= 0) {
                /* DATA/BDAT not found; if there are more than
                 * YF_BYTES_AFTER_DOT bytes of payload after the end of the
                 * last message, assume the payload contains the start of
                 * another "MAIL FROM:..." */
                if (payloadSize - msgSplits[msgIndex] > YF_BYTES_AFTER_DOT) {
                    msgData[msgIndex] = payloadSize;
                    msgBegin[msgIndex] = msgSplits[msgIndex];
                    hdrEnd[msgIndex] = payloadSize;
                    msgSplits[++msgIndex] = payloadSize;
                }
                break;
            }

            msgData[msgIndex] = msgBegin[msgIndex] = vects[1];
            /* assume email message goes to end of payload */
            msgSplits[msgIndex + 1] = payloadSize;

            if (tmprc == 2) {
                /* saw "BDAT <LENGTH>(| +LAST)"; if the character before
                 * vects[3] is not 'T', search for the last BDAT blob */
                if ('T' != payload[vects[3] - 1]) {
                    tmprc = pcre_exec(smtpRegexBdatLast, NULL, (char *)payload,
                                      payloadSize, msgData[msgIndex], 0,
                                      vects, NUM_CAPT_VECTS);
#if YFP_DEBUG
                    g_debug("SMTP bdat last check returned %d at offset %d"
                            "; vects[0] is %d",
                            tmprc, msgData[msgIndex], vects[0]);
#endif
                }

                if (tmprc > 1) {
                    /* parse the length of the last BDAT blob to find the end
                     * of the message */
                    unsigned long len;
                    char         *ep = (char *)payload;

                    errno = 0;
                    len = strtoul((char *)payload + vects[2], &ep, 10);
                    if (len > 0 || (0 == errno && ep != (char *)payload)) {
                        msgSplits[msgIndex + 1] =
                            MIN(vects[1] + len, payloadSize);
                    }
#if YFP_DEBUG
                    else {
                        ydpPayloadPrinter(
                            payload, payloadSize, vects[0],
                            (1 + vects[1] - vects[0]),
                            "Unable to parse BDAT length: %s; data",
                            strerror(errno));
                    }
#endif  /* YFP_DEBUG */
                }
            } else {
                /* saw DATA; search for <CRLF>.<CRLF> to find the end of
                 * msg */
                tmprc = pcre_exec(smtpRegexEndData, NULL, (char *)payload,
                                  payloadSize, msgData[msgIndex], 0,
                                  vects, NUM_CAPT_VECTS);
#if YFP_DEBUG
                g_debug("SMTP end data check returned %d at offset %d"
                        "; vects[0] is %d",
                        tmprc, msgData[msgIndex], vects[0]);
#endif
                if (tmprc > 0) {
                    msgSplits[msgIndex + 1] = vects[1];
                }
            }

            /* find the separator between headers and body; if not found, set
             * it to the next message split */
            tmprc = pcre_exec(smtpRegexBlankLine, NULL, (char *)payload,
                              msgSplits[msgIndex + 1], msgData[msgIndex], 0,
                              vects, NUM_CAPT_VECTS);
#if YFP_DEBUG
            g_debug("SMTP blank check returned %d at offset %d; vects[0] is %d",
                    tmprc, msgData[msgIndex], vects[0]);
#endif
            if (tmprc > 0) {
                hdrEnd[msgIndex] = vects[1];
            } else {
                hdrEnd[msgIndex] = msgSplits[msgIndex + 1];
            }

            ++msgIndex;
            if (msgIndex >= SMTP_MAX_EMAILS ||
                msgSplits[msgIndex] >= payloadSize)
            {
                break;
            }
        }

#if YFP_DEBUG
        g_debug("Found %d messages in payload of size %u:",
                msgIndex, payloadSize);
        for (i = 0; i < msgIndex; ++i) {
            g_debug("    msg# %d, smtpBegin %d, data %d, msgBegin %d,"
                    " blank %d, end %d",
                    i, msgSplits[i], msgData[i], msgBegin[i], hdrEnd[i],
                    msgSplits[i + 1]);
        }
#endif  /* YFP_DEBUG */

        /* Capture headers in order of importance since we may run out of room
         * in the DPI array */

        /* Check for hello, from, to, and subject in each message */
        YFP_DEBUG_STORE_COUNT(&prev, flowContext);
        for (i = 0; i < msgIndex && msgSplits[i] < payloadSize; ++i) {
            /* store the end of the message as a separator if it not at or
             * near the end of the payload */
            if (msgSplits[i + 1] + YF_BYTES_AFTER_DOT < payloadSize) {
                ydRunPluginRegex(flow, payload, 2, NULL, msgSplits[i + 1],
                                 YF_SMTP_MSGBOUND, SMTP_PORT_NUMBER);
                YFP_DEBUG_LOG_NEW(&prev, flowContext, "msg separator");
            }

            ydRunPluginRegex(flow, payload, msgData[i], smtpRegexHello,
                             msgSplits[i], YF_SMTP_HELO, SMTP_PORT_NUMBER);
            YFP_DEBUG_LOG_NEW(&prev, flowContext, "hello");

            ydRunPluginRegex(flow, payload, msgData[i], smtpRegexFrom,
                             msgSplits[i], YF_SMTP_FROM, SMTP_PORT_NUMBER);
            YFP_DEBUG_LOG_NEW(&prev, flowContext, "from");

            ydRunPluginRegex(flow, payload, msgData[i], smtpRegexTo,
                             msgSplits[i], YF_SMTP_TO, SMTP_PORT_NUMBER);
            YFP_DEBUG_LOG_NEW(&prev, flowContext, "to");

            ydRunPluginRegex(flow, payload, hdrEnd[i], smtpRegexSubject,
                             msgBegin[i], YF_SMTP_SUBJECT, SMTP_PORT_NUMBER);
            YFP_DEBUG_LOG_NEW(&prev, flowContext, "subject");
        }

        /* get filenames and urls throughout the payload */
        ydRunPluginRegex(flow, payload, payloadSize, smtpRegexFilename,
                         0, YF_SMTP_FILENAME, SMTP_PORT_NUMBER);
        YFP_DEBUG_LOG_NEW(&prev, flowContext, "filename");

        ydRunPluginRegex(flow, payload, payloadSize,
                         smtpRegexURL, 0, YF_SMTP_URL, SMTP_PORT_NUMBER);
        YFP_DEBUG_LOG_NEW(&prev, flowContext, "url");

        /* look for starttls, msg size, and headers per message */
        for (i = 0; i < msgIndex && msgSplits[i] < payloadSize; ++i) {
            ydRunPluginRegex(flow, payload, msgData[i], smtpRegexStartTLS,
                             msgSplits[i], YF_SMTP_STARTTLS, SMTP_PORT_NUMBER);
            YFP_DEBUG_LOG_NEW(&prev, flowContext, "starttls");

            ydRunPluginRegex(flow, payload, msgData[i], smtpRegexSize,
                             msgSplits[i], YF_SMTP_SIZE, SMTP_PORT_NUMBER);
            YFP_DEBUG_LOG_NEW(&prev, flowContext, "msg size");

            ydRunPluginRegex(flow, payload, hdrEnd[i], smtpRegexHeader,
                             msgBegin[i], YF_SMTP_HEADER, SMTP_PORT_NUMBER);
            YFP_DEBUG_LOG_NEW(&prev, flowContext, "header");
        }
    } else if (rc > 0 || flow->appLabel == SMTP_PORT_NUMBER) {
        YFP_DEBUG_STORE_COUNT(&prev, flowContext);
        ydRunPluginRegex(flow, payload, payloadSize, smtpRegexResponse, 0,
                         YF_SMTP_RESPONSE, SMTP_PORT_NUMBER);
        YFP_DEBUG_LOG_NEW(&prev, flowContext, "response");
    }
#endif /* ifdef YAF_ENABLE_DPI */

    if (rc > 0 || flow->appLabel == SMTP_PORT_NUMBER) {
        return SMTP_PORT_NUMBER;
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
    yfDPIData_t  *dpi = flowContext->dpi;
    yaf_smtp_t   *rec = NULL;
    int           count;

    fbVarfield_t *responseCode = NULL;
    fbVarfield_t *smtpTo = NULL;
    fbVarfield_t *smtpFrom = NULL;
    fbVarfield_t *smtpFilename = NULL;
    fbVarfield_t *smtpURL = NULL;
    yaf_smtp_message_t *smtpEmail;
    yaf_smtp_header_t  *smtpHeader;

    /* DPI counts, one for each list */
    int            numMatchesTo;
    int            numMatchesFrom;
    int            numMatchesFile;
    int            numMatchesURL;
    int            numMatchesHeader;
    const uint8_t *msgBound[SMTP_MAX_EMAILS + 1];
    int            numMessages;
    int            msgIndex;

    unsigned int   maxMsgCapt = 0;
    const uint8_t *msgBegin;
    const uint8_t *msgEnd;
    const uint8_t *colon;

    const yfFlowVal_t *current;
    const yfFlowVal_t *msgData = NULL;

    /*
     * FIXME: Consider changing this function so it does not cache the
     * msgData.  While we expect all msgData to be on one side of the
     * connection, we cannot know what data will actually be matched by this
     * plugin.
     *
     * The current approach is to initialize msgData when data is matched and
     * refuse to change it to the other direction.  A different approach is to
     * store the number of messages and the msgBound[]s for both the forward
     * and reverse directions.
     */

#if YFP_DEBUG
    g_debug("smtpplugin processing dpi of flow %p\n", flow);
#endif

    rec = (yaf_smtp_t *)fbSubTemplateListInit(stl, 3, YAF_SMTP_TID,
                                              yaf_smtp_tmpl, 1);
    rec->smtpHello.buf = NULL;
    rec->smtpStartTLS = 0;

    /* Create an empty basicList of SMTP response codes; fill the list as we
     * scan the data. */
    fbBasicListInit(&rec->smtpResponseList, 3, smtpElemResponse, 0);

#if YFP_DEBUG
    {
        char         buf[1024] = "";
        unsigned int pos = 0;
        int          i;
        for (i = 0; i < totalcap && pos < sizeof(buf); ++i) {
            pos += snprintf(buf + pos, (sizeof(buf) - pos), "%s%u",
                            ((pos > 0) ? ", " : ""), dpi[i].dpacketID);
        }
        g_debug("totalcap = %d, fwdcap = %d, flowContext->startOffset = %d,"
                " dpacketID = [%s]",
                totalcap, fwdcap, flowContext->startOffset, buf);
    }
#endif  /* YFP_DEBUG */

    /* Assume one message */
    numMessages = 1;

    /* Capture top-level data; determine whether forward or reverse direction
     * captured the client; capture the response codes; note bounds between
     * messages when multiple in a single conversation */
    for (count = flowContext->startOffset; count < totalcap; ++count) {
        current = ((count < fwdcap) ? &flow->val : &flow->rval);
        switch (dpi[count].dpacketID) {
          case YF_SMTP_HELO:
            if (rec->smtpHello.buf == NULL) {
                rec->smtpHello.buf = current->payload + dpi[count].dpacketCapt;
                rec->smtpHello.len = dpi[count].dpacketCaptLen;
            }
            if (msgData != current) {
                if (NULL == msgData) {
                    msgData = current;
                } else {
#if YFP_DEBUG
                    g_debug("msgData appears in both directions;"
                            " count = %d, ID = %d",
                            count, dpi[count].dpacketID);
#endif
                    break;
                }
            }
            if (dpi[count].dpacketCapt > maxMsgCapt) {
                maxMsgCapt = dpi[count].dpacketCapt;
            }
            break;
          case YF_SMTP_STARTTLS:
            rec->smtpStartTLS = 1;
            break;
          case YF_SMTP_RESPONSE:
            responseCode = (fbVarfield_t *)
                fbBasicListAddNewElements(&rec->smtpResponseList, 1);
            responseCode->buf = current->payload + dpi[count].dpacketCapt;
            responseCode->len = dpi[count].dpacketCaptLen;
#if YFP_DEBUG
            ydpPayloadPrinter(current->payload, current->paylen,
                              dpi[count].dpacketCapt, dpi[count].dpacketCaptLen,
                              "Response: ");
#endif
            break;
          case YF_SMTP_MSGBOUND:
            /* End of one message / Start of another */
            if (msgData != current) {
                if (NULL == msgData) {
                    msgData = current;
                } else {
#if YFP_DEBUG
                    g_debug("msgData appears in both directions;"
                            " count = %d, ID = %d",
                            count, dpi[count].dpacketID);
#endif
                    break;
                }
            }
            msgBound[numMessages] = current->payload + dpi[count].dpacketCapt;
            ++numMessages;
            if (dpi[count].dpacketCapt > maxMsgCapt) {
                maxMsgCapt = dpi[count].dpacketCapt;
            }
#if YFP_DEBUG
            g_debug("message separator #%d at offset %d",
                    numMessages - 1, dpi[count].dpacketCapt);
#endif
            break;
          case YF_SMTP_SIZE:
          case YF_SMTP_SUBJECT:
          case YF_SMTP_TO:
          case YF_SMTP_FROM:
          case YF_SMTP_FILENAME:
          case YF_SMTP_URL:
          case YF_SMTP_HEADER:
            if (msgData != current) {
                if (NULL == msgData) {
                    msgData = current;
                } else {
#if YFP_DEBUG
                    g_debug("msgData appears in both directions;"
                            " count = %d, ID = %d",
                            count, dpi[count].dpacketID);
#endif
                    break;
                }
            }
            if (dpi[count].dpacketCapt > maxMsgCapt) {
                maxMsgCapt = dpi[count].dpacketCapt;
            }
            break;
          default:
            g_debug("Unexpected dpacketID %d in %s plugin",
                    dpi[count].dpacketID, __FILE__);
            break;
        }
    }

#if YFP_DEBUG
    g_debug("fwd = %p, fwdlen = %u, rev = %p, revlen = %u, msgData = %p,"
            " maxMsgCapt = %u",
            &flow->val, flow->val.paylen, &flow->rval, flow->rval.paylen,
            msgData, maxMsgCapt);
#endif  /* YFP_DEBUG */

    if (NULL == msgData) {
        fbSubTemplateListInit(&rec->smtpMessageList, 3,
                              YAF_SMTP_MESSAGE_TID, yaf_smtp_message_tmpl, 0);
        return rec;
    }

    /* the first message begins at the start of the payload */
    msgBound[0] = msgData->payload;

    /* if no data was captured within the last bounded message, decrement the
     * number of messages; otherwise, set the bound of the final message to
     * the end of the payload */
    if (msgData->payload + maxMsgCapt <= msgBound[numMessages - 1]) {
#if YFP_DEBUG
        g_debug("numMessages = %d, maxMsgCapt = %d,"
                " msgBound[nm-1] = %ld, fwdlen = %u,"
                " decrementing numMessages",
                numMessages, maxMsgCapt,
                msgBound[numMessages - 1] - msgData->payload, flow->val.paylen);
#endif /* if YFP_DEBUG */
        --numMessages;
    } else {
#if YFP_DEBUG
        g_debug("numMessages = %d, maxMsgCapt = %d,"
                " msgBound[nm-1] = %ld, fwdlen = %u,"
                " setting msgBound to paylen",
                numMessages, maxMsgCapt,
                msgBound[numMessages - 1] - msgData->payload, flow->val.paylen);
#endif /* if YFP_DEBUG */
        msgBound[numMessages] = msgData->payload + msgData->paylen;
    }

    /* Create the STL of messages */
    smtpEmail = ((yaf_smtp_message_t *)fbSubTemplateListInit(
                     &rec->smtpMessageList, 3,
                     YAF_SMTP_MESSAGE_TID, yaf_smtp_message_tmpl,
                     numMessages));

    /* FIXME: Consider changing the following loop to build the lists in one
     * pass instead of looping through the data once to count things and then
     * again to fill the lists. */

    /* Process each message */
    for (msgIndex = 0; msgIndex < numMessages; ++msgIndex) {
        msgBegin = msgBound[msgIndex];
        msgEnd = msgBound[msgIndex + 1];

        /* for IEs stored in basicLists or STLs, count the number of items to
         * know how big to make the lists. */
        numMatchesTo = 0;
        numMatchesFrom = 0;
        numMatchesFile = 0;
        numMatchesURL = 0;
        numMatchesHeader = 0;

        for (count = flowContext->startOffset; count < totalcap; ++count) {
            if (msgData->payload + dpi[count].dpacketCapt >= msgBegin &&
                (msgData->payload + dpi[count].dpacketCapt <= msgEnd))
            {
                switch (dpi[count].dpacketID) {
                  case YF_SMTP_TO:
                    numMatchesTo++;
                    break;
                  case YF_SMTP_FROM:
                    numMatchesFrom++;
                    break;
                  case YF_SMTP_FILENAME:
                    numMatchesFile++;
                    break;
                  case YF_SMTP_URL:
                    numMatchesURL++;
                    break;
                  case YF_SMTP_HEADER:
                    numMatchesHeader++;
                    break;
                }
            }
        }
#if YFP_DEBUG
        g_debug("Message #%d (%ld--%ld): numTo = %d, numFrom = %d,"
                " numFile = %d, numURL = %d, numHeader = %d",
                msgIndex,
                msgBegin - msgData->payload, msgEnd - msgData->payload,
                numMatchesTo, numMatchesFrom,
                numMatchesFile, numMatchesURL, numMatchesHeader);
#endif /* if YFP_DEBUG */

        /* Create the basicLists and STLs */
        smtpTo = (fbVarfield_t *)fbBasicListInit(
            &smtpEmail->smtpToList, 3, smtpElemTo, numMatchesTo);

        smtpFrom = (fbVarfield_t *)fbBasicListInit(
            &smtpEmail->smtpFromList, 3, smtpElemFrom, numMatchesFrom);

        smtpFilename = (fbVarfield_t *)fbBasicListInit(
            &smtpEmail->smtpFilenameList, 3, smtpElemFilename, numMatchesFile);

        smtpURL = (fbVarfield_t *)fbBasicListInit(
            &smtpEmail->smtpURLList, 3, smtpElemURL, numMatchesURL);

        smtpHeader = (yaf_smtp_header_t *)fbSubTemplateListInit(
            &smtpEmail->smtpHeaderList, 3,
            YAF_SMTP_HEADER_TID, yaf_smtp_header_tmpl, numMatchesHeader);

        /* Fill the lists we just created */
        for (count = flowContext->startOffset; count < totalcap; ++count) {
            if (msgData->payload + dpi[count].dpacketCapt >= msgBegin &&
                msgData->payload + dpi[count].dpacketCapt <= msgEnd)
            {
                switch (dpi[count].dpacketID) {
                  case YF_SMTP_SIZE:
                    smtpEmail->smtpSize = (uint32_t)strtoul(
                        (char *)(msgData->payload + dpi[count].dpacketCapt),
                        NULL, 10);
                    break;
                  case YF_SMTP_SUBJECT:
                    if (NULL == smtpEmail->smtpSubject.buf) {
                        smtpEmail->smtpSubject.buf =
                            msgData->payload + dpi[count].dpacketCapt;
                        smtpEmail->smtpSubject.len = dpi[count].dpacketCaptLen;
#if YFP_DEBUG
                        ydpPayloadPrinter(
                            msgData->payload, msgData->paylen,
                            dpi[count].dpacketCapt, dpi[count].dpacketCaptLen,
                            "Subject");
#endif /* if YFP_DEBUG */
                    }
                    break;
                  case YF_SMTP_TO:
                    smtpTo->buf = msgData->payload + dpi[count].dpacketCapt;
                    smtpTo->len = dpi[count].dpacketCaptLen;
                    smtpTo = fbBasicListGetNextPtr(&smtpEmail->smtpToList,
                                                   smtpTo);
#if YFP_DEBUG
                    ydpPayloadPrinter(
                        msgData->payload, msgData->paylen,
                        dpi[count].dpacketCapt, dpi[count].dpacketCaptLen,
                        "To");
#endif /* if YFP_DEBUG */
                    break;
                  case YF_SMTP_FROM:
                    smtpFrom->buf = msgData->payload + dpi[count].dpacketCapt;
                    smtpFrom->len = dpi[count].dpacketCaptLen;
                    smtpFrom = fbBasicListGetNextPtr(&smtpEmail->smtpFromList,
                                                     smtpFrom);
#if YFP_DEBUG
                    ydpPayloadPrinter(
                        msgData->payload, msgData->paylen,
                        dpi[count].dpacketCapt, dpi[count].dpacketCaptLen,
                        "From");
#endif /* if YFP_DEBUG */
                    break;
                  case YF_SMTP_FILENAME:
                    smtpFilename->buf = msgData->payload +
                        dpi[count].dpacketCapt;
                    smtpFilename->len = dpi[count].dpacketCaptLen;
                    smtpFilename = fbBasicListGetNextPtr(
                        &smtpEmail->smtpFilenameList, smtpFilename);
#if YFP_DEBUG
                    ydpPayloadPrinter(
                        msgData->payload, msgData->paylen,
                        dpi[count].dpacketCapt - 50,
                        dpi[count].dpacketCaptLen + 60,
                        "Filename");
#endif /* if YFP_DEBUG */
                    break;
                  case YF_SMTP_URL:
                    smtpURL->buf = msgData->payload + dpi[count].dpacketCapt;
                    smtpURL->len = dpi[count].dpacketCaptLen;
                    smtpURL = fbBasicListGetNextPtr(&smtpEmail->smtpURLList,
                                                    smtpURL);
#if YFP_DEBUG
                    ydpPayloadPrinter(
                        msgData->payload, msgData->paylen,
                        dpi[count].dpacketCapt, dpi[count].dpacketCaptLen,
                        "URL");
#endif /* if YFP_DEBUG */
                    break;
                  case YF_SMTP_HEADER:
                    /* Header: split it at the ':' */
#if YFP_DEBUG
                    ydpPayloadPrinter(
                        msgData->payload, msgData->paylen,
                        dpi[count].dpacketCapt, dpi[count].dpacketCaptLen,
                        "Header");
#endif /* if YFP_DEBUG */
                    smtpHeader->smtpKey.buf =
                        msgData->payload + dpi[count].dpacketCapt;
                    colon = memchr(smtpHeader->smtpKey.buf, (int)(':'),
                                   dpi[count].dpacketCaptLen);
                    if (NULL == colon) {
                        smtpHeader->smtpKey.buf = NULL;
                        g_debug("Unable to find ':' in Email header");
                        break;
                    }
                    smtpHeader->smtpKey.len = colon - smtpHeader->smtpKey.buf;

                    /* initialze value length to remainder of capture len */
                    smtpHeader->smtpValue.len =
                        dpi[count].dpacketCaptLen - smtpHeader->smtpKey.len;

                    /* Move over the colon and any whitespace */
                    do {
                        ++colon;
                        --smtpHeader->smtpValue.len;
                    } while (isspace(*colon) && smtpHeader->smtpValue.len > 0);
                    smtpHeader->smtpValue.buf = (uint8_t *)colon;

                    smtpHeader = fbSubTemplateListGetNextPtr(
                        &smtpEmail->smtpHeaderList, smtpHeader);
                    break;
                }
            }
        }
        smtpEmail = fbSubTemplateListGetNextPtr(&rec->smtpMessageList,
                                                smtpEmail);
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

    /* top level yaf_smtp template */
    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_SMTP_NAME, YAF_SMTP_DESC,
                       SMTP_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    /* ruleset does not contain IE information, add metadata manually */
    bl_element = ydLookupNamedBlByID(CERT_PEN, smtpElemResponse->num);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, smtpElemResponse->num);
    }

    if (!ydInitTemplate(&yaf_smtp_tmpl, session, yaf_smtp_spec,
                        mdInfo, YAF_SMTP_TID, 0, err))
    {
        return FALSE;
    }

    /* child yaf_smtp_message template */
    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_SMTP_MESSAGE_NAME, YAF_SMTP_MESSAGE_DESC,
                       SMTP_PORT_NUMBER, YAF_SMTP_TID);

    /* ruleset does not contain IE information, add metadata manually */
    bl_element = ydLookupNamedBlByID(CERT_PEN, smtpElemTo->num);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, smtpElemTo->num);
    }
    bl_element = ydLookupNamedBlByID(CERT_PEN, smtpElemFrom->num);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, smtpElemFrom->num);
    }
    bl_element = ydLookupNamedBlByID(CERT_PEN, smtpElemFilename->num);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, smtpElemFilename->num);
    }
    bl_element = ydLookupNamedBlByID(CERT_PEN, smtpElemURL->num);
    if (bl_element) {
        fbTemplateInfoAddBasicList(mdInfo, bl_element->ent, bl_element->num,
                                   CERT_PEN, smtpElemURL->num);
    }

    if (!ydInitTemplate(&yaf_smtp_message_tmpl, session, yaf_smtp_message_spec,
                        mdInfo, YAF_SMTP_MESSAGE_TID, 0, err))
    {
        return FALSE;
    }

    /* grandchild yaf_smtp_header template */
    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_SMTP_HEADER_NAME, YAF_SMTP_HEADER_DESC,
                       SMTP_PORT_NUMBER, YAF_SMTP_MESSAGE_TID);

    if (!ydInitTemplate(&yaf_smtp_header_tmpl, session, yaf_smtp_header_spec,
                        mdInfo, YAF_SMTP_HEADER_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_smtp_t         *rec = (yaf_smtp_t *)flowContext->rec;
    yaf_smtp_message_t *message = NULL;

    fbBasicListClear(&rec->smtpResponseList);

    while ((message = fbSubTemplateListGetNextPtr(&rec->smtpMessageList,
                                                  message)))
    {
        fbBasicListClear(&message->smtpToList);
        fbBasicListClear(&message->smtpFromList);
        fbBasicListClear(&message->smtpFilenameList);
        fbBasicListClear(&message->smtpURLList);
        fbSubTemplateListClear(&message->smtpHeaderList);
    }

    fbSubTemplateListClear(&rec->smtpMessageList);
}
#endif  /* YAF_ENABLE_DPI */


/**
 * ydpInitialize
 *
 * this initializes the PCRE expressions needed to search the payload for SMTP
 * and enables DPI Information Elements.
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
#ifdef YAF_ENABLE_DPI
    GArray         *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;
    fbInfoModel_t  *model = ydGetDPIInfoModel();
    YC_ENABLE_ELEMENTS(yaf_smtp, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_smtp_message, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_smtp_header, pluginTemplates);
#endif  /* YAF_ENABLE_DPI */
    smtpRegexApplabel = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexApplabel", 0, err);

    if (!smtpRegexApplabel) {
        g_prefix_error(err, "in SMTP plugin: ");
        return -1;
    }

#ifndef YAF_ENABLE_DPI
    return 1;
#else
    smtpRegexDataBdat = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexDataBdat", 0, err);
    smtpRegexBdatLast = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexBdatLast", 0, err);
    smtpRegexBlankLine = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexBlankLine", 0, err);
    smtpRegexEndData = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexEndData", 0, err);
    smtpRegexFilename = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexFilename", 0, err);
    smtpRegexFrom = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexFrom", 0, err);

    smtpRegexHello = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexHello", 0, err);
    smtpRegexResponse = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexResponse", 0, err);
    smtpRegexSize = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexSize", 0, err);
    smtpRegexStartTLS = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexStartTLS", 0, err);
    smtpRegexSubject = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexSubject", 0, err);
    smtpRegexTo = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexTo", 0, err);
    smtpRegexURL = ycFindCompilePluginRegex(
        pluginRegexes, "smtpRegexURL", 0, err);

    smtpElemFilename = fbInfoModelGetElementByName(model, "smtpFilename");
    smtpElemFrom = fbInfoModelGetElementByName(model, "smtpFrom");
    smtpElemResponse = fbInfoModelGetElementByName(model, "smtpResponse");
    smtpElemTo = fbInfoModelGetElementByName(model, "smtpTo");
    smtpElemURL = fbInfoModelGetElementByName(model, "smtpURL");

    char *smtpRegexHeaderString = ycFindPluginRegex(pluginRegexes,
                                                    "smtpRegexHeader", err);
    if (smtpRegexHeaderString) {
        /* argv[0] is the plugin name; do not pass that to the function */
        GString *smtpRegexHeaderStringFinal =
            excludeRegexes(&argv[1], argc - 1, smtpRegexHeaderString);
        smtpRegexHeader = ydPcreCompile(
            smtpRegexHeaderStringFinal->str, 0, err);
        if (!smtpRegexHeader) {
            g_prefix_error(err, "Error parsing regex for plugin rule %s: ",
                           "smtpRegexHeader");
        }
        /* FIXME: Should the header be logged when argc > 1 and log-level is
         * verbose? */
        g_string_free(smtpRegexHeaderStringFinal, TRUE);
    }

    if (!smtpRegexBdatLast || !smtpRegexBlankLine || !smtpRegexDataBdat ||
        !smtpRegexEndData || !smtpRegexFilename || !smtpRegexFrom ||
        !smtpRegexHeader || !smtpRegexHello || !smtpRegexResponse ||
        !smtpRegexSize || !smtpRegexStartTLS || !smtpRegexSubject ||
        !smtpRegexTo || !smtpRegexURL)
    {
        g_prefix_error(err, "in SMTP plugin: ");
        return -1;
    }

    if (!smtpElemFilename || !smtpElemFrom || !smtpElemResponse ||
        !smtpElemTo || !smtpElemURL)
    {
        g_warning("Unable to find all the smtp elements in the info model");
        return 0;
    }

    return 1;
#endif  /* #else of #ifndef YAF_ENABLE_DPI */
}
