/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yaftab.c
 *  YAF Active Flow Table
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell, Chris Inacio
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
#include <airframe/logconfig.h>
#include <airframe/daeconfig.h>
#include <airframe/airutil.h>
#include <yaf/picq.h>
#include <yaf/yaftab.h>
#include <yaf/yafrag.h>
#include "yafctx.h"

#ifdef YAF_ENABLE_APPLABEL
#include "yafdpi.h"
#endif

#ifdef YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#ifdef YAF_ENABLE_P0F
#include "applabel/p0f/yfp0f.h"
#endif

#ifdef YAF_ENABLE_ENTROPY
#include <math.h>
#endif

#ifdef YAF_ENABLE_NDPI
#include <ndpi_main.h>
#endif

/**
 * YAF_MPLS:
 * If YAF was built with MPLS support, the MPLS labels are passed
 * to yfFlowPBuf, and the top 3 labels are hashed to create a key
 * into the Hash Table (flowtab->table).  The key retrieves a pointer
 * to a yfMPLSNode_t which contains a Hash Table, the MPLS labels, and
 * a counter.  This Hash Table is the new flow table.  The yfFlow_t struct
 * contains a pointer to the yfMPLSNode_t which contains a pointer to the
 * flow Hash Table that contains it.  Once the counter in the yfMPLSNode_t
 * is 0, the hash table is destroyed and the yfMPLSNode_t is freed.
 */

#ifndef YFDEBUG_FLOWTABLE
#define YFDEBUG_FLOWTABLE 0
#endif

#define YAF_STATE_ACTIVE        0x00000000
#define YAF_STATE_RST           0x00000001
#define YAF_STATE_FFIN          0x00000010
#define YAF_STATE_RFIN          0x00000020
#define YAF_STATE_FFINACK       0x00000040
#define YAF_STATE_RFINACK       0x00000080
#define YAF_STATE_FIN           0x000000F0
#define YAF_STATE_ATO           0x00000100

#define YF_FLUSH_DELAY 5000
#define YF_MAX_CQ      2500

#define YAF_PCAP_META_ROTATE 45000000
/* full path */
#define YAF_PCAP_META_ROTATE_FP 23000000

static int pcap_meta_num = 0;
static int pcap_meta_read = 0;

/* These constants define deprecated names for macro values.  They are defined
 * as constants since one cannot specify the deprecated attribute on macros.
 * They are declared 'extern' in yafcore.h. */
const uint16_t YAF_SAME_SIZE = YAF_ATTR_SAME_SIZE;
const uint16_t YAF_OUT_OF_SEQUENCE = YAF_ATTR_OUT_OF_SEQUENCE;
const uint16_t YAF_MP_CAPABLE = YAF_ATTR_MP_CAPABLE;
const uint16_t YAF_FRAGMENTS = YAF_ATTR_FRAGMENTS;

/* Must keep yfFlowNodeIPv4_st in synch with this struct. */
typedef struct yfFlowNode_st {
    /* previous node */
    struct yfFlowNode_st  *p;
    /* next node */
    struct yfFlowNode_st  *n;
    /* FIXME: Nothing appears to reference the flowtab */
    struct yfFlowTab_t    *flowtab;
    uint32_t               state;
    yfFlow_t               f;
} yfFlowNode_t;

/* Must conform to description in picq.h. */
typedef struct yfFlowQueue_st {
    yfFlowNode_t  *tail;
    yfFlowNode_t  *head;
} yfFlowQueue_t;


#ifdef YAF_ENABLE_COMPACT_IP4
/*
 * Compact IPv4 flow structures; allows the flow table to only allocate enough
 * space for IPv4 addresses for IPv4 flows. Requires the flow key to be the
 * last element of the flow, and the flow to be the last element of the
 * flow node. ALL CHANGES made to yfFlowKey_t and yfFlow_t in yafcore.h MUST
 * be reflected here or I'll not be held responsible for the results.
 */

typedef struct yfFlowKeyIPv4_st {
    uint16_t   sp;
    uint16_t   dp;
    uint8_t    proto;
    uint8_t    version;
    uint16_t   vlanId;
    uint8_t    tos;
#if defined(YAF_ENABLE_DAG_SEPARATE_INTERFACES) || defined(YAF_ENABLE_SEPARATE_INTERFACES)
    uint8_t    netIf;
#endif
    uint32_t   layer2Id;
    union {
        struct {
            uint32_t   sip;
            uint32_t   dip;
        } v4;
    } addr;
} yfFlowKeyIPv4_t;

typedef struct yfFlowIPv4_st {
    uint64_t          stime;
    uint64_t          etime;
#ifdef YAF_ENABLE_HOOKS
    void             *hfctx[YAF_MAX_HOOKS];
#endif
    uint32_t          rdtime;
#if defined(YAF_ENABLE_APPLABEL) || defined(YAF_ENABLE_NDPI)
    uint16_t          appLabel;
#endif
#if defined(YAF_ENABLE_APPLABEL) || defined(YAF_ENABLE_DPI)
    void             *dpictx;
#endif
#ifdef YAF_ENABLE_NDPI
    uint16_t          ndpi_master;
    uint16_t          ndpi_sub;
#endif
    uint8_t           reason;
    uint8_t           pcap_serial;
    uint8_t           sourceMacAddr[6];
    uint8_t           destinationMacAddr[6];

    uint8_t           pcap_file_no;
    uint8_t           pktdir;
    uint8_t           rtos;
    pcap_dumper_t    *pcap;
#ifdef YAF_MPLS
    yfMPLSNode_t     *mpls;
#endif
    yfMPTCPFlow_t     mptcp;
    yfFlowVal_t       val;
    yfFlowVal_t       rval;
    yfFlowKeyIPv4_t   key;
} yfFlowIPv4_t;

typedef struct yfFlowNodeIPv4_st {
    struct yfFlowNodeIPv4_st  *p;
    struct yfFlowNodeIPv4_st  *n;
    struct yfFlowTab_t        *flowtab;
    uint32_t                   state;
    yfFlowIPv4_t               f;
} yfFlowNodeIPv4_t;

#endif /* ifdef YAF_ENABLE_COMPACT_IP4 */

struct yfFlowTabStats_st {
    uint64_t   stat_octets;
    uint64_t   stat_packets;
    uint64_t   stat_seqrej;
    uint64_t   stat_flows;
    uint64_t   stat_uniflows;
    uint32_t   stat_peak;
    uint32_t   stat_flush;
#ifdef YAF_MPLS
    uint32_t   max_mpls_labels;
    uint32_t   stat_mpls_labels;
#endif
};

/* typedef struct yfFlowTab_st yfFlowTab_t;   // include/yaf/yaftab.h */
struct yfFlowTab_st {
    /* State */
    uint64_t                              ctime;
    uint64_t                              flushtime;
    GHashTable                           *table;
    GHashFunc                             hashfn;
    GEqualFunc                            hashequalfn;
#ifdef YAF_ENABLE_HOOKS
    /** Plugin context array for this yaf **/
    void                                **yfctx;
#endif
#ifdef YAF_MPLS
    yfMPLSNode_t                         *cur_mpls_node;
#endif
#ifdef YAF_ENABLE_NDPI
    struct ndpi_detection_module_struct  *ndpi_struct;
#endif
    /* active flow queue */
    yfFlowQueue_t                         aq;
    /* closed flow queue */
    yfFlowQueue_t                         cq;
    /* length of `aq` */
    uint32_t                              count;
    /* length of `cq` */
    uint32_t                              cq_count;

    /* Configuration */
    uint64_t                              active_ms;
    uint64_t                              idle_ms;
    uint32_t                              max_flows;
    uint32_t                              max_payload;

    uint64_t                              pcap_search_flowkey;
    uint64_t                              pcap_search_stime;
    char                                 *pcap_dir;
    GString                              *pcap_roll;
    char                                 *pcap_meta_name;
    FILE                                 *pcap_meta;
    uint64_t                              pcap_maxfile;
    long                                  pcap_last_offset;
    uint64_t                              pcap_last_time;
    uint8_t                               pcap_file_no;
    gboolean                              pcap_index;

    gboolean                              applabelmode;
    gboolean                              entropymode;
    gboolean                              flowstats_mode;
    gboolean                              force_read_all;
    gboolean                              fpexport_mode;
    gboolean                              macmode;
    gboolean                              mpls_mode;
    gboolean                              p0f_mode;
    gboolean                              silkmode;
    gboolean                              udp_multipkt_payload;
    gboolean                              uniflow;

    uint16_t                              udp_uniflow_port;

    /* Statistics */
    struct yfFlowTabStats_st              stats;
};

/**
 * protypes
 */
static gboolean
yfRotatePcapMetaFile(
    yfFlowTab_t  *flowtab);

/**
 * yfGetFlowTabStats
 *
 *
 */
void
yfGetFlowTabStats(
    yfFlowTab_t  *flowtab,
    uint64_t     *packets,
    uint64_t     *flows,
    uint64_t     *rej_pkts,
    uint32_t     *peak,
    uint32_t     *flush)
{
    *packets = flowtab->stats.stat_packets;
    *flows = flowtab->stats.stat_flows;
    *rej_pkts = flowtab->stats.stat_seqrej;
    *peak = flowtab->stats.stat_peak;
    *flush = flowtab->stats.stat_flush;
}


#ifdef YAF_MPLS
/**
 * yfMPLSHash
 *
 * hash function that takes the top 3 MPLS labels
 * and hashes them into a signle 32-bit integer.
 *
 * @param pointer to struct that holds MPLS values
 * @return 32-bit hashed integer of the 3 mpls labels
 */
static uint32_t
yfMPLSHash(
    yfMPLSNode_t  *mpls)
{
    return ((mpls->mpls_label[1] << 10) ^ (mpls->mpls_label[2] << 6) ^
            mpls->mpls_label[0]);
}


/**
 * yfMPLSEqual
 *
 * Compare 2 MPLS Nodes to see if they're equal.
 *
 * @param a
 * @param b
 * @return true/false
 */
static gboolean
yfMPLSEqual(
    yfMPLSNode_t  *a,
    yfMPLSNode_t  *b)
{
    if ((a->mpls_label[0] == b->mpls_label[0]) &&
        (a->mpls_label[1] == b->mpls_label[1]) &&
        (a->mpls_label[2] == b->mpls_label[2]))
    {
        return TRUE;
    } else {
        return FALSE;
    }
}
#endif /* ifdef YAF_MPLS */


/**
 * yfFlowKeyHash
 *
 * hash function that takes the 6-tuple for flow
 * identification and turns it into a single
 * 32-bit integer
 *
 * @param key pointer the the flow key which holds
 *        the set of values that uniquely identify
 *        a flow within yaf
 *
 * @return 32-bit hashed integer of the flow
 */
static uint32_t
yfFlowKeyHash(
    yfFlowKey_t  *key)
{
    /* Mask out priority/CFI bits */
    uint16_t vlan_mask = 0x0FFF & key->vlanId;

#ifdef YAF_ENABLE_DAG_SEPARATE_INTERFACES
    uint32_t netInterfaceHash;

    switch (key->netIf) {
      case 0:
        netInterfaceHash = 0x33333333;
        break;
      case 1:
        netInterfaceHash = 0x55555555;
        break;
      case 2:
        netInterfaceHash = 0xaaaaaaaa;
        break;
      case 3:
        netInterfaceHash = 0xbbbbbbbb;
        break;
      default:
        /* this is impossible because of the
         * dag structure is a 2-bit field for
         * this */
        g_warning("Invalid DAG interface code recorded: %d"
                  " - continuing processing", key->netIf);
        netInterfaceHash = 0xcccccccc;
    }

    if (key->version == 4) {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               (vlan_mask << 20) ^ key->addr.v4.sip ^
               key->addr.v4.dip ^ netInterfaceHash;
    } else {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               (vlan_mask << 20) ^
               *((uint32_t *)&(key->addr.v6.sip[0])) ^
               *((uint32_t *)&(key->addr.v6.sip[4])) ^
               *((uint32_t *)&(key->addr.v6.sip[8])) ^
               *((uint32_t *)&(key->addr.v6.sip[12])) ^
               *((uint32_t *)&(key->addr.v6.dip[0])) ^
               *((uint32_t *)&(key->addr.v6.dip[4])) ^
               *((uint32_t *)&(key->addr.v6.dip[8])) ^
               *((uint32_t *)&(key->addr.v6.dip[12])) ^
               netInterfaceHash;
    }
#endif /* ifdef YAF_ENABLE_DAG_SEPARATE_INTERFACES */

    if (key->version == 4) {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               (vlan_mask << 20) ^
               key->addr.v4.sip ^ key->addr.v4.dip;
    } else {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               (vlan_mask << 20) ^
               *((uint32_t *)&(key->addr.v6.sip[0])) ^
               *((uint32_t *)&(key->addr.v6.sip[4])) ^
               *((uint32_t *)&(key->addr.v6.sip[8])) ^
               *((uint32_t *)&(key->addr.v6.sip[12])) ^
               *((uint32_t *)&(key->addr.v6.dip[0])) ^
               *((uint32_t *)&(key->addr.v6.dip[4])) ^
               *((uint32_t *)&(key->addr.v6.dip[8])) ^
               *((uint32_t *)&(key->addr.v6.dip[12]));
    }
}


/**
 * yfFlowKeyHashNoVlan
 *
 * hash function that takes the 6-tuple for flow
 * identification and turns it into a single
 * 32-bit integer
 *
 * @param key pointer the the flow key which holds
 *        the set of values that uniquely identify
 *        a flow within yaf
 *
 * @return 32-bit hashed integer of the flow
 */
static uint32_t
yfFlowKeyHashNoVlan(
    yfFlowKey_t  *key)
{
#ifdef YAF_ENABLE_DAG_SEPARATE_INTERFACES
    uint32_t netInterfaceHash;

    switch (key->netIf) {
      case 0:
        netInterfaceHash = 0x33333333;
        break;
      case 1:
        netInterfaceHash = 0x55555555;
        break;
      case 2:
        netInterfaceHash = 0xaaaaaaaa;
        break;
      case 3:
        netInterfaceHash = 0xbbbbbbbb;
        break;
      default:
        /* this is impossible because of the
         *     dag structure is a 2-bit field for
         *     this */
        g_warning("Invalid DAG interface code recorded: %d"
                  " - continuing processing", key->netIf);
        netInterfaceHash = 0xcccccccc;
    }

    if (key->version == 4) {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               key->addr.v4.sip ^
               key->addr.v4.dip ^ netInterfaceHash;
    } else {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               *((uint32_t *)&(key->addr.v6.sip[0])) ^
               *((uint32_t *)&(key->addr.v6.sip[4])) ^
               *((uint32_t *)&(key->addr.v6.sip[8])) ^
               *((uint32_t *)&(key->addr.v6.sip[12])) ^
               *((uint32_t *)&(key->addr.v6.dip[0])) ^
               *((uint32_t *)&(key->addr.v6.dip[4])) ^
               *((uint32_t *)&(key->addr.v6.dip[8])) ^
               *((uint32_t *)&(key->addr.v6.dip[12])) ^
               netInterfaceHash;
    }
#endif /* ifdef YAF_ENABLE_DAG_SEPARATE_INTERFACES */
    if (key->version == 4) {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               key->addr.v4.sip ^ key->addr.v4.dip;
    } else {
        return (key->sp << 16) ^ key->dp ^
               (key->proto << 12) ^ (key->version << 4) ^
               *((uint32_t *)&(key->addr.v6.sip[0])) ^
               *((uint32_t *)&(key->addr.v6.sip[4])) ^
               *((uint32_t *)&(key->addr.v6.sip[8])) ^
               *((uint32_t *)&(key->addr.v6.sip[12])) ^
               *((uint32_t *)&(key->addr.v6.dip[0])) ^
               *((uint32_t *)&(key->addr.v6.dip[4])) ^
               *((uint32_t *)&(key->addr.v6.dip[8])) ^
               *((uint32_t *)&(key->addr.v6.dip[12]));
    }
}


/**
 * yfFlowKeyEqual
 *
 * compares two flows (a & b) based on their key value,
 * the hopefully unique 6-tuple of flow information to
 * see if the flows are the same
 *
 * @param
 *
 */
static gboolean
yfFlowKeyEqual(
    yfFlowKey_t  *a,
    yfFlowKey_t  *b)
{
    uint16_t a_vlan_mask = 0x0FFF & a->vlanId;
    uint16_t b_vlan_mask = 0x0FFF & b->vlanId;

#ifdef YAF_ENABLE_DAG_SEPARATE_INTERFACES
    if (a->netIf != b->netIf) {
        return FALSE;
    }
#endif

    if ((a->sp == b->sp) &&
        (a->dp == b->dp) &&
        (a->proto == b->proto) &&
        (a->version == b->version) &&
        (a_vlan_mask == b_vlan_mask))
    {
        if ((a->version == 4) &&
            (a->addr.v4.sip == b->addr.v4.sip) &&
            (a->addr.v4.dip == b->addr.v4.dip))
        {
            return TRUE;
        } else if ((a->version == 6) &&
                   (memcmp(a->addr.v6.sip, b->addr.v6.sip, 16) == 0) &&
                   (memcmp(a->addr.v6.dip, b->addr.v6.dip, 16) == 0))
        {
            return TRUE;
        } else {
            return FALSE;
        }
    } else {
        return FALSE;
    }
}


/**
 * yfFlowKeyEqualNoVlan
 *
 * compares two flows (a & b) based on their key value,
 * the hopefully unique 6-tuple of flow information to
 * see if the flows are the same
 *
 * @param
 *
 */
static gboolean
yfFlowKeyEqualNoVlan(
    yfFlowKey_t  *a,
    yfFlowKey_t  *b)
{
#ifdef YAF_ENABLE_DAG_SEPARATE_INTERFACES
    if (a->netIf != b->netIf) {
        return FALSE;
    }
#endif

    if ((a->sp == b->sp) &&
        (a->dp == b->dp) &&
        (a->proto == b->proto) &&
        (a->version == b->version))
    {
        if ((a->version == 4) &&
            (a->addr.v4.sip == b->addr.v4.sip) &&
            (a->addr.v4.dip == b->addr.v4.dip))
        {
            return TRUE;
        } else if ((a->version == 6) &&
                   (memcmp(a->addr.v6.sip, b->addr.v6.sip, 16) == 0) &&
                   (memcmp(a->addr.v6.dip, b->addr.v6.dip, 16) == 0))
        {
            return TRUE;
        } else {
            return FALSE;
        }
    } else {
        return FALSE;
    }
}


/**
 * yfFlowKeyReverse
 *
 * reverses the direction of a flow key, swaping the
 * source and destination fields appropriately within
 * the key record
 *
 * @param src pointer to the forward record
 * @param dst pointer to the reversed destination record
 *
 */
static void
yfFlowKeyReverse(
    yfFlowKey_t  *fwd,
    yfFlowKey_t  *rev)
{
    if (fwd->proto == YF_PROTO_ICMP || fwd->proto == YF_PROTO_ICMP6) {
        rev->sp = fwd->sp;
        rev->dp = fwd->dp;
    } else {
        rev->sp = fwd->dp;
        rev->dp = fwd->sp;
    }
    rev->proto = fwd->proto;
    rev->version = fwd->version;
    rev->vlanId = fwd->vlanId;
    if (fwd->version == 4) {
        rev->addr.v4.sip = fwd->addr.v4.dip;
        rev->addr.v4.dip = fwd->addr.v4.sip;
    } else if (fwd->version == 6) {
        memcpy(rev->addr.v6.sip, fwd->addr.v6.dip, 16);
        memcpy(rev->addr.v6.dip, fwd->addr.v6.sip, 16);
    }
#ifdef YAF_ENABLE_DAG_SEPARATE_INTERFACES
    rev->netIf = fwd->netIf;
#endif
}


/**
 * yfFlowKeyCopy
 *
 * copies a flow key from src to dst
 *
 * @param src pointer to the source flow key
 * @param dst pointer to the destination flow key
 *
 */
static void
yfFlowKeyCopy(
    yfFlowKey_t  *src,
    yfFlowKey_t  *dst)
{
#ifdef YAF_ENABLE_COMPACT_IP4
    if (src->version == 4) {
        memcpy(dst, src, sizeof(yfFlowKeyIPv4_t));
    } else
#endif  /* YAF_ENABLE_COMPACT_IP4 */
    {
        memcpy(dst, src, sizeof(yfFlowKey_t));
    }
}

#if 0
/**
 * yfFlowIncrementUniflow
 *
 * simple helper function to allow counting of unidirectional flows
 * (vs. captured biflows on the wire)
 *
 */
static void
yfFlowIncrementUniflow(
    yfFlowTab_t  *flowtab)
{
    (flowtab->stats.stat_uniflows)++;
}


#endif /* #if 0 */


#if YFDEBUG_FLOWTABLE == 1
/**
 * yfFlowDebug
 *
 *
 * @param msg
 * @param flow
 *
 */
static void
yfFlowDebug(
    const char  *msg,
    yfFlow_t    *flow)
{
    static GString *str = NULL;

    if (!str) {
        str = g_string_new(NULL);
    }

    g_string_printf(str, "%s ", msg);
    yfPrintString(str, flow);
    g_debug("%s", str->str);
}


/**
 * yfFlowTabVerifyIdleOrder
 *
 *
 * @param flowtab
 *
 */
static void
yfFlowTabVerifyIdleOrder(
    yfFlowTab_t  *flowtab)
{
    yfFlowNode_t *fn = NULL, *nfn = NULL;
    uint64_t      end;
    uint32_t      i;

    /* rip through the active queue making sure end time strictly decreases */
    for (fn = flowtab->aq.head, end = flowtab->aq.head->f.etime, i = 0;
         fn; end = fn->f.etime, fn = nfn, ++i)
    {
        nfn = fn->p;
        if (end < fn->f.etime) {
            g_debug("Flow inversion in active table position %u; "
                    "last end %llu, end %llu in flow:", i, end, fn->f.etime);
            yfFlowDebug("iiv", &(fn->f));
        }
    }
}


#endif /* if YFDEBUG_FLOWTABLE == 1 */

#ifdef YAF_MPLS
/**
 * yfMPLSNodeFree
 *
 * Free table and struct when the last node associated with the
 * set of MPLS labels has been closed
 *
 */
static void
yfMPLSNodeFree(
    yfFlowTab_t   *flowtab,
    yfMPLSNode_t  *mpls)
{
    g_hash_table_remove(flowtab->table, mpls);

    g_hash_table_destroy(mpls->tab);

    g_slice_free(yfMPLSNode_t, mpls);

    --(flowtab->stats.stat_mpls_labels);
}
#endif /* ifdef YAF_MPLS */


/**
 * yfFlowFree
 *
 * frees a flow (deallocates the memory and resets field
 * values to defaults) when the flow is no longer needed
 *
 * @param flowtab pointer to the flow table
 * @param fn node in the table to free
 *
 */
static void
yfFlowFree(
    yfFlowTab_t   *flowtab,
    yfFlowNode_t  *fn)
{
#ifdef YAF_ENABLE_PAYLOAD
    /* free payload if present */
    if (fn->f.val.payload) {
        g_slice_free1(flowtab->max_payload, fn->f.val.payload);
        g_slice_free1((sizeof(size_t) * YAF_MAX_PKT_BOUNDARY),
                      fn->f.val.paybounds);
    }
    if (fn->f.rval.payload) {
        g_slice_free1(flowtab->max_payload, fn->f.rval.payload);
        g_slice_free1((sizeof(size_t) * YAF_MAX_PKT_BOUNDARY),
                      fn->f.rval.paybounds);
    }
#endif /* ifdef YAF_ENABLE_PAYLOAD */
#ifdef YAF_ENABLE_HOOKS
    /* let the hook free its context */
    yfHookFlowFree(&(fn->f));
#endif

#ifdef YAF_ENABLE_APPLABEL
    ydFreeFlowContext(&(fn->f));
#endif

#ifdef YAF_ENABLE_FPEXPORT
    /* if present free the banner grabs for OS fingerprinting */
    if (fn->f.val.firstPacket) {
        g_slice_free1(YFP_IPTCPHEADER_SIZE, fn->f.val.firstPacket);
    }
    if (fn->f.val.secondPacket) {
        g_slice_free1(YFP_IPTCPHEADER_SIZE, fn->f.val.secondPacket);
    }
    if (fn->f.rval.firstPacket) {
        g_slice_free1(YFP_IPTCPHEADER_SIZE, fn->f.rval.firstPacket);
    }
    if (fn->f.rval.secondPacket) {
        g_slice_free1(YFP_IPTCPHEADER_SIZE, fn->f.rval.secondPacket);
    }
#endif /* ifdef YAF_ENABLE_FPEXPORT */
#ifdef YAF_ENABLE_P0F
    if (fn->f.val.osFingerprint) {
        g_free(fn->f.val.osFingerprint);
    }
    if (fn->f.rval.osFingerprint) {
        g_free(fn->f.rval.osFingerprint);
    }
#endif /* ifdef YAF_ENABLE_P0F */

    if (flowtab->flowstats_mode) {
        if (fn->f.val.stats) {
            g_slice_free(yfFlowStats_t, fn->f.val.stats);
        }
        if (fn->f.rval.stats) {
            g_slice_free(yfFlowStats_t, fn->f.rval.stats);
        }
    }

#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        --(fn->f.mpls->tab_count);
        if (fn->f.mpls->tab_count == 0) {
            /* remove node */
            yfMPLSNodeFree(flowtab, fn->f.mpls);
        }
    }
#endif /* ifdef YAF_MPLS */

    /* free flow */
#ifdef YAF_ENABLE_COMPACT_IP4
    if (fn->f.key.version == 4) {
        g_slice_free(yfFlowNodeIPv4_t, (yfFlowNodeIPv4_t *)fn);
    } else
#endif  /* YAF_ENABLE_COMPACT_IP4 */
    {
        g_slice_free(yfFlowNode_t, fn);
    }
}

/**
 * yfFlowTick
 *
 * advances a flow to the head of the activity
 * queue so when flows get timed out, only the
 * bottom of the queue is examined
 *
 * @param flowtable pointer to the flow table
 * @param fn pointer to the flow node entry in the
 *        table
 *
 */
static void
yfFlowTick(
    yfFlowTab_t   *flowtab,
    yfFlowNode_t  *fn)
{
    /* move flow node to head of queue */
    if (flowtab->aq.head != fn) {
        piqPick(&flowtab->aq, fn);
        piqEnQ(&flowtab->aq, fn);
    }
}


#ifdef YAF_ENABLE_APPLABEL
/**
 * yfFlowLabelApp
 *
 * when closing a flow out, if applabel is enabled, send
 * the flow payload through the labeling mechanism in order
 * to identify the protocol via payload inspection
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the flow node entry in the table
 *
 */
static void
yfFlowLabelApp(
    yfFlowTab_t   *flowtab,
    yfFlowNode_t  *fn)
{
    /* If the app labeler is enabled, let it inspect the packet
     * (for UDP & TCP packets anyway) */
    if (flowtab->applabelmode == TRUE &&
        ((fn->f.key.proto == 6) || (fn->f.key.proto == 17)))
    {
        ydScanFlow(&(fn->f));
    } else {
        fn->f.appLabel = 0;
    }
}
#endif /* ifdef YAF_ENABLE_APPLABEL */


#ifdef YAF_ENABLE_ENTROPY
/**
 * yfFlowDoEntropy
 *
 * when closing a flow and entropy calculation is enabled,
 * call this calculation to calculate the Shannon entropy
 * on the data stream
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the flow node entry in the table
 *
 */
static void
yfFlowDoEntropy(
    yfFlowTab_t   *flowtab,
    yfFlowNode_t  *fn)
{
    yfFlowVal_t *val;
    uint32_t entropyDist[256];
    double   entropyScratch;
    double   logPaylen;
    uint32_t loop;
    int      fwd_rev;

    /* if entropy is enabled, then we need to calculate it */
    /* FIXME deglobalize */
    if (!flowtab->entropymode) {
        fn->f.val.entropy = 0;
        fn->f.rval.entropy = 0;
        return;
    }

    /*
     *  First loop through each octet of payload and increment the
     *  entropyDist[] bin that corresponds to the octet.
     *
     *  Next compute the sum of these values across every bin:
     *
     *   ( bin[i] / SUM(bin[]) ) * log2( bin[i] / SUM(bin[]) )
     *
     *  where SUM(bin[]) is the payload length.  Using the properties of
     *  logarithms: this can be changed to
     *
     *   SUM( ( bin[i] / paylen ) * ( log2(bin[i]) - log2(paylen) ) )
     *
     *  The division by paylen can be pulled outside the SUM():
     *
     *   SUM( bin[i] * ( log2(bin[i]) - log2(paylen) ) ) / paylen
     *
     *  Moving "/paylen" outside SUM() may affect result slightly: in testing,
     *  of 364,385 entropy values computed in the data set, one value changed
     *  from 103 to 104.
     *
     *  Finally, change the sign of the result, divide by 8 (bits per byte)
     *  and multiply by 256 (to give a value in range 0 to 255).  This is
     *  equivalent to:
     *
     *   -32.0 * SUM ( bin[i] * ( log2(bin[i]) - log2(paylen) ) ) / paylen
     */

    for (fwd_rev = 0; fwd_rev < 2; ++fwd_rev) {
        val = ((0 == fwd_rev) ? &fn->f.val : &fn->f.rval);

        if (val->paylen <= 1) {
            val->entropy = 0;
        } else {
            logPaylen = log2((double)val->paylen);
            entropyScratch = 0.0;
            memset(entropyDist, 0, sizeof(entropyDist));
            for (loop = 0; loop < val->paylen; loop++) {
                entropyDist[val->payload[loop]]++;
            }
            for (loop = 0; loop < 256; loop++) {
                if (entropyDist[loop] > 0) {
                    entropyScratch +=
                        ((double)entropyDist[loop] *
                         (log2((double)entropyDist[loop]) - logPaylen));
                }
            }
            val->entropy = (uint8_t)(entropyScratch * -32.0
                                     / (double)val->paylen);
        }
    }
}


#endif /* ifdef YAF_ENABLE_ENTROPY */

/**
 * yfFlowClose
 *
 * close a flow and remove it from the active list, it will get flushed
 * out based on another timer; record the reason for closing the flow:
 * (time out, session end, etc.)
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the flow node entry in the flow table
 * @param reason reason code for closing the flow
 *
 */
static void
yfFlowClose(
    yfFlowTab_t   *flowtab,
    yfFlowNode_t  *fn,
    uint8_t        reason)
{
#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        g_hash_table_remove(fn->f.mpls->tab, &(fn->f.key));
    } else
#endif
    {
        /* remove flow from table */
        g_hash_table_remove(flowtab->table, &(fn->f.key));
    }

    /* store closure reason */
    fn->f.reason &= ~YAF_END_MASK;
    fn->f.reason |= reason;

    /* remove flow from active queue */
    piqPick(&flowtab->aq, fn);

    /* move flow node to close queue */
    piqEnQ(&flowtab->cq, fn);

#ifdef YAF_ENABLE_PAYLOAD

#ifdef YAF_ENABLE_APPLABEL
    /* do application label processing if necessary */
    if (flowtab->applabelmode) {
        yfFlowLabelApp(flowtab, fn);
    }
#endif /* ifdef YAF_ENABLE_APPLABEL */

#ifdef YAF_ENABLE_ENTROPY
    /* do entropy calculation if necessary */
    if (flowtab->entropymode) {
        yfFlowDoEntropy(flowtab, fn);
    }
#endif /* ifdef YAF_ENABLE_ENTROPY */

#ifdef YAF_ENABLE_HOOKS
    yfHookFlowClose(&(fn->f));
#endif

#endif /* ifdef YAF_ENABLE_PAYLOAD */

    /** count the flow in the close queue */
    ++(flowtab->cq_count);

    /* count the flow as inactive */
    --(flowtab->count);

    if (flowtab->pcap_dir) {
        if (fn->f.pcap) {
            pcap_dump_flush(fn->f.pcap);
            pcap_dump_close(fn->f.pcap);
        }
    }
}


#ifdef YAF_ENABLE_PAYLOAD
/**
 * yfActiveFlowCleanUp
 *
 * clear out payload length to make way
 * for next packet payload
 *
 */
static void
yfActiveFlowCleanUp(
    yfFlowTab_t   *flowtab,
    yfFlowNode_t  *fn)
{
    fn->f.val.paylen = 0;
    fn->f.rval.paylen = 0;
}


#endif /* ifdef YAF_ENABLE_PAYLOAD */
/**
 * yfCloseActiveFlow
 *
 * close a flow and write it but keep it active
 * mainly for udp-uniflow option.
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the flow node entry in the flow table
 * @param reason reason code for closing the flow
 *
 */
static void
yfCloseActiveFlow(
    yfFlowTab_t    *flowtab,
    yfFlowNode_t   *fn,
    yfFlowVal_t    *val,
    const uint8_t  *pkt,
    uint32_t        paylen,
    uint8_t         reason,
    uint32_t        iplen)
{
    yfFlowNode_t *tfn;  /*temp flow to write*/
    yfFlowVal_t  *valtemp;

#ifdef YAF_ENABLE_COMPACT_IP4
    if (fn->f.key.version == 4) {
        tfn = (yfFlowNode_t *)g_slice_dup(
            yfFlowNodeIPv4_t, (yfFlowNodeIPv4_t *)fn);
    } else
#endif /* ifdef YAF_ENABLE_COMPACT_IP4 */
    {
        tfn = g_slice_dup(yfFlowNode_t, fn);
    }

    if (&(fn->f.rval) == val) {
        yfFlowKeyReverse(&(fn->f.key), &(tfn->f.key));
        memcpy(&(tfn->f.val), val, sizeof(yfFlowVal_t));
        tfn->f.key.tos = fn->f.rtos;
    }

    /*"Uniflow"*/
    memset(&(tfn->f.rval), 0, sizeof(yfFlowVal_t));

    /* Since we are creating a new node - we need to allocate
     * hooks context for it */
#ifdef YAF_ENABLE_HOOKS
    /*Let the hook allocate its context */
    yfHookFlowAlloc(&(tfn->f), flowtab->yfctx);
#endif

#ifdef YAF_ENABLE_APPLABEL
    ydAllocFlowContext(&(tfn->f));
#endif

    tfn->f.rdtime = 0;
    tfn->f.val.pkt = 1;

    /* octet count of only this flow! */
    tfn->f.val.oct = iplen;

    /*Update start time of this flow - to now*/
    tfn->f.stime = flowtab->ctime;

    /* store closure reason - shouldn't have any other bits turned on */
    tfn->f.reason &= ~YAF_END_MASK;
    tfn->f.reason |= reason;

    tfn->n = NULL;
    tfn->p = NULL;
    valtemp = &(tfn->f.val);
    valtemp->stats = NULL;
#ifdef YAF_ENABLE_PAYLOAD
    valtemp->payload = NULL;

    /* Short-circuit no payload capture */
    if (flowtab->max_payload && paylen && pkt) {
        valtemp->payload = g_slice_alloc0(flowtab->max_payload);

        /* truncate capture length to payload limit */
        if (paylen > flowtab->max_payload) {
            paylen = flowtab->max_payload;
        }

        /* only need 1 entry in paybounds */
        valtemp->paybounds = (size_t *)g_slice_alloc0(sizeof(size_t) *
                                                      YAF_MAX_PKT_BOUNDARY);
        valtemp->paybounds[0] = paylen;

        memcpy(valtemp->payload, pkt, paylen);
        tfn->f.val.paylen = paylen;
    }
#endif /* ifdef YAF_ENABLE_PAYLOAD */
    /* move flow node to close queue */
    piqEnQ(&flowtab->cq, tfn);

#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        /* Since yfFlowFree frees UDP uniflows, but they're never
         * added to the mpls tables - we add one here, to account
         * for subtracting it in yfflowfree */
        ++(fn->f.mpls->tab_count);
    }
#endif  /* YAF_MPLS */

    ++(flowtab->cq_count);

#ifdef YAF_ENABLE_PAYLOAD

#ifdef YAF_ENABLE_APPLABEL
    /* do application label processing if necessary */
    tfn->f.appLabel = 0;
    if (flowtab->applabelmode) {
        yfFlowLabelApp(flowtab, tfn);
    }

    if (tfn->f.appLabel) {
        /* store in ongoing flow */
        fn->f.appLabel = tfn->f.appLabel;
    }
#endif /* ifdef YAF_ENABLE_APPLABEL */

#ifdef YAF_ENABLE_ENTROPY
    /* do entropy calculation if necessary */
    if (flowtab->entropymode) {
        yfFlowDoEntropy(flowtab, tfn);
    }
#endif /* ifdef YAF_ENABLE_ENTROPY */

#ifdef YAF_ENABLE_HOOKS
    yfHookFlowClose(&(tfn->f));
#endif

    yfActiveFlowCleanUp(flowtab, fn);
#endif /* ifdef YAF_ENABLE_PAYLOAD */
}


#ifdef YAF_ENABLE_NDPI
/*  Define malloc and free functions to pass into ndpi.  */
/*  FIXME: I do not think these are needed since recent versions of g_malloc()
 *  use malloc().  */
static void *
yf_ndpi_malloc(
    unsigned long   size)
{
    return g_malloc(size);
}

static void
yf_ndpi_free(
    void  *mem)
{
    g_free(mem);
}
#endif /* YAF_ENABLE_NDPI */


/**
 * yfFlowTabAlloc
 *
 * allocate (preferably from the slab allocator) another entry
 * into the flow table for a new flow
 *
 *
 * @return a pointer to the flow node entry in the flow table
 */
yfFlowTab_t *
yfFlowTabAlloc(
    const yfFlowTabConfig_t  *ftconfig,
    void                    **yfctx)
{
    yfFlowTab_t *flowtab = g_slice_new0(yfFlowTab_t);

    /* Copy the configuration */
    flowtab->idle_ms = ftconfig->idle_ms;
    flowtab->active_ms = ftconfig->active_ms;
    flowtab->max_flows = ftconfig->max_flows;
    flowtab->max_payload = ftconfig->max_payload;

    flowtab->applabelmode = ftconfig->applabel_mode;
    flowtab->entropymode = ftconfig->entropy_mode;
    flowtab->flowstats_mode = ftconfig->flowstats_mode;
    flowtab->force_read_all = ftconfig->force_read_all;
    flowtab->fpexport_mode = ftconfig->fpexport_mode;
    flowtab->macmode = ftconfig->mac_mode;
    flowtab->mpls_mode = ftconfig->mpls_mode;
    flowtab->p0f_mode = ftconfig->p0f_mode;
    flowtab->pcap_index = ftconfig->pcap_index;
    flowtab->silkmode = ftconfig->silk_mode;
    flowtab->udp_multipkt_payload = ftconfig->udp_multipkt_payload;
    flowtab->uniflow = ftconfig->uniflow_mode;

    flowtab->udp_uniflow_port = ftconfig->udp_uniflow_port;

#ifdef YAF_ENABLE_HOOKS
    flowtab->yfctx = yfctx;
#endif

    if (ftconfig->pcap_per_flow) {
        flowtab->pcap_dir = g_strdup(ftconfig->pcap_dir);
    } else if (ftconfig->pcap_dir) {
        flowtab->pcap_roll = g_string_new(NULL);
    } else if (ftconfig->pcap_meta_file && flowtab->pcap_index) {
        pcap_meta_read = -1;
    } else if (ftconfig->pcap_meta_file) {
        flowtab->pcap_roll = g_string_new(NULL);
    }

    if (ftconfig->pcap_meta_file) {
        if ((strlen(ftconfig->pcap_meta_file) == 1) &&
            ftconfig->pcap_meta_file[0] == '-')
        {
            flowtab->pcap_meta = stdout;
        } else {
            flowtab->pcap_meta_name = g_strdup(ftconfig->pcap_meta_file);
            yfRotatePcapMetaFile(flowtab);
        }
    }
    flowtab->pcap_maxfile = ftconfig->pcap_maxfile;

    if (ftconfig->pcap_flowkey) {
        flowtab->pcap_search_flowkey =
            strtoull(ftconfig->pcap_flowkey, NULL, 10);
    }

    if (ftconfig->pcap_stime) {
        flowtab->pcap_search_stime = strtoull(ftconfig->pcap_stime, NULL, 10);
    }

    if (ftconfig->no_vlan_in_key) {
        flowtab->hashfn = (GHashFunc)yfFlowKeyHashNoVlan;
        flowtab->hashequalfn = (GEqualFunc)yfFlowKeyEqualNoVlan;
    } else {
        flowtab->hashfn = (GHashFunc)yfFlowKeyHash;
        flowtab->hashequalfn = (GEqualFunc)yfFlowKeyEqual;
    }

#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        flowtab->table = g_hash_table_new((GHashFunc)yfMPLSHash,
                                          (GEqualFunc)yfMPLSEqual);
    } else
#endif /* ifdef YAF_MPLS */
    {
        flowtab->table = g_hash_table_new(flowtab->hashfn,
                                          flowtab->hashequalfn);
    }

#ifdef YAF_ENABLE_HOOKS
    yfHookValidateFlowTab(flowtab->yfctx, flowtab->max_payload,
                          flowtab->uniflow, flowtab->silkmode,
                          flowtab->applabelmode, flowtab->entropymode,
                          flowtab->p0f_mode,
                          flowtab->fpexport_mode,
                          flowtab->udp_multipkt_payload,
                          flowtab->udp_uniflow_port);
#endif /* ifdef YAF_ENABLE_HOOKS */

#ifdef YAF_ENABLE_NDPI
    if (ftconfig->ndpi) {
        NDPI_PROTOCOL_BITMASK all;
        set_ndpi_malloc(yf_ndpi_malloc);
        set_ndpi_free(yf_ndpi_free);
        flowtab->ndpi_struct = ndpi_init_detection_module();
        if (flowtab->ndpi_struct == NULL) {
            g_warning("Could not initialize NDPI");
            return NULL;
        }

        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(flowtab->ndpi_struct, &all);

        if (ftconfig->ndpi_proto_file) {
            ndpi_load_protocols_file(flowtab->ndpi_struct,
                                     ftconfig->ndpi_proto_file);
        }
    }
#endif /* ifdef YAF_ENABLE_NDPI */

    /* Done */
    return flowtab;
}


/**
 * yfFlowTabFree
 *
 * free's the entry in the flow table for a given flow entry *
 */
void
yfFlowTabFree(
    yfFlowTab_t  *flowtab)
{
    yfFlowNode_t *fn = NULL, *nfn = NULL;

    /* zip through the close queue freeing flows */
    for (fn = flowtab->cq.head; fn; fn = nfn) {
        nfn = fn->p;
        yfFlowFree(flowtab, fn);
    }

    /* now do the same with the active queue */
    for (fn = flowtab->aq.head; fn; fn = nfn) {
        nfn = fn->p;
        yfFlowFree(flowtab, fn);
    }

    /* Free GString */
    if (flowtab->pcap_roll) {
        g_string_free(flowtab->pcap_roll, TRUE);
    }

    if (flowtab->pcap_meta) {
        long cp = ftell(flowtab->pcap_meta);
        fseek(flowtab->pcap_meta, flowtab->pcap_last_offset, SEEK_SET);
        fprintf(flowtab->pcap_meta, "%" PRIu64 "|%010ld\n",
                flowtab->pcap_last_time, cp);
        fclose(flowtab->pcap_meta);
    }

    /* free the key index table */
    g_hash_table_destroy(flowtab->table);

#ifdef YAF_ENABLE_NDPI
    ndpi_exit_detection_module(flowtab->ndpi_struct);
#endif

    /* now free the flow table */
    g_slice_free(yfFlowTab_t, flowtab);
}


#ifdef YAF_MPLS
/**
 * yfMPLSGetNode
 *
 *  Finds an MPLS node entry in the MPLS table
 *  based on the labels in the MPLS header,
 *  creating it if needed, and updates
 *  `cur_mpls_node` on `flowtab`.
 */
static yfMPLSNode_t *
yfMPLSGetNode(
    yfFlowTab_t  *flowtab,
    yfL2Info_t   *l2info)
{
    yfMPLSNode_t *mpls;
    yfMPLSNode_t  key;

    memcpy(key.mpls_label, l2info->mpls_label, sizeof(uint32_t) * 3);

    if ((mpls = g_hash_table_lookup(flowtab->table, &key))) {
        flowtab->cur_mpls_node = mpls;
        return mpls;
    }

    /* create new mpls node */
    mpls = g_slice_new0(yfMPLSNode_t);

    memcpy(mpls->mpls_label, l2info->mpls_label, sizeof(uint32_t) * 3);

    mpls->tab = g_hash_table_new(flowtab->hashfn,
                                 flowtab->hashequalfn);
    flowtab->cur_mpls_node = mpls;

    g_hash_table_insert(flowtab->table, mpls, mpls);

    /* creation is 1, increment on #2 */
    /*++(mpls->tab_count);*/

    ++(flowtab->stats.stat_mpls_labels);
    if (flowtab->stats.stat_mpls_labels > flowtab->stats.max_mpls_labels) {
        flowtab->stats.max_mpls_labels = flowtab->stats.stat_mpls_labels;
    }

    return mpls;
}
#endif /* ifdef YAF_MPLS */


/**
 * yfFlowGetNode
 *
 * finds a flow node entry in the flow table for
 * the appropriate key value given
 *
 */
static yfFlowNode_t *
yfFlowGetNode(
    yfFlowTab_t  *flowtab,
    yfFlowKey_t  *key,
    yfFlowVal_t **valp)
{
    yfFlowKey_t   rkey;
    yfFlowNode_t *fn;
    GHashTable   *ht;

#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        ht = flowtab->cur_mpls_node->tab;
    } else
#endif  /* YAF_MPLS */
    {
        ht = flowtab->table;
    }

    /* Look for flow in table */
    if ((fn = g_hash_table_lookup(ht, key))) {
        /* Forward flow found. */
        *valp = &(fn->f.val);
        return fn;
    }

    /* Okay. Check for reverse flow. */
    yfFlowKeyReverse(key, &rkey);
    if ((fn = g_hash_table_lookup(ht, &rkey))) {
        /* Reverse flow found. */
        *valp = &(fn->f.rval);
        fn->f.rtos = key->tos;
        return fn;
    }

    /* Neither exists. Create a new flow and put it in the table. */
#ifdef YAF_ENABLE_COMPACT_IP4
    if (key->version == 4) {
        fn = (yfFlowNode_t *)g_slice_new0(yfFlowNodeIPv4_t);
    } else
#endif  /* YAF_ENABLE_COMPACT_IP4 */
    {
        fn = g_slice_new0(yfFlowNode_t);
    }

    /* Copy key */
    yfFlowKeyCopy(key, &(fn->f.key));

    /* set flow start time */
    fn->f.stime = flowtab->ctime;

    /* set flow end time as start time */
    fn->f.etime = flowtab->ctime;

    /* stuff the flow in the table */
    g_hash_table_insert(ht, &(fn->f.key), fn);

#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        fn->f.mpls = flowtab->cur_mpls_node;
        ++(flowtab->cur_mpls_node->tab_count);
    }
#endif  /* YAF_MPLS */

    /* This is a forward flow */
    *valp = &(fn->f.val);

    /* Count it */
    ++(flowtab->count);
    if (flowtab->count > flowtab->stats.stat_peak) {
        flowtab->stats.stat_peak = flowtab->count;
    }

#ifdef YAF_ENABLE_HOOKS
    /*Let the hook allocate its context */
    yfHookFlowAlloc(&(fn->f), flowtab->yfctx);
#endif


#ifdef YAF_ENABLE_APPLABEL
    ydAllocFlowContext(&(fn->f));
#endif

    /* All done */
    return fn;
}

/**
 * yfRotatePcapMetaFile
 *
 * rotate the pcap_meta_file
 *
 */
static gboolean
yfRotatePcapMetaFile(
    yfFlowTab_t  *flowtab)
{
    GString *namebuf = g_string_new(NULL);

    g_string_append_printf(namebuf, "%s", flowtab->pcap_meta_name);
    air_time_g_string_append(namebuf, time(NULL), AIR_TIME_SQUISHED);
    g_string_append_printf(namebuf, "_%05u.meta", pcap_meta_num);

    /* close current pcap_meta file */
    if (flowtab->pcap_meta) {
        long cp = ftell(flowtab->pcap_meta);
        fseek(flowtab->pcap_meta, flowtab->pcap_last_offset, SEEK_SET);
        fprintf(flowtab->pcap_meta, "%" PRIu64 "|%010ld\n",
                flowtab->pcap_last_time, cp);
        if (fclose(flowtab->pcap_meta)) {
            g_warning("Error (%d) Could not close current pcap "
                      "meta file: %s", errno, strerror(errno));
        }
        g_debug("Rotating Pcap Meta File, opening %s", namebuf->str);
    } else {
        g_debug("Opening Pcap Meta File %s", namebuf->str);
    }

    flowtab->pcap_meta = fopen(namebuf->str, "w");
    flowtab->pcap_last_offset = 0;
    if (flowtab->pcap_meta == NULL) {
        g_warning("Could not open new pcap meta file %s",
                  namebuf->str);
        g_warning("Error (%d): %s", errno, strerror(errno));
        g_string_free(namebuf, TRUE);
        return FALSE;
    }

    if (flowtab->ctime) {
        fprintf(flowtab->pcap_meta, "%" PRIu64 "|0000000000\n", flowtab->ctime);
        flowtab->pcap_last_time = flowtab->ctime;
    }

    g_string_free(namebuf, TRUE);
    pcap_meta_num++;
    return TRUE;
}


/**
 * yfUpdateRollingPcapFile
 *
 * update the rolling pcap filename in the flowtab for meta output
 *
 *
 */
void
yfUpdateRollingPcapFile(
    yfFlowTab_t  *flowtab,
    char         *new_file_name)
{
    if (flowtab->pcap_roll) {
        g_string_printf(flowtab->pcap_roll, "%s", new_file_name);
    }

    flowtab->pcap_file_no++;

    /* every 10 rolling pcaps change over the pcap meta file */
    if (flowtab->pcap_meta_name && flowtab->stats.stat_packets) {
        if (pcap_meta_read == -1) {
            if ((flowtab->stats.stat_packets % YAF_PCAP_META_ROTATE) == 0) {
                yfRotatePcapMetaFile(flowtab);
            }
        } else if ((flowtab->stats.stat_packets % YAF_PCAP_META_ROTATE_FP) ==
                   0)
        {
            yfRotatePcapMetaFile(flowtab);
        }
    }
}


/**
 * yfWritePcap
 *
 * write pcap to pcap-per-flow pcap file
 *
 * @param flowtab
 * @param flow
 * @param key
 * @param pbuf
 */
static void
yfWritePcap(
    yfFlowTab_t  *flowtab,
    yfFlow_t     *flow,
    yfFlowKey_t  *key,
    yfPBuf_t     *pbuf)
{
    GString      *namebuf;
    gboolean      fexists = FALSE;
    yfFlowNode_t *node;
    FILE         *pfile = NULL;
    uint32_t      rem_ms;

    if (flowtab->pcap_search_flowkey) {
        if (flowtab->hashfn(key) == flowtab->pcap_search_flowkey) {
            if (flowtab->pcap_search_stime) {
                if (flow->stime != flowtab->pcap_search_stime) {
                    return;
                }
            }
        } else {
            return;
        }

        if (flow->pcap == NULL) {
            if (g_file_test(flowtab->pcap_dir, G_FILE_TEST_EXISTS)) {
                pfile = fopen(flowtab->pcap_dir, "ab");
                if (pfile == NULL) {
                    g_warning("Pcap Create File Error: %s",
                              pcap_geterr((pcap_t *)pbuf->pcapt));
                    return;
                }
                /* need to append to pcap - libpcap doesn't have an append fn*/
                flow->pcap = (pcap_dumper_t *)pfile;
            } else {
                flow->pcap = pcap_dump_open(pbuf->pcapt, flowtab->pcap_dir);
            }
            if (flow->pcap == NULL) {
                g_warning("Pcap Create File Error: %s",
                          pcap_geterr((pcap_t *)pbuf->pcapt));
                return;
            }
        }
    }

    if (flow->pcap == NULL) {
        namebuf = g_string_new(NULL);
        rem_ms = (flow->stime % 1000);
        rem_ms = (rem_ms > 1000) ? (rem_ms / 10) : rem_ms;
        g_string_append_printf(namebuf, "%s/%03u", flowtab->pcap_dir,
                               rem_ms);
        g_mkdir(namebuf->str, 0777);
        g_string_append_printf(namebuf, "/%u-", flowtab->hashfn(key));
        air_time_g_string_append(namebuf, (flow->stime / 1000),
                                 AIR_TIME_SQUISHED);
        g_string_append_printf(namebuf, "_%d.pcap", flow->pcap_serial);
        if (g_file_test(namebuf->str, G_FILE_TEST_EXISTS)) {
            fexists = TRUE;
            pfile = fopen(namebuf->str, "ab");
            if (pfile == NULL) {
                goto err;
            }
            /* need to append to pcap - libpcap doesn't have an append fn*/
            flow->pcap = (pcap_dumper_t *)pfile;
        } else {
            flow->pcap = pcap_dump_open(pbuf->pcapt, namebuf->str);
        }

        if (flow->pcap == NULL) {
            goto err;
        }

        g_string_free(namebuf, TRUE);
    } else if (flowtab->pcap_maxfile) {
        pfile = pcap_dump_file(flow->pcap);

        if ((ftell(pfile) > (long)flowtab->pcap_maxfile)) {
            pcap_dump_flush(flow->pcap);
            pcap_dump_close(flow->pcap);
            flow->pcap_serial += 1;
            namebuf = g_string_new(NULL);
            rem_ms = (flow->stime % 1000);
            rem_ms = (rem_ms > 1000) ? (rem_ms / 10) : rem_ms;
            g_string_append_printf(namebuf, "%s/%03u", flowtab->pcap_dir,
                                   rem_ms);
            g_string_append_printf(namebuf, "/%u-", flowtab->hashfn(key));
            air_time_g_string_append(namebuf, (flow->stime / 1000),
                                     AIR_TIME_SQUISHED);
            g_string_append_printf(namebuf, "_%d.pcap", flow->pcap_serial);
            flow->pcap = pcap_dump_open(pbuf->pcapt, namebuf->str);

            if (flow->pcap == NULL) {
                goto err;
            }
            g_string_free(namebuf, TRUE);
        }
    }

    pcap_dump((u_char *)flow->pcap, &(pbuf->pcap_hdr), pbuf->payload);
    return;

  err:

    /* close pcap files for stale flows */

    node = flowtab->aq.tail;
    /* go until we have closed 1 */
    while (node) {
        if (node->f.pcap) {
            pcap_dump_flush(node->f.pcap);
            pcap_dump_close(node->f.pcap);
            node->f.pcap = NULL;
            break;
        }
        node = node->n;
    }

    /* if the file exists - use fopen */
    if (fexists) {
        pfile = fopen(namebuf->str, "ab");
        if (pfile == NULL) {
            g_string_free(namebuf, TRUE);
            return;
        }
        flow->pcap = (pcap_dumper_t *)pfile;
    } else {
        flow->pcap = pcap_dump_open(pbuf->pcapt, namebuf->str);
    }

    if (flow->pcap == NULL) {
        g_warning("Pcap-per-flow Create File Error: %s",
                  pcap_geterr((pcap_t *)pbuf->pcapt));
        g_string_free(namebuf, TRUE);
        return;
    }

    g_string_free(namebuf, TRUE);
    pcap_dump((u_char *)flow->pcap, &(pbuf->pcap_hdr), pbuf->payload);
}


/**
 * yfWritePcapMetaIndex
 *
 *
 */
static void
yfWritePcapMetaIndex(
    yfFlowTab_t  *flowtab,
    gboolean      packets)
{
    long     cp;
    uint64_t count;
    int      rotate = 10000;

    if (packets) {
        count = flowtab->stats.stat_packets;
    } else {
        count = flowtab->stats.stat_flows;
        rotate = 5000;
    }

    if (flowtab->stats.stat_packets == 1) {
        fprintf(flowtab->pcap_meta, "%" PRIu64 "|0000000000\n", flowtab->ctime);
        flowtab->pcap_last_time = flowtab->ctime;
    }

    if (!count) {
        return;
    }

    if ((count % rotate) == 0) {
        cp = ftell(flowtab->pcap_meta);
        if (cp == 0) {
            fprintf(flowtab->pcap_meta, "%" PRIu64 "|0000000000\n",
                    flowtab->ctime);
            flowtab->pcap_last_time = flowtab->ctime;
        } else {
            fseek(flowtab->pcap_meta, flowtab->pcap_last_offset, SEEK_SET);
            fprintf(flowtab->pcap_meta, "%" PRIu64 "|%010ld\n",
                    flowtab->pcap_last_time, cp);
            fseek(flowtab->pcap_meta, cp, SEEK_SET);
            flowtab->pcap_last_offset = cp;
            fprintf(flowtab->pcap_meta, "%" PRIu64 "|0000000000\n",
                    flowtab->ctime);
            flowtab->pcap_last_time = flowtab->ctime;
        }
    }
}


/**
 * yfWritePcapMetaFile
 *
 *
 */
static void
yfWritePcapMetaFile(
    yfFlowTab_t   *flowtab,
    yfFlowNode_t  *fn,
    yfPBuf_t      *pbuf,
    uint32_t       hash,
    uint32_t       pcap_len)
{
    int rv;

    if (pcap_meta_read == -1) {
        yfWritePcapMetaIndex(flowtab, TRUE);
        rv = fprintf(flowtab->pcap_meta, "%u|%llu|%d|%llu|%d\n",
                     hash, (long long unsigned int)fn->f.stime,
                     pbuf->pcap_caplist,
                     (long long unsigned int)pbuf->pcap_offset,
                     pcap_len);
        if (rv < 0) {
            if (yfRotatePcapMetaFile(flowtab)) {
                yfWritePcapMetaIndex(flowtab, TRUE);
                fprintf(flowtab->pcap_meta, "%u|%llu|%d|%llu|%d\n",
                        hash, (long long unsigned int)fn->f.stime,
                        pbuf->pcap_caplist,
                        (long long unsigned int)pbuf->pcap_offset,
                        pcap_len);
            }
        } else if ((flowtab->stats.stat_packets % YAF_PCAP_META_ROTATE) == 0) {
            yfRotatePcapMetaFile(flowtab);
        }
    } else {
        if (flowtab->pcap_index) {
            /* print every packet */
            yfWritePcapMetaIndex(flowtab, TRUE);
            rv = fprintf(flowtab->pcap_meta, "%u|%llu|%s|%llu|%d\n",
                         hash, (long long unsigned int)fn->f.stime,
                         flowtab->pcap_roll->str,
                         (long long unsigned int)pbuf->pcap_offset, pcap_len);
            if (rv < 0) {
                if (yfRotatePcapMetaFile(flowtab)) {
                    yfWritePcapMetaIndex(flowtab, TRUE);
                    fprintf(flowtab->pcap_meta, "%u|%llu|%s|%llu|%d\n",
                            hash, (long long unsigned int)fn->f.stime,
                            flowtab->pcap_roll->str,
                            (long long unsigned int)pbuf->pcap_offset,
                            pcap_len);
                }
            } else if ((flowtab->stats.stat_packets %
                        YAF_PCAP_META_ROTATE_FP) == 0)
            {
                yfRotatePcapMetaFile(flowtab);
            }
        } else if (flowtab->pcap_file_no != fn->f.pcap_file_no) {
            /* print when the flow rolls over multiple files */
            yfWritePcapMetaIndex(flowtab, FALSE);
            fprintf(flowtab->pcap_meta, "%u|%llu|%s\n",
                    hash, (long long unsigned int)fn->f.stime,
                    flowtab->pcap_roll->str);
            fn->f.pcap_file_no = flowtab->pcap_file_no;
            return;
        }
    }
}


/**
 * yfFlowPktGenericTpt
 *
 * generate flow information about packets that are not TCP
 *
 *
 * @param flowtab
 * @param fn
 * @param val
 * @param pkt
 * @param caplen
 *
 */
static void
yfFlowPktGenericTpt(
    yfFlowTab_t    *flowtab,
    yfFlowNode_t   *fn,
    yfFlowVal_t    *val,
    const uint8_t  *pkt,
    uint32_t        caplen)
{
#ifdef YAF_ENABLE_PAYLOAD
    int p;

    /* Short-circuit nth packet or no payload capture */
    if (!flowtab->max_payload ||
        (val->pkt && !flowtab->udp_multipkt_payload) ||
        !caplen)
    {
        return;
    }

    /* truncate capture length to payload limit */
    if (caplen + val->paylen > flowtab->max_payload) {
        caplen = flowtab->max_payload - val->paylen;
    }

    /* allocate */

    if (!val->payload) {
        val->payload = g_slice_alloc0(flowtab->max_payload);
        val->paybounds = (size_t *)g_slice_alloc0(sizeof(size_t) *
                                                  YAF_MAX_PKT_BOUNDARY);
    }

    memcpy(val->payload + val->paylen, pkt, caplen);

    /* Set pointer to payload for packet boundary */
    if (val->pkt < YAF_MAX_PKT_BOUNDARY) {
        p = val->pkt;
        val->paybounds[p] = val->paylen;
    }

    val->paylen += caplen;

#endif /* ifdef YAF_ENABLE_PAYLOAD */
}


/**
 * yfFlowPktTCP
 *
 * process a TCP packet into the flow table specially, capture
 * all the special TCP information, flags, seq, etc.
 *
 * @param flowtab pointer to the flow table
 * @param fn pointer to the node for the relevent flow in the flow table
 * @param val
 * @param pkt pointer to the packet payload
 * @param caplen length of the capture (length of pkt)
 * @param tcpinfo pointer to the parsed tcp information
 * @param headerVal pointer to the full packet information, including IP & TCP
 * @param headerLen length of headerVal
 *
 */
static void
yfFlowPktTCP(
    yfFlowTab_t    *flowtab,
    yfFlowNode_t   *fn,
    yfFlowVal_t    *val,
    const uint8_t  *pkt,
    uint32_t        caplen,
    yfTCPInfo_t    *tcpinfo,
    uint8_t        *headerVal,
    uint16_t        headerLen)
{
#ifdef YAF_ENABLE_PAYLOAD
    uint32_t appdata_po;
    uint32_t last_seq_num = val->lsn;
    int      p;
#endif

    /*Update flags in flow record - may need to upload iflags if out of order*/
    if (val->pkt && (tcpinfo->seq > val->isn)) {
        /* Union flags */
        val->uflags |= tcpinfo->flags;
    } else {
        if (val->pkt && (tcpinfo->seq <= val->isn)) {
            /*if packets out of order - don't lose other flags - add to
             * uflags*/
            val->uflags |= val->iflags;
        }
        /* Initial flags */
        val->iflags = tcpinfo->flags;
        /* Initial sequence number */
        val->isn = tcpinfo->seq;
    }

    val->lsn = tcpinfo->seq;

    /* Update flow state for FIN flag */
    if (val == &(fn->f.val)) {
        if (tcpinfo->flags & YF_TF_FIN) {
            fn->state |= YAF_STATE_FFIN;
        }
        if ((fn->state & YAF_STATE_RFIN) && (tcpinfo->flags & YF_TF_ACK)) {
            fn->state |= YAF_STATE_FFINACK;
        }
    } else {
        if (tcpinfo->flags & YF_TF_FIN) {
            fn->state |= YAF_STATE_RFIN;
        }
        if ((fn->state & YAF_STATE_FFIN) && (tcpinfo->flags & YF_TF_ACK)) {
            fn->state |= YAF_STATE_RFINACK;
        }
    }

    /* Update flow state for RST flag */
    if (tcpinfo->flags & YF_TF_RST) {
        fn->state |= YAF_STATE_RST;
    }

    if (flowtab->flowstats_mode && (tcpinfo->flags & YF_TF_URG)) {
        val->stats->tcpurgct++;
    }

    /** MPTCP stuff */
    if (tcpinfo->mptcp.flags & 0x01) {
        /* MP_CAPABLE */
        val->attributes |= YAF_ATTR_MP_CAPABLE;
    }

    if (tcpinfo->flags & YF_TF_SYN) {
        if (!fn->f.mptcp.token && tcpinfo->mptcp.token) {
            fn->f.mptcp.token = tcpinfo->mptcp.token;
        }
        /* initial priority is set in the MP_JOIN SYN or SYN/ACK */
        if (tcpinfo->mptcp.flags & 0x02) {
            fn->f.mptcp.flags |= YF_MF_PRIORITY;
        }
    } else if (tcpinfo->mptcp.flags & 0x02) {
        fn->f.mptcp.flags |= YF_MF_PRIO_CHANGE;
    }

    if (!fn->f.mptcp.idsn) {
        fn->f.mptcp.idsn = tcpinfo->mptcp.idsn;
    }

    fn->f.mptcp.mss = tcpinfo->mptcp.mss;

    fn->f.mptcp.flags |= (tcpinfo->mptcp.flags & 0xFC);

    if (!fn->f.mptcp.addrid) {
        fn->f.mptcp.addrid = tcpinfo->mptcp.addrid;
    }

#ifdef YAF_ENABLE_P0F
    /* run through p0f if it's enabled here */
    if (flowtab->p0f_mode) {
        /* do os fingerprinting if enabled */
        if (NULL == val->osname) {
            GError  *err = NULL;
            struct packetDecodeDetails_st packetDetails;
            gboolean fuzzyMatched;

            /* run everything through the p0f finger printer now */
            if (!yfpPacketParse(headerVal, headerLen, &packetDetails, &err)) {
                g_clear_error(&err);
            } else {
                if (!yfpSynFindMatch(&packetDetails, TRUE, &fuzzyMatched,
                                     &(val->osname), &(val->osver),
                                     &(val->osFingerprint), &err))
                {
                    g_warning("Error finger printing packet: %s",
                              err->message);
                    g_clear_error(&err);
                }
            }
        }
    }
#endif /* ifdef YAF_ENABLE_P0F */

#ifdef YAF_ENABLE_FPEXPORT
    if (flowtab->fpexport_mode && headerVal) {
        /* Let's capture the detailed header information for the first 3
         * packets
         * mostly for external OS id'ing*/
        if (&(fn->f.val) == val) {
            if (NULL == val->firstPacket) {
                val->firstPacket = g_slice_alloc0(YFP_IPTCPHEADER_SIZE);
                val->firstPacketLen = headerLen;
                memcpy(val->firstPacket, headerVal, headerLen);
            } else if (NULL == val->secondPacket) {
                val->secondPacket = g_slice_alloc0(YFP_IPTCPHEADER_SIZE);
                val->secondPacketLen = headerLen;
                memcpy(val->secondPacket, headerVal, headerLen);
            }
        } else {
            if (NULL == val->firstPacket) {
                val->firstPacket = g_slice_alloc0(YFP_IPTCPHEADER_SIZE);
                val->firstPacketLen = headerLen;
                memcpy(val->firstPacket, headerVal, headerLen);
            }
        }
    }
#endif /* ifdef YAF_ENABLE_FPEXPORT */

#ifdef YAF_ENABLE_PAYLOAD
    /* short circuit no payload capture, continuation,
     * payload full, or no payload in packet */
    if (!flowtab->max_payload || !(val->iflags & YF_TF_SYN) ||
        caplen == 0)
    {
        return;
    }

    if (last_seq_num == (tcpinfo->seq + 1)) {
        /* TCP KEEP ALIVE */
        return;
    }

    /* Find app data offset in payload buffer */
    appdata_po = tcpinfo->seq - (val->isn + 1);

    /* allocate and copy */
    if (!val->payload) {
        val->payload = g_slice_alloc0(flowtab->max_payload);
        val->paybounds = (size_t *)g_slice_alloc0(sizeof(size_t) *
                                                  YAF_MAX_PKT_BOUNDARY);
    }

    if (val->pkt < YAF_MAX_PKT_BOUNDARY) {
        p = val->pkt;
        val->paybounds[p] = appdata_po;
    }

    /* leave open the case in which we receive an out of order packet */
    if ((val->paylen == flowtab->max_payload) &&
        (appdata_po >= flowtab->max_payload))
    {
        return;
    }

    /* Short circuit entire packet after capture filter */
    if (appdata_po >= flowtab->max_payload) {return;}

    /* truncate payload copy length to capture length */
    if ((appdata_po + caplen) > flowtab->max_payload) {
        caplen = flowtab->max_payload - appdata_po;
        if (caplen > flowtab->max_payload) {
            caplen = flowtab->max_payload;
        }
    }

    if (val->paylen < appdata_po + caplen) {
        val->paylen = appdata_po + caplen;
    }
    memcpy(val->payload + appdata_po, pkt, caplen);
#endif /* ifdef YAF_ENABLE_PAYLOAD */
}


static void
yfFlowStatistics(
    yfFlowNode_t  *fn,
    yfFlowVal_t   *val,
    uint64_t       ptime,
    uint32_t       datalen)
{
    if (val->stats->ltime) {
        val->stats->aitime += (ptime - val->stats->ltime);
    }

    if (val->pkt > 1 && val->pkt < 12) {
        val->stats->iaarray[val->pkt - 2] = (ptime - val->stats->ltime);
    }

    val->stats->ltime = fn->f.etime;

    if (datalen) {
        /* that means there is some payload */
        if (val == &(fn->f.rval)) {
            fn->f.pktdir |= (1 << (fn->f.val.stats->nonemptypktct +
                                   val->stats->nonemptypktct));
        }
        if (val->stats->nonemptypktct < 10) {
            val->stats->pktsize[val->stats->nonemptypktct] = datalen;
        }
        val->stats->nonemptypktct++;
        if (datalen < YAF_SMALL_PKT_BOUND) {
            val->stats->smallpktct++;
        } else if (datalen > YAF_LARGE_PKT_BOUND) {
            val->stats->largepktct++;
        }
        val->stats->payoct += datalen;
        if (val->stats->firstpktsize == 0) {
            val->stats->firstpktsize = datalen;
        }
        if (datalen > val->stats->maxpktsize) {
            val->stats->maxpktsize = datalen;
        }
    }
}


static void
yfAddOutOfSequence(
    yfFlowTab_t  *flowtab,
    yfFlowKey_t  *key,
    size_t        pbuflen,
    yfPBuf_t     *pbuf)
{
    yfFlowNode_t *fn = NULL;
    yfFlowNode_t *tn = NULL;
    yfFlowNode_t *nfn = NULL;
    yfFlowKey_t   rkey;
    uint64_t      end;
    yfFlowVal_t  *val = NULL;
    yfTCPInfo_t  *tcpinfo = &(pbuf->tcpinfo);
    yfL2Info_t   *l2info = &(pbuf->l2info);
    uint8_t      *payload = (pbuflen >= YF_PBUFLEN_BASE) ?
        pbuf->payload : NULL;
    size_t        paylen = (pbuflen >= YF_PBUFLEN_BASE) ?
        pbuf->paylen : 0;
    uint32_t      datalen = (pbuf->iplen - pbuf->allHeaderLen +
                             l2info->l2hlen);
    uint32_t      pcap_len = 0;
    gboolean      rev = FALSE;
    GHashTable   *ht;

#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        ht = flowtab->cur_mpls_node->tab;
        yfMPLSGetNode(flowtab, l2info);
    } else
#endif /* ifdef YAF_MPLS */
    {
        ht = flowtab->table;
    }

    /* Count the packet and its octets */
    ++(flowtab->stats.stat_packets);
    flowtab->stats.stat_octets += pbuf->iplen;

    if (payload) {
        if (paylen >= pbuf->allHeaderLen) {
            paylen -= pbuf->allHeaderLen;
            payload += pbuf->allHeaderLen;
        } else {
            paylen = 0;
            payload = NULL;
        }
    }

    /* Look for flow in table */
    if ((fn = g_hash_table_lookup(ht, key))) {
        /* Forward flow found. */
        val = &(fn->f.val);
    }

    if (fn == NULL) {
        /* Okay. Check for reverse flow. */
        yfFlowKeyReverse(key, &rkey);
        rev = TRUE;
        if ((fn = g_hash_table_lookup(ht, &rkey))) {
            /* Reverse flow found. */
            val = &(fn->f.rval);
        }
    }

    if (fn == NULL) {
        /* Neither exists. Create a new flow and put it in the table. */
#ifdef YAF_ENABLE_COMPACT_IP4
        if (key->version == 4) {
            fn = (yfFlowNode_t *)g_slice_new0(yfFlowNodeIPv4_t);
        } else
#endif  /* YAF_ENABLE_COMPACT_IP4 */
        {
            fn = g_slice_new0(yfFlowNode_t);
        }

        /* Copy key */
        yfFlowKeyCopy(key, &(fn->f.key));

        /* set flow start time */
        fn->f.stime = pbuf->ptime;

        /* set flow end time as start time */
        fn->f.etime = pbuf->ptime;

        /* stuff the flow in the table */
        g_hash_table_insert(ht, &(fn->f.key), fn);

        /* This is a forward flow */
        val = &(fn->f.val);

        /* Count it */
        ++(flowtab->count);
#ifdef YAF_MPLS
        if (flowtab->mpls_mode) {
            fn->f.mpls = flowtab->cur_mpls_node;
            ++(flowtab->cur_mpls_node->tab_count);
        }
#endif  /* YAF_MPLS */

        if (flowtab->count > flowtab->stats.stat_peak) {
            flowtab->stats.stat_peak = flowtab->count;
        }

#ifdef YAF_ENABLE_HOOKS
        /*Let the hook allocate its context */
        yfHookFlowAlloc(&(fn->f), flowtab->yfctx);
#endif

#ifdef YAF_ENABLE_APPLABEL
        ydAllocFlowContext(&(fn->f));
#endif
    }

    if (val->pkt == 0) {
        /* Note Mac Addr */
        if (flowtab->macmode && (val == &(fn->f.val))) {
            if (l2info) {
                memcpy(fn->f.sourceMacAddr, l2info->smac,
                       ETHERNET_MAC_ADDR_LENGTH);
                memcpy(fn->f.destinationMacAddr, l2info->dmac,
                       ETHERNET_MAC_ADDR_LENGTH);
            }
        }
        /* Allocate Flow Statistics */
        if (flowtab->flowstats_mode) {
            val->stats = g_slice_new0(yfFlowStats_t);
        }
    }

    /* packet exists now, update info */

    /* Do payload and TCP stuff */
    if (fn->f.key.proto == YF_PROTO_TCP) {
        /* Handle TCP flows specially (flags, ISN, sequenced payload) */
        if (datalen) {
            if (val->appkt == 0) {
                val->first_pkt_size = datalen;
            } else {
                if (datalen == val->first_pkt_size) {
                    if (val->appkt == 1) {
                        val->attributes |= YAF_ATTR_SAME_SIZE;
                    }
                } else {
                    /* Don't consider TCP KEEP ALIVE */
                    if (val->lsn != (tcpinfo->seq + 1)) {
                        val->attributes &= ~YAF_ATTR_SAME_SIZE;
                    }
                }
            }
            val->appkt += 1;
        }
#if defined(YAF_ENABLE_P0F) || defined(YAF_ENABLE_FPEXPORT)
        yfFlowPktTCP(flowtab, fn, val, payload, paylen, tcpinfo,
                     pbuf->headerVal, pbuf->headerLen);
#else
        yfFlowPktTCP(flowtab, fn, val, payload, paylen, tcpinfo, NULL, 0);
#endif
    } else {
        if (val->pkt == 0) {
            val->first_pkt_size = pbuf->iplen;
        } else {
            if (pbuf->iplen == val->first_pkt_size) {
                if (val->pkt == 1) {
                    val->attributes |= YAF_ATTR_SAME_SIZE;
                }
            } else {
                val->attributes &= ~YAF_ATTR_SAME_SIZE;
            }
        }
        if ((val->pkt == 0 || flowtab->udp_multipkt_payload)) {
            if (((flowtab->udp_uniflow_port != 1) &&
                 (flowtab->udp_uniflow_port != fn->f.key.sp) &&
                 (flowtab->udp_uniflow_port != fn->f.key.dp)))
            {
                /* Get first packet payload from non-TCP flows */
                yfFlowPktGenericTpt(flowtab, fn, val, payload, paylen);
            }
        }
    }

    /* set flow attributes - this flow is out of order */
    val->attributes |= YAF_ATTR_OUT_OF_SEQUENCE;

    /* Mark if fragmented */
    if (pbuf->frag == 1) {
        val->attributes |= YAF_ATTR_FRAGMENTS;
    }

    /* Count packets and octets */
    val->oct += pbuf->iplen;
    val->pkt += 1;

    /* don't update end time - stime could be greater than etime */

    /* Update stats */
    if (flowtab->flowstats_mode) {
        yfFlowStatistics(fn, val, pbuf->ptime, datalen);
    }

#ifdef YAF_ENABLE_HOOKS
    /* Hook Flow Processing */
    yfHookFlowPacket(&(fn->f), val, payload,
                     paylen, pbuf->iplen, tcpinfo, l2info);
#endif

    pcap_len = pbuf->pcap_hdr.caplen + 16;

    /* Write Packet to Pcap-Per-Flow pcap file */
    if (flowtab->pcap_dir) {
        /* what we actually hold in yaf dependent on max-payload */
        pbuf->pcap_hdr.caplen = (pbuflen > YF_PBUFLEN_BASE) ? pbuf->paylen : 0;
        if (val == &(fn->f.rval)) {
            yfFlowKeyReverse(key, &rkey);
            yfWritePcap(flowtab, &(fn->f), &rkey, pbuf);
        } else {
            yfWritePcap(flowtab, &(fn->f), key, pbuf);
        }
    }

    /* Write Pcap Meta Info */
    if (flowtab->pcap_meta) {
        if (rev) {
            yfWritePcapMetaFile(flowtab, fn, pbuf, flowtab->hashfn(&rkey),
                                pcap_len);
        } else {
            yfWritePcapMetaFile(flowtab, fn, pbuf, flowtab->hashfn(key),
                                pcap_len);
        }
    }

    /* if udp-uniflow-mode, close UDP flow now */
    if ((fn->f.key.proto == YF_PROTO_UDP) && (flowtab->udp_uniflow_port != 0)) {
        if (((flowtab->udp_uniflow_port == 1) ||
             (flowtab->udp_uniflow_port == fn->f.key.sp) ||
             (flowtab->udp_uniflow_port == fn->f.key.dp)))
        {
            yfCloseActiveFlow(flowtab, fn, val, payload, paylen,
                              YAF_END_UDPFORCE, pbuf->iplen);
        }
    }

    /* close flow, or move it to head of queue */
    if ((fn->state & YAF_STATE_FIN) == YAF_STATE_FIN ||
        fn->state & YAF_STATE_RST)
    {
        yfFlowClose(flowtab, fn, YAF_END_CLOSED);
        return;
    }

    /* Check for inactive timeout - this flow might be idled out on arrival */
    if ((flowtab->ctime - pbuf->ptime) > flowtab->idle_ms) {
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
        return;
    } else if (flowtab->idle_ms == 0) {
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
        return;
    }

    if (flowtab->aq.head == NULL) {
        yfFlowTick(flowtab, fn);
        return;
    }

    /* rip through the active queue and put this in the right spot */
    /* first remove the node */
    piqPick(&flowtab->aq, fn);

    for (tn = flowtab->aq.head; tn; tn = nfn) {
        end = tn->f.etime;
        nfn = tn->p;
        if (end <= fn->f.etime) {
            if (tn != flowtab->aq.head) {
                /* nfn is previous node */
                nfn = tn->n;
                /* point previous (next) to new node */
                nfn->p = fn;
                /* point current previous to new node */
                tn->n = fn;
                /* point new node's next to current */
                fn->p = tn;
                /* point new node's previous to previous */
                fn->n = nfn;
                /*yfFlowTabVerifyIdleOrder(flowtab);*/
            } else {
                /* we're at the head */
                /* set new node's previous to current head */
                fn->p = tn;
                /* set current's head next to new node */
                tn->n = fn;
                /* set flowtab head to new node */
                flowtab->aq.head = fn;
            }
            return;
        }
    }

    /* if this happens, we are at the tail */
    if (flowtab->aq.tail) {
        nfn = flowtab->aq.tail;
        /* this flow's next (in non-Brian land - previous) is the tail */
        fn->n = nfn;
        /* the tail's previous (next) now points to new node */
        nfn->p = fn;
        /* tail is now new node */
        flowtab->aq.tail = fn;
    } else {
        /* shouldn't get here but if we do,just get rid of this troublemaker.*/
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
    }
}


#ifdef YAF_ENABLE_NDPI

/**
 * yfNDPIApplabel
 *
 */
static void
yfNDPIApplabel(
    yfFlowTab_t  *flowtab,
    yfFlow_t     *flow,
    uint8_t      *payload,
    size_t        paylen)
{
    struct ndpi_flow_struct *nflow;
    struct ndpi_id_struct src, dst;
    ndpi_protocol proto;

    if (paylen == 0) {
        return;
    }

    nflow = malloc(sizeof(struct ndpi_flow_struct));
    memset(nflow, 0, sizeof(struct ndpi_flow_struct));
    memset(&src, 0, sizeof(struct ndpi_id_struct));
    memset(&dst, 0, sizeof(struct ndpi_id_struct));

    proto = ndpi_detection_process_packet(flowtab->ndpi_struct, nflow, payload,
                                          paylen, flow->etime, &src, &dst);
    flow->ndpi_master = proto.master_protocol;
    flow->ndpi_sub = proto.app_protocol;

    /* g_debug("proto is %d other is %d", proto.master_protocol,
     * proto.protocol); */
    ndpi_free_flow(nflow);
}


#endif /* ifdef YAF_ENABLE_NDPI */

/**
 * yfFlowPBuf
 *
 * parse a packet buffer structure and turn it into a flow record
 * this may update an existing flow record, or get a new flow record
 * and populate it.  It calls various functions to decode the
 * packet buffer and extract protocol details
 *
 * @param flowtab pointer to the flow table
 * @param pbuflen length of the packet buffer
 * @param pbuf pointer to the packet data
 *
 */
void
yfFlowPBuf(
    yfFlowTab_t  *flowtab,
    size_t        pbuflen,
    yfPBuf_t     *pbuf)
{
    yfFlowKey_t *key = &(pbuf->key);
    yfFlowKey_t rkey;
    yfFlowVal_t *val = NULL;
    yfFlowNode_t *fn = NULL;
    yfTCPInfo_t *tcpinfo = &(pbuf->tcpinfo);
    yfL2Info_t *l2info = &(pbuf->l2info);
    uint8_t *payload = (pbuflen >= YF_PBUFLEN_BASE) ?
        pbuf->payload : NULL;
    size_t paylen = (pbuflen >= YF_PBUFLEN_BASE) ?
        pbuf->paylen : 0;
    uint32_t datalen = (pbuf->iplen - pbuf->allHeaderLen +
                        l2info->l2hlen);
    uint32_t pcap_len = 0;
#ifdef YAF_ENABLE_APPLABEL
    uint16_t tapp = 0;
#endif

    /* skip and count out of sequence packets */
    if (pbuf->ptime < flowtab->ctime) {
        if (!flowtab->force_read_all) {
            ++(flowtab->stats.stat_seqrej);
            return;
        } else {
            yfAddOutOfSequence(flowtab, key, pbuflen, pbuf);
            return;
        }
    }

    /* update flow table current time */
    flowtab->ctime = pbuf->ptime;

    /* Count the packet and its octets */
    ++(flowtab->stats.stat_packets);
    flowtab->stats.stat_octets += pbuf->iplen;

    if (payload) {
        if (paylen >= pbuf->allHeaderLen) {
            paylen -= pbuf->allHeaderLen;
            payload += pbuf->allHeaderLen;
        } else {
            paylen = 0;
            payload = NULL;
        }
    }

#ifdef YAF_ENABLE_HOOKS
    /* Run packet hook; allow it to veto continued processing of the packet */
    if (!yfHookPacket(key, payload, paylen,
                      pbuf->iplen, tcpinfo, l2info))
    {
        return;
    }
#endif /* ifdef YAF_ENABLE_HOOKS */

#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        yfMPLSGetNode(flowtab, l2info);
    }
#endif  /* YAF_MPLS */

    /* Get a flow node for this flow */
    fn = yfFlowGetNode(flowtab, key, &val);
    /* Check for active timeout or counter overflow */
    if (((pbuf->ptime - fn->f.stime) > flowtab->active_ms) ||
        (flowtab->silkmode && (val->oct + pbuf->iplen > UINT32_MAX)))
    {
        yfFlowClose(flowtab, fn, YAF_END_ACTIVE);
#ifdef YAF_ENABLE_APPLABEL
        /* copy applabel over */
        if (flowtab->applabelmode) {tapp = fn->f.appLabel;}
#endif
        /* get a new flow node containing this packet */
        fn = yfFlowGetNode(flowtab, key, &val);
        /* set continuation flag in silk mode */
        if (flowtab->silkmode) {fn->f.reason = YAF_ENDF_ISCONT;}
#ifdef YAF_ENABLE_APPLABEL
        /* copy applabel into new flow */
        if (flowtab->applabelmode) {fn->f.appLabel = tapp;}
#endif
    }

    /* Check for inactive timeout - esp when reading from pcap */
    if ((pbuf->ptime - fn->f.etime) > flowtab->idle_ms) {
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
        /* get a new flow node for the current packet */
        fn = yfFlowGetNode(flowtab, key, &val);
    }

    /* First Packet? */
    if (val->pkt == 0) {
        val->vlan = key->vlanId;
        if (flowtab->macmode && val == &(fn->f.val)) {
            /* Note Mac Addr */
            if (l2info) {
                memcpy(fn->f.sourceMacAddr, l2info->smac,
                       ETHERNET_MAC_ADDR_LENGTH);
                memcpy(fn->f.destinationMacAddr, l2info->dmac,
                       ETHERNET_MAC_ADDR_LENGTH);
            }
        }
        /* Allocate Flow Statistics */
        if (flowtab->flowstats_mode) {
            val->stats = g_slice_new0(yfFlowStats_t);
        }
        /* Calculate reverse RTT */
        if (val == &(fn->f.rval)) {
            fn->f.rdtime = pbuf->ptime - fn->f.stime;
        }
    }

    /* Do payload and TCP stuff */
    if (fn->f.key.proto == YF_PROTO_TCP) {
        /* Handle TCP flows specially (flags, ISN, sequenced payload) */
        if (datalen) {
            if (val->appkt == 0) {
                val->first_pkt_size = datalen;
            } else {
                if (datalen == val->first_pkt_size) {
                    if (val->appkt == 1) {
                        val->attributes |= YAF_ATTR_SAME_SIZE;
                    }
                } else {
                    /* Don't consider TCP KEEP ALIVE */
                    if (val->lsn != (tcpinfo->seq + 1)) {
                        val->attributes &= ~YAF_ATTR_SAME_SIZE;
                    }
                }
            }
            val->appkt += 1;
        }
#if defined(YAF_ENABLE_P0F) || defined(YAF_ENABLE_FPEXPORT)
        yfFlowPktTCP(flowtab, fn, val, payload, paylen, tcpinfo,
                     pbuf->headerVal, pbuf->headerLen);
#else
        yfFlowPktTCP(flowtab, fn, val, payload, paylen, tcpinfo, NULL, 0);
#endif
    } else {
        if (val->pkt == 0) {
            val->first_pkt_size = pbuf->iplen;
        } else {
            if (pbuf->iplen == val->first_pkt_size) {
                if (val->pkt == 1) {
                    val->attributes |= YAF_ATTR_SAME_SIZE;
                }
            } else {
                val->attributes &= ~YAF_ATTR_SAME_SIZE;
            }
        }
        if ((val->pkt == 0 || flowtab->udp_multipkt_payload)) {
            if (((flowtab->udp_uniflow_port != 1) &&
                 (flowtab->udp_uniflow_port != fn->f.key.sp) &&
                 (flowtab->udp_uniflow_port != fn->f.key.dp)))
            {
                /* Get first packet payload from non-TCP flows */
                yfFlowPktGenericTpt(flowtab, fn, val, payload, paylen);
            }
        }
    }

#ifdef YAF_ENABLE_SEPARATE_INTERFACES
    val->netIf = pbuf->key.netIf;
#endif

    /* Count packets and octets */
    val->oct += pbuf->iplen;
    val->pkt += 1;

    /* Mark if fragmented */
    if (pbuf->frag == 1) {
        val->attributes |= YAF_ATTR_FRAGMENTS;
    }

    /* update flow end time */
    fn->f.etime = pbuf->ptime;

    /* Update stats */
    if (flowtab->flowstats_mode) {
        yfFlowStatistics(fn, val, pbuf->ptime, datalen);
    }

#ifdef YAF_ENABLE_HOOKS
    /* Hook Flow Processing */
    yfHookFlowPacket(&(fn->f), val, payload, paylen, pbuf->iplen,
                     tcpinfo, l2info);
#endif

    pcap_len = pbuf->pcap_hdr.caplen + 16;
    /* Write Packet to Pcap-Per-Flow pcap file */
    if (flowtab->pcap_dir) {
        /* what we actually hold in yaf dependent on max-payload */
        pbuf->pcap_hdr.caplen = (pbuflen > YF_PBUFLEN_BASE) ? pbuf->paylen : 0;
        if (val == &(fn->f.rval)) {
            yfFlowKeyReverse(key, &rkey);
            yfWritePcap(flowtab, &(fn->f), &rkey, pbuf);
        } else {
            yfWritePcap(flowtab, &(fn->f), key, pbuf);
        }
    }

    /* Write Pcap Meta Info */
    if (flowtab->pcap_meta) {
        if (val == &(fn->f.rval)) {
            yfFlowKeyReverse(key, &rkey);
            yfWritePcapMetaFile(flowtab, fn, pbuf, flowtab->hashfn(&rkey),
                                pcap_len);
        } else {
            yfWritePcapMetaFile(flowtab, fn, pbuf, flowtab->hashfn(key),
                                pcap_len);
        }
    }

#ifdef YAF_ENABLE_NDPI
    if (flowtab->ndpi_struct && payload && (fn->f.ndpi_master == 0)) {
        yfNDPIApplabel(flowtab, &(fn->f),
                       payload - pbuf->allHeaderLen + l2info->l2hlen,
                       paylen + pbuf->allHeaderLen - l2info->l2hlen);
    }
#endif /* ifdef YAF_ENABLE_NDPI */

    /* if udp-uniflow-mode, close UDP flow now */
    if ((fn->f.key.proto == YF_PROTO_UDP) && (flowtab->udp_uniflow_port != 0)) {
        if (((flowtab->udp_uniflow_port == 1) ||
             (flowtab->udp_uniflow_port == fn->f.key.sp) ||
             (flowtab->udp_uniflow_port == fn->f.key.dp)))
        {
            yfCloseActiveFlow(flowtab, fn, val, payload, paylen,
                              YAF_END_UDPFORCE, pbuf->iplen);
        }
    }

    if (flowtab->idle_ms == 0) {
        /* each pkt as a flow */
        yfFlowClose(flowtab, fn, YAF_END_IDLE);
        return;
    }

    /* close flow, or move it to head of queue */
    if ((fn->state & YAF_STATE_FIN) == YAF_STATE_FIN ||
        fn->state & YAF_STATE_RST)
    {
        yfFlowClose(flowtab, fn, YAF_END_CLOSED);
    } else {
        yfFlowTick(flowtab, fn);
    }
}


/**
 * yfUniflow
 *
 * creates a uniflow record from a biflow record, in order to split
 * the record into a single record for uniflow only collection systems
 *
 * @param bf pointer to normal biflow yaf flow record
 * @param uf pointer to a new flow record, that will have its rev
 *           (reverse) values NULLed
 *
 */
static void
yfUniflow(
    yfFlow_t  *bf,
    yfFlow_t  *uf)
{
#ifdef YAF_ENABLE_COMPACT_IP4
    if (bf->key.version == 4) {
        memcpy(uf, bf, sizeof(yfFlowIPv4_t));
    } else
#endif  /* YAF_ENABLE_COMPACT_IP4 */
    {
        memcpy(uf, bf, sizeof(yfFlow_t));
    }
    memset(&(uf->rval), 0, sizeof(yfFlowVal_t));
    uf->rdtime = 0;
}

/**
 * yfUniflowReverse
 *
 * reverses the flow information in the biflow in order to generate
 * two uniflow outputs
 *
 *
 * @param bf pointer to biflow record
 * @param uf pointer to uniflow record to fill in
 *
 * @return TRUE on success, FALSE on error
 */
static gboolean
yfUniflowReverse(
    yfFlow_t  *bf,
    yfFlow_t  *uf)
{
    if (!(bf->rval.pkt)) {return FALSE;}

    /* calculate reverse time */
    uf->stime = bf->stime + bf->rdtime;
    uf->etime = bf->etime;
    uf->rdtime = 0;

    memcpy(uf->sourceMacAddr, bf->destinationMacAddr,
           ETHERNET_MAC_ADDR_LENGTH);
    memcpy(uf->destinationMacAddr, bf->sourceMacAddr,
           ETHERNET_MAC_ADDR_LENGTH);

    /* reverse key */
    yfFlowKeyReverse(&bf->key, &uf->key);

    /* copy and reverse value */
    memcpy(&(uf->val), &(bf->rval), sizeof(yfFlowVal_t));
    memset(&(uf->rval), 0, sizeof(yfFlowVal_t));

    /* copy reason */
    uf->reason = bf->reason;
    uf->key.tos = bf->rtos;

    /* all done */
    return TRUE;
}


/**
 * yfFlowTabFlush
 *
 *
 *
 */
gboolean
yfFlowTabFlush(
    void      *yfContext,
    gboolean   close,
    GError   **err)
{
    gboolean wok = TRUE;
    yfFlowNode_t *fn = NULL;
    yfFlow_t uf;
    yfContext_t *ctx = (yfContext_t *)yfContext;
    yfFlowTab_t *flowtab = ctx->flowtab;

    if (!close && flowtab->flushtime &&
        (flowtab->ctime < flowtab->flushtime + YF_FLUSH_DELAY)
        && (flowtab->cq_count < YF_MAX_CQ))
    {
        return TRUE;
    }

    flowtab->flushtime = flowtab->ctime;

    /* Count the flush */
    ++flowtab->stats.stat_flush;

    /* Verify flow table order */
    /* yfFlowTabVerifyIdleOrder(flowtab);*/
    /* close idle flows */
    while (flowtab->aq.tail &&
           (flowtab->ctime - flowtab->aq.tail->f.etime > flowtab->idle_ms))
    {
        yfFlowClose(flowtab, flowtab->aq.tail, YAF_END_IDLE);
    }

    /* close limited flows */
    while (flowtab->max_flows &&
           flowtab->aq.tail &&
           flowtab->count >= flowtab->max_flows)
    {
        yfFlowClose(flowtab, flowtab->aq.tail, YAF_END_RESOURCE);
    }

    /* close all flows if flushing all */
    while (close && flowtab->aq.tail) {
        yfFlowClose(flowtab, flowtab->aq.tail, YAF_END_FORCED);
    }

    /* flush flows from close queue */
    while ((fn = piqDeQ(&flowtab->cq))) {
        /* quick accounting of asymmetric/uniflow records present */
        if ((fn->f.rval.oct == 0) && (fn->f.rval.pkt == 0)) {
            ++(flowtab->stats.stat_uniflows);
        }
        /* write flow */
        if (flowtab->uniflow) {
            /* Uniflow mode. Split flow in two and write. */
            yfUniflow(&(fn->f), &uf);
            wok = yfWriteFlow(ctx, &uf, err);
            if (wok) {
                ++(flowtab->stats.stat_flows);
            }
            if (wok && yfUniflowReverse(&(fn->f), &uf)) {
                wok = yfWriteFlow(ctx, &uf, err);
                if (wok) {
                    ++(flowtab->stats.stat_flows);
                }
            }
        } else {
            /* Biflow mode. Write flow whole. */
            wok = yfWriteFlow(ctx, &(fn->f), err);
            if (wok) {
                ++(flowtab->stats.stat_flows);
            }
        }
        --(flowtab->cq_count);

        /* free it */
        yfFlowFree(flowtab, fn);

        /* return error if necessary */
        if (!wok) {return wok;}
    }

    return TRUE;
}


/**
 * yfFlowTabCurrentTime
 *
 *
 *
 *
 */
uint64_t
yfFlowTabCurrentTime(
    const yfFlowTab_t  *flowtab)
{
    return flowtab->ctime;
}


/**
 * yfFlowDumpStats
 *
 * prints out statistics about flow, packet rates along with some
 * internal diagnostic type statistics as requested
 *
 *
 * @param flowtab pointer to the flow table
 * @param timer a glib timer to calculate rates for the flow table
 *
 *
 */
uint64_t
yfFlowDumpStats(
    yfFlowTab_t  *flowtab,
    GTimer       *timer)
{
    g_debug("Processed %llu packets into %llu flows:",
            (long long unsigned int)flowtab->stats.stat_packets,
            (long long unsigned int)flowtab->stats.stat_flows);
    if (timer) {
        g_debug("  Mean flow rate %.2f/s.",
                ((double)flowtab->stats.stat_flows /
                 g_timer_elapsed(timer, NULL)));
        g_debug("  Mean packet rate %.2f/s.",
                ((double)flowtab->stats.stat_packets /
                 g_timer_elapsed(timer, NULL)));
        g_debug("  Virtual bandwidth %.4f Mbps.",
                ((((double)flowtab->stats.stat_octets * 8.0) / 1000000) /
                 g_timer_elapsed(timer, NULL)));
    }
    g_debug("  Maximum flow table size %u.", flowtab->stats.stat_peak);
    g_debug("  %u flush events.", flowtab->stats.stat_flush);
#ifdef YAF_MPLS
    if (flowtab->mpls_mode) {
        g_debug("  %u Max. MPLS Nodes.", flowtab->stats.max_mpls_labels);
    }
#endif
    if (flowtab->stats.stat_seqrej) {
        g_warning("Rejected %" PRIu64 " out-of-sequence packets.",
                  flowtab->stats.stat_seqrej);
    }
    g_debug("  %" PRIu64 " asymmetric/unidirectional flows detected (%2.2f%%)",
            flowtab->stats.stat_uniflows,
            (((double)flowtab->stats.stat_uniflows) /
             ((double)flowtab->stats.stat_flows)) * 100);

    return flowtab->stats.stat_packets;
}
