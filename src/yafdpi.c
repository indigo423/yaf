/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafdpi.c
 *
 *  This file contains all of the functions directly related to the generic
 *  processing of deep packet inspection, which includes application labeling.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio, Emily Sarneso, Dillon Lareau
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

#ifdef YAF_ENABLE_APPLABEL

#include "yafdpi.h"
#include "yaf/yafDPIPlugin.h"
#include <ltdl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#ifdef YAF_ENABLE_DPI
#include "../../../infomodel/yaf_dpi.i"
#endif

#ifndef YFDEBUG_APPLABEL
#define YFDEBUG_APPLABEL 0
#endif

#ifndef YF_APPLABEL_TIMING
#define YF_APPLABEL_TIMING 0
#endif
#if !YF_APPLABEL_TIMING
#define YF_APPLABEL_TIMING_DECL(t_)
#define YF_APPLABEL_TIMING_STOP(idx_, t_)
#else
#define YF_APPLABEL_TIMING_DECL(t_)     clock_t t_ = clock()
#define YF_APPLABEL_TIMING_STOP(scanConf_, t_)  \
    do{                                         \
        (scanConf_)->timing += clock() - t_;    \
        ++(scanConf_)->count;                   \
    }while(0)
#endif  /* YF_APPLABEL_TIMING */


/**
 *
 * Macros
 *
 */
#define YAF_SEARCH_PATH "/usr/local/lib/yaf"
#define ALT_SEARCH_PATH "/usr/lib/yaf"
#define ALT_SEARCH_PATH64 "/usr/lib64/yaf"

/* Syntax version of the yafDPIRules.conf file.  This should be incremented
 * when we change the syntax in some incompatible way. */
#define YAF_DPIRULES_VERSION  1

/* The name of the function defined in Lua, available to yafDPIRules, that
 * returns YAF_DPIRULES_VERSION */
#define YAF_DPIRULES_VERSION_VARNAME  "yaf_get_dpi_version"

/* The name of the function defined in Lua, available to yafDPIRules, that
 * returns the version of yaf */
#define YAF_VERSION_VARNAME    "yaf_get_yaf_version"

/* The maximum number of applabel regexes allowed in the config file */
#define MAX_PAYLOAD_RULES   1024

/* String prepended to the protocol name to get the template name */
#define YAF_TEMPLATE_PREFIX "yaf_"

/* Details of the template used when there is no DPI */
#define YAF_DPI_EMPTY_TID   0xC209
#define YAF_DPI_EMPTY_NAME  "yaf_empty"
#define YAF_DPI_EMPTY_DESC  NULL

/* Suffix used when searching for the basiclist corresponding to an IE */
#define NAMED_LIST_SUFFIX   "List"

/* pcre rule limit */
#define NUM_SUBSTRING_VECTS 60

/* limit the length of captured strings */
#define PER_FIELD_LIMIT     200
#define PER_RECORD_LIMIT    1000

/* Limit on the number of regex rules per regex DPI protocol */
#define NUM_REGEX_LIMIT     40


/**
 *
 * Structures
 *
 */
typedef struct protocolRegexFields_st {
    pcre                   *rule;
    pcre_extra             *extra;
    const fbInfoElement_t  *elem;
    uint16_t                info_element_id;
    size_t                  BLoffset;
} protocolRegexFields;

typedef struct payloadScanConf_st {
    uint16_t   applabel;
    enum applabelType_en {
        APPLABEL_REGEX, APPLABEL_PLUGIN, APPLABEL_EMPTY, APPLABEL_SIGNATURE
    } applabelType;
#if YF_APPLABEL_TIMING
    uint64_t   count;
    uint64_t   timing;
#endif
    union {
        struct {
            uint8_t      protocol;
            pcre        *scannerExpression;
            pcre_extra  *scannerExtra;
        } regexFields;
        struct {
            char                *pluginName;
            lt_dlhandle          handle;
            ydpScanPayload_fn    func;
        } pluginArgs;
    } applabelArgs;
    enum dpiType_en {
        DPI_REGEX, DPI_PLUGIN, DPI_MIXED, DPI_EMPTY
    } dpiType;

#ifdef YAF_ENABLE_DPI
    /* These aren't unioned because dpi can be both plugin and regex */
    /* plugin details */
    ydpProcessDPI_fn      dpiProcessFunc;
    ydpAddTemplates_fn    initTemplateFunc;
    ydpFreeRec_fn         freeRecFunc;
    /* regex details */
    int                   numRules;
    int                   numBLs; /* multiple rules may have the same BL */
    char                 *name;
    uint16_t              templateID;
    fbTemplate_t         *template;
    fbInfoElementSpec_t  *specs;
    protocolRegexFields   regexFields[MAX_PAYLOAD_RULES];
#endif  /* YAF_ENABLE_DPI */

    pluginExtras_t        pluginExtras;

} payloadScanConf_t;

/**
 *
 * Global Variables
 *
 */

/* These hold copies of the pointers in the yafdpictx->dpiActiveHash table */
static payloadScanConf_t  *ruleTable[MAX_PAYLOAD_RULES];
static unsigned int        numPayloadRules = 0;
static payloadScanConf_t  *sigTable[MAX_PAYLOAD_RULES];
static unsigned int        numSigRules = 0;

/* Global context for functions which do not support passing in the context */
static yfDPIContext_t     *dpiyfctx = NULL;

#ifdef YAF_ENABLE_DPI
/* Template for the when there is no DPI */
static fbTemplate_t       *dpiEmptyTemplate;

static fbInfoElementSpec_t yaf_empty_spec[] = {
    {"paddingOctets", 1, 0 },
    FB_IESPEC_NULL
};
#endif  /* YAF_ENABLE_DPI */

/**
 *
 * local functions
 *
 */
#ifdef YAF_ENABLE_DPI
static uint8_t
ydRunConfRegex(
    ypDPIFlowCtx_t  *flowContext,
    const uint8_t   *payloadData,
    unsigned int     payloadSize,
    uint32_t         offset,
    yfFlow_t        *flow,
    yfFlowVal_t     *val);

static void *
ydProcessGenericRegex(
    ypDPIFlowCtx_t       *flowContext,
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    uint8_t               fwdcap,
    uint8_t               totalcap,
    uint16_t              stlTID,
    fbTemplate_t         *stlTemplate);
#endif  /* YAF_ENABLE_DPI */

static uint16_t
ydScanPayload(
    const uint8_t  *payloadData,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val);

#if YFDEBUG_APPLABEL
static void
ydPayloadPrinter(
    const uint8_t *payloadData,
    unsigned int   payloadSize,
    unsigned int   numPrint,
    const char    *prefixString,
    ...);
#endif /* if YFDEBUG_APPLABEL */

/**
 * @brief Helper to deallocate pluginTemplate elements
 *
 * @param element the element to cleanup
 */
static void
ydClearPluginTemplates(
    pluginTemplate_t  *element)
{
    g_free(element->templateName);
    for (guint i = 0; i < element->templateElements->len; ++i) {
        char *c = g_array_index(element->templateElements, char *, i);
        g_free(c);
    }
    g_array_free(element->templateElements, TRUE);
}

/**
 * @brief Helper to deallocate pluginRegex elements
 *
 * @param element the element to cleanup
 */
static void
ydClearPluginRegex(pluginRegex_t *element) {
    g_free(element->ruleName);
    g_free(element->ruleRegex);
}

/* Hash table macros, wraps the applabel in GINT_TO_POINTER */
#define ydHashContains(h, k) g_hash_table_contains(h, GINT_TO_POINTER(k))
#define ydHashLookup(h, k) \
    ((payloadScanConf_t *)(g_hash_table_lookup(h, GINT_TO_POINTER(k))))
#define ydHashInsert(h, k, v) \
    g_hash_table_insert(h, GINT_TO_POINTER(k), (gpointer)(v))
#define ydHashRemove(h, k) g_hash_table_lookup(h, GINT_TO_POINTER(k))

/**
 * ydHashFindOrCreate
 *
 * Wraps ydHashInsert. Either gets the existing element or allocates and
 * inserts a new one.
 *
 */
static payloadScanConf_t *
ydHashFindOrCreate(
    GHashTable  *hashTable,
    uint16_t     applabel)
{
    payloadScanConf_t *scanConf;
    scanConf = ydHashLookup(hashTable, applabel);
    if (!scanConf) {
        scanConf = g_slice_new0(payloadScanConf_t);
        scanConf->applabel = applabel;
        ydHashInsert(hashTable, applabel, scanConf);
        /* initialize the arrays to hold plugins' extras */
        scanConf->pluginExtras.pluginRegexes =
            g_array_new(FALSE, TRUE, sizeof(pluginRegex_t));
        g_array_set_clear_func(scanConf->pluginExtras.pluginRegexes,
                               (GDestroyNotify)ydClearPluginRegex);
        scanConf->pluginExtras.pluginTemplates = g_array_new(FALSE, TRUE,
                                                     sizeof(pluginTemplate_t));
        g_array_set_clear_func(scanConf->pluginExtras.pluginTemplates,
                                (GDestroyNotify)ydClearPluginTemplates);
    }
    return scanConf;
}


/*
 * Lua helper functions
 *
 */

/**
 * Implements a lua_Cfunction that yafDPIRules can call to get the expected
 * version of the rules file.
 */
static int
ydGetDPIVersion(
    lua_State  *L)
{
    lua_pushinteger(L, YAF_DPIRULES_VERSION);
    return 1;
}

/**
 * Implements a lua_Cfunction that yafDPIRules can call to get the version of
 * yaf.
 */
static int
ydGetYAFVersion(
    lua_State  *L)
{
    lua_pushstring(L, PACKAGE_VERSION);
    return 1;
}

/*
 *  Gets global `key`, converts it to a number, and returns it.  Returns
 *  `novalue` if global does not exist or cannot be converted to a number.
 */
static int
ydLuaGetGlobalNumber(
    lua_State   *L,
    const char  *key,
    int          novalue)
{
    int result;
    int ltype;
    int ok = 1;

    ltype = lua_getglobal(L, key);
    switch (ltype) {
      case LUA_TNUMBER:
        result = (int)lua_tointeger(L, -1);
        break;
      case LUA_TSTRING:
        result = lua_tointegerx(L, -1, &ok);
        if (!ok) {
            result = novalue;
        }
        break;
      case LUA_TNIL:
      default:
        result = novalue;
        break;
    }
    lua_pop(L, 1);

    return result;
}

#ifdef YAF_ENABLE_DPI
#if 0
/* not needed currently */
/*
 *  Gets global key, converts it to a boolean, and returns it.  Returns
 *  `novalue` if global does not exist.
 */
static int
ydLuaGetGlobalBoolean(
    lua_State   *L,
    const char  *key,
    int          novalue)
{
    int result;
    int ltype;

    ltype = lua_getglobal(L, key);
    switch (ltype) {
      case LUA_TNIL:
        result = novalue;
        break;
      case LUA_TBOOLEAN:
      default:
        result = lua_toboolean(L, -1);
        break;
    }
    lua_pop(L, 1);

    return result;
}
#endif  /* 0 */
#endif  /* YAF_ENABLE_DPI */

/*
 *  Returns the length of the item at `index` on the Lua stack.
 */
static int
ydLuaGetLen(
    lua_State  *L,
    int         index)
{
    int len = 0;

    lua_len(L, index);
    len = lua_tointeger(L, -1);
    lua_pop(L, 1);

    return len;
}

/*
 *  Gets field `key` from the table at the top of the Lua stack.  If the value
 *  is nil, returns a newly allocated copy of `novalue`.  Otherwise, converts
 *  it the value to a string and returns it in newly allocated memory.
 */
static char *
ydLuaGetFieldString(
    lua_State   *L,
    const char  *key,
    const char  *novalue)
{
    char *result;
    int ltype;

    lua_pushstring(L, key);
    ltype = lua_gettable(L, -2);

    switch (ltype) {
      case LUA_TSTRING:
      case LUA_TNUMBER:
        result = g_strdup(lua_tostring(L, -1));
        break;
      case LUA_TNIL:
      default:
        result = g_strdup(novalue);
        break;
    }
    lua_pop(L, 1);

    return result;
}

/*
 *  Gets field `key` from the table at the top of the Lua stack, converts it
 *  to a number, and returns it.
 */
static int
ydLuaGetFieldNumber(
    lua_State   *L,
    const char  *key,
    int          novalue)
{
    int result;
    int ltype;
    int ok = 1;

    lua_pushstring(L, key);
    ltype = lua_gettable(L, -2);

    switch (ltype) {
      case LUA_TNUMBER:
        result = (int)lua_tointeger(L, -1);
        break;
      case LUA_TSTRING:
        result = lua_tointegerx(L, -1, &ok);
        if (!ok) {
            result = novalue;
        }
        break;
      case LUA_TNIL:
      default:
        result = novalue;
        break;
    }
    lua_pop(L, 1);

    return result;
}

/*
 *  Gets field `key` from the table at the top of the Lua stack, converts it
 *  to a boolean, and returns it.
 */
static int
ydLuaGetFieldBoolean(
    lua_State   *L,
    const char  *key,
    int          novalue)
{
    int result;
    int ltype;

    lua_pushstring(L, key);
    ltype = lua_gettable(L, -2);

    switch (ltype) {
      case LUA_TNIL:
        result = novalue;
        break;
      case LUA_TBOOLEAN:
      default:
        result = lua_toboolean(L, -1);
        break;
    }
    lua_pop(L, 1);

    return result;
}


/**
 *  Returns the symbol 'symbol' in the plugin stored on 'scanConf'. On error,
 *  sets 'err' and returns NULL.
 */
static lt_ptr
ydScanConfLibrarySymbol(
    payloadScanConf_t  *scanConf,
    const char         *symbol,
    GError            **err)
{
    lt_ptr funcPtr = lt_dlsym(scanConf->applabelArgs.pluginArgs.handle,
                              symbol);
    if (NULL == funcPtr) {
        const lt_dlinfo *info =
            lt_dlgetinfo(scanConf->applabelArgs.pluginArgs.handle);
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                    "Could not find function \"%s\" in plugin \"%s\""
                    " loaded from \"%s\"",
                    symbol, info->name, info->filename);
    }
    return funcPtr;
}


#ifdef YAF_ENABLE_DPI
/**
 *  Handles the "elements" Lua array from the yafDPIRules.conf file.  Checks
 *  each entry and creates a new IE.
 */
static void
ydParseConfigElements(
    lua_State      *L)
{
    fbInfoElement_t newelem = FB_IE_NULL;
    fbInfoModel_t         *model = ydGetDPIInfoModel();
    const fbInfoElement_t *ie;
    char *name = NULL;
    int isstring;
    int count;
    int id = -1;
    int i;

#if YFDEBUG_APPLABEL
    int  top = lua_gettop(L);
#endif

    count = ydLuaGetLen(L, -1);

    /* To make it easier to use 'continue' in the for() loop, there is a
     * lua_pop() just inside it. Push a dummy value to pop once inside */
    lua_pushstring(L, "dummy");
    for (i = 1; i <= count; ++i) {
        lua_pop(L, 1);
        g_free(name);
        name = NULL;

#if YFDEBUG_APPLABEL
        if (lua_gettop(L) != top) {
            g_error("Lua stack-size mismatch processing elements."
                    " Stack initially had %d elements, now has %d;"
                    " last id processed was %d", top, lua_gettop(L), id);
        }
#endif /* if YFDEBUG_APPLABEL */

        if (LUA_TTABLE != lua_rawgeti(L, -1, i)) {
            g_warning("In DPI config file:"
                      " elements row #%d is not a valid table (type is %s)",
                      i, lua_typename(L, lua_type(L, -1)));
            continue;
        }
        id = ydLuaGetFieldNumber(L, "id", -28);
        if (id <= 0 || id > 0x3fff) {
            if (-28 == id) {
                g_warning("In DPI config file while parsing elements #%d:"
                          " table does not have a valid id.", i);
            } else {
                g_warning("In DPI config file while parsing elements #%d:"
                          " id=%d is outside the range %d to %d.",
                          i, id, 1, 0x3fff);
            }
            continue;
        }
        ie = fbInfoModelGetElementByID(model, id, CERT_PEN);
        if (NULL != ie) {
            g_warning("In DPI config file while parsing elements #%d:"
                      " id=%d is already defined (%s)",
                      i, id, fbInfoElementGetName(ie));
            continue;
        }

        name = ydLuaGetFieldString(L, "name", NULL);
        if (NULL == name) {
            g_warning("In DPI config file while parsing elements #%d:"
                      " table does not have a valid name.", i);
            continue;
        }
        ie = fbInfoModelGetElementByName(model, name);
        if (NULL != ie) {
            g_warning("In DPI config file while parsing elements #%d:"
                      " name=%s is already defined (ent=%u, id=%u)",
                      i, name, fbInfoElementGetPEN(ie),
                      fbInfoElementGetId(ie));
            continue;
        }

        isstring = ydLuaGetFieldBoolean(L, "is_string", 0);

        newelem.name = name;
        newelem.ent = CERT_PEN;
        newelem.num = id;
        newelem.len = FB_IE_VARLEN;
        newelem.type = (isstring) ? FB_STRING : FB_OCTET_ARRAY;
        newelem.flags = 0;
        fbInfoModelAddElement(model, &newelem);
    }

    g_free(name);
    lua_pop(L, 1);
}
#endif  /* #ifdef YAF_ENABLE_DPI */


/**
 * @brief Parses the "plugin_rules" table within an applabel table in the Lua
 * Applabel/DPI config file. This is used when the dpi_type is "plugin".
 *
 * @param scanConf
 * @param L
 * @param err
 * @return The number of plugin rules. returns -1 on error.
 */
static int
ydParseConfigPluginRegex(
    payloadScanConf_t  *scanConf,
    lua_State          *L,
    GError            **err)
{
    pluginRegex_t tempPluginRule;
    uint8_t     tempNumRules = 0;
    int         j = 1;

    lua_pushstring(L, "plugin_rules");
    int         pluginRulesType = lua_gettable(L, -2);
    if (LUA_TNIL == pluginRulesType) {
        /* plugin_rules was not specified. */
        lua_pop(L, 1);
        return 0;
    }
    if (LUA_TTABLE != pluginRulesType) {
        /* plugin_rules was specified but is not a table. */
        g_warning("In DPI config file while parsing label %d:"
                  " plugin_rules is not a table;"
                  " ignoring plugin rules.",
                  scanConf->applabel);
        lua_pop(L, 2);
        return 0;
    }

    /* Iterate over all rules in "plugin_rules" subtable */
    tempNumRules = 0;
    lua_pushnil(L);  /* first key */
    while (lua_next(L, -2) > 0) {
        /* key (rule name) is at index -2 and value (regex) is at index -1 */
        if (LUA_TSTRING != lua_type(L, -2)) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "plugin_rule key is not a valid string"
                        " in label %d (type is %s)",
                        scanConf->applabel, lua_typename(L, lua_type(L, -2)));
            lua_pop(L, 3); /* reset the lua stack */
            return -1;
        }
        if (LUA_TSTRING != lua_type(L, -1)) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "plugin_rule regex for key %s is not a valid string"
                        " in label %d (type is %s)",
                        lua_tostring(L, -2),
                        scanConf->applabel, lua_typename(L, lua_type(L, -1)));
            lua_pop(L, 3); /* reset the lua stack */
            return -1;
        }

        /* save the ruleName and regex */
        tempPluginRule.ruleName = g_strdup(lua_tostring(L, -2));
        tempPluginRule.ruleRegex = g_strdup(lua_tostring(L, -1));
        g_array_append_val(scanConf->pluginExtras.pluginRegexes,
                           tempPluginRule);

        /* removes 'value' but keeps 'key' for next iteration */
        lua_pop(L, 1);
        tempNumRules++;
        j++;
    }

    lua_pop(L, 1); /* Pops rules table */
    return tempNumRules;
}


#ifdef YAF_ENABLE_DPI
/**
 * @brief Parses the "dpi_templates" table within an applabel table in the Lua
 * Applabel/DPI config file. This is used when the dpi_type is "plugin".
 *
 * @param scanConf
 * @param L
 * @param err
 * @return The number of template rules. returns -1 on error.
 */
static int
ydParseConfigTemplates(
    payloadScanConf_t  *scanConf,
    lua_State          *L,
    GError            **err)
{
    pluginTemplate_t tempPluginTemplate;
    uint8_t          tempNumTemplates = 0;

    lua_pushstring(L, "dpi_templates");
    int              dpiTemplatesType = lua_gettable(L, -2);
    if (LUA_TNIL == dpiTemplatesType) {
        /* dpi_templates was not specified. silently ignore. */
        lua_pop(L, 1);
        return 0;
    }
    if (LUA_TTABLE != dpiTemplatesType) {
        /* dpi_templates was specified but is not a table. */
        g_warning("In DPI config file while parsing label %d:"
                  " dpi_templates is not a table;",
                  scanConf->applabel);
        lua_pop(L, 1);
        return 0;
    }

    /* Iterate over all templates in "dpi_templates" subtable */
    lua_pushnil(L);
    while (lua_next(L, -2) > 0) {
        /* key (template name) is at index -2 and value (element table) is at
         * index -1 */
        if (LUA_TSTRING != lua_type(L, -2)) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "dpi template name is not a valid string"
                        " in label %d (type is %s)",
                        scanConf->applabel, lua_typename(L, lua_type(L, -2)));
            lua_pop(L, 3); /* reset the lua stack */
            return -1;
        }
        if (LUA_TTABLE != lua_type(L, -1)) {
            g_warning("In DPI config file while parsing label");
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "dpi element for dpi template %s is not a valid table"
                        " in label %d (type is %s)",
                        lua_tostring(L, -2),
                        scanConf->applabel, lua_typename(L, lua_type(L, -1)));
            lua_pop(L, 3); /* reset the lua stack */
            return -1;
        }

        int numElements = ydLuaGetLen(L, -1);
        if (!numElements) {
            g_warning("In DPI config file while parsing label %d:"
                      " ignoring the %s dpi template's"
                      " elements table since it is empty",
                      scanConf->applabel, lua_tostring(L, -2));
        }

        tempPluginTemplate.templateName = g_strdup(lua_tostring(L, -2));

        GArray *templateElements = g_array_new(FALSE, TRUE, sizeof(char *));

        /* Iterate over the template elements and add them to the
         * templateElements GArray */
        for (int i = 1; i <= numElements; ++i) {
            if (lua_rawgeti(L, -1, i) != LUA_TSTRING) {
                g_warning("In DPI config file while parsing dpi template %s:"
                          " Ignoring element that is not a string"
                          " (type is %s)",
                          tempPluginTemplate.templateName,
                          lua_typename(L, lua_type(L, -1)));
            } else {
                const char *element = g_strdup(lua_tostring(L, -1));
                g_array_append_val(templateElements, element);
            }
            lua_pop(L, 1);
        }
        tempPluginTemplate.templateElements = templateElements;
        g_array_append_val(scanConf->pluginExtras.pluginTemplates,
                           tempPluginTemplate);

        lua_pop(L, 1);
        tempNumTemplates++;
    }

    lua_pop(L, 1); /* Pops dpi_templates table */
    return tempNumTemplates;
}


/**
 *  Parses the "dpi_rules" table and "dpi_template_id" and "dpi_name" values
 *  within an applabel table in the Lua Applabel/DPI config file.  This is
 *  used when the dpi_type is "regex" or "regex-plugin".
 */
static int
ydParseConfigDpiRegex(
    payloadScanConf_t  *scanConf,
    lua_State          *L,
    GError            **err)
{
    fbInfoModel_t         *model = ydGetDPIInfoModel();
    const fbInfoElement_t *bl_element;
    fbInfoElementSpec_t    spec = {"basicList", 0, 0};
    protocolRegexFields   *regexField;
    const fbInfoElement_t *elem = NULL;
    int        tempNumRules = 0;
    int        numRules;
    int        active;
    int        j;
    int        loop;
    gboolean   found;
    char       *elem_name;
    char       *regex;

    /* Vars for regex compilation */
    const char *errorString;
    pcre       *newRule;
    pcre_extra *newExtra;

    /* These will be null for dpi_mixed and that is okay */
    scanConf->templateID = ydLuaGetFieldNumber(L, "dpi_template_id", 0);
    scanConf->name = ydLuaGetFieldString(L, "dpi_name", NULL);
    if (NULL == scanConf->name) {
        char namebuf[32];
        snprintf(namebuf, sizeof(namebuf), "dpi%u_template",
                 scanConf->applabel);
        scanConf->name = g_strdup(namebuf);
    }

    lua_pushstring(L, "dpi_rules");
    if (LUA_TTABLE != lua_gettable(L, -2)) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                    "dpi_rules is not a valid table in label %d (type is %s)",
                    scanConf->applabel, lua_typename(L, lua_type(L, -1)));
        lua_pop(L, 1);
        return -1;
    }

    /* Iterate over all rules in "dpi_rules" subtable */
    numRules = ydLuaGetLen(L, -1);
    if (!numRules) {
#if YFDEBUG_APPLABEL
        g_warning("In DPI config file while parsing label %d:"
                  " Disabling DPI for this label"
                  " since dpi_rules table is empty",
                  scanConf->applabel);
#endif
        scanConf->dpiType = DPI_EMPTY;
        lua_pop(L, 1);
        return 0;
    }

    /* Create an array large enough to hold all rules; we resize it at the
     * end */
    scanConf->specs = g_new0(fbInfoElementSpec_t, 1 + numRules);
    for (j = 1; j <= numRules; j++) {
        if (LUA_TTABLE != lua_rawgeti(L, -1, j)) {
            g_warning("In DPI config file while parsing label %d:"
                      " DPI rule #%d is not a valid table (type is %s);"
                      " ignoring DPI rule.",
                      scanConf->applabel, j, lua_typename(L, lua_type(L, -1)));
            lua_pop(L, 1);
            continue;
        }

        /* ignore if active is present and false */
        active = ydLuaGetFieldBoolean(L, "active", 1);
        if (!active) {
            lua_pop(L, 1);
            continue;
        }

        /* look up the info element by name */
        elem_name = ydLuaGetFieldString(L, "elem_name", NULL);
        if (NULL == elem_name) {
            g_warning("In DPI config file while parsing label %d:"
                      " DPI rule #%d does not have elem_name;"
                      " ignoring DPI rule.",
                      scanConf->applabel, j);
            lua_pop(L, 1);
            continue;
        }
        elem = fbInfoModelGetElementByName(model, elem_name);
        if (!elem) {
            g_warning("In DPI config file while parsing label %d:"
                      " DPI rule #%d uses an element name '%s' that"
                      " does not exist in the info model;"
                      " ignoring DPI rule.",
                      scanConf->applabel, j, elem_name);
            g_free(elem_name);
            lua_pop(L, 1);
            continue;
        }
        /* FIXME: Change code so the CERT PEN is not required/implied */
        if (CERT_PEN != fbInfoElementGetPEN(elem)) {
            g_warning("In DPI config file while parsing label %d:"
                      " DPI rule #%d uses an element name '%s' whose"
                      " private enterprise number does not equal CERT's (%d);"
                      " ignoring DPI rule.",
                      scanConf->applabel, j, elem_name, CERT_PEN);
            g_free(elem_name);
            lua_pop(L, 1);
            continue;
        }

        g_free(elem_name);

        /* compile and set the regex */
        regex = ydLuaGetFieldString(L, "regex", NULL);
        if (NULL == regex) {
            g_warning("In DPI config file while parsing label %d:"
                      " DPI rule #%d (%s) does not have a regex;"
                      " ignoring DPI rule.",
                      scanConf->applabel, j, fbInfoElementGetName(elem));
            lua_pop(L, 1);
            continue;
        }
        newRule = ydPcreCompile(regex, PCRE_MULTILINE, err);
        if (NULL == newRule) {
            g_prefix_error(err,
                           "In DPI config file while parsing label %d:"
                           " DPI rule #%d (%s) had an error parsing regex: ",
                           scanConf->applabel, j, fbInfoElementGetName(elem));
            g_free(regex);
            return -1;
        }
        newExtra = pcre_study(newRule, 0, &errorString);
        g_free(regex);

        /* convenience pointer to this rule */
        regexField = &scanConf->regexFields[scanConf->numRules];

        regexField->info_element_id = fbInfoElementGetId(elem);
        regexField->elem = elem;
        regexField->rule = newRule;
        regexField->extra = newExtra;

        /* check to see if we already have a BL for this element, since there
         * may be multiple regex entries for the same IE */
        found = FALSE;
        for (loop = 0; loop < scanConf->numRules; loop++) {
            if (scanConf->regexFields[loop].info_element_id ==
                regexField->info_element_id)
            {
                regexField->BLoffset =
                    scanConf->regexFields[loop].BLoffset;
                found = TRUE;
                break;
            }
        }
        /* if there isn't an existing BL, make one and add it */
        if (!found) {
            bl_element = ydLookupNamedBlByName(elem);
            if (bl_element) {
                spec.name = fbInfoElementGetName(bl_element);
            } else {
                spec.name = "basicList";
            }

            memcpy(scanConf->specs + scanConf->numBLs, &spec,
                   sizeof(fbInfoElementSpec_t));
            regexField->BLoffset = (sizeof(fbBasicList_t) * scanConf->numBLs);
            scanConf->numBLs++;
        }
        scanConf->numRules++;
        tempNumRules++;

        lua_pop(L, 1); /* Pops individual rule table */
    }
    scanConf->specs = g_renew(fbInfoElementSpec_t, scanConf->specs,
                              1 + scanConf->numRules);

    lua_pop(L, 1); /* Pops rules table */

    return tempNumRules;
}
#endif  /* YAF_ENABLE_DPI */


/**
 *  Loads the plugin specified by `pluginName`, finds its ScanPayload
 *  function, and checks for an "args" array within an applabel table to get
 *  the arguments for the plugin.  Stores the plugin's handle and its
 *  arguments on 'scanConf'.  Returns TRUE on success.  Sets 'err' and returns
 *  FALSE on error.
 */
static gboolean
ydParseConfigLoadPlugin(
    payloadScanConf_t *scanConf,
    const char        *pluginName,
    gboolean           applabelOnly,
    lua_State         *L,
    GHashTable        *dlhash,
    GError           **err)
{
    lt_dlhandle modHandle;
    lt_ptr   funcPtr;
    int      ltype;
    int      numArgs = 0;
    int      i;
    int      rc;
    char   **argStrings;

    /* store the plugin-name */
    scanConf->applabelArgs.pluginArgs.pluginName = g_strdup(pluginName);

    /*
     * Allocate argStrings to hold the plugin name.  Check for "args" in the
     * Lua table for this applabel.  If found, include them in argStrings.
     */

    lua_pushstring(L, "args");
    ltype = lua_gettable(L, -2);
    if (LUA_TTABLE == ltype) {
        numArgs = ydLuaGetLen(L, -1);
    } else if (LUA_TNIL != ltype) {
        g_warning("In DPI config file while parsing label %d:"
                  " args is not a valid table (type is %s)",
                  scanConf->applabel, lua_typename(L, ltype));
    }

    /* Add 1 to 'numArgs' for the plug-in name.  When allocating 'argStrings',
     * add an extra value to hold a terminating NULL so that g_strfreev() can
     * be used to free it. */
    ++numArgs;
    argStrings = g_new0(char *, numArgs + 1);
    (argStrings)[0] = g_strdup(pluginName);

    /* Use "i < numArgs" since we added one to its Lua length */
    for (i = 1; i < numArgs; ++i) {
        ltype = lua_rawgeti(L, -1, i);
        switch (ltype) {
          case LUA_TSTRING:
          case LUA_TNUMBER:
            (argStrings)[i] = g_strdup(lua_tostring(L, -1));
            break;
          case LUA_TBOOLEAN:
            (argStrings)[i] = g_strdup(lua_toboolean(L, -1) ? "true" : "false");
            break;
          case LUA_TNIL:
          default:
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "In DPI config file while parsing label %d:"
                        " args item #%d is not a string, boolean, or number"
                        " (type is %s)",
                        scanConf->applabel, i, lua_typename(L, ltype));
            g_strfreev(argStrings);
            return FALSE;
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);  /* pop the args table */

#if YFDEBUG_APPLABEL
    g_debug("  plugin args: ");
    for (i = 0; i < numArgs; ++i) {
        g_debug("    \"%s\" ", (argStrings)[i]);
    }
#endif /* if YFDEBUG_APPLABEL */

    /*
     *  Load the library (dlopen()) and find the ydpScanPayload function.
     */

    /* see if we have already loaded this library, if not, load it */
    modHandle = (lt_dlhandle)g_hash_table_lookup(dlhash, pluginName);
    if (NULL == modHandle) {
        modHandle = lt_dlopenext(pluginName);
        if (NULL == modHandle) {
            const char *dlerr = lt_dlerror();
            if (NULL == dlerr) {
                dlerr = "Unknown libtool error";
            }
            g_critical("Couldn't open library \"%s\": %s", pluginName, dlerr);
            g_critical("Library search path set to %s", lt_dlgetsearchpath());
            g_critical("Set LTDL_LIBRARY_PATH to correct location.");
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "Couldn't open library \"%s\": %s",
                        pluginName, dlerr);
            g_strfreev(argStrings);
            return FALSE;
        }
        g_hash_table_insert(dlhash, g_strdup(pluginName), modHandle);

#if YFDEBUG_APPLABEL
        const lt_dlinfo *info = lt_dlgetinfo(modHandle);
        g_debug("  Loading %s plugin from %s", info->name, info->filename);
#endif
    }

    scanConf->applabelArgs.pluginArgs.handle = modHandle;

    /* find and store the ydpScanPayload function pointer */
    funcPtr = ydScanConfLibrarySymbol(scanConf, "ydpScanPayload", err);
    if (NULL == funcPtr) {
        g_strfreev(argStrings);
        return FALSE;
    }
    scanConf->applabelArgs.pluginArgs.func = (ydpScanPayload_fn)funcPtr;

    /* check for and call the initialization function if existent */
    funcPtr = lt_dlsym(modHandle, "ydpInitialize");
    if (funcPtr) {
        rc = ((ydpInitialize_fn)funcPtr)(
            numArgs, argStrings, scanConf->applabel, applabelOnly,
            (void *)&(scanConf->pluginExtras), err);
        if (rc <= 0) {
            if (rc < 0 && err && !*err) {
                g_set_error(err,  YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                            "ydpInitialize() in plugin %s returned"
                            " error code %d",
                            pluginName, rc);
            } else {
                g_debug("Applabel plugin %s is disabled", pluginName);
            }
            /* disable */
            scanConf->applabelType = APPLABEL_EMPTY;
            g_strfreev(argStrings);
            return (0 == rc);
        }
    }
    /* free the GArray and its elements */
    g_array_free(scanConf->pluginExtras.pluginRegexes, TRUE);
    g_array_free(scanConf->pluginExtras.pluginTemplates, TRUE);

    g_strfreev(argStrings);

    return TRUE;
}


/**
 *  Parses the applabels table in the Lua Applabels/DPI config file.  Returns
 *  the number of rules added or returns -1 on error and sets 'err'.
 */
static int
ydParseConfigApplabels(
    yfDPIContext_t *ctx,
    lua_State      *L,
    GHashTable     *dlhash,
    GError         **err)
{
    payloadScanConf_t     *scanConf;
    int        i, j;
    int        numLabels;

    /* Vars for config file values*/
    enum applabelType_en labelType = APPLABEL_EMPTY;
    int         active;
    int         label = -1;
    char       *labelTypeString;
    char       *value;
    int        tempNumRules = 0;
    int        ltype;
    int        port;
    int        numPorts;
#ifdef YAF_ENABLE_DPI
    char       *dpiType;
#endif  /* YAF_ENABLE_DPI */

    /* Vars for regex compilation */
    const char *errorString;
    int         protocol;
    pcre       *newRule;
    pcre_extra *newExtra;

#if YFDEBUG_APPLABEL
    int  top = lua_gettop(L);
#endif

    /* loop over each applabel */
    numLabels = ydLuaGetLen(L, -1);
    for (i = 1; i <= numLabels; i++) {
#if YFDEBUG_APPLABEL
        if (lua_gettop(L) != top) {
            g_error("Lua stack-size mismatch processing appable."
                    " Stack initially had %d elements, now has %d;"
                    " last label processed was %d", top, lua_gettop(L), label);
        }
#endif /* if YFDEBUG_APPLABEL */

        /* ensure it is a table */
        if (LUA_TTABLE != lua_rawgeti(L, -1, i)) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "In DPI config file: applabels entry number %d"
                        " is not a valid table (type is %s).",
                        i, lua_typename(L, lua_type(L, -1)));
            return -1;
        }

        /* check for optional "active" setting */
        active = ydLuaGetFieldBoolean(L, "active", 1);
        if (!active) {
            lua_pop(L, 1);
            continue;
        }

        /* get the required "label" field */
        label = ydLuaGetFieldNumber(L, "label", -1);
        if (label <= 0 || label > UINT16_MAX) {
#if YFDEBUG_APPLABEL
            g_warning("In DPI config file: Ignoring invalid label %d", label);
#endif
            lua_pop(L, 1);
            continue;
        }

        /* get and check the required "label_type" field */
        labelTypeString = ydLuaGetFieldString(L, "label_type", "none");
        if (0 == g_strcmp0(labelTypeString, "regex")) {
            labelType = APPLABEL_REGEX;
        } else if (0 == g_strcmp0(labelTypeString, "plugin")) {
            labelType = APPLABEL_PLUGIN;
        } else if (0 == g_strcmp0(labelTypeString, "signature")) {
            labelType = APPLABEL_SIGNATURE;
        } else {
            if (0 != g_strcmp0(labelTypeString, "none")) {
                g_warning("In DPI config file while parsing label %d:"
                          " Unrecognized label_type '%s'; ignoring rule.",
                          label, labelTypeString);
            }
            g_free(labelTypeString);
            labelTypeString = NULL;
            lua_pop(L, 1);
            continue;
        }
        g_free(labelTypeString);
        labelTypeString = NULL;

        /* ensure there is room in the destination array */
        if (APPLABEL_SIGNATURE == labelType) {
            if (MAX_PAYLOAD_RULES == numSigRules) {
                g_warning("In DPI config file while parsing label %d:"
                          " Ignoring rule since maximum number of signature"
                          " rules (%d) has been reached",
                          label, MAX_PAYLOAD_RULES);
                lua_pop(L, 1);
                continue;
            }
        } else {
            if (MAX_PAYLOAD_RULES == numPayloadRules) {
                g_warning("In DPI config file while parsing label %d:"
                          " Ignoring rule since maximum number of application"
                          " labeler rules (%d) has been reached",
                          label, MAX_PAYLOAD_RULES);
                lua_pop(L, 1);
                continue;
            }
        }

        /* get the required "value" field but do not parse it yet */
        value = ydLuaGetFieldString(L, "value", NULL);
        if (NULL == value) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "No value provided for applabel %d rule", label);
            goto parseError;
        }

        /* create scanConf struct for this applabel */
        if (ydHashContains(ctx->dpiActiveHash, label)) {
            g_warning("In DPI config file: Ignoring applabels entry number %d"
                      " which uses the previously seen label or port %d",
                      i, label);
            g_free(value);
            value = NULL;
            lua_pop(L, 1);
            continue;
        }
        scanConf = ydHashFindOrCreate(ctx->dpiActiveHash, label);
        scanConf->applabelType = labelType;

        /* store scanConf in appropriate array */
        if (APPLABEL_SIGNATURE == scanConf->applabelType) {
            sigTable[numSigRules] = scanConf;
            numSigRules++;
        } else {
            ruleTable[numPayloadRules] = scanConf;
            numPayloadRules++;
        }

        /* check for optional "protocol" field; -88 == arbitrary "not set" */
        protocol = ydLuaGetFieldNumber(L, "protocol", -88);
        if (-88 == protocol) {
            /* not present (most likely) */
            protocol = 0;
        } else if (protocol < 0 || protocol > UINT8_MAX) {
            g_debug("In DPI config file for applabel %d rule:"
                    " Ignoring invalid protocol %d",
                    label, protocol);
            protocol = 0;
        } else if (0 != protocol && 6 != protocol && 17 != protocol) {
            g_debug("Setting protocol to %d for applabel %d rule"
                    " despite applabel only being active for"
                    " TCP(6) and UDP(17) flow records",
                    protocol, label);
        }

        /* either parse the value as a regex or load a plugin */
        if (scanConf->applabelType == APPLABEL_REGEX ||
            scanConf->applabelType == APPLABEL_SIGNATURE)
        {
            /* For regex/signature labels, construct and store the regex */
#if YFDEBUG_APPLABEL
            g_debug("applabel rule # %u, regex, label value %d ",
                    numPayloadRules, label);
            g_debug("  regex \"%s\"", value);
#endif
            newRule = ydPcreCompile(value, 0, err);
            if (NULL == newRule) {
                g_prefix_error(err,
                               "In DPI config file while parsing label %d:"
                               " error parsing applabel regex: ",
                               label);
                goto parseError;
            }
            newExtra = pcre_study(newRule, 0, &errorString);

            scanConf->applabelArgs.regexFields.scannerExpression = newRule;
            scanConf->applabelArgs.regexFields.scannerExtra = newExtra;
            scanConf->applabelArgs.regexFields.protocol = protocol;

        } else if (scanConf->applabelType == APPLABEL_PLUGIN) {
            /* For plugin labels, open the library and find the scanPayload
             * func */
#if YFDEBUG_APPLABEL
            g_debug("applabel rule # %u, plugin, label value %d ",
                    numPayloadRules, label);
#endif

            /* Plugin DPI check for a plugin_rules element in the label config
             */
            int numRules = ydParseConfigPluginRegex(scanConf, L, err);
            if (-1 == numRules) {
                goto parseError;
            }
            tempNumRules += numRules;

#ifdef YAF_ENABLE_DPI
            /* Plugin DPI check for a dpi_templates element in the label
             * config */
            int numEnabled = ydParseConfigTemplates(scanConf, L, err);
            if (-1 == numEnabled) {
                goto parseError;
            }
#endif /* ifdef YAF_ENABLE_DPI */

            if (!ydParseConfigLoadPlugin(scanConf, value, ctx->dpiApplabelOnly,
                                         L, dlhash, err))
            {
                goto parseError;
            }
            if (scanConf->applabelType != APPLABEL_PLUGIN) {
                --numPayloadRules;
            }
            scanConf->applabelArgs.regexFields.protocol = protocol;
        }

        /* check for an optional "ports" field specifying additional entries
         * to make into the ctx->dpiActiveHash */
        lua_pushstring(L, "ports");
        ltype = lua_gettable(L, -2);
        switch (ltype) {
          case LUA_TNIL:
            break;
          case LUA_TNUMBER:
            port = lua_tointeger(L, -1);
            if (port <= 0 || port > UINT16_MAX) {
                g_warning("In DPI config file for applabel %d rule:"
                          " Ignoring invalid ports value %d",
                          scanConf->applabel, port);
            } else if (ydHashContains(ctx->dpiActiveHash, port)) {
                g_warning("In DPI config file for applabel %d rule:"
                          " Ignoring ports value %d which is already in use",
                          scanConf->applabel, port);
            } else {
                ydHashInsert(ctx->dpiActiveHash, port, scanConf);
            }
            break;
          case LUA_TTABLE:
            numPorts = ydLuaGetLen(L, -1);
            for (j = 1; j <= numPorts; ++j) {
                if (lua_rawgeti(L, -1, j) != LUA_TNUMBER) {
                    g_warning("In DPI config file while parsing label %d:"
                              " Ignoring ports value that is not a number"
                              " (type is %s)",
                              scanConf->applabel,
                              lua_typename(L, lua_type(L, -1)));
                } else {
                    port = lua_tointeger(L, -1);
                    if (port <= 0 || port > UINT16_MAX) {
                        g_warning("In DPI config file for applabel %d rule:"
                                  " Ignoring invalid ports value %d",
                                  scanConf->applabel, port);
                    } else if (ydHashContains(ctx->dpiActiveHash, port)) {
                        g_warning("In DPI config file for applabel %d rule:"
                                  " Ignoring ports value %d"
                                  " which is already in use",
                                  scanConf->applabel, port);
                    } else {
                        ydHashInsert(ctx->dpiActiveHash, port, scanConf);
                    }
                }
                lua_pop(L, 1);
            }
            break;
          default:
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "In DPI config file for appabel %d rule:"
                        " ports is not a valid table or number (type is %s)",
                        scanConf->applabel, lua_typename(L, ltype));
            break;
        }
        lua_pop(L, 1);

#ifndef YAF_ENABLE_DPI
        scanConf->dpiType = DPI_EMPTY;
#else
        /* Identify the DPI type and store the appropriate data */
        dpiType = ydLuaGetFieldString(L, "dpi_type", "none");
        if (ctx->dpiApplabelOnly) {
            scanConf->dpiType = DPI_EMPTY;
        } else if (APPLABEL_EMPTY == scanConf->applabelType ||
                   APPLABEL_SIGNATURE == scanConf->applabelType)
        {
            scanConf->dpiType = DPI_EMPTY;
        } else if (0 == g_strcmp0(dpiType, "regex")) {
            scanConf->dpiType = DPI_REGEX;
        } else if (0 == g_strcmp0(dpiType, "plugin")) {
            scanConf->dpiType = DPI_PLUGIN;
            if (scanConf->applabelType != APPLABEL_PLUGIN) {
                g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                            "A dpi_type of plugin for a non-plugin label_type"
                            " is currently not supported. Label %d",
                            scanConf->applabel);
                g_free(dpiType);
                goto parseError;
            }
        } else if (0 == g_strcmp0(dpiType, "regex-plugin")) {
            scanConf->dpiType = DPI_MIXED;
            if (scanConf->applabelType != APPLABEL_PLUGIN) {
                g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                            "A dpi_type of regex-plugin for a non-plugin"
                            " label_type is currently not supported."
                            "Label %d", scanConf->applabel);
                g_free(dpiType);
                goto parseError;
            }
        } else if (0 == g_strcmp0(dpiType, "none")) {
            /* Nothing to do for empty DPI*/
            scanConf->dpiType = DPI_EMPTY;
        } else {
            g_warning("In DPI config file while parsing label %d:"
                      " Unrecognized dpi_type '%s'; ignoring dpi",
                      label, dpiType);
            scanConf->dpiType = DPI_EMPTY;
        }
        g_free(dpiType);

        /* Regex or mixed DPI expect a dpi_rules element in the label config */
        if (scanConf->dpiType == DPI_REGEX || scanConf->dpiType == DPI_MIXED) {
            int numRules = ydParseConfigDpiRegex(scanConf, L, err);
            if (-1 == numRules) {
                goto parseError;
            }
            tempNumRules += numRules;
        }

        /* Has to be a separate 'if' clause for mixed types that use both */
        if (scanConf->dpiType == DPI_PLUGIN || scanConf->dpiType == DPI_MIXED) {
            lt_ptr  funcPtr;

            /* Currently plugin DPIs are only allowed with plugin applabels */
            if (scanConf->applabelType != APPLABEL_PLUGIN) {
                g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                            "Cannot use PLUGIN DPI with non-PLUGIN applabel");
                goto parseError;
            }
            /* load the additional 3 functions from the library */
            /* ydpProcessDPI */
            funcPtr = ydScanConfLibrarySymbol(scanConf, "ydpProcessDPI", err);
            if (NULL == funcPtr) {
                goto parseError;
            }
            scanConf->dpiProcessFunc = (ydpProcessDPI_fn)funcPtr;

            /* ydpAddTemplates */
            funcPtr = ydScanConfLibrarySymbol(scanConf, "ydpAddTemplates", err);
            if (NULL == funcPtr) {
                goto parseError;
            }
            scanConf->initTemplateFunc = (ydpAddTemplates_fn)funcPtr;

            /* ydpFreeRec */
            funcPtr = ydScanConfLibrarySymbol(scanConf, "ydpFreeRec", err);
            if (NULL == funcPtr) {
                goto parseError;
            }
            scanConf->freeRecFunc = (ydpFreeRec_fn)funcPtr;
        }
#endif  /* YAF_ENABLE_DPI */

        g_free(labelTypeString);
        g_free(value);
        labelTypeString = value = NULL;
        lua_pop(L, 1);
    }

    return tempNumRules;

  parseError:
    g_free(labelTypeString);
    g_free(value);
    return -1;
}


/**
 * ydParseConfigFile
 *
 * Reads and parses the yafDPIRules file.  Returns TRUE on success.  On error,
 * sets the `err` parameter and returns FALSE.
 *
 * @param ctx          the DPI context
 * @param ruleFileName a filepath for the rule definition file
 * @param err          an error return variable
 *
 */
static gboolean
ydParseConfigFile(
    yfDPIContext_t  *ctx,
    const char      *ruleFileName,
    GError         **err)
{
    lua_State  *L = luaL_newstate();
    const char *varname;
    int         rc;
    int         tmpnum;

    /* Vars for config file values*/
    GHashTable *dlhash;
    int         ltype;
    int         tempNumRules = 0;
    char    *ltdl_lib_path = NULL;

    /* initialize the dynamic loader library */
    rc = lt_dlinit();
    if (0 != rc) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                    "error initializing the dynamic loader library: \"%s\"",
                    lt_dlerror());
        return FALSE;
    }
    /* if LTDL_LIBRARY_PATH is set - add this one first */
    ltdl_lib_path = getenv("LTDL_LIBRARY_PATH");
    if (ltdl_lib_path) {
        lt_dladdsearchdir(ltdl_lib_path);
    }

#ifdef YAF_APPLABEL_PATH
    /* add the applabel path based on libdir at build time */
    lt_dladdsearchdir(YAF_APPLABEL_PATH);
#else
    /* add /usr/local/lib/yaf to path since libtool can never find it */

    lt_dladdsearchdir(YAF_SEARCH_PATH);
    lt_dladdsearchdir(ALT_SEARCH_PATH);
    lt_dladdsearchdir(ALT_SEARCH_PATH64);
#endif /* ifdef YAF_APPLABEL_PATH */

    /* create the hash table for library handle names to library modules */
    dlhash = g_hash_table_new_full(&g_str_hash, &g_str_equal, &g_free, NULL);

    /* Load lua libraries */
    luaopen_base(L);
    luaopen_io(L);
    luaopen_string(L);
    luaopen_math(L);

    /* Push yaf_get_dpi_version into the global environment */
    lua_pushcfunction(L, ydGetDPIVersion);
    lua_setglobal(L, YAF_DPIRULES_VERSION_VARNAME);

    /* Push yaf_get_yaf_version into the global environment */
    lua_pushcfunction(L, ydGetYAFVersion);
    lua_setglobal(L, YAF_VERSION_VARNAME);

    /* Open and run lua conf file */
    if (luaL_loadfile(L, ruleFileName)) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Could not open and parse the DPI config file \"%s\": %s",
                    ruleFileName, lua_tostring(L, -1));
        lua_close(L);
        g_hash_table_destroy(dlhash);
        return FALSE;
    }
    if (lua_pcall(L, 0, 0, 0)) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Could not run the DPI config file \"%s\" as Lua code: %s",
                    ruleFileName, lua_tostring(L, -1));
        lua_close(L);
        g_hash_table_destroy(dlhash);
        return FALSE;
    }

    /* check file version; -99 is an arbitrary value for "not set" */
    varname = "dpirules_version";
    tmpnum = ydLuaGetGlobalNumber(L, varname, -99);
    if (tmpnum != YAF_DPIRULES_VERSION) {
        if (-99 == tmpnum) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "In DPI config file \"%s\": a \"%s\""
                        " variable (an integer) must be defined",
                        ruleFileName, varname);
        } else {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "The DPI config file \"%s\" sets %s to a value"
                        " (%d) that is not supported by yaf-" PACKAGE_VERSION,
                        ruleFileName, varname, tmpnum);
        }
        lua_close(L);
        g_hash_table_destroy(dlhash);
        return FALSE;
    }

#ifdef YAF_ENABLE_DPI
    /* TODO: make arguments to DPI */
    varname = "per_field_limit";
    tmpnum = ydLuaGetGlobalNumber(L, varname, PER_FIELD_LIMIT);
    if (0 >= tmpnum || tmpnum <= UINT16_MAX) {
        ctx->dpi_user_limit = tmpnum;
    } else {
        g_warning("In DPI config file: %s is too large (%d),"
                  " setting to default.", varname, tmpnum);
        ctx->dpi_user_limit = PER_FIELD_LIMIT;
    }

    varname = "per_record_limit";
    tmpnum = ydLuaGetGlobalNumber(L, varname, PER_RECORD_LIMIT);
    if (0 >= tmpnum || tmpnum <= UINT16_MAX) {
        ctx->dpi_total_limit = tmpnum;
    } else {
        g_warning("In DPI config file: %s is too large (%d),"
                  " setting to default.", varname, tmpnum);
        ctx->dpi_total_limit = PER_RECORD_LIMIT;
    }

    /* Get, check and parse the "elements" array */
    varname = "elements";
    ltype = lua_getglobal(L, varname);
    if (LUA_TTABLE == ltype) {
        ydParseConfigElements(L);
    } else if (LUA_TNIL != ltype) {
        g_warning("In DPI config file: %s is not a valid table (type is %s)",
                  varname, lua_typename(L, ltype));
    }
    lua_pop(L, 1);  /* pop the elements table */
#endif  /* YAF_ENABLE_DPI */


    /* Get, check and parse the "applabels" array */
    varname = "applabels";
    ltype = lua_getglobal(L, varname);
    if (LUA_TTABLE != ltype) {
        if (LUA_TNIL == ltype) {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "In DPI config file \"%s\": an \"%s\""
                        " variable (a table) must be defined",
                        ruleFileName, varname);
        } else {
            g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                        "In DPI config file \"%s\": value \"%s\""
                        " is not a valid table (type is %s)",
                        ruleFileName, varname, lua_typename(L, ltype));
        }
        lua_close(L);
        g_hash_table_destroy(dlhash);
        return FALSE;
    }

    tempNumRules = ydParseConfigApplabels(ctx, L, dlhash, err);
    if (-1 == tempNumRules) {
        lua_close(L);
        g_hash_table_destroy(dlhash);
        return FALSE;
    }
    lua_pop(L, 1);

    /*
     * get rid of the module handle lookup hash; this creates a mem leak of
     * the module handles
     */
    g_hash_table_destroy(dlhash);

    g_debug("Application Labeler accepted %d rules.", numPayloadRules);
    g_debug("Application Labeler accepted %d signatures.", numSigRules);
#ifdef YAF_ENABLE_DPI
    if (!ctx->dpiApplabelOnly) {
        g_debug("DPI rule scanner accepted %d rules from the DPI Rule File",
                tempNumRules);
    }
#endif /* ifdef YAF_ENABLE_DPI */

    /* debug */
    lua_close(L);
    return TRUE;
}

/* TODO: Possibly guard 2nd ydScanPayload call on type == PLUGIN*/
/* TODO: Possibly integrate ydRunConfRegex calls next to ydScanPayload calls */
void
ydScanFlow(
    yfFlow_t  *flow)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)(flow->dpictx);
    yfDPIContext_t *ctx = NULL;

    /* Check DPI status and alloc DPI array */
    if (NULL == flowContext || NULL == (ctx = flowContext->yfctx)) {
        return;
    }
    if (!ctx->dpiInitialized) {
        return;
    }

    /* Applabel and plugin DPI in in the forward direction */
    if (!flow->appLabel && flow->val.paylen) {
        flow->appLabel = ydScanPayload(flow->val.payload, flow->val.paylen,
                                       flow, &(flow->val));
    }

#ifdef YAF_ENABLE_DPI
    /* If applabel worked, run plugin DPI in reverse direction */
    if (!ctx->dpiApplabelOnly) {
        uint16_t        tempAppLabel = 0;

        flowContext->captureFwd = flowContext->dpinum;

        if (flowContext->captureFwd > YAF_MAX_CAPTURE_SIDE) {
            /* Max out at 25 per side  - usually won't happen in this case*/
            flowContext->dpinum = YAF_MAX_CAPTURE_SIDE;
            flowContext->captureFwd = YAF_MAX_CAPTURE_SIDE;
        }

        if (flow->appLabel && flow->rval.paylen) {
            /* call to applabel's scan payload */
            tempAppLabel = ydScanPayload(flow->rval.payload, flow->rval.paylen,
                                         flow, &(flow->rval));
        }

        /* If we pick up captures from another appLabel it messes with lists */
        if ((tempAppLabel != flow->appLabel)) {
            flowContext->dpinum = flowContext->captureFwd;
        }
    }
#endif  /* YAF_ENABLE_DPI */

    /* Applabel and plugin DPI in reverse if forward didn't get anything */
    if (!flow->appLabel && flow->rval.paylen) {
        flow->appLabel = ydScanPayload(flow->rval.payload, flow->rval.paylen,
                                       flow, &(flow->rval));
    }

#ifdef YAF_ENABLE_DPI
    /* Run forward and reverse regex DPI */
    if (!ctx->dpiApplabelOnly && flow->appLabel) {
        uint8_t         newDPI;
        payloadScanConf_t *scanConf;

        scanConf = ydHashLookup(ctx->dpiActiveHash, flow->appLabel);

        if (scanConf && scanConf->dpiType == DPI_REGEX) {
            /* Do DPI Processing from Rule Files */
            if (flow->val.paylen) {
                newDPI = ydRunConfRegex(flowContext, flow->val.payload,
                                        flow->val.paylen, 0, flow, &flow->val);
                flowContext->captureFwd += newDPI;
            }
            if (flow->rval.paylen) {
                ydRunConfRegex(flowContext, flow->rval.payload,
                               flow->rval.paylen, 0, flow, &flow->rval);
            }
        }
    }
#endif  /* YAF_ENABLE_DPI */
}

/**
 * ydScanPayload
 *
 * this iterates through all of the defined payload identifiers, as needed,
 * to determine what the payload type is.  It stops on the first match,
 *  so ordering does matter
 *
 * @param payloadData a pointer into the payload body
 * @param payloadSize the size of the payloadData in octects (aka bytes)
 *
 * @return a 16-bit int, usually mapped to a well known port, identifying
 *         the protocol, 0 if no match was found or any type of error occured
 *         during processing
 */
static uint16_t
ydScanPayload(
    const uint8_t  *payloadData,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#define NUM_CAPT_VECTS 18
    unsigned int loop = 0;
    int          rc = 0;
    int          captVects[NUM_CAPT_VECTS];
    payloadScanConf_t *scanConfs[2] = {NULL, NULL};

    /* ydPayloadPrinter(payloadData, payloadSize, 500, "ydScanPayload");*/
    /* first check the signature table to see if any signatures should
     * be executed first  - check both directions and only check once */
    if (numSigRules > 0 && (val == &(flow->val))) {
        for (loop = 0; loop < numSigRules; loop++) {
            rc = pcre_exec(
                sigTable[loop]->applabelArgs.regexFields.scannerExpression,
                sigTable[loop]->applabelArgs.regexFields.scannerExtra,
                (char *)payloadData, payloadSize, 0, 0, captVects,
                NUM_CAPT_VECTS);
            if (rc > 0) {
                /* Found a signature match */
                return sigTable[loop]->applabel;
            }
            if (flow->rval.paylen) {
                rc = pcre_exec(
                    sigTable[loop]->applabelArgs.regexFields.scannerExpression,
                    sigTable[loop]->applabelArgs.regexFields.scannerExtra,
                    (char *)flow->rval.payload, flow->rval.paylen, 0, 0,
                    captVects, NUM_CAPT_VECTS);
                if (rc > 0) {
                    /* Found a signature match on reverse direction */
                    return sigTable[loop]->applabel;
                }
            }
        }
    }

    /* next check for a rule table match based on the srcPort or dstPort of
     * the flow */
    for (loop = 0; loop < 2; ++loop) {
        payloadScanConf_t *scanConf;

        scanConf = ydHashLookup(dpiyfctx->dpiActiveHash,
                                ((0 == loop) ? flow->key.sp : flow->key.dp));
        if (!scanConf) {
            continue;
        }
        scanConfs[loop] = scanConf;

        if (0 != scanConf->applabelArgs.regexFields.protocol &&
            flow->key.proto != scanConf->applabelArgs.regexFields.protocol)
        {
            continue;
        }

        if (APPLABEL_REGEX == scanConf->applabelType) {
            YF_APPLABEL_TIMING_DECL(t0);
            rc = pcre_exec(scanConf->applabelArgs.regexFields.scannerExpression,
                           scanConf->applabelArgs.regexFields.scannerExtra,
                           (char *)payloadData, payloadSize, 0, 0, captVects,
                           NUM_CAPT_VECTS);
            YF_APPLABEL_TIMING_STOP(scanConf, t0);
            if (rc > 0) {
#if YFDEBUG_APPLABEL
                ydPayloadPrinter(payloadData, payloadSize, 20,
                                 "protocol match (%u, %u)",
                                 scanConf->applabel, rc);
#endif
                return scanConf->applabel;
            }
        } else if (APPLABEL_PLUGIN == scanConf->applabelType) {
            /* call the plugin's ydpScanPayload() function */
            YF_APPLABEL_TIMING_DECL(t0);
            rc = scanConf->applabelArgs.pluginArgs.func(
                payloadData, payloadSize, flow, val);
            YF_APPLABEL_TIMING_STOP(scanConf, t0);
            if (rc > 0) {
#if YFDEBUG_APPLABEL
                ydPayloadPrinter(payloadData, payloadSize, 20,
                                 "protocol match (%u, %u)",
                                 scanConf->applabel, rc);
#endif
                if (rc == 1) {
                    return scanConf->applabel;
                } else {
                    return rc;
                }
            }
        }
    }

    /* there is not a match; exhaustively try all the rules in definition
     * order */
    for (loop = 0; loop < numPayloadRules; loop++) {
        if (scanConfs[0] == ruleTable[loop] ||
            scanConfs[1] == ruleTable[loop])
        {
            /* skip; it was previously checked */
            continue;
        }

        if (0 != ruleTable[loop]->applabelArgs.regexFields.protocol &&
            (flow->key.proto !=
                ruleTable[loop]->applabelArgs.regexFields.protocol))
        {
            /* skip; mismatched protocol */
            continue;
        }

        if (APPLABEL_REGEX == ruleTable[loop]->applabelType) {
            YF_APPLABEL_TIMING_DECL(t0);
            rc = pcre_exec(
                ruleTable[loop]->applabelArgs.regexFields.scannerExpression,
                ruleTable[loop]->applabelArgs.regexFields.scannerExtra,
                (char *)payloadData, payloadSize, 0, 0, captVects,
                NUM_CAPT_VECTS);
            YF_APPLABEL_TIMING_STOP(ruleTable[loop], t0);
            if (rc > 0) {
#if YFDEBUG_APPLABEL
                ydPayloadPrinter(payloadData, payloadSize, 20,
                                 "protocol match (%u, %u)",
                                 ruleTable[loop]->applabel, rc);
#endif
                return ruleTable[loop]->applabel;
            }
        } else if (APPLABEL_PLUGIN == ruleTable[loop]->applabelType) {
            /* call the plugin's ydpScanPayload() function */
            YF_APPLABEL_TIMING_DECL(t0);
            rc = ruleTable[loop]->applabelArgs.pluginArgs.func(
                payloadData, payloadSize, flow, val);
            YF_APPLABEL_TIMING_STOP(ruleTable[loop], t0);
            if (rc > 0) {
#if YFDEBUG_APPLABEL
                ydPayloadPrinter(payloadData, payloadSize, 20,
                                 "protocol match (%u, %u)",
                                 ruleTable[loop]->applabel, rc);
#endif
                /* If plugin returns 1 -
                 * return whatever value is in the conf file */
                /* Plugins can identify more than 1 type of protocol */
                if (rc == 1) {
                    return ruleTable[loop]->applabel;
                } else {
                    return rc;
                }
            }
        }
    }

#if YFDEBUG_APPLABEL
    if (NULL != payloadData) {
        ydPayloadPrinter(payloadData, payloadSize, 40,
                         "non-matching payload data is");
    } else {
        g_debug("no payload present\n");
    }
#endif /* if YFDEBUG_APPLABEL */

    return 0;
}


/**
 * ydAllocFlowContext
 *
 * Allocates the context structure for the DPI in a flow.
 *
 *
 * FIXME: This context is used for either applabel or DPI, and when yaftab.c
 * creates a flow template, it checks for the presence of "flow->dpictx".
 * Therefore, when using "yaf --applabel" without --dpi, the flow records get
 * an empty yafDPIList subTemplateLiate.
 *
 */
void
ydAllocFlowContext(
    yfFlow_t  *flow)
{
    if (NULL == dpiyfctx || !dpiyfctx->dpiInitialized) {
        return;
    }

    ypDPIFlowCtx_t *newFlowContext = g_slice_new0(ypDPIFlowCtx_t);
    flow->dpictx = (void *)newFlowContext;
    newFlowContext->yfctx = dpiyfctx;

#ifdef YAF_ENABLE_DPI
    if (!dpiyfctx->dpiApplabelOnly) {
        newFlowContext->dpinum = 0;
        newFlowContext->startOffset = 0;
        newFlowContext->exbuf = NULL;
        /* TODO: Move this to places where it only gets alloc'd when we have
         * dpi */
        newFlowContext->dpi = g_slice_alloc0(YAF_MAX_CAPTURE_FIELDS *
                                             sizeof(yfDPIData_t));
    }
#endif  /* YAF_ENABLE_DPI */
}


/**
 * flowFree
 *
 * @param flow pointer to the flow structure with the context information
 *
 */
void
ydFreeFlowContext(
    yfFlow_t  *flow)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)(flow->dpictx);

    if (NULL == flowContext) {
        return;
    }

#ifdef YAF_ENABLE_DPI
    g_slice_free1((sizeof(yfDPIData_t) * YAF_MAX_CAPTURE_FIELDS),
                  flowContext->dpi);
#endif  /* YAF_ENABLE_DPI */

    g_slice_free(ypDPIFlowCtx_t, flowContext);
}


#ifdef YAF_ENABLE_DPI
/**
 * getDPIInfoModel
 *
 * returns a pointer to the DPI info model, allocates if it doesn't exist
 *
 */
fbInfoModel_t *
ydGetDPIInfoModel(
    void)
{
    static fbInfoModel_t *yaf_dpi_model = NULL;
    if (!yaf_dpi_model) {
        yaf_dpi_model = fbInfoModelAlloc();
        fbInfoModelAddElementArray(yaf_dpi_model,
                                   infomodel_array_static_yaf_dpi);
    }

    return yaf_dpi_model;
}


/**
 * flowWrite
 *
 *  this function gets called when the flow data is getting serialized to be
 *  written into ipfix format.  This function must put its data into the
 *  output STL. This function is responsible for initializing the STL.
 *
 * @param rec
 * @param flow
 * @param err
 *
 * @return FALSE if closing the flow should be delayed, TRUE if the data is
 *         available and the flow can be closed
 *
 */
gboolean
ydWriteDPIList(
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    GError              **err)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)(flow->dpictx);
    yfDPIContext_t *ctx;
    payloadScanConf_t *scanConf;

    if (NULL == flowContext) {
        goto err;
    }

    ctx = flowContext->yfctx;

    if (!ctx->dpiInitialized || ctx->dpiApplabelOnly
        || !flowContext->dpinum || !flow->appLabel)
    {
        goto err;
    }

    /*If there's no reverse payload & No Fwd captures this has to be uniflow*/
    if (!flow->rval.payload && !flowContext->captureFwd) {
        flowContext->startOffset = flowContext->captureFwd;
        flowContext->captureFwd = flowContext->dpinum;
        goto err;
    }

    /* make sure we have data to write */
    if ((flowContext->startOffset >= flowContext->dpinum)) {
        /* won't pass condition to free */
        flowContext->startOffset = flowContext->dpinum + 1;
        goto err;
    }

    /* make sure DPI is turned on for this protocol */
    scanConf = ydHashLookup(ctx->dpiActiveHash, flow->appLabel);
    if (NULL == scanConf || DPI_EMPTY == scanConf->dpiType) {
        goto err;
    }

    switch (scanConf->dpiType) {
      case DPI_REGEX:
        flowContext->rec = ydProcessGenericRegex(flowContext, stl, flow,
                                                 flowContext->captureFwd,
                                                 flowContext->dpinum,
                                                 scanConf->templateID,
                                                 scanConf->template);
        break;
      case DPI_PLUGIN:
        /* call the plugin's ydpProcessDPI() function */
        flowContext->rec = scanConf->dpiProcessFunc(flowContext, stl, flow,
                                                    flowContext->captureFwd,
                                                    flowContext->dpinum);
        if (flowContext->rec == NULL) {
            goto err;
        }
        break;
        /* Check if the new method failed for plugins */
      default:
        goto err;
    }

    /* For UNIFLOW -> we'll only get back to hooks if uniflow is set */
    /* This way we'll use flow->val.payload & offsets will still be correct */
    flowContext->startOffset = flowContext->captureFwd;
    flowContext->captureFwd = flowContext->dpinum;
    return TRUE;

  err:
    /* No DPI or something unexpected, initialize empty list */
    fbSubTemplateListInit(stl, 3, YAF_DPI_EMPTY_TID, dpiEmptyTemplate, 0);
    return TRUE;
}

/**
 * ydLookupNamedBlByName
 *
 * Lookup the named basic list corresponding to a given information element
 * using provided information element.
 *
 * @param ie - fbInfoElement pointer to the IE contained within the requested
 * named basic list
 *
 * @return the fbInfoElement pointer for the named basic list, NULL on failure.
 */
const fbInfoElement_t *
ydLookupNamedBlByName(
    const fbInfoElement_t  *ie)
{
    char           name_buf[1024];
    fbInfoModel_t *model = ydGetDPIInfoModel();
    const fbInfoElement_t *list;

    snprintf(name_buf, sizeof(name_buf), "%s%s", ie->name, NAMED_LIST_SUFFIX);
    list = fbInfoModelGetElementByName(model, name_buf);
    if (list && fbInfoElementGetType(list) == FB_BASIC_LIST) {
        return list;
    }
    return NULL;
}

/**
 * ydLookupNamedBlByID
 *
 * Lookup the named basic list corresponding to a given information element
 * using provided enterprise number and id.
 *
 * @param ent - Enterprise number
 * @param id - Information Element ID
 *
 * @return the fbInfoElement pointer for the named basic list, NULL on failure.
 */
const fbInfoElement_t *
ydLookupNamedBlByID(
    uint32_t   ent,
    uint16_t   id)
{
    const fbInfoElement_t *ie;
    fbInfoModel_t *model = ydGetDPIInfoModel();

    ie = fbInfoModelGetElementByID(model, id, ent);
    if (ie == NULL) {
        return NULL;
    }
    return ydLookupNamedBlByName(ie);
}

/**
 * getTemplate
 *
 * gets the IPFIX data template for the information that will be returned
 *
 * @return a pointer to the fixbuf info element array for the templates
 *
 */
gboolean
ydAddDPITemplatesToSession(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t *mdInfo;
    const fbInfoElement_t *bl_element;
    int            i;
    char           nameBuf[1024];
    payloadScanConf_t *scanConf;
    GHashTableIter iter;
    gpointer       value;
    uint16_t       tid;

    if (NULL == dpiyfctx) {
        return TRUE;
    }

    if (!dpiyfctx->dpiInitialized) {
        return TRUE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_DPI_EMPTY_NAME, YAF_DPI_EMPTY_DESC, 0,
                       FB_TMPL_MD_LEVEL_1);
    if (!ydInitTemplate(&dpiEmptyTemplate, session, yaf_empty_spec,
                        mdInfo, YAF_DPI_EMPTY_TID, 0, err))
    {
        return FALSE;
    }
    if (dpiyfctx->dpiApplabelOnly) {
        return TRUE;
    }

    /* FIXME: Since the same scanConf can be in the hash table keyed by
     * different ports, we could be generating the same templates multiple
     * times.  Consider changing this to use the ruleTable instead. */
    g_hash_table_iter_init(&iter, dpiyfctx->dpiActiveHash);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        scanConf = (payloadScanConf_t *)value;
        if (scanConf->dpiType != DPI_EMPTY) {
            switch (scanConf->dpiType) {
              case DPI_PLUGIN:
                /* call the plugin's ydpAddTemplates() function */
                if (!scanConf->initTemplateFunc(session, err)) {
                    g_prefix_error(err,
                                   "Error adding templates for plugin \"%s\"",
                                   scanConf->name);
                    return FALSE;
                }
                break;
              case DPI_REGEX:
                mdInfo = fbTemplateInfoAlloc();
                snprintf(nameBuf, sizeof(nameBuf), "%s%s",
                         YAF_TEMPLATE_PREFIX, scanConf->name);
                fbTemplateInfoInit(mdInfo, nameBuf, NULL, scanConf->applabel,
                                   FB_TMPL_MD_LEVEL_1);

                /* iterate through all IEs defined in the config file,
                 *  add to metadata */
                for (i = 0; i < scanConf->numRules; i++) {
                    bl_element = ydLookupNamedBlByName(
                        scanConf->regexFields[i].elem);
                    if (bl_element == NULL) {
                        continue;
                    }
                    fbTemplateInfoAddBasicList(
                        mdInfo, bl_element->ent, bl_element->num,
                        scanConf->regexFields[i].elem->ent,
                        scanConf->regexFields[i].elem->num);
                }

                tid = ydInitTemplate(&scanConf->template, session,
                                     scanConf->specs, mdInfo,
                                     scanConf->templateID, 0, err);
                if (!tid) {
                    g_prefix_error(err,
                                   "Error adding templates for plugin \"%s\"",
                                   scanConf->name);
                    return FALSE;
                }
                scanConf->templateID = tid;
                break;
              default:
                break;
            }
        }
    }

    return TRUE;
}
#endif  /* YAF_ENABLE_DPI */


/**
 * dpiInit
 *
 * Initializes the global context, parses the options string and passes the
 * rules file to ypInitializeProtocolRules for reading.
 *
 */
void
ydInitDPI(
    gboolean    dpiEnabled,
    const char *dpiProtos,
    const char *rulesFileName)
{
    GError        *err = NULL;
    gchar **labels;
    long appLabel;
    GHashTableIter iter;
    payloadScanConf_t *scanConf;
    unsigned int i;
    unsigned int count;
    int *activeApplabels;

    if (NULL == rulesFileName) {
        rulesFileName = YAF_CONF_DIR "/yafDPIRules.conf";
    }

    dpiyfctx = g_slice_new0(yfDPIContext_t);

    /* Initialize dpi context */
    dpiyfctx->dpiInitialized = FALSE;
    if (!dpiEnabled) {
        dpiyfctx->dpiApplabelOnly = TRUE;
    }
#ifdef YAF_ENABLE_DPI
    dpiyfctx->dpi_user_limit = PER_FIELD_LIMIT;
    dpiyfctx->dpi_total_limit = PER_RECORD_LIMIT;
#endif  /* YAF_ENABLE_DPI */
    dpiyfctx->dpiActiveHash = g_hash_table_new_full(NULL, NULL, NULL,
                                                    (GDestroyNotify)g_free);

    g_debug("Initializing Applabel/DPI Rules from File %s", rulesFileName);
    if (!ydParseConfigFile(dpiyfctx, rulesFileName, &err)) {
        g_warning("Error setting up Applabel/DPI: %s", err->message);
        g_warning("WARNING: Running without Applabel/DPI support");
        g_clear_error(&err);
        return;
    }

    /* Parse the dpiProtos string */
    if (!dpiEnabled) {
        /* do nothing */
    } else if (!dpiProtos) {
        g_debug("DPI Running for ALL Protocols");
    } else {
        labels = g_strsplit(dpiProtos, ",", -1);
        activeApplabels = g_new(int, strlen(dpiProtos));
        count = 0;
        for (i = 0; labels[i] != NULL; ++i) {
            appLabel = strtol(labels[i], NULL, 10);
            if (appLabel > 0 && appLabel <= UINT16_MAX) {
                scanConf = ydHashLookup(dpiyfctx->dpiActiveHash, appLabel);
                if (!scanConf || scanConf->applabelType == APPLABEL_EMPTY
                    || scanConf->dpiType == DPI_EMPTY)
                {
                    g_debug("No DPI rules defined for label %ld", appLabel);
                } else {
                    activeApplabels[count++] = appLabel;
                }
            }
        }
        g_strfreev(labels);

        /* FIXME: Ensure this works correctly when multiple hash table keys
         * exist for the same scanConf */
        g_hash_table_iter_init(&iter, dpiyfctx->dpiActiveHash);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&scanConf)) {
            for (i = 0; i < count; ++i) {
                if (scanConf->applabel == activeApplabels[i]) {
                    break;
                }
            }
            /* Didn't find applabel in enabled array, disable DPI */
            if (i == count) {
                scanConf->dpiType = DPI_EMPTY;
            }
        }
        g_free(activeApplabels);
        g_debug("DPI Running for %d Protocols", count);
    }

    /* TODO: Bring back in plugin form? */
    /*yfAlignmentCheck1(); */

    dpiyfctx->dpiInitialized = TRUE;
}


#ifdef YAF_ENABLE_DPI
/**
 * ydPluginHasRegex
 *
 * Checks to see if the given elementID matches a rule in the rule set.
 */
static gboolean
ydPluginHasRegex(
    uint16_t            elementID,
    payloadScanConf_t  *scanConf)
{
    int loop;

    for (loop = 0; loop < scanConf->numRules; loop++) {
        if (elementID == scanConf->regexFields[loop].info_element_id) {
            return TRUE;
        }
    }

    return FALSE;
}
#endif  /* YAF_ENABLE_DPI */

/**
 * @brief Find a Regex. Used by plugins.
 *
 * @param g GArray to search
 * @param target The target string to search for
 * @param err GError in case of error. Bad regex or not found
 * @return Stringon success, NULL on failure. Sets GError with more details.
 */
char *
ycFindPluginRegex(
    const GArray   *g,
    const char     *target,
    GError        **err)
{
    for (uint8_t loop = 0; loop < g->len; ++loop) {
        pluginRegex_t *p = &g_array_index(g, pluginRegex_t, loop);
        if (strcmp(p->ruleName, target) == 0) {
            return p->ruleRegex;
        }
    }
    g_set_error(err,  YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                "Required plugin regex fields are missing from config file."
                " Requires plugin rule: %s.",
                target);
    return NULL;
}


/**
 * @brief Find and compile a Regex. Used by plugins.
 *
 * @param g GArray to search
 * @param target The target string to search for
 * @param options options to be used in PCRE compilation
 * @param err GError in case of error. Bad regex or not found
 * @return pcre* on success, NULL on failure. Sets GError with more details.
 */
pcre *
ycFindCompilePluginRegex(
    const GArray   *g,
    const char     *target,
    int             options,
    GError        **err)
{
    const char *regexString = ycFindPluginRegex(g, target, err);
    if (!regexString) {
        return NULL;
    }

    pcre *regex = ydPcreCompile(regexString, options, err);
    if (!regex) {
        g_prefix_error(err, "Error parsing regex for plugin rule %s: ",
                       target);
        return NULL;
    }
    return regex;
}

#ifdef YAF_ENABLE_DPI
/**
 * @brief Enables an Information Element in a spec array
 * requires the spec to be FB_IESPEC_NULL terminated
 *
 * @param spec the spec array holding the IE to enable
 * @param elementName the name of the element to enable
 * @return 1 if element was found and enabled, 0 if element was not found or enabled
 */
int16_t
ycEnableElement(
    fbInfoElementSpec_t  *spec,
    const char           *elementName)
{
    int i = 0;
    while (spec[i].name != NULL) {
        if (strcmp(spec[i].name, elementName) == 0) {
            if (spec[i].flags != 0) {
                spec[i].flags = 0;
                return 1;
            } else {
                return 0;
            }
        }
        i++;
    }
    return 0;
}

/**
 * @brief Enables Information Elements in a spec array
 *
 * @param spec the spec array holding the IEs
 * @param pluginTemplates the array that holds the plugin's DPI template rules pluginTemplate_st
 * @param templateName the name of the DPI template to use
 * @return number of enabled elements
 * warns if templateName is not found in the plugin templatesi.
 */

int16_t
ycEnableElements(
    fbInfoElementSpec_t  *spec,
    const GArray         *pluginTemplates,
    const char           *templateName)
{
    int16_t numEnabled = 0;
    /* find the pluginTemplate that has the same templateName */
    for (guint i = 0; i < pluginTemplates->len; ++i) {
        const pluginTemplate_t *template = &g_array_index(pluginTemplates,
                                                          pluginTemplate_t, i);
        if (strcmp(template->templateName, templateName) == 0) {
            /* enable each element specified by the template elements array */
            for (guint j = 0; j < template->templateElements->len; ++j) {
                const char *elementName = g_array_index(
                    template->templateElements, char *, j);
                numEnabled += ycEnableElement(spec, elementName);
            }
            return numEnabled;
        }
    }
    /* could not find a template in pluginTemplates that matches the
     * templateName. */
    g_warning("Could not find a DPI template in yafDPIRules.conf's"
              " dpi_templates that matches \"%s\"."
              " ignoring template rule", templateName);
    return numEnabled;
}


/**
 *  Stores data in the the flow->dpictx->dpi[] array.
 *
 *  Returns immediately if there is no payloadScanConf_t for `applabel`, if
 *  DPI is not enabled or initialized, if the dpi[] array is at its maximum
 *  length (YAF_MAX_CAPTURE_FIELDS), or if the length of DPI data is at the
 *  dpi_total_limit.
 *
 *  The data to store may be strings found from executing regexes or values
 *  passed directly into this function (in order from most-to-least used):
 *
 *  -- When `expression` is NULL and this function is not being called from a
 *  "regex-plugin" plugin, a new element is added to the dpi[] array with
 *  dpacketID set to `elementID`, dpacketCapt set to `offset`, and
 *  dpacketCaptLen set to `caplen`.
 *
 *  -- If `expression` is non NULL, it is repeatedly matched against the `pkt`
 *  data, starting at `offset`, and considering `caplen` bytes of the `pkt`.
 *  If a match is found, a new element is added to the dpi[] array with
 *  dpacketID set to `elementID`.  If the regex contained capturing parens,
 *  dpacketCapt set to the start of the first capture and dpacketCaptLen to
 *  its length; otherwise dpacketCapt is set to the start of the matching text
 *  and dpacketCaptLen to its length.  Another attempt to match is made
 *  starting from the end of the capture or the end of the complete matched
 *  data, repeating until no match is found or the limits are reached.
 *
 *  -- If `expression` is NULL and this function is being called from a
 *  "regex-plugin" plugin, the function invokes the same helper function
 *  (ydRunConfRegex()) used by a pure "regex" plugin (see ydScanFlow()).
 *
 *  NOTES: The value stored in dpacketCaptLen will be set to `dpi_user_limit`
 *  if an attempt is made to set it to a larger value.  An element will not be
 *  added to the array if adding dpacketCaptLen bytes of data to the total
 *  length (flowContext->dpi_len) would cause it to exceed dpi_total_limit.
 *  This happens silently, but compiling with YFDEBUG_APPLABEL will enable
 *  messages about these conditions at the --debug (--verbose) log level.
 *
 */
void
ydRunPluginRegex(
    yfFlow_t       *flow,
    const uint8_t  *pkt,
    size_t          caplen,
    pcre           *expression,
    uint32_t        offset,
    uint16_t        elementID,
    uint16_t        applabel)
{
    ypDPIFlowCtx_t    *flowContext;
    yfDPIContext_t    *ctx;
    payloadScanConf_t *scanConf;
    unsigned int       captCount;

    if (caplen == 0 && applabel != 53) {
        return;
    }

    flowContext = (ypDPIFlowCtx_t *)(flow->dpictx);
    if (NULL == flowContext) {
        return;
    }

    ctx = flowContext->yfctx;
    if (!ctx->dpiInitialized || ctx->dpiApplabelOnly) {
        return;
    }

    captCount = flowContext->dpinum;
    if ((captCount >= YAF_MAX_CAPTURE_FIELDS) ||
        (flowContext->dpi_len >= ctx->dpi_total_limit))
    {
        return;
    }

    scanConf = ydHashLookup(ctx->dpiActiveHash, applabel);
    if (NULL == scanConf || DPI_EMPTY == scanConf->dpiType) {
        return;
    }

    if (expression) {
        int          vects[NUM_SUBSTRING_VECTS];
        unsigned int captCountCurrent = 0;
        yfDPIData_t *dpi;
        int          rc;

        while (((rc = pcre_exec(expression, NULL, (const char *)pkt, caplen,
                                offset, 0, vects, NUM_SUBSTRING_VECTS)) > 0))
        {
            dpi = &flowContext->dpi[captCount];
            if (rc > 1) {
                offset = vects[3];
                dpi->dpacketCaptLen = vects[3] - vects[2];
                dpi->dpacketCapt = vects[2];
            } else {
                offset = vects[1];
                dpi->dpacketCaptLen = vects[1] - vects[0];
                dpi->dpacketCapt = vects[0];
            }
            if (dpi->dpacketCaptLen > ctx->dpi_user_limit) {
#if YFDEBUG_APPLABEL
                g_debug("Limit reached for DPI regex for appLabel %d, ID %u:"
                        " Truncating item capture length of %u to the max (%u)",
                        applabel, elementID, dpi->dpacketCaptLen,
                        ctx->dpi_user_limit);
#endif /* if YFDEBUG_APPLABEL */
                dpi->dpacketCaptLen = ctx->dpi_user_limit;
            }

            dpi->dpacketID = elementID;
            flowContext->dpi_len += dpi->dpacketCaptLen;
            if (flowContext->dpi_len > ctx->dpi_total_limit) {
                /* if we passed the limit - don't add this one */
#if YFDEBUG_APPLABEL
                g_debug("Limit reached for DPI regex for appLabel %d, ID %u:"
                        " New item's length of %u would cause DPI total"
                        " length (%zu) to exceed the max (%u)",
                        applabel, elementID, dpi->dpacketCaptLen,
                        flowContext->dpi_len - dpi->dpacketCaptLen,
                        ctx->dpi_total_limit);
#endif /* if YFDEBUG_APPLABEL */
                break;
            }
            captCount++;
            captCountCurrent++;
            if ((captCount >= YAF_MAX_CAPTURE_FIELDS) ||
                (captCountCurrent >= YAF_MAX_CAPTURE_SIDE))
            {
#if YFDEBUG_APPLABEL
                if (captCount >= YAF_MAX_CAPTURE_FIELDS) {
                    g_debug("Limit reached for DPI appLabel %d, ID %u:"
                            " Total field capture count is at maximum (%u)",
                            applabel, elementID, captCount);
                } else {
                    g_debug("Limit reached for DPI appLabel %d, ID %u:"
                            " Per-direction capture count is at maximum (%u)",
                            applabel, elementID, captCountCurrent);
                }
#endif  /* YFDEBUG_APPLABEL */
                break;
            }
        }
#if YFDEBUG_APPLABEL
        if (rc != PCRE_ERROR_NOMATCH && rc < 0) {
            g_debug("Issue with DPI regex for appLabel %d, ID %u:"
                    " Regex matching returned unexpected error code %d"
                    " at payload byte offset %u",
                    applabel, elementID, rc, offset);
        }
#endif  /* YFDEBUG_APPLABEL */

    } else if (scanConf->numRules && ydPluginHasRegex(elementID, scanConf)) {
        /* there are regexs in yafDPIRules.conf */
        flow->appLabel = applabel;
        captCount += ydRunConfRegex(flowContext, pkt, caplen, offset, flow,
                                    NULL);
    } else {
        if (caplen > ctx->dpi_user_limit) {
#if YFDEBUG_APPLABEL
            g_debug("Limit reached for DPI appLabel %d, ID %u:"
                    " Truncating item capture length of %zu to the max (%u)",
                    applabel, elementID, caplen, ctx->dpi_user_limit);
#endif
            caplen = ctx->dpi_user_limit;
        }
        flowContext->dpi[captCount].dpacketCaptLen = caplen;
        flowContext->dpi[captCount].dpacketID = elementID;
        flowContext->dpi[captCount].dpacketCapt = offset;
        flowContext->dpi_len += caplen;
        if (flowContext->dpi_len > ctx->dpi_total_limit) {
            /* if we passed the limit - don't add this one */
#if YFDEBUG_APPLABEL
            g_debug("Limit reached for DPI appLabel %d, ID %u:"
                    " New item's length of %zu would cause DPI total"
                    " length (%zu) to exceed the max (%u)",
                    applabel, elementID, caplen, flowContext->dpi_len - caplen,
                    ctx->dpi_total_limit);
#endif /* if YFDEBUG_APPLABEL */
            return;
        }
        captCount++;
    }

    flowContext->dpinum = captCount;
}



/**
 * ypFreeLists
 *
 */
void
ydFreeDPILists(
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow)
{
    ypDPIFlowCtx_t    *flowContext = (ypDPIFlowCtx_t *)(flow->dpictx);
    yfDPIContext_t    *ctx = NULL;
    payloadScanConf_t *scanConf;
    int                loop;
    fbBasicList_t     *temp;

    if (NULL == flowContext) {
        goto err;
    }

    ctx = flowContext->yfctx;

    if (!ctx->dpiInitialized || ctx->dpiApplabelOnly
        || !flowContext->dpinum || !flow->appLabel)
    {
        goto err;
    }

    scanConf = ydHashLookup(ctx->dpiActiveHash, flow->appLabel);
    if (NULL == scanConf || DPI_EMPTY == scanConf->dpiType) {
        goto err;
    }

    if (!flowContext->startOffset && !flow->rval.payload) {
        /* Uniflow case: captures must be in rev payload but
         * we don't have it now */
        /* Biflow case: startOffset is 0 and fwdcap is 0, we did get something
         * and its in the rev payload */
        goto err;
    }

    if (flowContext->startOffset <= flowContext->dpinum) {
        switch (scanConf->dpiType) {
          case DPI_REGEX:
            temp = (fbBasicList_t *)flowContext->rec;
            for (loop = 0; loop < scanConf->numRules; loop++) {
                fbBasicListClear(temp);
                temp++;
            }
            break;
          case DPI_PLUGIN:
            /* call the plugin's ydpFreeRec() function */
            scanConf->freeRecFunc(flowContext);
            break;
          default:
            goto err;
        }

        fbSubTemplateListClear(stl);

        if (flowContext->exbuf) {
            g_slice_free1(ctx->dpi_total_limit, flowContext->exbuf);
        }
    }
  err:
    /* No DPI or something unexpected, free empty list */
    fbSubTemplateListClear(stl);
}


static uint8_t
ydRunConfRegex(
    ypDPIFlowCtx_t  *flowContext,
    const uint8_t   *payloadData,
    unsigned int     payloadSize,
    uint32_t         offset,
    yfFlow_t        *flow,
    yfFlowVal_t     *val)
{
    int         rc = 0;
    int         loop;
    int         subVects[NUM_SUBSTRING_VECTS];
    int         offsetptr;
    uint8_t     captCount = flowContext->dpinum;
    uint8_t     captDirection = 0;
    yfDPIData_t *dpi;
    const pcre        *ruleHolder;
    const pcre_extra  *extraHolder;
    payloadScanConf_t *scanConf;
    yfDPIContext_t    *ctx = flowContext->yfctx;

    if ((captCount >= YAF_MAX_CAPTURE_FIELDS) ||
        (flowContext->dpi_len >= ctx->dpi_total_limit))
    {
        return 0;
    }

    scanConf = ydHashLookup(ctx->dpiActiveHash, flow->appLabel);
    if (NULL == scanConf || DPI_EMPTY == scanConf->dpiType) {
        return 0;
    }

    for (loop = 0; loop < scanConf->numRules; loop++) {
        ruleHolder = scanConf->regexFields[loop].rule;
        extraHolder = scanConf->regexFields[loop].extra;
        offsetptr = offset;
        while (((rc = pcre_exec(ruleHolder, extraHolder,
                                (char *)payloadData, payloadSize, offsetptr,
                                0, subVects, NUM_SUBSTRING_VECTS)) > 0))
        {
            dpi = &flowContext->dpi[captCount];
            dpi->dpacketID = scanConf->regexFields[loop].info_element_id;
            /* Get only matched substring - don't need Labels */
            if (rc > 1) {
                offsetptr = subVects[3];
                dpi->dpacketCaptLen = subVects[3] - subVects[2];
                dpi->dpacketCapt = subVects[2];
            } else {
                offsetptr = subVects[1];
                dpi->dpacketCaptLen = subVects[1] - subVects[0];
                dpi->dpacketCapt = subVects[0];
            }
            if (0 == dpi->dpacketCaptLen) {
                /* if capture length is zero, try the next rule */
#if YFDEBUG_APPLABEL
                g_debug("Issue with DPI Rule #%d for appLabel %d, IE %d:"
                        " Capture length is 0 bytes",
                        loop + 1, flow->appLabel, dpi->dpacketID);
#endif
                break;
            }

            /* truncate capture length to capture limit */
            if (dpi->dpacketCaptLen > ctx->dpi_user_limit) {
#if YFDEBUG_APPLABEL
                g_debug("Limit reached for DPI Rule #%d for appLabel %d, IE %d:"
                        " Truncating item capture length of %u to the max (%u)",
                        loop + 1, flow->appLabel, dpi->dpacketID,
                        dpi->dpacketCaptLen, ctx->dpi_user_limit);
#endif /* if YFDEBUG_APPLABEL */
                dpi->dpacketCaptLen = ctx->dpi_user_limit;
            }
            flowContext->dpi_len += dpi->dpacketCaptLen;
            if (flowContext->dpi_len > ctx->dpi_total_limit) {
                /* buffer full */
#if YFDEBUG_APPLABEL
                g_debug("Limit reached for DPI Rule #%d for appLabel %d, IE %d:"
                        " New item's length of %u would cause DPI total"
                        " length (%zu) to exceed the max (%u)",
                        loop + 1, flow->appLabel, dpi->dpacketID,
                        dpi->dpacketCaptLen,
                        flowContext->dpi_len - dpi->dpacketCaptLen,
                        ctx->dpi_total_limit);
#endif /* if YFDEBUG_APPLABEL */
                goto END;
            }
            captCount++;
            captDirection++;
            if ((captCount >= YAF_MAX_CAPTURE_FIELDS) ||
                (captDirection >= YAF_MAX_CAPTURE_SIDE))
            {
#if YFDEBUG_APPLABEL
                if (captCount >= YAF_MAX_CAPTURE_FIELDS) {
                    g_debug("Limit reached for DPI appLabel %d, IE %u:"
                            " Total field capture count is at maximum (%u)",
                            flow->appLabel, dpi->dpacketID, captCount);
                } else {
                    g_debug("Limit reached for DPI appLabel %d, IE %u:"
                            " Per-direction capture count is at maximum (%u)",
                            flow->appLabel, dpi->dpacketID, captDirection);
                }
#endif  /* YFDEBUG_APPLABEL */
                goto END;
            }
        }
        if (rc != PCRE_ERROR_NOMATCH && rc < 0) {
            g_debug("Issue with DPI Rule #%d for appLabel %d, IE %d:"
                    " Regex matching returned unexpected error code %d",
                    loop + 1, flow->appLabel,
                    scanConf->regexFields[loop].info_element_id, rc);
        }
    }

  END:
    flowContext->dpinum = captCount;
    return captDirection;
}


uint16_t
ydInitTemplate(
    fbTemplate_t              **newTemplate,
    fbSession_t                *session,
    const fbInfoElementSpec_t  *spec,
    fbTemplateInfo_t           *mdInfo,
    uint16_t                    tid,
    uint32_t                    flags,
    GError                    **err)
{
    fbInfoModel_t *model = ydGetDPIInfoModel();
    fbTemplate_t  *intTmpl  = NULL;
    fbTemplate_t  *extTmpl  = NULL;
    uint16_t       id;

    intTmpl = fbTemplateAlloc(model);
    extTmpl = fbTemplateAlloc(model);

    if (spec) {
        if (!fbTemplateAppendSpecArray(intTmpl, spec, 0xffffffff, err)) {
            g_prefix_error(err, ("Error creating internal template %#06x(%u)"
                                 " from spec array"),
                           tid, tid);
            goto ERROR;
        }
        if (!fbTemplateAppendSpecArray(extTmpl, spec, flags, err)) {
            g_prefix_error(err, ("Error creating external template %#06x(%u)"
                                 " from spec array with flags=%u"),
                           tid, tid, flags);
            goto ERROR;
        }
    }

#ifndef YAF_ENABLE_METADATA_EXPORT
    fbTemplateInfoFree(mdInfo);
    mdInfo = NULL;
#endif

    id = fbSessionAddTemplate(session, TRUE, tid, intTmpl, mdInfo, err);
    if (!id) {
        g_prefix_error(err, "Error adding internal template %#06x", tid);
        goto ERROR;
    }
    if (!fbSessionAddTemplate(session, FALSE, id, extTmpl, mdInfo, err)) {
        g_prefix_error(err, "Error adding external template %#06x", tid);
        goto ERROR;
    }

    *newTemplate = intTmpl;
    return id;

  ERROR:
    fbTemplateFreeUnused(extTmpl);
    fbTemplateFreeUnused(intTmpl);
    return 0;
}


static void *
ydProcessGenericRegex(
    ypDPIFlowCtx_t       *flowContext,
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    uint8_t               fwdcap,
    uint8_t               totalcap,
    uint16_t              stlTID,
    fbTemplate_t         *stlTemplate)
{
    yfDPIData_t    *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    void           *rec = NULL;
    uint8_t         start = flowContext->startOffset;
    int             total = 0;
    fbVarfield_t   *varField = NULL;
    uint16_t        temp_element;
    uint8_t         totalIndex[YAF_MAX_CAPTURE_FIELDS];
    int             loop, oloop;
    fbBasicList_t  *blist;
    yfFlowVal_t    *flowVal;
    payloadScanConf_t *scanConf;

    /* should always succeed; was tested in caller */
    scanConf = ydHashLookup(ctx->dpiActiveHash, flow->appLabel);

    rec = fbSubTemplateListInit(stl, 3, stlTID, stlTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    /**
     *  Init basic lists for each element defined in
     *  scanConf->regexFields[*].elem
     */
    for (loop = 0, blist = rec; loop < scanConf->numRules; loop++, blist++) {
        fbBasicListInit(blist, 3, scanConf->regexFields[loop].elem, 0);
    }

    for (oloop = 0; oloop < scanConf->numRules; oloop++) {
        temp_element = scanConf->regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            blist = (fbBasicList_t *)((uint8_t *)rec +
                                      scanConf->regexFields[oloop].BLoffset);
            varField = (fbVarfield_t *)fbBasicListInit(
                blist, 3, scanConf->regexFields[oloop].elem, total);

            if (!varField) {
                total = 0;
                varField = NULL;
                continue;
            }

            /* fill the basic lists */
            for (loop = 0; loop < total; loop++) {
                flowVal = (totalIndex[loop] < fwdcap) ? &flow->val :
                    &flow->rval;
                if (dpi[totalIndex[loop]].dpacketCapt +
                    dpi[totalIndex[loop]].dpacketCaptLen
                    > flowVal->paylen)
                {
                    continue;
                }
                if (flowVal->payload) {
                    varField->buf = flowVal->payload +
                        dpi[totalIndex[loop]].dpacketCapt;
                    varField->len = dpi[totalIndex[loop]].dpacketCaptLen;
                }
                if (loop + 1 < total) {
                    varField++;
                }
            }
            total = 0;
            varField = NULL;
        }
    }

    return (void *)rec;
}

void *
ydProcessGenericPlugin(
    ypDPIFlowCtx_t       *flowContext,
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    uint8_t               fwdcap,
    uint8_t               totalcap,
    uint16_t              stlTID,
    const fbTemplate_t   *stlTemplate,
    const char           *blIEName)
{
    yfDPIData_t   *dpi   = flowContext->dpi;
    fbVarfield_t  *varField;
    void          *rec   = NULL;
    fbInfoModel_t *model = ydGetDPIInfoModel();
    int            count = flowContext->startOffset;

    rec = fbSubTemplateListInit(stl, 3, stlTID, stlTemplate, 1);

    varField = (fbVarfield_t *)fbBasicListInit(
        rec, 3, fbInfoModelGetElementByName(model, blIEName), totalcap);

    while (count < fwdcap && varField) {
        varField->buf = flow->val.payload + dpi[count].dpacketCapt;
        varField->len = dpi[count].dpacketCaptLen;
        varField = fbBasicListGetNextPtr(rec, varField);
        count++;
    }

    if (fwdcap < totalcap && flow->rval.payload) {
        while (count < totalcap && varField) {
            varField->buf = flow->rval.payload + dpi[count].dpacketCapt;
            varField->len = dpi[count].dpacketCaptLen;
            varField = fbBasicListGetNextPtr(rec, varField);
            count++;
        }
    }

    return (void *)rec;
}

#endif  /* YAF_ENABLE_DPI */


/*
 *  Evaluates to `c` if it is a printable ASCII character and not a control
 *  char; otherwise `.`.
 */
#define YF_TO_ASCII(c)                                                  \
    ((g_ascii_isprint(c) && !g_ascii_iscntrl(c)) ? (char)(c) : '.')

void
ydHexdumpPayload(
    const yfFlow_t *flow,
    int             maxBytes,
    const char     *title)
{
    GString *str = g_string_sized_new(0x4000);
    unsigned int len;
    unsigned int offset;
    const yfFlowVal_t *val;
    int i;

    if (title) {
        g_string_append(str, title);
    }
    if (0 == maxBytes) {
        return;
    }

    for (i = 0; i < 2; ++i) {
        val = ((0 == i) ? &flow->val : &flow->rval);
        if (!val->payload || !val->paylen) {
            continue;
        }
        len = (((maxBytes < 0) || (val->paylen <= (unsigned int)maxBytes))
               ? val->paylen
               : (unsigned int)maxBytes);
        if ('\n' != str->str[str->len]) {
            g_string_append_c(str, '\n');
        }
        offset = 0;
        for (offset = 0; len - offset >= 16; offset += 16) {
            g_string_append_printf(str, "%08x"
                                   "  %02x %02x %02x %02x %02x %02x %02x %02x"
                                   "  %02x %02x %02x %02x %02x %02x %02x %02x"
                                   "  %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
                                   offset,
                                   (uint8_t)val->payload[offset + 0x0],
                                   (uint8_t)val->payload[offset + 0x1],
                                   (uint8_t)val->payload[offset + 0x2],
                                   (uint8_t)val->payload[offset + 0x3],
                                   (uint8_t)val->payload[offset + 0x4],
                                   (uint8_t)val->payload[offset + 0x5],
                                   (uint8_t)val->payload[offset + 0x6],
                                   (uint8_t)val->payload[offset + 0x7],
                                   (uint8_t)val->payload[offset + 0x8],
                                   (uint8_t)val->payload[offset + 0x9],
                                   (uint8_t)val->payload[offset + 0xa],
                                   (uint8_t)val->payload[offset + 0xb],
                                   (uint8_t)val->payload[offset + 0xc],
                                   (uint8_t)val->payload[offset + 0xd],
                                   (uint8_t)val->payload[offset + 0xe],
                                   (uint8_t)val->payload[offset + 0xf],
                                   YF_TO_ASCII(val->payload[offset + 0x0]),
                                   YF_TO_ASCII(val->payload[offset + 0x1]),
                                   YF_TO_ASCII(val->payload[offset + 0x2]),
                                   YF_TO_ASCII(val->payload[offset + 0x3]),
                                   YF_TO_ASCII(val->payload[offset + 0x4]),
                                   YF_TO_ASCII(val->payload[offset + 0x5]),
                                   YF_TO_ASCII(val->payload[offset + 0x6]),
                                   YF_TO_ASCII(val->payload[offset + 0x7]),
                                   YF_TO_ASCII(val->payload[offset + 0x8]),
                                   YF_TO_ASCII(val->payload[offset + 0x9]),
                                   YF_TO_ASCII(val->payload[offset + 0xa]),
                                   YF_TO_ASCII(val->payload[offset + 0xb]),
                                   YF_TO_ASCII(val->payload[offset + 0xc]),
                                   YF_TO_ASCII(val->payload[offset + 0xd]),
                                   YF_TO_ASCII(val->payload[offset + 0xe]),
                                   YF_TO_ASCII(val->payload[offset + 0xf]));
        }
        if (offset < len) {
            size_t j;
            g_string_append_printf(str, "%08x", offset);
            for (j = offset; j < len; ++j) {
                /* extra space before 0th and 8th value in row */
                g_string_append_printf(str, "%s%02x",
                                       ((j & 0x7) == 0) ? "  " : " ",
                                       val->payload[j]);
            }
            g_string_append_printf(str, "%*s",
                                   (int)((3 * (offset + 16 - j)) +
                                         (((j - offset) <= 8) ? 1 : 0) + 2),
                                   "");
            for (j = offset; j < len; ++j) {
                g_string_append_c(str, YF_TO_ASCII(val->payload[j]));
            }
            g_string_append_c(str, '\n');
        }
        g_string_append_printf(str, "%08x", len);
    }
    if (str->len) {
        g_debug("%s", str->str);
    }
    g_string_free(str, TRUE);
}

#if YFDEBUG_APPLABEL
/**
 * ydPayloadPrinter
 *
 * this is used for debug purposes to print out the start of the payload data,
 * useful in checking if the app labeler is getting anything correct when
 * adding
 * new protocols
 *
 * @param payloadData a pointer to the payload array
 * @param payloadSize the size of the payloadData array
 * @param numPrint amount of the payload data to print
 * @param prefixString string to add to the front of the payload dump
 *
 */
static void
ydPayloadPrinter(
    const uint8_t *payloadData,
    unsigned int   payloadSize,
    unsigned int   numPrint,
    const char    *format,
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
        if (numPrint > payloadSize) {
            numPrint = payloadSize;
        }
        if (numPrint > PAYLOAD_PRINTER_ARRAY_LENGTH) {
            numPrint = PAYLOAD_PRINTER_ARRAY_LENGTH;
        }
    }
    for (loop = 0; loop < numPrint; ++loop) {
        dumpArray[loop] = YF_TO_ASCII(*(payloadData + loop));
    }
    dumpArray[loop] = '\0';

    g_debug("%s: \"%s\"", prefixString, dumpArray);
}
#endif /* if YFDEBUG_APPLABEL */


pcre *
ydPcreCompile(
    const char  *regex,
    int          options,
    GError     **err)
{
    const char *errorString;
    int         errorOffset;
    pcre       *compiled;

    compiled = pcre_compile(regex, options, &errorString, &errorOffset, NULL);
    if (NULL == compiled) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                    "%s\n\tregex: %s\n\terror: %*s",
                    errorString, regex, errorOffset, "^");
    }
    return compiled;
}


void
ydPrintApplabelTiming(
    void)
{
#if YF_APPLABEL_TIMING
    unsigned int loop;

    if (0 == numPayloadRules) {
        return;
    }

    g_debug("Applabel Timing");
    g_debug("  %-5s, %10s, %12s, %15s",
            "Proto", "TestCount", "TotalSeconds", "Microsec/Test");
    for (loop = 0; loop < numPayloadRules; ++loop) {
        if (APPLABEL_EMPTY != ruleTable[loop]->applabelType
            && ruleTable[loop]->timing != 0)
        {
            double seconds =
                (double)ruleTable[loop]->timing / (double)CLOCKS_PER_SEC;
            g_debug("  %5u, %10" PRIu64 ", %12.6f, %15.9f",
                    ruleTable[loop]->applabel, ruleTable[loop]->count,
                    seconds, seconds * 1000000.0 / ruleTable[loop]->count);
        }
    }
#endif  /* YF_APPLABEL_TIMING */
}
#endif /* ifdef YAF_ENABLE_APPLABEL */
