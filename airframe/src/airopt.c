/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  airopt.c
 *  Airframe options interface
 *
 *  ------------------------------------------------------------------------
 *  Authors: Tony Cebzanov
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

#define _AIRFRAME_SOURCE_
#include <airframe/airopt.h>
#include <glib/gprintf.h>

struct _AirOptionCtx {
    GOptionContext  *octx;
    int             *argc;
    char          ***argv;
};

void
air_opterr(
    const char  *fmt,
    ...)
{
    va_list ap;

    fprintf(stderr, "Command-line argument error: \n");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\nUse --help for usage.\n");

    exit(1);
}


AirOptionCtx *
air_option_context_new(
    const char      *helpstr,
    int             *argc,
    char          ***argv,
    AirOptionEntry  *entries)
{
    AirOptionCtx   *aoctx;
    GOptionContext *octx = NULL;

    aoctx = g_new0(AirOptionCtx, 1);
    octx = g_option_context_new(helpstr);
    if (entries) {
        g_option_context_add_main_entries(octx, entries, NULL);
    }

    aoctx->argc = argc;
    aoctx->argv = argv;
    aoctx->octx = octx;

    return aoctx;
}


gboolean
air_option_context_add_group(
    AirOptionCtx    *aoctx,
    const char      *shortname,
    const char      *longname,
    const char      *description,
    AirOptionEntry  *entries)
{
    g_assert(aoctx != NULL);
    g_assert(aoctx->octx != NULL);

    {
        GOptionGroup *ogroup;

        /* create an option group */
        ogroup = g_option_group_new(shortname, longname,
                                    description, NULL, NULL);
        g_option_group_add_entries(ogroup, entries);
        g_option_context_add_group(aoctx->octx, ogroup);

        return TRUE;
    }

    return FALSE;
}


void
air_option_context_parse(
    AirOptionCtx  *aoctx)
{
    GError *oerr = NULL;

    g_option_context_parse(aoctx->octx, aoctx->argc, aoctx->argv, &oerr);
    if (oerr) {
        air_opterr("%s", oerr->message);
    }
}


void
air_option_context_set_help_enabled(
    AirOptionCtx  *aoctx)
{
    g_assert(aoctx != NULL);
    g_assert(aoctx->octx != NULL);
    g_option_context_set_help_enabled(aoctx->octx, TRUE);
}


void
air_option_context_usage(
    AirOptionCtx  *aoctx)
{
    g_assert(aoctx != NULL);
    g_assert(aoctx->octx != NULL);

    g_fprintf(stderr, "%s",
              g_option_context_get_help(aoctx->octx, FALSE, NULL));
}


void
air_option_context_free(
    AirOptionCtx  *aoctx)
{
    g_option_context_free(aoctx->octx);
    g_free(aoctx);
}
