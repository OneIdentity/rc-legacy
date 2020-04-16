/* GDM - The Gnome Display Manager
 * Copyright (C) 1998, 1999, 2000 Martin K. Petersen <mkp@mkp.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <dlfcn.h>
#include <syslog.h>

#include <security/pam_appl.h>
#include "gdm.h"
#include "vicious.h"

#include "gdm_prompt_plugin.h"

/** The configuration entry for specifying the location of the prompt plugin */
#define GDM_KEY_PROMPT_MODULE "greeter/PromptPlugin="

#define SYM_PROMPT_MODULE_START "gdm_prompt_plugin_start"
#define SYM_PROMPT_MODULE_STOP "gdm_prompt_plugin_stop"

/** The singleton instance of the PAM prompt plugin */
static gdm_prompt_plugin_t *G_plugin = NULL;

/** Load and start a prompt plugin */
static int gdm_prompt_plugin_start(int prompt_type)
{
    VeConfig *config = NULL;
    const char *lib = NULL;
    void *handle = NULL;
    int rval = 0;

    /* Check if plugin is already running */
    if (G_plugin != NULL)
    {
        syslog(LOG_DEBUG, 
               "[%s] PAM prompt plugin is already running", 
               __FILE__);
        goto FINISH;       
    }

    /* Get the prompt plugin from the configuration */
    config = ve_config_get (GDM_CONFIG_FILE);
    lib = ve_config_get_string(config, GDM_KEY_PROMPT_MODULE);
    if (lib == NULL || strcmp(lib, "") == 0)
    {
        syslog(LOG_DEBUG, "[%s] no PAM prompt plugin defined", __FILE__);
        rval = 1;
        goto FINISH;
    }

    /* Load the library */
    dlerror();
    if ((handle = dlopen(lib, RTLD_NOW)) == NULL)
    {
        syslog(LOG_DEBUG, 
               "[%s] failed to load PAM prompt plugin '%s': %s",
               __FILE__, lib, dlerror());
        rval = 1;
        goto FINISH;
    }
    syslog(LOG_DEBUG, "[%s] loaded PAM prompt plugin '%s'", __FILE__, lib);

    if ((G_plugin = calloc(1, sizeof(*G_plugin))) == NULL)
    {
        syslog(LOG_DEBUG, "[%s] memory allocation failure", __FILE__);
        rval = 1;
        goto FINISH;
    }
    
    /* Get the function for fetching the function list from the loaded plugin */
    if ((G_plugin->start = dlsym(handle, SYM_PROMPT_MODULE_START)) == NULL)
    {
        syslog(LOG_DEBUG, 
               "[%s] PAM prompt plugin is missing symbol '%s'",
               __FILE__,
               SYM_PROMPT_MODULE_START);
        rval = 1;
        goto FINISH;
    }
    if ((G_plugin->stop = dlsym(handle, SYM_PROMPT_MODULE_STOP)) == NULL)
    {
        syslog(LOG_DEBUG, 
               "[%s] PAM prompt plugin is missing symbol '%s'",
               __FILE__,
               SYM_PROMPT_MODULE_STOP);
        rval = 1;
        goto FINISH;
    }

    /* Now start the PAM prompt plugin */
    rval = G_plugin->start(G_plugin, prompt_type);

FINISH:
    /* Cleanup on error */
    if (rval != 0 && G_plugin != NULL)
    {
        if (G_plugin->stop != NULL)
        {
            G_plugin->stop(G_plugin);
        }
        g_free(G_plugin);
        G_plugin = NULL;
    }

    return rval;
}

/** Stop a PAM prompt plugin */
static int gdm_prompt_plugin_stop(void)
{
    int rval = 0;

    if (G_plugin != NULL)
    {
       syslog(LOG_DEBUG, "[%s] stopping PAM prompt plugin", __FILE__);
       rval = G_plugin->stop(G_plugin);
       g_free(G_plugin);
       G_plugin = NULL;
    }

    return rval;
}

/** Handle a PAM prompt plugin */
int gdm_prompt_plugin_handle(const char *prompt_type)
{
    int rval = 0;

    if (prompt_type == NULL || strcmp(prompt_type, "") == 0)
    {
        rval = gdm_prompt_plugin_stop();
    }
    else if (strcmp(prompt_type, "PAM_PROMPT_ECHO_ON") == 0)
    {
        rval = gdm_prompt_plugin_start(PAM_PROMPT_ECHO_ON);
    }
    else if (strcmp(prompt_type, "PAM_PROMPT_ECHO_OFF") == 0)
    {
        rval = gdm_prompt_plugin_start(PAM_PROMPT_ECHO_OFF);
    }
    else
    {
        syslog(LOG_DEBUG, 
               "[%s] unknown prompt type: '%s'", 
               __FILE__, prompt_type);
    }

    return rval;
}
