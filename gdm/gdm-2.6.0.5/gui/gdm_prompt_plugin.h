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

#ifndef __GDM_PROMPT_PLUGIN
#define __GDM_PROMPT_PLUGIN

typedef struct gdm_prompt_plugin gdm_prompt_plugin_t;

struct gdm_prompt_plugin {
  /* Function for starting the plugin */
  int (*start)(gdm_prompt_plugin_t *plugin, int prompt_type);
  /* Function for stopping the plugin */
  int (*stop)(gdm_prompt_plugin_t *plugin);
  /* Space for storing data required by the plugin */
  void *data;
} gdm_prompt_plugin;

/* Handle a PAM prompt via a plugin.
 *
 * Loads a plugin for PAM prompts, then asks the plugin to handle the
 * specified prompt.
 *
 * The PAM prompt plugin is configured in the [greeter] section of the GDM
 * configuration file, using the key "PromptPlugin". For example:
 *
 *   [greeter]
 *   PromptPlugin=/usr/local/lib/libgdm_prompt_plugin_pkcs11.so
 *
 * If a value is not found for the PromptPlugin key, then no action is
 * performed.
 *
 * The prompt is represented as a string with the following values:
 *
 *  o "PAM_PROMPT_ECHO_ON" - start handling a PAM_PROMPT_ECHO_ON request
 *  o "PAM_PROMPT_ECHO_OFF" - start handling a PAM_PROMPT_ECHO_OFF request
 *  o NULL or "" - stop handling the current request
 *
 * Note that the gdm_prompt_plugin_handle() function will convert the string
 * to the required PAM constant before invoking the plugin's internal
 * functions.
 *
 * Typically the function is called with a PAM conversation function as
 * follows:
 *
 *   switch (message->msg_style) {
 *   case PAM_PROMPT_ECHO_ON:
 *      gdm_slave_greeter_ctl_no_ret(GDM_PROMPT_PLUGIN, "PAM_PROMPT_ECHO_ON");
 *      s = gdm_slave_greeter_ctl(GDM_PROMPT, message->msg);
 *      gdm_slave_greeter_ctl_no_ret(GDM_PROMPT_PLUGIN, NULL);
 *      break;
 *   case PAM_PROMPT_ECHO_OFF:
 *      gdm_slave_greeter_ctl_no_ret(GDM_PROMPT_PLUGIN, "PAM_PROMPT_ECHO_OFF");
 *      s = gdm_slave_greeter_ctl(GDM_NOECHO, message->msg);
 *      gdm_slave_greeter_ctl_no_ret(GDM_PROMPT_PLUGIN, NULL);
 *      break;
 *
 * The PAM prompt request is sent to the greeter process via the 
 * GDM_PROMPT_PLUGIN command, and the plugin is loaded and executed within
 * the greeter process. The plugin must send its response to the request to 
 * stdout, terminated by the special character STX (0x02) and a new line.
 *
 * The implementation of a PAM prompt plugin must include two functions:
 *
 *   int gdm_prompt_plugin_start(gdm_prompt_plugin_t *plugin, 
 *                               int prompt_type);
 *
 *   int gdm_prompt_plugin_stop(gdm_prompt_plugin_t *plugin);
 *
 * The PAM prompt plugin would typically start a new thread in the
 * gdm_prompt_plugin_start() function. This thread would monitor some 
 * external event (such as smartcard insertion or touchpad response), and 
 * write a response back to stdout when the event occurs. 
 *
 * Note that the greeter process itself may obtain a response to the PAM 
 * prompt (such as a username entered in an edit field) and terminate the 
 * plugin via the gdm_prompt_plugin_stop() function call. Typically this 
 * would cause the plugin to stop monitoring the external event and 
 * terminate the thread.
 *
 * @param prompt_type a string representing the PAM prompt type. This string 
 * is case-sensitive and may be NULL.
 *
 * @return 0 on success, 1 if an error occurs.
 */
int gdm_prompt_plugin_handle(const char *prompt_type);

#endif /* GDM_PROMPT_PLUGIN */
