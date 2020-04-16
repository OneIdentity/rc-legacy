/* GDM - The Gnome Display Manager
 * Copyright (C) 1999, 2000 Martin K. Petersen <mkp@mkp.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef __GDM_PROMPT_MODULE
#define __GDM_PROMPT_MODULE

typedef struct gdm_prompt_plugin gdm_prompt_plugin_t;

struct gdm_prompt_plugin {
  int (*start)(gdm_prompt_plugin_t *plugin, int prompt_type);
  int (*stop)(gdm_prompt_plugin_t *plugin);
  void *data;
} gdm_prompt_plugin;

int gdm_prompt_plugin_handle(const char *prompt_type);

#endif /* GDM_PROMPT_MODULE */
