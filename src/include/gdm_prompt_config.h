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

#ifndef __GDM_PROMPT_CONFIG_H
#define __GDM_PROMPT_CONFIG_H

/* Get the value of a key in the specified confguration file.
 *
 * The configuration file is of the form
 *
 *   [section]
 *     property=value
 *     property=value
 *   
 *   [section]
 *     property=value
 *
 * The key is of the form "section/property".
 *
 * @param config_file the path to the configuration file. Must not be
 * NULL.
 * 
 * @param key the key in the configuration file. Must not be NULL.
 *
 * @return the value of the key, or NULL if the value cannot be obtained.
 */
const char *gdm_prompt_config_get_string(const char *config_file,
                                         const char *key);

#endif /* __GDM_PROMPT_CONFIG_H */
