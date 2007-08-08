/* $Vintela: cmd.c,v 1.4 2005/05/19 10:51:08 davidl Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#if STDC_HEADERS
# include <string.h>
# include <stdlib.h>
#endif

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "ktedit.h"

/*
 * Command dispatch module.
 *  - parses command lines
 *  - provides help on commands
 *  - searchs and dispatches control to command implementations
 */

static struct cmdtab {
    const char *name;
    const struct command *impl;
} commandtab[] = {
    /* Keep these in alphabetical order */
    { "?",    	&cmd_help },
    { "copy", 	&cmd_copy },
    { "cp",   	&cmd_copy },
    { "delete", &cmd_delete },
    { "dump",   &cmd_dump },
    { "help", 	&cmd_help },
    { "list", 	&cmd_list },
    { "ls",   	&cmd_list },
    { "rm",   	&cmd_delete },
    { "undump", &cmd_undump },
    { "version", &cmd_version },
};
#define ncommands (sizeof commandtab / sizeof commandtab[0])

/* Comparator function for bsearch'ing the commandtab */
static int
cmdcmp(const void *k, const void *c)
{
    return strcmp((const char *)k, ((struct cmdtab *)c)->name);
}

/* Returns the named command, or NULL if not found */
static struct cmdtab *
find_command(const char *name)
{
    return (struct cmdtab *)bsearch(name, commandtab, ncommands,
	    sizeof commandtab[0], cmdcmp);
}

/* Dispatches a command, or prints an error message */
int
run_command(int argc, char *argv[])
{
    struct cmdtab *cmd;

    if (argc == 0)
	return 0;
    cmd = find_command(argv[0]);
    if (!cmd) {
	fprintf(stderr, "%s: unknown command\n", argv[0]);
	return 1;
    } else {
	optind = 1;
	return (*cmd->impl->func)(argc, argv);
    }
}



/* Command to print out the tool version */
static int
version(int argc, char *argv[])
{
    if (argc != 1) {
	fprintf(stderr, "usage: %s\n", argv[0]);
	return 1;
    }
    printf("%s <%s>\n", PACKAGE_STRING, PACKAGE_BUGREPORT);
    return 0;
}
struct command cmd_version = { version, "displays tool version" };

/* Command to print out some help on known commands */
static int
help(int argc, char **argv)
{
    int i;
    struct cmdtab *cmd;

    switch (argc) {
	case 1:
	    for (i = 0; i < ncommands; i++) {
		cmd = &commandtab[i];
		if (cmd->impl->help)
		    printf("\t%-20s  %s\n", cmd->name, cmd->impl->help);
	    }
	    break;

	case 2:
	    cmd = find_command(argv[1]);
	    if (!cmd) {
		printf("%s: unknown command\n", argv[1]);
		return 1;
	    } else if (!cmd->impl->help) {
		printf("%s: no help available\n", argv[1]);
		return 1;
	    } else
		printf("\t%-20s  %s\n", cmd->name, cmd->impl->help);
	    break;

	default:
	    fprintf(stderr, "usage: %s [command-name]\n", argv[0]);
	    return 1;
    }
    return 0;
}
struct command cmd_help = { help, "displays this text" };
