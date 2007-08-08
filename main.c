/* (c) 2005, Quest Software, Inc. All rights reserved. */
/* $Vintela: main.c,v 1.6 2005/10/13 11:32:27 davidl Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#if STDC_HEADERS
# include <stdlib.h>
# include <libgen.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "ktedit.h"

#define MAXWORDS 1024

/* Process command line arguments and invoke command processing loop */
int
main(int argc, char *argv[])
{
    int ch;
    int error = 0;
    int result;
    int eflag = 0;
    FILE *input;
    const char *keytab = NULL;

    input = stdin;
    current_filename = "<stdin>";

    while ((ch = getopt(argc, argv, "+df:k:")) != -1)
	switch (ch) {
	    case 'd':		/* increase debugging */
		debug++;
		break;
	    case 'e':		/* exit immediately on error */
		eflag = 1;
		break;
	    case 'f':		/* read commands from file */
		if ((input = fopen(optarg, "r")) == NULL) {
		    perror(optarg);
		    exit(1);
		}
		current_filename = optarg;
		break;
	    case 'k':		/* open keytab */
		keytab = optarg;
		break;
	    case '+': 		/* Portability: The + means POSIX to Linux */
		fprintf(stderr, "Unknown option -+\n");
	    default:
		error = 1;
	}
    if (argc != optind && input != stdin)
   	error = 1;

    if (error) {
	fprintf(stderr, 
		"usage: %s [-de] [-k keytab] [-f commandfile | comamnd]\n",
		argv[0]);
	exit(2);
    }

    /* Open the default keytab */
    keytab_init(keytab);
   
    if (argc != optind) {
	/* Process command specified on command line */
	input = NULL;
	current_filename = "<cmdline>";
	current_lineno = 1;
	result = run_command(argc - optind, argv + optind);
    } else {
	int interactive = isatty(fileno(input));
	int count;
	const char *prompt = basename(argv[0]);
	char *line, buffer[16384], *words[MAXWORDS];

	/* Read command lines from stdin, or a command file */
	result = 0;
	for (;;) {
	    if (interactive) 
		fprintf(stderr, "%s> ", prompt);
	    line = fgets(buffer, sizeof buffer, input);
	    if (!line) break;
	    current_lineno++;
	    count = splitline(line, words, MAXWORDS);
	    result = run_command(count, words);
	    if (result && eflag)
		break;
	}
    }
    exit(result);
}
