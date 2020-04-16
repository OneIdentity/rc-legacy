/* (c) 2005, Quest Software, Inc. All rights reserved. */

/* error.c */
extern int debug;
extern int current_lineno;
extern const char *current_filename;
void	warning(const char *fmt, ...);
void	die(const char *fmt, ...);
#define dprintf(f,a...) do { if (debug) fprintf(stderr,f ,##a); } while (0)

/* splitline.c */
int	splitline(char *line, char *word[], int wordsz);

/* cmd.c */
struct command {
    int (*func)(int argc, char **argv);
    const char *help;
};
int	run_command(int argc, char *argv[]);

/* keytab.c */
void	keytab_init(const char *);

extern struct command cmd_help, 
       		      cmd_version, 
		      cmd_copy, 
		      cmd_list, 
		      cmd_delete,
		      cmd_dump,
		      cmd_undump;
       		
/* compat.c */
#if !HAVE_ASPRINTF
int	asprintf(char **p, const char *fmt, ...);
#endif
