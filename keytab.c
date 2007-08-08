/* (c) 2005, Quest Software, Inc. All rights reserved. */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#if STDC_HEADERS
# include <ctype.h>
# include <stdlib.h>
# include <string.h>
#else
# if !HAVE_STRCHR
#  define strchr  index
# endif
char *strchr();
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_KRB5_H
# include <krb5.h>
#endif

# include <errno.h>

#include "ktedit.h"

#if !HAVE_TIMEGM
time_t timegm(struct tm *tm);
#endif

#if HAVE_GETOPT_H
# include <getopt.h>
#endif

#if HAVE_KRB5_C_STRING_TO_KEY
  /* MIT API */
# define krb5_keytype krb5_enctype
# define GET_KEYBLOCK(entry)  (entry)->key
# define GET_KEYTYPE(entry)   (entry)->key.enctype
# define GET_KEYLENGTH(entry) (entry)->key.length
# define GET_KEYDATA(entry)   (entry)->key.contents

static krb5_error_code
krb5_string_to_keytype(krb5_context ctx, char *str, krb5_keytype *enctype)
{
    char buf[512];
    int i;

    if (krb5_string_to_enctype((char *)(str), enctype) == 0)
	return 0;
    for (i = 0; i < 64; i++)
	if (krb5_enctype_to_string(i, buf, sizeof buf) == 0 &&
	    strcmp(buf, str) == 0) 
	{
	    *enctype = i;
	    return 0;
	}
    return KRB5KDC_ERR_ETYPE_NOSUPP;
}

static krb5_error_code
krb5_keytype_to_string(krb5_context ctx, krb5_keytype enctype,
	char **strp)
{
    char buf[512];
    krb5_error_code error;

    error = krb5_enctype_to_string(enctype, buf, sizeof buf);
    if (!error)
	*strp = strdup(buf);
    return error;
}

#elif HAVE_KRB5_KEYTYPE_TO_STRING
  /* HEIMDAL API */
# define GET_KEYBLOCK(entry)  (entry)->keyblock
# define GET_KEYTYPE(entry)   (entry)->keyblock.keytype
# define GET_KEYLENGTH(entry) (entry)->keyblock.keyvalue.length
# define GET_KEYDATA(entry)   (entry)->keyblock.keyvalue.data
#else
# error unknown API
#endif

#if !HAVE_KRB5_XFREE
static krb5_error_code 
krb5_xfree(void *p) {
    if (p) free(p);
    return 0;
}
#endif

#if !HAVE_KRB5_PRINCIPAL_MATCH
# define krb5_principal_match(c,a,b) krb5_principal_compare(c,a,b) /* XXX */
#endif

#if !HAVE_KRB5_GET_ERR_TEXT && HAVE_ERROR_MESSAGE
# define krb5_get_err_text(c,e) error_message(e)
#endif

/* A structure used to match entries in a keytab */
typedef struct entry_match {
    krb5_keytype	keytype;
#define ANY_KEYTYPE ((krb5_keytype)-1)
    krb5_kvno		kvno;
#define ANY_KVNO    ((krb5_kvno)0)
    krb5_principal	principal;	/* actually a 'glob' principal */
} entry_match;

/* The currently active keytab */
static krb5_context ctx;
static char keytab_name[1024];
static krb5_keytab  kt;

/* Warn about a kerberos error */
static void
kwarn(krb5_error_code error, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "Warning: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", krb5_get_err_text(ctx, error));
    va_end(ap);
}

/* Convert a kerberos timestamp to a string. Returns ptr to static storage. */
static const char *
timestamp_to_string(krb5_timestamp timestamp, int full)
{
    time_t t = (time_t)timestamp;
    struct tm *tm;
    time_t distance;
    static char buf[64];

    tm = localtime(&t);
    if (!tm) return "<error>";
    distance = time(0) - t;
    if (full)
	strftime(buf, sizeof buf, "%c", tm);
    else if (distance < 0)
	return "(future)";
    else if (distance < 12 * 60 * 60)
	strftime(buf, sizeof buf, "%H:%M:%S", tm);
    else if (distance < 7 * 24 * 60 * 60)
	strftime(buf, sizeof buf, "%a %H%p", tm);
    else if (distance < 30 * 24 * 60 * 60)
	strftime(buf, sizeof buf, "%d %b", tm);
    else if (distance < 365 * 24 * 60 * 60)
	strftime(buf, sizeof buf, "%b %Y", tm);
    return buf;
}

/* ISO 8601 time format yyyy-mm-ddThh:mm:ssZ */
static const char *
time_to_utctime(time_t t)
{
    struct tm *tm;
    static char buffer[1024];
    tm = gmtime(&t);
    if (!tm) return NULL;
    snprintf(buffer, sizeof buffer,
	    "%04u-%02u-%02uT%02u:%02u:%02uZ",
	    tm->tm_year + 1900,
	    tm->tm_mon + 1,
	    tm->tm_mday,
	    tm->tm_hour,
	    tm->tm_min,
	    tm->tm_sec);
    return buffer;
}

/* counterpart to time_to_utctime() */
static int
utctime_to_time(const char *s, time_t *tp)
{
    struct tm tm;
    time_t t;

    memset(&tm, 0, sizeof tm);
    if (sscanf(s, "%u-%u-%uT%u:%u:%uZ",
		&tm.tm_year,
		&tm.tm_mon,
		&tm.tm_mday,
		&tm.tm_hour,
		&tm.tm_min,
		&tm.tm_sec) != 6) return 0;
    tm.tm_year -= 1900;
    tm.tm_mon--;
    t = timegm(&tm);

    if (t == (time_t)-1)
	return 0;
    *tp = t;
    return 1;
}

static const char *
timestamp_to_utctime(krb5_timestamp timestamp)
{
    return time_to_utctime((time_t)timestamp);
}

static int
utctime_to_timestamp(const char *s, krb5_timestamp *timestamp)
{
    return utctime_to_time(s, (time_t *)timestamp);
}

static int
string_to_keytype(krb5_context ctx, const char *str, krb5_keytype *keytypep)
{
    if (isdigit(str[0])) {
	*keytypep = (krb5_keytype)atoi(str);
	return 1;
    } else if (krb5_string_to_keytype(ctx, str, keytypep) == 0) 
	return 1;
    else 
	return 0;
}

/* 
 * Parses a keytab entry match expression, which is of the form
 *     [ {*|keytype-name|keytype-number} ':' [ kvno ':' ] ] glob-principal
 * Returns 0 on failure in parsing
 */
static int
parse_entry_match(krb5_context ctx, const char *str, entry_match *match)
{
    char *c;
    krb5_error_code error;

    match->kvno = ANY_KVNO;
    match->keytype = ANY_KEYTYPE;
    c = strchr(str, ':');
    if (c) {
	*c = '\0';
	if (strcmp(str, "*") == 0)
	    match->keytype = ANY_KEYTYPE;
	else if (!string_to_keytype(ctx, str, &match->keytype)) {
	    fprintf(stderr, "unknown keytype '%s'\n", str);
	    return 0;
	}
	str = c + 1;
	if (isdigit(str[0])) {
	    c = strchr(str, ':');
	    *c = '\0';
	    match->kvno = atoi(str);
	    str = c + 1;
	}
    }
    if ((error = krb5_parse_name(ctx, str, &match->principal)) != 0) {
	fprintf(stderr, "malformed match principal '%s'\n", str);
	return 0;
    }
    return 1;
}

/*
 * Frees resources allocated in an entry_match
 */
static void
free_entry_match(krb5_context ctx, struct entry_match *match)
{
    krb5_free_principal(ctx, match->principal);
}

/**
 * Returns true if the keytab entry matches the principal glob, the
 * key version number (if not ANY_KVNO) and the keytype (if not ANY_KEYTYPE)
 */
static int
entry_matches(krb5_context ctx, krb5_keytab_entry *entry, entry_match *match)
{
    if (match->kvno != ANY_KVNO 
	    && match->kvno != entry->vno)
	return 0;
    if (match->keytype != ANY_KEYTYPE 
	    && match->keytype != GET_KEYTYPE(entry))
	return 0;
    if (!krb5_principal_match(ctx, entry->principal, match->principal))
	return 0;
    return 1;
}

/**
 * Initialises the keytab commands.
 * @param keytab a keytab string specified by the -k option (or NULL)
 */
void
keytab_init(const char *keytab)
{
    krb5_error_code error;

    error = krb5_init_context(&ctx);
    if (error) die("krb5_init_context");

    if (keytab) {
	strncpy(keytab_name, keytab, sizeof keytab_name);
	error = krb5_kt_resolve(ctx, keytab, &kt);
	if (error) {
	    kwarn(error, "krb5_kt_resolve: %s", keytab_name);
	    return;
	}
    } else {
	error = krb5_kt_default(ctx, &kt);
	if (error) {
	    kwarn(error, "krb5_kt_default: %s", keytab_name);
	    return;
	}
	(void)krb5_kt_default_name(ctx, keytab_name, sizeof keytab_name);
    }
}

/**
 * Lists the contents of a keytab
 * Usage:  ls [-l]
 */
static int
list(int argc, char **argv)
{
    krb5_error_code error;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    int ch, i, argerr = 0;
    int lflag = 0;
    int nflag = 0;
    char *matchexpr = NULL;
    entry_match match;

    while ((ch = getopt(argc, argv, "ln")) != -1)
	switch (ch) {
	    case 'l': lflag = 1; break;	/* long format */
	    case 'n': nflag = 1; break; /* numeric format */
	    default: argerr = 1; break;
	}

    if (optind < argc) 
	matchexpr = argv[optind++];
    if (argerr || argc != optind) {
	fprintf(stderr, "usage: %s [-ln] [matchexpr]\n", argv[0]);
	return 1;
    }

    if (matchexpr != NULL) {
	if (!parse_entry_match(ctx, matchexpr, &match))
	    return 1;
    }

    error = krb5_kt_start_seq_get(ctx, kt, &cursor);
    if (error) {
	kwarn(error, "krb5_kt_start_seq_get %s", keytab_name);
	return 1;
    }

    if (lflag)
	printf("%-3.3s %-5.5s %-10.10s %s\n", 
		"Vno", "Type", "Time", "Principal");
    else
	printf("%3s %-10.10s %s\n", "Vno", "Type", "Principal");

    while ((error = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
	char *keytype_string = NULL;
	char *principal_string = NULL;
	krb5_keytype keytype;

	if (matchexpr && !entry_matches(ctx, &entry, &match))
	    goto nomatch;

        keytype = (krb5_keytype)GET_KEYTYPE(&entry);
	if (!nflag) {
	    error = krb5_keytype_to_string(ctx, keytype, &keytype_string);
	    if (error) {
		kwarn(error, "krb5_keytype_to_string");
		asprintf(&keytype_string, "%d", (int)keytype);
	    }
	}
	error = krb5_unparse_name(ctx, entry.principal, &principal_string);
	if (error)
	    kwarn(error, "krb5_unparse_name");

	if (lflag) {
	    /* Print a long version */
	    if (nflag)
		printf("%3d %5d %10d %s\n", 
		    entry.vno, (int)keytype,
		    entry.timestamp,
		    principal_string ? principal_string : "");
	    else
		printf("%3d %-5.5s %-10.10s %s\n", 
		    entry.vno,
		    keytype_string, timestamp_to_string(entry.timestamp, 0),
		    principal_string ? principal_string : "<error>");
	    printf("      ");
	    for (i = 0; i < GET_KEYLENGTH(&entry) &&
		    	i < 24; i++)
		printf("%s%02x", i ? ":" : "", 
			((unsigned char *)GET_KEYDATA(&entry))[i]);
	    if (i < GET_KEYLENGTH(&entry)) printf("...");
	    printf("\n");
	} else {
	    if (nflag)
		printf("%3d %-10d %s\n", 
		    entry.vno, (int)keytype,
		    principal_string ? principal_string : "<error>");
	    else
		printf("%3d %-10.10s %s\n", 
		    entry.vno, keytype_string,
		    principal_string ? principal_string : "<error>");
	}
	if (keytype_string) {
	    error = krb5_xfree(keytype_string);
	    if (error) kwarn(error, "krb5_xfree");
	}
	if (principal_string) {
	    error = krb5_xfree(principal_string);
	    if (error) kwarn(error, "krb5_xfree");
	}
nomatch:
	error = krb5_kt_free_entry(ctx, &entry);
	if (error)
	    kwarn(error, "krb5_kt_free_entry");
    }
    if (error && error != KRB5_KT_END)
	kwarn(error, "krb5_kt_next_entry %s", keytab_name);
    error = krb5_kt_end_seq_get(ctx, kt, &cursor);
    if (error)
	kwarn(error, "krb5_kt_end_seq_get %s", keytab_name);
    if (matchexpr)
	free_entry_match(ctx, &match);
    return 0;
}
struct command cmd_list = { list, "lists entries in current keytab" };

/**
 * Command to delete entries in a keytab
 */
static int
delete(int argc, char **argv)
{
    int deleted;
    krb5_error_code error;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    entry_match match;

    if (argc != 2) {
	fprintf(stderr, "usage: %s <entry-descriptor>\n", argv[0]);
	return 1;
    }

    if (!parse_entry_match(ctx, argv[1], &match))
	return 1;

    error = krb5_kt_start_seq_get(ctx, kt, &cursor);
    if (error) {
	kwarn(error, "krb5_kt_start_seq_get %s", keytab_name);
	return 1;
    }

    deleted = 0;
    while ((error = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
	if (!entry_matches(ctx, &entry, &match))
	    goto nomatch;
	error = krb5_kt_remove_entry(ctx, kt, &entry);
	if (error) {
	    kwarn(error, "krb5_kt_remove_entry");
	    (void)krb5_kt_free_entry(ctx, &entry);
	    (void)free_entry_match(ctx, &match);
	    return 1;
	}
	(void)krb5_kt_start_seq_get(ctx, kt, &cursor);
	deleted++;
   nomatch:
	error = krb5_kt_free_entry(ctx, &entry);
	if (error)
	    kwarn(error, "krb5_kt_free_entry");
    }
    if (error && error != KRB5_KT_END)
	kwarn(error, "krb5_kt_next_entry %s", keytab_name);
    error = krb5_kt_end_seq_get(ctx, kt, &cursor);
    if (error)
	kwarn(error, "krb5_kt_end_seq_get %s", keytab_name);
    (void)free_entry_match(ctx, &match);
    printf("%s: removed %d entr%s\n", argv[0], 
	    deleted, deleted == 1 ? "y" : "ies");
    return 0;
}
struct command cmd_delete = { delete, "deletes entries from the keytab" };

/**
 * Command to copy entries in a keytab to a different principal
 */
static int
copy(int argc, char **argv)
{
    int counted;
    krb5_error_code error;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    struct new_entry {
	krb5_keytab_entry entry;
	struct new_entry *next;
    } *new_entries = NULL, *ne;
    entry_match match;
    krb5_principal principal;

    if (argc != 3) {
	fprintf(stderr, "usage: %s <entry-pattern> <new-principal>\n", 
		argv[0]);
	return 1;
    }

    if (!parse_entry_match(ctx, argv[1], &match))
	return 1;

    error = krb5_parse_name(ctx, argv[2], &principal);
    if (error) {
	kwarn(error, "krb5_parse_name '%s'", argv[2]);
	(void)free_entry_match(ctx, &match);
	return 1;
    }

    error = krb5_kt_start_seq_get(ctx, kt, &cursor);
    if (error) {
	kwarn(error, "krb5_kt_start_seq_get %s", keytab_name);
	return 1;
    }

    /* Extract the contents of one of the entries */
    while ((error = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
	if (!entry_matches(ctx, &entry, &match))
	    goto nomatch;

	ne = (struct new_entry *)malloc(sizeof *ne);
	if (ne == NULL) {
	    fprintf(stderr, "malloc");
	    exit(1);
	}
	ne->next = new_entries;
	new_entries = ne;

	if ((error = krb5_copy_keyblock_contents(ctx, &GET_KEYBLOCK(&entry),
		&GET_KEYBLOCK(&ne->entry))) != 0)
	{
	    kwarn(error, "krb5_copy_keyblock_contents");
	    new_entries = ne->next;
	    free(ne);
	} else {
	    ne->entry.vno = entry.vno;
	    ne->entry.timestamp = entry.timestamp;
	    ne->entry.principal = principal;
	}

   nomatch:
	error = krb5_kt_free_entry(ctx, &entry);
	if (error)
	    kwarn(error, "krb5_kt_free_entry");
    }
    if (error && error != KRB5_KT_END)
	kwarn(error, "krb5_kt_next_entry %s", keytab_name);
    error = krb5_kt_end_seq_get(ctx, kt, &cursor);
    if (error)
	kwarn(error, "krb5_kt_end_seq_get %s", keytab_name);
    (void)free_entry_match(ctx, &match);

    /* Insert the new entries */
    counted = 0;
    while (new_entries) {
	ne = new_entries;
	new_entries = ne->next;

	error = krb5_kt_add_entry(ctx, kt, &ne->entry);
	if (error)
	    kwarn(error, "krb5_kt_add_entry");
	else
	    counted++;
	krb5_free_keyblock_contents(ctx, &GET_KEYBLOCK(&ne->entry));
	free(ne);
    }
    krb5_free_principal(ctx, principal);

    printf("%s: copied %d entr%s\n", argv[0], counted, 
	    counted == 1 ? "y" : "ies");
    return counted > 0 ? 0 : 1;
}
struct command cmd_copy = { copy, "copies entries in the keytab" };

/**
 * Dumps the contents of a keytab to a text file, suitable for undumping
 * Usage:  dump
 */
static int
dump(int argc, char **argv)
{
    krb5_error_code error;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    int ch, i, argerr = 0;
    int ret = 0;

    while ((ch = getopt(argc, argv, "")) != -1)
	switch (ch) {
	    default: argerr = 1; break;
	}

    if (argerr || argc != optind) {
	fprintf(stderr, "usage: %s \n", argv[0]);
	return 1;
    }

    error = krb5_kt_start_seq_get(ctx, kt, &cursor);
    if (error) {
	kwarn(error, "krb5_kt_start_seq_get %s", keytab_name);
	return 1;
    }

    printf("# keytab dump from %s %s\n", keytab_name, time_to_utctime(time(0)));

    while ((error = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
	char *keytype_string = NULL;
	char *principal_string = NULL;

	krb5_keytype keytype = (krb5_keytype)GET_KEYTYPE(&entry);

	error = krb5_keytype_to_string(ctx, keytype, &keytype_string);
	if (error) {
	    kwarn(error, "krb5_keytype_to_string");
	    asprintf(&keytype_string, "%d", (int)keytype);
	}

	error = krb5_unparse_name(ctx, entry.principal, &principal_string);
	if (error) {
	    kwarn(error, "krb5_unparse_name");
	    ret = 1;
	}

	printf("%s %d ", 
	    principal_string ? principal_string : "<error>",
	    entry.vno);
	if (strchr(keytype_string, ' '))
	    printf("\"%s\" ", keytype_string);
	else
	    printf("%s ", keytype_string);

	putchar('[');
	for (i = 0; i < GET_KEYLENGTH(&entry); i++) {
	    if (i && ((i & 7) == 0)) printf(":");
	    printf("%02x", ((unsigned char *)GET_KEYDATA(&entry))[i]);
	}
	putchar(']');

	/* printf(" # %s\n", timestamp_to_utctime(entry.timestamp)); */
	putchar('\n');

	if (keytype_string) {
	    error = krb5_xfree(keytype_string);
	    if (error) kwarn(error, "krb5_xfree");
	}
	if (principal_string) {
	    error = krb5_xfree(principal_string);
	    if (error) kwarn(error, "krb5_xfree");
	}
nomatch:
	error = krb5_kt_free_entry(ctx, &entry);
	if (error)
	    kwarn(error, "krb5_kt_free_entry");
    }
    if (error && error != KRB5_KT_END) {
	kwarn(error, "krb5_kt_next_entry %s", keytab_name);
	ret = 1;
    }
    error = krb5_kt_end_seq_get(ctx, kt, &cursor);
    if (error)
	kwarn(error, "krb5_kt_end_seq_get %s", keytab_name);
    return ret;
}
struct command cmd_dump = { dump, "dumps keytab in undumpable text form" };

/**
 * Undumps stdin and writes keytab entries.
 * Lines starting with '#' are ignored.
 * Blank lines are ignored.
 * If the -r flag is given, all entries in the keytab are initially deleted.
 */
static int
undump(int argc, char **argv)
{
    krb5_error_code error;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    int ch, i, argerr = 0;
    int rflag = 0;
    int ret = 0;
    int deleted;
    static char buffer[8192];
    char *line;
    int lineno;
    int entry_count;

    while ((ch = getopt(argc, argv, "r")) != -1)
	switch (ch) {
	    default: argerr = 1; break;
	}

    if (argerr || argc != optind) {
	fprintf(stderr, "usage: %s [-r]\n", argv[0]);
	return 1;
    }

    error = krb5_kt_start_seq_get(ctx, kt, &cursor);
    if (error == ENOENT) goto nodelete;
    if (error) {
	kwarn(error, "krb5_kt_start_seq_get %s", keytab_name);
	return 1;
    }

    /* Delete all the existing entries */
    deleted = 0;
    while ((error = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
	error = krb5_kt_remove_entry(ctx, kt, &entry);
	if (error) {
	    kwarn(error, "krb5_kt_remove_entry");
	    (void)krb5_kt_free_entry(ctx, &entry);
	    return 1;
	}
	(void)krb5_kt_start_seq_get(ctx, kt, &cursor);
	deleted++;
   nomatch:
	error = krb5_kt_free_entry(ctx, &entry);
	if (error)
	    kwarn(error, "krb5_kt_free_entry");
    }
    if (error && error != KRB5_KT_END)
	kwarn(error, "krb5_kt_next_entry %s", keytab_name);
    error = krb5_kt_end_seq_get(ctx, kt, &cursor);
    if (error)
	kwarn(error, "krb5_kt_end_seq_get %s", keytab_name);
    if (deleted)
	printf("%s: removed existing %d entr%s\n", argv[0], 
	    deleted, deleted == 1 ? "y" : "ies");

nodelete:
    /* Read in the new entries */
    lineno = 0;
    entry_count = 0;
    while ((line = fgets(buffer, sizeof buffer, stdin)) != NULL) {
	krb5_keytab_entry entry;
	char principalbuf[8192];
	int kvno;
	char keytypebuf[256];
	/* char timestampbuf[256]; */
	char keybuf[8192];
	char keydatabuf[4096];
	int i, keylen, lonibble;
	int scans;
	char *s;

	lineno++;
	while (*line && isspace(*line))	line++; /* skip whitespace */
	if (line[0] == '#' || line[0] == '\n') continue; /* ignore blank */

	/* Copy the principal bug in separately to process backslashes */
	s = principalbuf;
	while (*line && !isspace(*line) && 
		s < principalbuf + sizeof principalbuf - 2)
       	{
	    if (*line == '\\')
		*s++ = *line++;
	    if (*line)
		*s++ = *line++;
	}
	*s++ = '\0';

	/* Use scanf for the rest of the line, which is simpler */
	scans = sscanf(line, " %u \"%256[^\"]\" [%[0-9a-fA-F: ]]",
		    &kvno, keytypebuf, keybuf);
	if (scans != 3)
	scans = sscanf(line, " %u %256s [%[0-9a-fA-F: ]]",
		    &kvno, keytypebuf, keybuf);
        if (scans != 3)
	{
	    fprintf(stderr, "%s: line %d: bad format at element %d\n", 
		    argv[0], lineno, scans + 1);
	    ret = 1;
	    continue;
	}
/*
	if (!utctime_to_timestamp(timestampbuf, 
		    (krb5_timestamp *)&entry.timestamp)) 
	{
	    fprintf(stderr, "%s: line %d: malformed timestamp\n", 
		    argv[0], lineno);
	    ret = 1;
	    continue;
	}
*/
	if (!string_to_keytype(ctx, keytypebuf, 
		    (krb5_keytype *)&GET_KEYTYPE(&entry))) 
	{
	    fprintf(stderr, "%s: line %d: bad keytype \"%s\"\n", argv[0], 
		    lineno, keytypebuf);
	    ret = 1;
	    continue;
	}
	for (lonibble = 0, keylen = 0, s = keybuf;
	       	*s && keylen < sizeof keydatabuf; s++)
       	{
	    unsigned char value;
	    if (*s >= '0' && *s <= '9')
		value = *s - '0';
	    else if (*s >= 'a' && *s <= 'f')
		value = *s - 'a' + 10;
	    else if (*s >= 'A' && *s <= 'F')
		value = *s - 'A' + 10;
	    else
		continue;
	    if (!lonibble) {
		keydatabuf[keylen] = value << 4;
		lonibble = 1;
	    } else {
		keydatabuf[keylen] |= value;
		lonibble = 0;
		keylen++;
	    }
	}
	if (lonibble) {
	    fprintf(stderr, "%s: line %d: short key\n", argv[0], lineno);
	    ret = 1;
	    continue;
	}

	error = krb5_parse_name(ctx, principalbuf, &entry.principal);
	if (error) {
	    kwarn(error, "%s: line %d: krb5_parse_name", argv[0], lineno);
	    ret = 1;
	    continue;
	}

	GET_KEYLENGTH(&entry) = keylen;
	GET_KEYDATA(&entry) = keydatabuf;
	entry.vno = kvno;

	error = krb5_kt_add_entry(ctx, kt, &entry);
	if (error) {
	    kwarn(error, "krb5_kt_add_entry");
	    ret = 1;
	} else
	    entry_count++;
	krb5_free_principal(ctx, entry.principal);
    }
    printf("added %d entries to %s\n", entry_count, keytab_name);
    return ret;
}
struct command cmd_undump = { undump, "writes keys on stdin to keytab" };


#if !HAVE_TIMEGM
time_t timegm(struct tm *tm)
{
    time_t t;
    char *tz = getenv("TZ");
    setenv("TZ", "UTC", 1);
    tzset();
    t = mktime(tm);
    if (tz)
	setenv("TZ", tz, 1);
    else
	unsetenv("TZ");
    tzset();
    return t;
}
#endif
