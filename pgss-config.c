#include <gssapi.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <pgssapi.h>
#include "pgss-config.h"
#include "pgss-dispatch.h"
#include "pgss-gss2.h"

struct mechconf {
    struct mechconf *next;       /* list chain for get_configs() */
    struct mechconf *hash_next;  /* list chain for find_config()  */
    gss_OID mech;
    struct config *config;
};

#define MAX_OIDS	64
#define lengthof(a)	(sizeof (a)/sizeof (a)[0])
#define new(T) 		((T *)malloc(sizeof (T)))
#define iseol(ch)	((ch) == '\n' || (ch) == EOF || (ch) == '#')

/*
 * Reads a configuration file into a hash table keyed by mechanism OIDs.
 * 
 * Two structures are used to maintain the mapping between OIDs and
 * provider configuration details: a hash table for efficient lookup
 * of OID to provider, and a singly-linked list to support queries about
 * what configuration is active.
 */

#define HASHLEN 17
static struct mechconf *config_hash_table[HASHLEN];
static struct mechconf *mechconf_list;
static char config_last_error[256];

/* Return true if two OIDs are equal. Safe to use with NULL OIDs. */
#define OID_EQUALS(o1, o2) \
    ((o1) == (o2) || \
     ((o1) && (o2) && (o1)->length == (o2)->length && \
      memcmp((o1)->elements, (o2)->elements, (o1)->length)))

/* A table of short OID aliases */
static struct {
    const char *name;
    gss_OID oid;
} oid_aliases[] = {
    { "krb5", &_pgss_KRB5_MECHANISM }
};

const char *
_pgss_config_last_error()
{
    return config_last_error;
}

/*
 * Iterate over the mech oid -> config mapping.
 * |state| should initially point to a NULL value.
 * Returns NULL when the mapping is exhausted.
 */
struct config *
_pgss_config_iterate(void **state, gss_OID *mech_return)
{
    struct mechconf **next = (struct mechconf **)state;

    if (*next == NULL)
    	*next = mechconf_list;
    else
    	*next = (*next)->next;

    if (*next) {
    	*mech_return = (*next)->mech;
    	return (*next)->config;
    } else {
    	*mech_return = NULL;
    	return NULL;
    }
}

/*
 * Computes the hash index of mechanism OID |mech|.
 */
static unsigned int
hash_mech(gss_OID mech)
{
    unsigned int h = 0;
    OM_uint32 i;

    if (mech == GSS_C_NO_OID)
	return 0;
    for (i = 0; i < mech->length; i++)
	h = (h << 7) ^ ((unsigned char *)mech->elements)[i];
    return h % HASHLEN;
}

/*
 * Returns the config structure corresponding to mechanism OID |mech|.
 * Returns NULL if not found.
 */
struct config *
_pgss_config_find(gss_OID mech)
{
    struct mechconf *m;

    for (m = config_hash_table[hash_mech(mech)]; m; m = m->hash_next)
	if (OID_EQUALS(mech, m->mech))
	    return m->config;
    return NULL;
}

/*
 * Inserts a config entry into the hash table.
 * Sets the 'hash_next' and 'next' members of the config structure.
 * Returns -1 if out of memory
 *          0 if entry for |mech| already exists
 *          1 on success
 */
static int
insert_config(gss_OID mech, struct config *config)
{
    struct mechconf **mp;
    struct mechconf *m;

    mp = &config_hash_table[hash_mech(mech)];
    for (; *mp; mp = &(*mp)->hash_next)
	if (OID_EQUALS(mech, (*mp)->mech))
	    return 0;

    m = new(struct mechconf);
    if (!m)
	return -1;

    m->mech = mech;
    m->config = config;

    /* Insert into hash table */
    *mp = m;
    m->hash_next = NULL;

    /* Insert into linked list */
    m->next = mechconf_list;
    mechconf_list = m;

    return 1;
}

/*
 * State structure used while tokenising a configuration file.
 */
struct filestate {
    FILE *file;	    /* Currently open file */
    int nextch;	    /* Character being processed */
    int lineno;	    /* Line number of the next character */
    const char *filename; /* Filename */
    int error_lineno;
    const char *error;
};

/* Returns the next character with 1-lookahead. */
static int
nextch(struct filestate *state)
{
    int ch;
       
    ch = state->nextch;
    if (ch != EOF) {
	state->nextch = getc(state->file);
	if (state->nextch == '\n')
		state->lineno++;
    }
    return ch;
}

static void
ungetch(struct filestate *state, int ch)
{
    if (state->nextch == '\n')
    	state->lineno--;
    if (state->nextch != EOF)
	ungetc(state->nextch, state->file);
    state->nextch = ch;
}

/* Consumes whitespace (including escaped newlines) but stops
 * before consuming the end-of-line \n */
static void
skip_whitespace(struct filestate *state)
{
    while (state->nextch != EOF)
    	switch (state->nextch) {
	    case '\n':
		return;
	    case '\\':
		nextch(state);
		if (state->nextch == '\n' || state->nextch == EOF) {
		    nextch(state);
		    continue;
		}
		ungetch(state, '\\');
		return;
	    default:
		if (!isspace(state->nextch))
			return;
		nextch(state);
		continue;
	}
}

/* Consumes all characters up to and including the end-of-line \n.
 * (Escapes before the newline are not treated specially)
 */
static void
skip_to_eol(struct filestate *state)
{
    while (state->nextch != EOF && state->nextch != '\n')
	nextch(state);
    if (state->nextch == '\n')
    	nextch(state);
}

/* Reads a word up to unquoted whitespace or delim.
 * The word may be quoted with ' or " and escapes are reduced.
 * Allocates and fills in a memory buffer with an unescaped string.
 * Escaped newlines are ignored.
 * Returns NULL if a memory allocation failed.
 */
static char *
read_word(struct filestate *state, int delim)
{
    char *buf, *newbuf;
    int bufspc, len;
    int quote = 0, quote_lineno;
    int empty = 1;

    if (state->nextch == EOF || isspace(state->nextch)) {
    	state->error = "Expected word missing";
	state->error_lineno = state->lineno;
    	return NULL;
    }

    /* The buffer is |len| bytes full, and has |bufspc| capacity */
    len = 0;
    bufspc = 128;
    buf = (char *)malloc(bufspc);
    if (!buf) {
    	state->error = "Out of memory";
	state->error_lineno = state->lineno;
	return NULL;
    }

    while (state->nextch != EOF && (quote || !isspace(state->nextch)))
    {
	int ch = state->nextch;

	if (!quote && (ch == delim || ch == '#'))
	    break;

	empty = 0;

	if (quote && ch == quote) {
	    quote = 0;
	    nextch(state);
		continue;
	}
	if (!quote && (ch == '\"' || ch == '\'')) {
	    quote = ch;
	    quote_lineno = state->lineno;
	    nextch(state);
	    continue;
	}

	if (ch == '\n') {
	    free(buf);
	    state->error = "unclosed quote";
	    state->error_lineno = quote_lineno;
	    return NULL;
	}


	if (ch == '\\') {
	    nextch(state);
	    ch = state->nextch;
	    if (ch == '\n' || ch == EOF) {
	        nextch(state);
	    	continue;
	    }
	}

	/* Grow the word buffer exponentially */
	if (len + 1 >= bufspc) {
	    bufspc *= 2;
	    newbuf = realloc(buf, bufspc);
	    if (!newbuf) {
		free(buf);
		return NULL;
	    }
	}
	buf[len++] = ch;
	nextch(state);
    }
    if (empty) {
    	free(buf);
	state->error = "missing word";
	state->error_lineno = state->lineno;
	return NULL;
    }

    if (quote) {
    	free(buf);
	state->error = "unclosed quote";
	state->error_lineno = quote_lineno;
	return NULL;
    }
    buf[len] = '\0';

    return buf;
}

static gss_OID
str2oid(const char *str) {
    OM_uint32 major, minor;
    gss_buffer_desc buf;
    gss_OID oid;
    int i;

    for (i = 0; i < lengthof(oid_aliases); i++)
    	if (strcmp(str, oid_aliases[i].name) == 0)
	    return oid_aliases[i].oid;

    buf.length = strlen(str);
    buf.value = (char *)str;
    major = gss_str_to_oid(&minor, &buf, &oid);
    if (GSS_ERROR(major))
    	return NULL;
    return oid;
}

/*
 * Reads a configuration file and inserts correspnding config entries.
 * The |filename| string pointer should not be altered later.
 * Lazy with memory management since errors are generally fatal.
 * Returns -1 on error (sets _pgss_config_last_error())
 *          0 on success.
 */
int
_pgss_load_config_file(const char *filename)
{
    int ch;
    int lineno, config_lineno;
    FILE *file;
    struct config *config;
    char *oidstr = NULL, *name, *param;
    struct filestate state;
    gss_OID oid;

    state.file = fopen(filename, "r");
    if (!state.file)
	return -1;

    state.filename = filename;
    state.lineno = 1;
    state.error = NULL;
    state.error_lineno = 0;
    nextch(&state);

    while (state.nextch != EOF) {
	config_lineno = state.lineno;
	skip_whitespace(&state);

	/* Ignore blank lines and comment lines */
	if (iseol(state.nextch)) {
	    skip_to_eol(&state);
	    continue;
	}

	/* Allocate a new config structure */
	config = new(struct config);
	if (!config)  {
	    state.error = "Out of memory";
	    state.error_lineno = config_lineno;
	    goto error;
	}
	memset(config, 0, sizeof *config);
	config->lineno = config_lineno;
	config->filename = filename;

	/* Read a set of OIDs delimited by ',' */
	for (;;) {
	    lineno = state.lineno;
	    oidstr = read_word(&state, ',');
	    if (oidstr == NULL)
		goto error;
	    if (strcmp(oidstr, "*") == 0)
	    	oid = GSS_C_NO_OID;
	    else {
	        oid = str2oid(oidstr);
		if (!oid) {
		    state.error = "bad OID";
		    state.error_lineno = lineno;
		    goto error;
		}
	    }

	    /* Insert the unpopulated config structure now. */
	    switch (insert_config(oid, config)) {
	      case -1:
	    	state.error_lineno = lineno;
		state.error = "Out of memory";
		goto error;
	      case 0:
	    	state.error_lineno = lineno;
		state.error = oid ? "duplicate OID" : "duplicate wildcard oid";
		goto error;
	    }
			
	    skip_whitespace(&state);
	    free(oidstr);
	    oidstr = NULL;
	    if (state.nextch != ',')
	    	break;
	    nextch(&state);
	    skip_whitespace(&state);
	}

	/* The library name is a bare word */
	config->name = read_word(&state, -1);
	if (!config->name)
	    goto error;
	if (*config->name == '=') {
	    state.error_lineno = lineno;
	    state.error = "name cannot begin with '='";
	    goto error;
	}
	skip_whitespace(&state);

	/* Parameters are bare words (with an optional '=' separator) */
	config->nparams = 0;
	while (!iseol(state.nextch)) {
	    if (config->nparams >= lengthof(config->params)) {
	    	state.error = "too many parameters";
		state.lineno = state.lineno;
		goto error;
	    }
	    param = read_word(&state, -1);
	    if (!param)
	    	goto error;
	    if (*param == '=') {
		state.error_lineno = lineno;
		state.error = "parameter cannot begin with '='";
		goto error;
	    }
	    config->params[config->nparams++] = param;
	    skip_whitespace(&state);
	}

	skip_to_eol(&state);
    }
    return 0;

error:
    snprintf(config_last_error, sizeof config_last_error, "%s:%d: %s",
    	state.filename, state.error_lineno, state.error);
    return -1;
}

/* Returns a non-NULL value if the key matches the parameter "key[=value]" */
static const char *
keymatch(const char *key, const char *param)
{
    const char *k, *p;

    for (k = key, p = param; *k && *p && *p != '='; k++, p++)
    	if (*k != *p)
	    return NULL;
    if (*k)
    	return NULL;
    return *p ? p : p + 1;
}

const char *
_pgss_config_get_param(const struct config *cfg, const char *key)
{
    int i;
    const char *value;

    for (i = 0; i < cfg->nparams; i++) {
    	value = keymatch(key, cfg->params[i]);
	if (value)
	    return value;
    }
    return NULL;
}
