#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "gssapi.h"
#include "pgssapi.h"
#include "pgss-common.h"
#include "pgss-config.h"
#include "pgss-dispatch.h"
#include "pgss-gss2.h"

/* An element in the mech->config mapping */
struct mechconf {
    struct mechconf *next;       /* list chain for get_configs() */
    struct mechconf *hash_next;  /* list chain for find_config()  */
    gss_OID mech;
    struct config *config;
};

/* State structure used while tokenising a configuration file. */
struct filestate {
    FILE *file;		    /* Currently open file */
    const char *filename;   /* Name of the currently open file */
    int nextch;		    /* Character being processed */
    int lineno;		    /* Line number of the next character */
    int error_lineno;	    /* Line nuber where last error occurred */
    const char *error;	    /* Static text describing last error */
};

/* Prototypes */
static unsigned int hash_mech(gss_OID mech);
static gss_OID	    dup_oid(gss_OID oid);
static void	    free_oid(gss_OID *oid);
static int	    insert_config(gss_OID mech, struct config *config);
static int	    remove_config(gss_OID mech);
static int	    nextch(struct filestate *state);
static void	    ungetch(struct filestate *state, int ch);
static void	    skip_whitespace(struct filestate *state);
static void	    skip_to_eol(struct filestate *state);
static char *	    read_word(struct filestate *state, int delim);
static gss_OID	    word_to_oid(const char *str);
static int	    load_default_config(void);
static int	    expand_wildcard_configs(void);

#define MAX_OIDS	64
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
static int config_locked;
static int config_loaded;
static char config_last_error[256];

/* A table of short OID aliases */
static struct {
    const char *name;
    gss_OID oid;
} oid_aliases[] = {
    { "krb5", &_pgss_KRB5_MECHANISM }
};

/* Returns the last error text generated by config loading */
const char *
_pgss_config_last_error()
{
    return config_last_error;
}

/*
 * Iterates over the mech oid -> config mapping.
 * |state| should initially point to a NULL value.
 * Returns NULL when the mapping is exhausted.
 */
struct config *
_pgss_config_next(void **state, gss_OID *mech_return)
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

/* Deep copies an OID */
static gss_OID
dup_oid(gss_OID oid)
{
    gss_OID copy;

    copy = malloc(sizeof *copy);
    if (!copy)
	return NULL;

    if (oid->length) {
	copy->elements = malloc(oid->length);
	if (!copy->elements) {
	    free(copy);
	    return NULL;
	}
    } else
	copy->elements = NULL;

    copy->length = oid->length;
    if (oid->length)
	memcpy(copy->elements, oid->elements, oid->length);
    return copy;
}

/* Frees an OID allocated with dup_oid */
static void
free_oid(gss_OID *oid)
{
    if (*oid) {
	if ((*oid)->elements)
	    free((*oid)->elements);
	free(*oid);
	*oid = NULL;
    }
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
    struct mechconf *m;
    int hash;

    if (_pgss_config_find(mech))
	return 0;

    m = new(struct mechconf);
    if (!m)
	return -1;

    m->mech = mech;
    m->config = config;

    /* Insert into hash table */
    hash = hash_mech(mech);
    m->hash_next = config_hash_table[hash];
    config_hash_table[hash] = m;

    /* Insert into linked list */
    m->next = mechconf_list;
    mechconf_list = m;

    return 1;
}

/* Removes a config. Returns 1 if the config was removed. */
static int
remove_config(gss_OID mech)
{
    struct mechconf **m, *delete, **p;

    for (m = &config_hash_table[hash_mech(mech)]; *m; m = &(*m)->hash_next)
	if (OID_EQUALS(mech, (*m)->mech)) {

	    /* Remove from the hash table */
	    delete = *m;
	    *m = delete->hash_next;

	    /* Remove from the linked list */
	    for (p = &mechconf_list; *p; p = &(*p)->next)
		if (*p == delete) {
		    *p = delete->next;
		    break;
		}

	    /* Release memory */
	    free(delete);
	    return 1;
	}
    return 0;
}

/* Returns the next character with single-lookahead. */
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

/* Puts a character back on the input stream */
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
    int quote = 0, quote_lineno = -1;
    int empty = 1;

    if (state->nextch == EOF || isspace(state->nextch)) {
    	state->error = "expected word";
	state->error_lineno = state->lineno;
    	return NULL;
    }

    /* The buffer is |len| bytes full, and has |bufspc| capacity */
    len = 0;
    bufspc = 128;
    buf = (char *)malloc(bufspc);
    if (!buf) {
    	state->error = "out of memory";
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

/*
 * Converts a configuration string into an OID. The string could
 * either be a conventional dotted OID, or an alias such as "krb5".
 * Caller must free the returned OID.
 */
static gss_OID
word_to_oid(const char *str) {
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
 * Reads a configuration file and appends correspnding config entries.
 * (This only parses the config file - and does not load any libraries)
 * The |filename| string is borrowed.
 * Lazy with memory management since errors are fatal.
 * Returns -1 on error (sets _pgss_config_last_error())
 *          0 on success.
 */
int
_pgss_load_config_file(const char *filename)
{
    int lineno, config_lineno;
    struct config *config;
    char *oidstr = NULL, *param;
    struct filestate state;
    gss_OID oid;

    if (config_locked) {
	snprintf(config_last_error, sizeof config_last_error, 
		"PGSS config tables are busy");
	return -1;
    }

    state.file = fopen(filename, "r");
    if (!state.file) {
	snprintf(config_last_error, sizeof config_last_error, "%s: %s",
		filename ? filename : "(null)", strerror(errno));
	return -1;
    }

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
	    state.error = "out of memory";
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
	        oid = word_to_oid(oidstr);
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
		state.error = "out of memory";
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
    config_loaded = 1;
    return 0;

error:
    snprintf(config_last_error, sizeof config_last_error, "%s:%d: %s",
    	state.filename, state.error_lineno, state.error);
    return -1;
}

/* Loads the default config file. Returns -1 on error */
static int
load_default_config()
{
    return _pgss_load_config_file("/etc/pgss.conf");
}

/*
 * Returns the value assigned to the given parameter, or NULL if not set.
 */
const char *
_pgss_config_get_param(const struct config *cfg, const char *key)
{
    int i;
    const char *k, *p;

    for (i = 0; i < cfg->nparams; i++) {
	for (k = key, p = cfg->params[i]; *k && *k == *p; k++, p++)
	    ;
	if (!*k) {
	    if (!*p)
		return "";
	    if (*p == '=')
		return p + 1;
	}
    }
    return NULL;
}

/* Loads a dispatcher for the given config */
struct pgss_dispatch *
_pgss_config_get_dispatch(struct config *cfg)
{
    if (!cfg->dispatch)
	/* XXX for now, always use the dynamic loader provider */
    	cfg->dispatch = _pgss_dl_provider(cfg);
    return cfg->dispatch;
}

/* Returns the default mechanism, or NO_OID if there is none */
gss_OID
_pgss_get_default_mech()
{
    /* If there is only one mechanism, then it is the default */
    void *state;
    struct config *config;
    gss_OID oid, oid2;

    state = NULL;
    config = _pgss_config_next(&state, &oid);
    if (!config)
	return GSS_C_NO_OID;		/* No mechanisms */
    config = _pgss_config_next(&state, &oid2);
    if (!config)
	return oid;			/* Only one mechanism */

    /* Search for the first config with a param 'default' */
    state = NULL;
    while ((config = _pgss_config_next(&state, &oid)) != NULL)
	if (_pgss_config_get_param(config, "default"))
	    return oid;

    return GSS_C_NO_OID;		/* No mech marked as 'default' */
}

/* 
 * Replaces any wildcard config (i.e. where mech == NULL) with multiple
 * config entries, each with a mech obtained from indicate_mechs().
 */
static int
expand_wildcard_configs()
{
    struct config *config;
    OM_uint32 major, minor, i;
    struct pgss_dispatch *dispatch;
    const char *reason = NULL;
    gss_OID_set mechs;
    gss_OID mech;

    config = _pgss_config_find(GSS_C_NO_OID);
    if (!config)
	return 0;

    remove_config(GSS_C_NO_OID);

    dispatch =_pgss_config_get_dispatch(config);
    if (!dispatch) {
	reason = "couldn't load dispatcher for wildcard config";
	goto out;
    }

    if (!dispatch->gss_indicate_mechs)
	return 0;		    /* No mechs! */

    major = (*dispatch->gss_indicate_mechs)(&minor, &mechs);
    if (GSS_ERROR(major)) {
	reason = "provider's gss_indicate_mechs failed";
	goto out;
    }

    for (i = 0; i < mechs->count; i++) {
	mech = mechs->elements + i;
	if (!_pgss_config_find(mech)) {
	    gss_OID mech_copy = dup_oid(mech);
	    if (!mech_copy) {
		reason = "out of memory";
		break;
	    }
	    insert_config(mech_copy, config);
	}
    }

    if (dispatch->gss_release_oid_set)
	(void)(*dispatch->gss_release_oid_set)(&minor, &mechs);

out:
    if (reason) {
	snprintf(config_last_error, sizeof config_last_error, 
		"expand_wildcard_configs(): %s", reason);
	return -1;
    } else
	return 0;
}

/* 
 * Ensure that the config tables are valid.
 * Returns 0 if successfully or already initialised, or -1 on error.
 */
int
_pgss_init()
{
    if (config_locked)
	return 0;

    if (expand_wildcard_configs() == -1)
	return -1;

    if (!config_loaded && load_default_config() == -1)
	return -1;

    config_locked = 1;
    return 0;
}
