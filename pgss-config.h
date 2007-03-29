
/*
 * A structure representing a single configuration line from a 
 * configuration file. The syntax of a line is
 *    oid[,oid...] name [key=value ...]
 * where name is normally treated as a path to a shared library.
 * The oid can be either '*', a dotted numeric or a constant identifier.
 * The key=value parameters may be quoted etc.
 */

#define MAX_PARAMS	64

struct config {
    char *name;			    /* name to use */
    int nparams;		    /* number of parameters */
    char *params[MAX_PARAMS];	    /* name=value parameters */
    struct pgss_dispatch *dispatch; /* loaded provider (NULL if unloaded) */
    int lineno;			    /* position of 1st oid in config file */
    const char *filename;	    /* config file name */
};

/* Iterates through config structure. State should start at NULL. */
struct config *_pgss_config_next(void **state, gss_OID *mech_return);

/* Returns the config associated with an OID, or NULL if not found */
struct config *_pgss_config_find(gss_OID mech);

/* Returns a description of the last error */
const char *_pgss_config_last_error(void);

/* Loads configuration information from the file. (Do not call twice) */
int _pgss_load_config_file(const char *filename);

/* Returns the key associated with a config entry, or NULL if not defined */
const char *_pgss_config_get_param(const struct config *cfg, const char *key);

/* Returns the 'default' mechanism. If only one mech is defined, that's it. */
gss_OID _pgss_get_default_mech(void);
