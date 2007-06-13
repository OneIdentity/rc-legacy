/*===========================================================================
 * Project:     vasidmap - Simple utility that returns the local Username
 *              that correspond to a mapped Windows user
 *
 * Author:      Simo Sorce <simo.sorce@quest.com>
 *              Matt Peterson <matt.peterson@quest.com>
 *
 * File:        vasidmap.c
 *
 * Description: Main implementation source file
 *=========================================================================*/
/* (c) 2006 Quest Software, Inc. All rights reserved. */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>

#include <vas.h>

#define VAS_API_VERSION_SUPPORTS(major,minor) \
        (VAS_API_VERSION_MAJOR == major && VAS_API_VERSION_MINOR >= minor)

#if !VAS_API_VERSION_SUPPORTS(4,2)
# error "Requires VAS 3.0.2 or later"
#endif

#define INPUT_NAME 0
#define INPUT_UID 1
#define INPUT_GID 2
#define INPUT_SID 3

#define OUTPUT_UID 1
#define OUTPUT_GID 2

/* Prototypes */
static void usage(const char *progname);
static long strtougid(const char *s);
static void get_proper_creds(vas_ctx_t *vasctx, vas_id_t **vasid);

/* Prints a usage message */
static void usage(const char *progname)
{
    fprintf(stderr, 
            "Usage: %s [-f] [-ugsnUG] argument\n"
	    "  Supported invocations:\n"
            "           [domain\\]user\n"
            "       -u  uid\n"
            "       -g  gid\n"
            "       -un user-name\n"
            "       -gn group-name\n"
            "       -sU user-sid\n"
            "       -sG group-sid\n"
            "  The -f flag forces credentials to be obtained\n",
	    progname);
}

/* Converts a string into a long integer, exiting on conversion errors */
static long strtougid(const char *s) {
    long id;
    char *endptr = NULL;

    id = strtol(s, &endptr, 0);
    errno = 0;
    if (!*s || *endptr || errno == ERANGE)
	errx(1, "invalid uid/gid '%.100s'", s);

    return id;
}

/*
 * Obtains credentials for querying the directory.
 * If the invoker is root, then try to obtain host/ credentials,
 * otherwise obtain credentials of the invoking user
 */
static void get_proper_creds(vas_ctx_t *vasctx, vas_id_t **vasid) {

    int verr;

    if (getuid()) {
        /* we are not root, let's if we have credentials, or warn the user */
        if (vas_id_alloc(vasctx, NULL, vasid)) {
            errx(1, "vas_id_alloc: %s", vas_err_get_string(vasctx, 1));
        }

        if ((verr = vas_id_is_cred_established(vasctx, *vasid)) != VAS_ERR_SUCCESS) {
            warnx("vas_id_is_cred_established: %s", vas_err_get_string(vasctx, 1));
            if (verr == VAS_ERR_CRED_NEEDED) {
                fprintf(stderr, "Please use vastool kinit to obtain "
                                "a Kerberos ticket.");
            }
            else if (verr == VAS_ERR_CRED_EXPIRED) {
                fprintf(stderr, "Please use vastool kinit to obtain "
                                "a new Kerberos ticket.");
            }
            exit(1);
        }
    } else { 
        /* we are root, let's use the host credentials */
        if (vas_id_alloc(vasctx, "host/", vasid)) {
            errx(1, "vas_id_alloc as host/: %s", vas_err_get_string(vasctx, 1));
        }
    
        if (vas_id_is_cred_established(vasctx, *vasid)) {
            if (vas_id_establish_cred_keytab(vasctx, *vasid,
                                             VAS_ID_FLAG_USE_MEMORY_CCACHE |
                                             VAS_ID_FLAG_KEEP_COPY_OF_CRED, NULL)) {
                errx(1, "vas_id_establish_cred_keytab: %s",
                        vas_err_get_string(vasctx, 1));
            }
        }
    }
}

int main( int argc, char *argv[] )
{
    const char *str = NULL;
    vas_err_t vaserr = 0;
    vas_ctx_t *vasctx = NULL;
    vas_id_t *vasid = NULL;
    int input = INPUT_NAME, output = 0, fflag = 0, nflag = 0;
    int ch, opterror = 0;
    extern int optind;
    extern char *optarg;

    /* Process command line arguments. */
    while ((ch = getopt(argc, argv, "fGgnsUu")) != -1)
	switch (ch) {
            case 'f':
                fflag = 1;			/* force */
                break;

            case 'u':
                input = INPUT_UID;
                break;

            case 'g':
                input = INPUT_GID;
                break;
 
            case 's':
                input = INPUT_SID;
                break;

            case 'U':
                output = OUTPUT_UID;
                break;

            case 'G':
                output = OUTPUT_GID;
                break;

            case 'n':				/* interpret as name */
                nflag = 1;
                break;

            default:
		opterror = 1;
        }

    /* Check for option inconsistencies */
    if (nflag && input == INPUT_SID)
	opterror = 1;
    if (output && input != INPUT_SID)
	opterror = 1;
    if (input == INPUT_SID && !output)
	opterror = 1;

    if (optind < argc)
	str = argv[optind++];
    else
	opterror = 1;

    if (optind < argc)
	opterror = 1;

    if (opterror) {
	usage(argv[0]);
	exit(1);
    }

    (void)vas_log_init(3, 9, 0, 0, 0);

    /* Allocate a VAS context */
    if ((vaserr = vas_ctx_alloc(&vasctx))) {
	switch (vaserr) {
	    case VAS_ERR_INVALID_PARAM: 
		errx(1, "vas_ctx_alloc: invalid parameter");
	    case VAS_ERR_NO_MEMORY: 
		errx(1, "vas_ctx_alloc: no memory");
	    default:
		errx(1, "vas_ctx_alloc: %u", vaserr);
	}
    }

    /* Use the host's keytab when forcing with the -f option. */
    if (fflag) {
        get_proper_creds(vasctx, &vasid);
    }
    
    /*
     * account name => username
     */
    if ((input == INPUT_NAME)) {
	char *user_string;
        const char *backslash;
	vas_user_t *vasuser;
	struct passwd *pwent;

	/* Strip leading domain from DOMAIN\USER names */
        if ((backslash = strchr(str, '\\')) != NULL) {
	    const char *anames[] = { "namingContexts", NULL };
	    const char *nnames[] = { "ncName", "nETBIOSName", "dnsRoot", NULL };
	    vas_attrs_t *vasattrs;
	    char *domain;
	    char *domain_dn;
	    char *dcuri;
	    char *filter;
            int filter_sz;
	    char *conf_dn = NULL;
	    char **vals;
	    int num, i;
	    char *nbt_domain;
	    char *user_realm;
	    char *username;
	    int user_string_sz;

	    if (!fflag) {
		/* We need to do authenticated operations against the AD LDAP server.
		 * If the force option has not been specified we need to set up the
		 * host credentials
		 */
                get_proper_creds(vasctx, &vasid);
	    }

	    if (!(username = strdup(backslash+1))) {
		errx(1, "Memory allocation error.");
	    }
   
	    if (!(nbt_domain = malloc(backslash-str+1))) {
		errx(1, "Memory allocation error.");
	    }
	    snprintf(nbt_domain, backslash-str+1, "%s", str);
    
	    /* find out the domain we are joined to */
	    if (vas_info_joined_domain(vasctx, &domain, &domain_dn) != VAS_ERR_SUCCESS) {
                errx(1, "vas_info_joined_domain: %s", 
                        vas_err_get_string(vasctx, 1));
	    }

	    if ((dcuri = malloc(strlen(domain) + 7)) == NULL) {
		errx(1, "Memory allocation error.");
	    }
	    snprintf(dcuri, strlen(domain) + 7, "DC://@%s", domain);
   
	    if (vas_attrs_alloc(vasctx, vasid, &vasattrs) != VAS_ERR_SUCCESS) {
		errx(1, "vas_attrs_alloc: %s", vas_err_get_string(vasctx, 1));
	    }

	    /* find the configuration naming context */
	    if (vas_attrs_find(vasctx,
			       vasattrs,
			       dcuri,
			       "base",
			       "",
			       "(objectclass=*)",
			       anames) != VAS_ERR_SUCCESS) {
		errx(1, "vas_attrs_find: %s", vas_err_get_string(vasctx, 1));
	    }

	    if (vas_vals_get_string(vasctx,
				    vasattrs,
				    "namingContexts",
				    &vals,
				    &num) != VAS_ERR_SUCCESS) {
		errx(1, "vas_vals_get_string: %s", 
                        vas_err_get_string(vasctx, 1));
	    }

	    for (i = 0; i < num; i++) {
		if (strncmp(vals[i], "CN=Configuration,", 17) == 0) {
		    conf_dn = vals[i];
		}
	    }
	    if (!conf_dn) {
		errx(1, "Search error: Configuration partition not found!");
	    }
    
            filter_sz = strlen(domain_dn) + 15;
	    if ((filter = malloc(filter_sz)) == NULL) {
		errx(1, "Memory allocation error.");
	    }
	    snprintf(filter, filter_sz, "(nETBIOSName=%s)", nbt_domain);

            /* find out the principal name from the short domain name */
	    if (vas_attrs_find(vasctx,
			       vasattrs,
			       dcuri,
			       "sub",
			       conf_dn,
			       filter,
			       nnames) != VAS_ERR_SUCCESS) {
		errx(1, "vas_attrs_find: %s", vas_err_get_string(vasctx, 1));
	    }

	    if (vas_vals_get_string(vasctx,
				    vasattrs,
				    "dnsRoot",
				    &vals,
				    &num) != VAS_ERR_SUCCESS) {
		errx(1, "vas_vals_get_string: %s", 
                        vas_err_get_string(vasctx, 1));
	    }

	    /* in any case we can get only the first name */
	    if (num == 0) {
		errx(1, "Search error: domain realm not found");
	    }

	    if (!(user_realm = strdup(vals[0]))) {
		errx(1, "Memory allocation error.");
	    }
	    for (i = 0; user_realm[i]; i++) {
		user_realm[i] = (char)toupper(user_realm[i]);
	    }

            user_string_sz = strlen(user_realm)+strlen(username)+2;
	    if (!(user_string = malloc(user_string_sz))) {
		errx(1, "Memory allocation error.");
	    }
	    snprintf(user_string, user_string_sz, "%s@%s", username, 
                    user_realm);
    
	} else {
	    user_string = strdup(str);
	}

        if (vas_user_init(vasctx, vasid, user_string, VAS_NAME_FLAG_NO_LDAP, 
                    &vasuser)) 
        {
            /* try again bypassing the cache */
	    if (!fflag) {
		/* We need to do authenticated operations against the AD 
                 * LDAP server. If the force option has not been specified 
                 * we need to set up the host credentials.
		 */
                get_proper_creds(vasctx, &vasid);
	    }

            if (vas_user_init(vasctx, vasid, user_string, VAS_NAME_FLAG_NO_CACHE, &vasuser)) {
                printf("UNKNOWN_USER\n");
                errx(1, "vas_user_init '%.100s': %s", user_string, 
                        vas_err_get_string(vasctx, 1));
            }
	}


        if (vas_user_get_pwinfo(vasctx, vasid, vasuser, &pwent))
       	{
            printf("UNKNOWN_USER\n");
            errx(1, "vas_user_get_pwinfo '%.100s': %s", user_string,
                    vas_err_get_string(vasctx, 1));
        }

        printf("%s\n", pwent->pw_name);
    }

    /*
     * -u uid        => sid
     * -un username  => sid
     */
    else if (input == INPUT_UID) {
        const char *id;
        char *sidstr;
	struct passwd *pwent;
	vas_user_t *vasuser;

	/* Convert '-u uid' into a username */
        if (!nflag) {
	    errno = 0;
	    if ((pwent = getpwuid(strtougid(str))) == NULL) {
		if (errno) {
		    err(1, "getpwuid '%.100s'", str);
                } else {
		    errx(1, "getpwuid '%.100s': not found", str);
                }
	    }
            id = pwent->pw_name;
	} else {
            id = str;
        }

        if (vas_user_init(vasctx, vasid, id, VAS_NAME_FLAG_NO_LDAP, &vasuser)){
	    errx(1, "vas_user_init '%.100s': %s", id, 
		    vas_err_get_string(vasctx, 1));
        }

	if (vas_user_get_sid(vasctx, vasid, vasuser, &sidstr)) {
	    errx(1, "vas_user_get_sid '%.100s': %s", id, 
		    vas_err_get_string(vasctx, 1));
        }
	printf("%s\n", sidstr);
    }

    /*
     * -sU sid => uid
     */
    else if (input == INPUT_SID && output == OUTPUT_UID) {
	vas_user_t *vasuser;
	struct passwd *pwent;

        if (vas_user_init(vasctx, vasid, str, VAS_NAME_FLAG_NO_LDAP, &vasuser)){
	    errx(1, "vas_user_init '%.100s': %s", str, 
		    vas_err_get_string(vasctx, 1));
        }

	if (vas_user_get_pwinfo(vasctx, vasid, vasuser, &pwent)) {
	    errx(1, "vas_user_get_pwinfo '%.100s': %s", str,
		    vas_err_get_string(vasctx, 1));
        }

	printf("%d\n", pwent->pw_uid);
    }

    /*
     * -g gid        => sid
     * -gn groupname => sid
     */
    else if (input == INPUT_GID) {
        const char *id;
        char *sidstr;
	vas_group_t *vasgrp;
	struct group *grent;

	/* Convert '-g gid' into a groupname */
        if (!nflag) {
	    errno = 0;
	    if ((grent = getgrgid(strtougid(str))) == NULL) {
		if (errno) {
		    err(1, "getgrgid '%.100s'", str);
                } else {
		    errx(1, "getgrgid '%.100s': not found", str);
                }
            }
            id = grent->gr_name;
        } else {
            id = str;
        }

        if (vas_group_init(vasctx, vasid, id, VAS_NAME_FLAG_NO_LDAP, &vasgrp)) {
	    errx(1, "vas_group_init '%.100s': %s", id, 
		    vas_err_get_string(vasctx, 1));
        }

	if (vas_group_get_sid(vasctx, vasid, vasgrp, &sidstr)) {
	    errx(1, "vas_group_get_sid '%.100s': %s", id, 
		    vas_err_get_string(vasctx, 1));
        }
	printf("%s\n", sidstr);
    }

    /*
     * -sG sid => gid
     */
    else if (input == INPUT_SID && output == OUTPUT_GID) {
	vas_group_t *vasgrp;
	struct group *grent;

        if (vas_group_init(vasctx, vasid, str, VAS_NAME_FLAG_NO_LDAP, &vasgrp)){
	    errx(1, "vas_group_init '%.100s': %s", str, 
		    vas_err_get_string(vasctx, 1));
        }

	if (vas_group_get_grinfo(vasctx, vasid, vasgrp, &grent)) {
	    errx(1, "vas_group_get_pwinfo '%.100s': %s", str,
		    vas_err_get_string(vasctx, 1));
        }

	printf("%d\n", grent->gr_gid);
    }

    else {
        errx(1, "internal error: unreachable");
    }

    exit(0);
}

