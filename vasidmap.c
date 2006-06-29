/*===========================================================================
 * Project:     vusermap - Simple utility that returns the local Username
 *              that correspond to a mapped Windows user
 *
 * Author:      Simo Sorce <simo.sorce@quest.com>
 *              Matt Peterson <matt.peterson@quest.com>
 *
 * File:        vusermap.c
 *
 * Description: Main implementation source file
 *=========================================================================*/
/* (c) 2006 Quest Software, Inc. All rights reserved. */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>

#include <vas.h>

#define INPUT_NAME 0
#define INPUT_UID 1
#define INPUT_GID 2
#define INPUT_SID 3

#define OUTPUT_UID 1
#define OUTPUT_GID 2

static void usage(const char *progname);

static void usage(const char *progname)
{
    fprintf(stderr, 
            "Usage: %s [-f] [-ugsnUG] identifier\n"
	    "  Valid option combinations are:\n"
            "           account\n"
            "       -u  uid\n"
            "       -g  gid\n"
            "       -un user-name\n"
            "       -gn group-name\n"
            "       -sU user-sid\n"
            "       -sG group-sid\n",
	    progname);
}

/* Converts a string into a long, exiting on conversion errors */
long
strtougid(const char *s)
{
    long id;
    char *endptr = NULL;

    id = strtol(s, &endptr, 0);
    errno = 0;
    if (!*s || *endptr || errno == ERANGE)
	errx(1, "invalid uid/gid '%.100s'", s);

    return id;
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
    int exitcode = 1;
    
    if( vas_library_version_check( VAS_API_VERSION_MAJOR, 
                                   VAS_API_VERSION_MINOR,
                                   VAS_API_VERSION_MICRO ) )
        errx(1, "Requires " VAS_API_VERSION_STR " or newer");

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
        if (vas_id_alloc(vasctx, "host/", &vasid))
	    errx(1, "vas_id_alloc host/: %s", vas_err_get_string(vasctx, 1));

	if (vas_id_establish_cred_keytab(vasctx, vasid,
		   VAS_ID_FLAG_USE_MEMORY_CCACHE |
		   VAS_ID_FLAG_KEEP_COPY_OF_CRED, NULL))
	    errx(1, "vas_id_establish_cred_keytab: %s",
		   vas_err_get_string(vasctx, 1));
    }
    
    /*
     * account name => username
     */
    if ((input == INPUT_NAME)) {
        char *upn;
        const char *backslash;
	struct passwd *pwent;

	/* Strip leading domain from DOMAIN\USER names */
        if ((backslash = strchr(str, '\\')) != NULL)
            str = backslash + 1;

        if (vas_name_to_principal(vasctx, str, VAS_NAME_TYPE_USER,
		    VAS_NAME_FLAG_FOREST_SCOPE, &upn))
       	{
            warn("vas_name_to_principal '%.100s': %s", str,
                    vas_err_get_string(vasctx, 1));
            printf("UNKNOWN_USER");
	    exit(0);
        }

	errno = 0;
        if ((pwent = getpwnam(upn)) == NULL) {
	    err(1, "getpwnam '%.100s'", upn);
        }

        printf("%s\n", pwent->pw_name);
	exit(0);
    }

    /*
     * -u uid        => sid
     * -un username  => sid
     */
    if (input == INPUT_UID) {
        const char *id;
        char *sidstr;
	struct passwd *pwent;
	vas_user_t *vasuser;

	/* Convert '-u uid' into a username */
        if (!nflag) {
	    errno = 0;
	    if ((pwent = getpwuid(strtougid(str))) == NULL)
		err(1, "getpwuid '%.100s'", str);
            id = pwent->pw_name;
	} else
            id = str;

        if (vas_user_init(vasctx, vasid, id, VAS_NAME_FLAG_NO_LDAP, &vasuser))
	    errx(1, "vas_user_init '%.100s': %s", id, 
		    vas_err_get_string(vasctx, 1));

	if (vas_user_get_sid(vasctx, vasid, vasuser, &sidstr))
	    errx(1, "vas_user_get_sid '%.100s': %s", id, 
		    vas_err_get_string(vasctx, 1));
	printf("%s\n", sidstr);
	exit(0);
    }

    /*
     * -sU sid => uid
     */
    if (input == INPUT_SID && output == OUTPUT_UID) {
        char *sidstr;
	vas_user_t *vasuser;
	struct passwd *pwent;

        if (vas_user_init(vasctx, vasid, str, VAS_NAME_FLAG_NO_LDAP, &vasuser))
	    errx(1, "vas_user_init '%.100s': %s", str, 
		    vas_err_get_string(vasctx, 1));

	if (vas_user_get_pwinfo(vasctx, vasid, vasuser, &pwent)) 
	    errx(1, "vas_user_get_pwinfo '%.100s': %s", str,
		    vas_err_get_string(vasctx, 1));

	printf("%d\n", pwent->pw_uid);
	exit(0);
    }

    /*
     * -g gid        => sid
     * -gn groupname => sid
     */
    if (input == INPUT_GID) {
        const char *id;
        char *sidstr;
	vas_group_t *vasgrp;
	struct group *grent;

	/* Convert '-g gid' into a groupname */
        if (!nflag) {
	    errno = 0;
	    if ((grent = getgrgid(strtougid(str))) == NULL)
		err(1, "getpwgid '%.100s'", str);
            id = grent->gr_name;
        } else
            id = str;

        if (vas_group_init(vasctx, vasid, id, VAS_NAME_FLAG_NO_LDAP, &vasgrp))
	    errx(1, "vas_group_init '%.100s': %s", id, 
		    vas_err_get_string(vasctx, 1));

	if (vas_group_get_sid(vasctx, vasid, vasgrp, &sidstr))
	    errx(1, "vas_group_get_sid '%.100s': %s", id, 
		    vas_err_get_string(vasctx, 1));
	printf("%s\n", sidstr);
	exit(0);
    }

    /*
     * -sG sid => gid
     */
    if (input == INPUT_SID && output == OUTPUT_GID) {
        char *sidstr;
	vas_group_t *vasgrp;
	struct group *grent;

        if (vas_group_init(vasctx, vasid, str, VAS_NAME_FLAG_NO_LDAP, &vasgrp))
	    errx(1, "vas_group_init '%.100s': %s", str, 
		    vas_err_get_string(vasctx, 1));

	if (vas_group_get_grinfo(vasctx, vasid, vasgrp, &grent)) 
	    errx(1, "vas_group_get_pwinfo '%.100s': %s", str,
		    vas_err_get_string(vasctx, 1));

	printf("%d\n", grent->gr_gid);
	exit(0);
    }

    errx(1, "internal error: unreachable");
}

