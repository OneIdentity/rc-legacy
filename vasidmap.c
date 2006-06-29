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

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <vas.h>

static void display_usage( void )
{
    fprintf(stderr, 
            "Usage: vasidmap [options] <username|uid|gid|sid>\n"
	    "       options:\n"
	    "         -u input is a uid\n"
            "            -n input is a user name\n"
	    "         -g input is a gid\n"
            "            -n input is a group name\n"
	    "         -s input is a sid (requires -U|-G)\n"
	    "            -U output the uid\n"
	    "            -G output the gid\n"
	    "       default output is the unix username (UPM aware)\n");
}

#define INPUT_NAME 0
#define INPUT_UID 1
#define INPUT_GID 2
#define INPUT_SID 3

#define OUTPUT_UID 1
#define OUTPUT_GID 2

int main( int argc, char *argv[] )
{
    const char *str = NULL;
    vas_err_t vaserr = 0;
    vas_ctx_t *vasctx = NULL;
    vas_id_t *vasid = NULL;
    vas_user_t *vasuser = NULL;
    vas_group_t *vasgrp = NULL;
    struct passwd *pwent = NULL;
    struct group *grent = NULL;
    int input = 0, output = 0, force = 0, name = 0;
    
    if( vas_library_version_check( VAS_API_VERSION_MAJOR, 
                                   VAS_API_VERSION_MINOR,
                                   VAS_API_VERSION_MICRO ) ) {
        fprintf( stderr, 
                 "ERROR: Version of VAS API library is too old.  This program needs"
                 VAS_API_VERSION_STR" or newer.\n");

        vaserr = VAS_ERR_FAILURE;
        goto FINISHED;
                  
    }

    if (argc < 2) {
        goto OPTERROR;
    } else {
        int i;

        str = argv[argc-1];
        for (i = 1; i < argc-1; i++) {
	    if (argv[i][0] != '-') {
                goto OPTERROR; 
            }

            switch (argv[i][1]) {
            case 'f':
                force = 1;
                break;

            case 'u':
                if (input) {
                    fprintf(stderr, "ERROR: -u -g -s are mutually exclusive options.\n");
                    goto OPTERROR;
                }
                input = INPUT_UID;
                break;

            case 'g':
                if (input) {
                    fprintf(stderr, "ERROR: -u -g -s are mutually exclusive options.\n");
                    goto OPTERROR;
                }
                input = INPUT_GID;
                break;
 
            case 's':
                if (input) {
                    fprintf(stderr, "ERROR: -u -g -s are mutually exclusive options.\n");
                    goto OPTERROR;
                }
                input = INPUT_SID;
                break;

            case 'U':
                if (output) {
                    fprintf(stderr, "ERROR: -U -G are mutually exclusive options.\n");
                    goto OPTERROR;
                }
                output = OUTPUT_UID;
                break;

            case 'G':
                if (output) {
                    fprintf(stderr, "ERROR: -U -G are mutually exclusive options.\n");
                    goto OPTERROR;
                }
                output = OUTPUT_GID;
                break;

            case 'n':
                name = 1;
                break;

            default:
                /* no match throw an error */
                fprintf(stderr, "ERROR: invalid option [%s]\n", argv[i]);
                goto OPTERROR;
            }
        }

        if ( (name && (input == INPUT_SID)) ||
             (output && (input != INPUT_SID) ||
             (input == INPUT_SID) && (!output))
           ) {
            fprintf(stderr, "ERROR: invalid option combination\n");
            goto OPTERROR;
        }
    }

    if ((vaserr = vas_ctx_alloc(&vasctx))) {
        fprintf(stderr, 
                "ERROR: Unable to allocate VAS CTX. %s\n", 
                vas_err_get_string( vasctx, 1 ) );
        goto FINISHED;
    }

    if (force) {
        if ((vaserr = vas_id_alloc(vasctx, "host/", &vasid))) {
            fprintf(stderr, 
                    "ERROR: Unable to allocate VAS ID for 'host/'. %s\n", 
                    vas_err_get_string(vasctx, 1));
            goto FINISHED;
        }

        if ((vaserr = vas_id_establish_cred_keytab(vasctx,
                                                   vasid,
                                                   VAS_ID_FLAG_USE_MEMORY_CCACHE | 
                                                   VAS_ID_FLAG_KEEP_COPY_OF_CRED,
                                                    NULL))) {
            fprintf(stderr, 
                    "ERROR: Unable to establish credentials for 'host/'. %s\n", 
                    vas_err_get_string( vasctx, 1 ) );
            goto FINISHED;
        }
    }
    
    if ((input == INPUT_NAME)) {
        char *upn;
        const char *name;

        if ((name = strchr(str, '\\')) != NULL) {
            name++;
        } else {
            name = str;
        }

        if ((vaserr = vas_name_to_principal(vasctx,
                                            name,
                                            VAS_NAME_TYPE_USER,
                                            VAS_NAME_FLAG_FOREST_SCOPE,
                                            &upn))) {
            fprintf(stderr, 
                    "ERROR: Unable to initalize VAS user: %s. %s\n", 
                    str, vas_err_get_string(vasctx, 1));

            fprintf(stdout, "UNKNOWN_USER");
            goto FINISHED;
        }

        pwent = getpwnam(upn);
        if (pwent == NULL) {
	    fprintf (stderr, "ERROR: User not found! (errno=%d).\n", errno);
            free(upn);
	    goto FINISHED;
        }

        fprintf (stdout, "%s\n", pwent->pw_name);
        free(upn);
        vaserr = VAS_ERR_SUCCESS;
    }

    if ((input == INPUT_UID) ||
        ((input == INPUT_SID) && (output == OUTPUT_UID))) {
        char *sidstr;
        const char *id;

        if (name || output) {
            id = str;
        } else {
            uid_t uid;
            errno = 0;
            uid = strtol(str);
            if (errno) {
	        fprintf (stderr, "ERROR: Invalid User UID [%s]! (errno=%d).\n", str, errno);
	        goto FINISHED;
            }
            pwent = getpwuid(uid);
            if (pwent == NULL) {
	        fprintf (stderr, "ERROR: UID %s not found! (errno=%d).\n", str, errno);
	        goto FINISHED;
            }
            id = pwent->pw_name;
        }

        if ((vaserr = vas_user_init(vasctx, 
                                    vasid, 
                                    id, 
                                    VAS_NAME_FLAG_NO_LDAP, 
                                    &vasuser))) {
            fprintf(stderr, 
                    "ERROR: Unable to initalize VAS user with id: %s. %s\n", 
                    id,
                    vas_err_get_string(vasctx, 1));
            goto FINISHED;
        }

        if (input == INPUT_UID) {
            if ((vaserr = vas_user_get_sid(vasctx, vasid, vasuser, &sidstr))) {
                fprintf(stderr, 
                        "ERROR: Unable to obtain sid for user with id: %s. %s\n", 
                        id, vas_err_get_string(vasctx, 1));
                goto FINISHED;
            }

            fprintf(stdout, "%s\n", sidstr);
            free(sidstr);
            vaserr = VAS_ERR_SUCCESS;
        } else {
            if ((vaserr = vas_user_get_pwinfo(vasctx, vasid, vasuser, &pwent))) {
                fprintf(stderr,
                        "ERROR: Unable to obtain pwinfo for sid: %s. %s\n", 
                        sidstr, vas_err_get_string(vasctx, 1));
                goto FINISHED;
            }

            fprintf(stdout, "%d\n", pwent->pw_uid);
            vaserr = VAS_ERR_SUCCESS;
        }
    }

    if ((input == INPUT_GID) ||
        ((input == INPUT_SID) && (output == OUTPUT_GID))) {
        char *sidstr;
        const char *id;

        if (name || output) {
            id = str;
        } else {
            gid_t gid;
            errno = 0;
            gid = strtol(str);
            if (errno) {
	        fprintf (stderr, "ERROR: Invalid Group GID [%s]! (errno=%d).\n", str, errno);
	        goto FINISHED;
            }
            grent = getgrgid(gid);
            if (grent == NULL) {
	        fprintf (stderr, "ERROR: GID %s not found! (errno=%d).\n", str, errno);
	        goto FINISHED;
            }
            id = grent->gr_name;
        }

        if ((vaserr = vas_group_init(vasctx, 
                                     vasid, 
                                     id,
                                     VAS_NAME_FLAG_NO_LDAP, 
                                     &vasgrp))) {
            fprintf(stderr, 
                    "ERROR: Unable to initalize VAS group with id: %s. %s\n", 
                    id,
                    vas_err_get_string(vasctx, 1));
            goto FINISHED;
        }

        if (input == INPUT_GID) {
            if ((vaserr = vas_group_get_sid(vasctx, vasid, vasgrp, &sidstr))) {
                fprintf(stderr, 
                        "ERROR: Unable to obtain sid for group with id: %s. %s\n", 
                        id, vas_err_get_string(vasctx, 1));
                goto FINISHED;
            }

            fprintf(stdout, "%s\n", sidstr);
            free(sidstr);
            vaserr = VAS_ERR_SUCCESS;
        } else {
            if ((vaserr = vas_group_get_grinfo(vasctx, vasid, vasgrp, &grent))) {
                fprintf(stderr,
                        "ERROR: Unable to obtain grinfo for sid: %s. %s\n", 
                        sidstr, vas_err_get_string(vasctx, 1));
                goto FINISHED;

            }

            fprintf(stdout, "%d\n", grent->gr_gid);
            vaserr = VAS_ERR_SUCCESS;
        }
    }

FINISHED:
    if (vasuser) vas_user_free(vasctx, vasuser);
    if (vasgrp) vas_group_free(vasctx, vasgrp);
    if (vasid) vas_id_free(vasctx, vasid);
    if (vasctx) vas_ctx_free(vasctx);

    return vaserr;

OPTERROR:
    display_usage();
    vaserr = VAS_ERR_FAILURE;
    goto FINISHED;
}

