/* (c) 2009 Quest Software, Inc. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Quest Software, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * vasidmapd - minimal LDAP service intended to be used as a back-end
 * for Samba idmap_ldap.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>
#include <signal.h>
#include <stdlib.h>

#include <vas.h>
#include <ber.h>
#include <ldap.h>

#define VAS_API_VERSION_SUPPORTS(major,minor) \
            (VAS_API_VERSION_MAJOR == major && VAS_API_VERSION_MINOR >= minor)

#if !VAS_API_VERSION_SUPPORTS(4,2)
# error "Requires VAS 3.0.2 or later"
#endif

#if SIZEOF_GID_T == SIZEOF_LONG
# define GID_T_FMT    "%ld"
#elif SIZEOF_GID_T == SIZEOF_INT
# define GID_T_FMT    "%d"
#endif

#if SIZEOF_UID_T == SIZEOF_LONG
# define UID_T_FMT    "%ld"
#elif SIZEOF_UID_T == SIZEOF_INT
# define UID_T_FMT    "%d"
#endif

#if SIZEOF_PID_T == SIZEOF_LONG
# define PID_T_FMT    "%ld"
#elif SIZEOF_PID_T == SIZEOF_INT
# define PID_T_FMT    "%d"
#endif

#if HAVE_SYSLOG
# include <syslog.h>
# define DEBUG(level, fmt, va...) do { \
    if (debug >= level) \
        syslog(LOG_DAEMON | LOG_DEBUG, fmt , ## va); \
  } while (0)

/* Use syslog for warn() and err() */
#define warnx(fmt, va...) do {  \
    syslog(LOG_DAEMON | LOG_WARNING, fmt , ## va);  \
    warnx(fmt , ## va);  \
  } while (0)
#define warn(fmt, va...) do {  \
    syslog(LOG_DAEMON | LOG_WARNING, fmt ": %m" , ## va);  \
    warn(fmt , ## va);  \
  } while (0)
#define errx(ec, fmt, va...) do {  \
    syslog(LOG_DAEMON | LOG_ERR, fmt , ## va);  \
    errx(ec, fmt , ## va);  \
  } while (0)
#define err(ec, fmt, va...) do {  \
    syslog(LOG_DAEMON | LOG_ERR, fmt ": %m" , ## va);  \
    err(ec, fmt , ## va);  \
  } while (0)
#else
/* Prints a message to stderr only when the debug level is 
 * at 'level' or higher */
# define DEBUG(level, fmt, va...)  \
    do { if (debug >= level) fprintf(stderr, fmt , ## va); } while (0)
#endif

/* 
 * This convenience macro prints into a DER-encoded berval
 * in one step. It takes care of error handling.
 * On success, sets local variable ret to 0 and returns.
 * On error, sets ret to -1 and branches to the FINISHED label.
 */
#define BERVAL_PRINTF(reply, fmt, va...)                    \
    do {                                                    \
        BerElement *be = ber_alloc_t(BER_USE_DER);          \
        if (be == NULL) {                                   \
            warnx("ber_alloc_t failed");                    \
            ret = -1;                                       \
            goto FINISHED;                                  \
        }                                                   \
        ret = ber_printf(be, fmt , ## va);                  \
        if (ret == -1) {                                    \
            warnx("ber_printf failed");                     \
            ber_free(be, 1);                                \
            goto FINISHED;                                  \
        }                                                   \
        ret = ber_flatten(be, reply);                       \
        ber_free(be, 1);                                    \
        if (ret == -1) {                                    \
            warnx("ber_flatten failed");                    \
            goto FINISHED;                                  \
        }                                                   \
    } while (0)

#if !HAVE_SOCKLEN_T
# undef socklen_t
# define socklen_t int
#endif

/* Prototypes */
static void usage(const char *prog);
static int search_result_ok(ber_int_t msgid, struct berval **reply);
static int vlmapd_sid_to_id(vas_ctx_t *vasctx, vas_id_t *vasid, 
        ber_int_t msgid, char *sid, BerElement *berep);
static int vlmapd_uid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, 
        ber_int_t msgid, char *val, BerElement *berep);
static int vlmapd_gid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid,
        ber_int_t msgid, char *val, BerElement *berep);
static int vlmapd_search_idpool(ber_int_t msgid, struct berval **reply);
static int vlmapd_search(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid,
        BerElement *be, struct berval **reply);
static int vlmapd_bind(ber_int_t msgid, struct berval **reply);
static int vlmapd_generic_error(ber_int_t msgid, ber_tag_t msgtype,
        struct berval **reply);
static int vmapd_query(vas_ctx_t *vasctx, vas_id_t *vasid,
        struct berval *query, struct berval **reply);
static int vmapd_recv(int sd, struct berval *query);
static int vmapd_send(int sd, struct berval *reply);
static int vmapd_server(int sd);
static void become_daemon(void);


int debug;                          /* Set by the -d option */
const char *service_name = "host/"; /* Set by the -s option */

/* Displays command line usage message */
static void usage(const char *prog) 
{
        fprintf(stderr, "usage: %s"
               " [-A ipaddr] [-d level] [-p port]"
               " [-s spn]"
               " [-D] [-F]\n", prog);
}

/* Constructs the reply message: SEARCH_RESULT{SUCCESS} */
static int search_result_ok(ber_int_t msgid, struct berval **reply)
{
	int ret;

	BERVAL_PRINTF(reply, "{it{eoo}}", msgid, LDAP_RES_SEARCH_RESULT, 
                LDAP_SUCCESS, NULL, 0, NULL, 0);
FINISHED:
	return ret;
}

/* Common failure macro; logs a message and returns an empty search result */
#define FAIL(level, fmt, va...) do { \
        DEBUG(level, fmt , ## va); \
        goto FINISHED; \
    } while (0);

static int vlmapd_sid_to_id(vas_ctx_t *vasctx, vas_id_t *vasid,
                            ber_int_t msgid, char *sid, BerElement *berep)
{
    char num[12];
    char *attr;
    vas_user_t *vasuser = NULL;
    vas_group_t *vasgrp = NULL;
    struct passwd *pwent = NULL;
    struct group *grent = NULL;
    int major, minor;
    int ret;

    vas_product_version( &major, &minor, NULL);
    DEBUG(2, "libvas major: %d, minor: %d\n", major, minor);

    DEBUG(1, "\nLook up Unix ID for sid: %s\n", sid);

    /* check to see if the SID is a Group */
    DEBUG(1, "Looking up as group...\n");

    if ((vas_group_init(vasctx,
                        vasid, 
                        sid, 
                        VAS_NAME_FLAG_NO_LDAP,
                        &vasgrp )) == 0) {
        if (vas_group_get_grinfo(vasctx, 
                                 vasid, 
                                 vasgrp, 
                                 &grent) == 0) {
            snprintf(num, sizeof num, GID_T_FMT, grent->gr_gid);
            attr = "gidNumber";

            /* this version is bugged double check we actually really got a group */
            if (major == 3 && minor == 0) {
                if (grent->gr_mem[0] != NULL) {

                    /* If there are members this is definitively group */
                    goto SUCCESS;

                } else {

                    /* No members ... let's see if it is a user instead */                    
                    DEBUG(1, "Memberhip empty! Looking up as a user...\n");
                
                    if ((vas_user_init(vasctx,
                                       vasid,
                                       sid,
                                       VAS_NAME_FLAG_NO_LDAP,
                                       &vasuser)) == 0) {
                        if (vas_user_get_pwinfo(vasctx, 
                                                vasid, 
                                                vasuser, 
                                                &pwent) == 0) {
                            /* SID is a user.  Return Unix UID */
                            snprintf(num, sizeof num, UID_T_FMT, pwent->pw_uid);
                            attr = "uidNumber";

                            goto SUCCESS;
                        }
                    }
                    /* it wasn't a user after all let's go on assuming it is a group */
                }
            }

            goto SUCCESS;
        }
        else {

            DEBUG(1, 
                  "   WARNING: no grinfo. %s\n",
                  vas_err_get_string(vasctx, 1));

            if (major == 3 && minor == 0) { /* ( major == 3 && minor == 0 ) */
                /* 
                 * THIS IS A REALLY BAD HACK FOR VAS 3.0.X
                 *
                 * This code check an error string if it begins with "Group" we know that 
                 * this is a legitimate group that is not Unix enabled and we can goto 
                 * FINISHED with out trying to resolve the SID as a user 
                 *
                 * Yes, I know, this is a really bad hack. Fortunately this code will
                 * not be executed if we're on product version > 3.1.x 
                 */
                if ( strncmp( vas_err_get_string(vasctx, 1), "Group", 5) == 0 )
                {
                    FAIL(1, "ERROR: Could not map SID to a GID\n");
                }

                DEBUG(1, "   WARNING: may not be a group.\n" );
            }
            else { /* VAS 3.1 and later */
                FAIL(1, "ERROR: Could not map SID to a Unix ID\n");
	    }
        }
    }
    else {
        DEBUG(1,
              "   WARNING: Unable to initialize VAS group. %s\n",
              vas_err_get_string(vasctx, 1));
    }

    /* check to see if the SID is a User */
    DEBUG(1, "Looking up as a user...\n");

    if ((vas_user_init(vasctx,
                       vasid,
                       sid,
                       VAS_NAME_FLAG_NO_LDAP,
                       &vasuser)) == 0) {
        if (vas_user_get_pwinfo(vasctx, 
                                vasid, 
                                vasuser, 
                                &pwent) == 0) {
            /* SID is a user.  Return Unix UID */
            snprintf(num, sizeof num, UID_T_FMT, pwent->pw_uid);
            attr = "uidNumber";
        }
        else {
            FAIL(1, 
                  "   ERROR: no pwinfo. %s\n",
                  vas_err_get_string(vasctx, 1));
        }
    }
    else {
        FAIL(1, 
              "   ERROR: Unable to initalize VAS user. %s\n", 
              vas_err_get_string(vasctx, 1));
    }

SUCCESS:
    DEBUG(1, 
          "SUCCESS: converted SID to %s: %s.\n",
          pwent?"UID":"GID", 
          num);

    ret = ber_printf(berep, "{it{s{{s{s}}{s{s}}{s{s}}}}}",
                  msgid, LDAP_RES_SEARCH_ENTRY,
                  "CN=VAS-Idmapper",
                  "sambaSID",sid,
                  "objectClass", "sambaIdmapEntry",
                  attr, num);

FINISHED:
    if ( vasuser ) vas_user_free( vasctx, vasuser );
    if ( vasgrp ) vas_group_free( vasctx, vasgrp );
    if ( pwent ) free( pwent );
    if ( grent ) free( grent );

    return ret;
}

static int vlmapd_uid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, 
        ber_int_t msgid, char *val, BerElement *berep)
{
	vas_user_t *vasuser;
	struct passwd *pwent = NULL;
	char *sid;
	uid_t uid;
	int ret;

	errno = 0;
	uid = (uid_t)strtol(val, NULL, 10);
	if (errno != 0) {
		DEBUG(1, "ERROR Conversion to uid_t failed.\n"
                         "            (val=[%s],errno=%d)\n", 
                         val, errno);
		return 0;
	}

	if (uid == 0) {
		DEBUG(1, "ERROR: not handling request for uid 0\n");
		return 0;
	}

	if ((pwent = getpwuid(uid)) == NULL) {
		DEBUG(1, "ERROR: uid (%d) not found!\n", uid);
		return 0;
	}

	if (strcmp(pwent->pw_passwd, "VAS") != 0) {
	    DEBUG(1, "ERROR: uid " UID_T_FMT " not from VAS\n", uid);
	    return 0;
	}

	if ((vas_user_init(vasctx, vasid, pwent->pw_name,
				   VAS_NAME_FLAG_FOREST_SCOPE,
				   &vasuser)) != VAS_ERR_SUCCESS) {
		DEBUG(1, "ERROR Unable to initalize VAS user:%s.\n"
                         "            [%s]\n",
                         pwent->pw_name,
                         vas_err_get_string(vasctx, 1));
		return 0;
	}

	if ((vas_user_get_sid(vasctx, vasid, vasuser, &sid)) != VAS_ERR_SUCCESS) {
		DEBUG(1, "ERROR Unable to get the SID of user %s.\n"
                         "            [%s]\n",
			 sid,
			 vas_err_get_string(vasctx, 1));
		vas_user_free(vasctx, vasuser);
		return 0;
	}

	vas_user_free(vasctx, vasuser);

	DEBUG(1, "SUCCESS: converted UID " UID_T_FMT " to SID %s.\n", uid, sid);

        ret = ber_printf(berep, "{it{s{{s{s}}{s{s}}{s{s}}}}}",
		        msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			"uidNumber", val);

	return ret;
}

static int vlmapd_gid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *val, BerElement *berep)
{
	vas_group_t *vasgrp;
	struct group *grent = NULL;
	char *sid;
	gid_t gid;
	int ret;

	errno = 0;
	gid = (gid_t)strtol(val, NULL, 10);
	if (errno != 0) {
		DEBUG(1, "ERROR Conversion to gid_t failed.\n"
                         "            (val=[%s],errno=%d)\n", 
                         val, errno);
		return 0;
	}

	if (gid == 0) {
	    DEBUG(1, "ERROR: not handling request for gid 0\n");
	    return 0;
	}

	if ((grent = getgrgid(gid)) == NULL) {
		DEBUG(1, "ERROR: gid " GID_T_FMT " not found!\n", gid);
		return 0;
	}

	if (strcmp(grent->gr_passwd, "VAS") != 0) {
	    DEBUG(1, "ERROR: gid " GID_T_FMT " not from VAS\n", gid);
	    return 0;
	}

	if ((vas_group_init(vasctx, vasid, grent->gr_name,
				    VAS_NAME_FLAG_FOREST_SCOPE,
				    &vasgrp)) != VAS_ERR_SUCCESS) {
		DEBUG(1, "ERROR Unable to initalize VAS group:%s.\n"
                         "            [%s]\n",
                         grent->gr_name,
                         vas_err_get_string(vasctx, 1));
		return 0;
	}

	if ((vas_group_get_sid(vasctx, vasid, vasgrp, &sid)) != VAS_ERR_SUCCESS) {
		DEBUG(1, "ERROR Unable to get the SID"
                         " of group %s.\n"
                         "            [%s]\n",
			 sid,
			 vas_err_get_string(vasctx, 1));
		vas_group_free(vasctx, vasgrp);
		return 0;
	}

	vas_group_free(vasctx, vasgrp);

        DEBUG(1, "SUCCESS: converted GID " GID_T_FMT " to SID %s.\n", gid, sid);

        ret = ber_printf(berep, "{it{s{{s{s}}{s{s}}{s{s}}}}}",
		        msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			"gidNumber", val);

	return ret;
}

static int vlmapd_search_idpool(ber_int_t msgid, struct berval **reply)
{
	int ret;

	/* return a face unixidpool entry with uidNumber, 
         * gidNumber and objectclass */

	BERVAL_PRINTF(reply, "{it{s{{s{s}}{s{s}}{s{s}}}}}{it{eoo}}",
			 msgid, LDAP_RES_SEARCH_ENTRY,
				"CN=VAS-Idmapper",
				"objectClass", "sambaUnixIdPool",
				"uidNumber", "1000",
				"gidNumber", "1000",
			 msgid, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS, 
                         NULL, 0, NULL, 0);
FINISHED:
	return ret;
}

#define FILTER_TAG_AND              0xA0
#define FILTER_TAG_OR               0xA1
#define FILTER_TAG_EQUALITY_MATCH   0xA3
#define FILTER_TAG_PRESENT          0x87

/* Handles an LDAP search request, and constructs a reply. */
static int vlmapd_search(vas_ctx_t *vasctx, vas_id_t *vasid, 
        ber_int_t msgid, BerElement *be, struct berval **reply)
{
	BerElement *berep;
	ber_tag_t ft, tag;
	char name[4096], val[4096];
	int nl, vl;
	int multi = 0;
	int ret;

	/* Skip everything up to the Filter 
         * ("seeiib" -> dn, deref, sizel, timel, typesb)
         * See RFC 2251 section 4.5.1
         */
	ret = ber_scanf(be, "xxxxxxt", &ft);
	if (ret == -1) {
                warnx("malformed SearchRequest");
		return -1;
	}

        DEBUG(3, "search filter tag %02x\n", ft);

	switch (ft) {

	case FILTER_TAG_PRESENT: /* 87 */
		nl = sizeof name;
		ret = ber_scanf(be, "s", name, &nl);
		if (ret == -1) {
                        warnx("malformed AttributeDescription");
			return -1;
		}
                DEBUG(3, "(%.*s=*)\n", nl, name);
		/* XXX if name=="objectclass" then we should dump all 
		 * objects? */
		ret = search_result_ok(msgid, reply);
		break;
	       
	case FILTER_TAG_EQUALITY_MATCH: /* a3 */
		/* equality check what is it about */
		nl = sizeof name;
                vl = sizeof val;
		ret = ber_scanf(be, "{ss}", name, &nl, val, &vl);
		if (ret == -1) {
                        warnx("malformed AttributeValueAssertion");
			return -1;
		}
                DEBUG(3, "(%.*s=%.*s)\n", nl, name, vl, val);
		if (strncasecmp(name, "objectclass", nl) == 0) {
			if (strncasecmp(val, "sambaUnixIdPool", vl) == 0) {
				ret = vlmapd_search_idpool(msgid, reply);
				break;
			}	
		}

		/* return nothing for everything else */
		ret = search_result_ok(msgid, reply);
		break;

	case FILTER_TAG_AND: /* a0 */
                berep = ber_alloc_t(BER_USE_DER);
                if (berep == NULL) {
                        warnx("ber_alloc_t failed");
                        return -1;
                }

		/* and filter we need further investigation */
		nl = sizeof name;
                vl = sizeof val;
		ret = ber_scanf(be, "{{ss}", name, &nl, val, &vl);
		if (ret == -1) {
                        warnx("expected filter (&(=)...)");
			ber_free(berep, 1);
			return -1;
		}

                DEBUG(3, "(&(%.*s=%.*s)...)\n", nl, name, vl, val);

		if (strncasecmp(name, "objectclass", nl) != 0 ||
                    strncasecmp(val, "sambaIdmapEntry", vl) != 0) {
			/* return nothing for everything else */
			ret = search_result_ok(msgid, reply);
			break;
		}

		tag = ber_peek_tag(be, &nl);
		if (tag == FILTER_TAG_OR) {
			multi = 1;
			ret = ber_scanf(be, "{");
		} else if (tag == FILTER_TAG_EQUALITY_MATCH) {
			multi = 0;
		} else {
			warnx("invalid filter tag, expected (=) or (|...)");
			ber_free(berep, 1);
			return -1;
		}
		ret = 0;

		while (ret != -1) {
                        nl = sizeof name;
                        vl = sizeof val;
                        ret = ber_scanf(be, "{ss}", name, &nl, val, &vl);
                        if (ret == -1) {
				/* end of sequence? */
				continue;
                        }
                        DEBUG(3, "(&...(%.*s=%.*s))\n", nl, name, vl, val);

                        if (strncasecmp(name, "sambaSID", nl) == 0) {
                                vlmapd_sid_to_id(vasctx, vasid, msgid, val, berep);

                        } else if (strncasecmp(name, "uidNumber", nl) == 0) {
                                vlmapd_uid_to_sid(vasctx, vasid, msgid, val, berep);

                        } else if (strncasecmp(name, "gidNumber", nl) == 0) {
                                vlmapd_gid_to_sid(vasctx, vasid, msgid, val, berep);

                        } else {
                                DEBUG(1, "skipping unexpected attribute request: [%s]\n", name);
                        }

			/* to tell if we are done with the filter, see if the
			 * next section is a filter tag (equality) or not. If
			 * it's not, then we don't want to parse the attrs or
			 * later sections of the be */
			tag = ber_peek_tag(be, &nl);
			if (tag != FILTER_TAG_EQUALITY_MATCH)
			    break;
		}

		ret = ber_scanf(be, "}");
		if (ret == -1) {
			warnx("expected filter end");
			ber_free(berep, 1);
			return -1;
		}
		if (multi) {
			ret = ber_scanf(be, "}");
			if (ret == -1) {
				warnx("expected filter end");
				ber_free(berep, 1);
				return -1;
			}
		}

                /* end results message */
                ret = ber_printf(berep, "{it{eoo}}",
                                 msgid, LDAP_RES_SEARCH_RESULT,
                                 LDAP_SUCCESS,
                                 NULL, 0,
                                 NULL, 0);
		if (ret == -1) {
                        warnx("ber_printf failed");
                        ber_free(berep, 1);
		}
	
                ret = ber_flatten(berep, reply);
                ber_free(berep, 1);
                if (ret == -1) {
                        warnx("ber_flatten failed");
			return -1;
                }
		break;

	default:
		/* answer all is ok */
		ret = search_result_ok(msgid, reply);
		break;
	}

	return ret;
}

static int vlmapd_bind(ber_int_t msgid, struct berval **reply)
{
	int ret;

        DEBUG(1, "returning success to a BindRequest\n");

	BERVAL_PRINTF(reply, "{it{eoo}}", msgid, LDAP_RES_BIND, 
                LDAP_SUCCESS, NULL, 0, NULL, 0);
FINISHED:
	return ret;
}

static int vlmapd_generic_error(ber_int_t msgid, ber_tag_t msgtype, 
        struct berval **reply)
{
	int ret;

	DEBUG(1, "returning error on non-search request\n");

	BERVAL_PRINTF(reply, "{it{eoo}}", msgid, msgtype + 1,
                LDAP_INSUFFICIENT_ACCESS, NULL, 0, NULL, 0);
FINISHED:
	return ret;
}

static int vmapd_query(vas_ctx_t *vasctx, vas_id_t *vasid, 
        struct berval *query, struct berval **reply)
{
	BerElement *be;
	ber_int_t msgid;
	ber_tag_t msgtype;
        int ret;

	be = ber_init(query);
	if (be == NULL) {
                warnx("malformed query");
		ret = -1;
                goto FINISHED;
	}

	ret = ber_scanf(be, "{it{", &msgid, &msgtype) == BER_ERROR ? -1 : 0;
        if (ret == -1) {
            warnx("malformed query");
            goto FINISHED;
        }

	switch (msgtype) {
	case LDAP_REQ_BIND:
		ret = vlmapd_bind(msgid, reply);
                break;
	case LDAP_REQ_SEARCH:
		ret = vlmapd_search(vasctx, vasid, msgid, be, reply);
                break;
	default:
		ret = vlmapd_generic_error(msgid, msgtype, reply);
                break;
	}

FINISHED:
        if (be) {
            ber_free(be, 1);
        }
	return ret;
}

#define SHORT_MSG_SIZE 129

/* Reads a <tag,value,len> from the wire into a berval structure.
 * Checks that it is a SEQUENCE (LDAPMessage).
 * On success, returns 0, and caller must free query->bv_val.
 * On error, return -1.
 * On connection closed with no bytes read, returns -2.
 */
static int vmapd_recv(int sd, struct berval *query)
{
	ssize_t ret;
	ssize_t len;
	unsigned char *buf, *newbuf;
	int skip, target, vlen;

	buf = (unsigned char *)malloc(SHORT_MSG_SIZE);
        if (buf == NULL) {
            warnx("malloc");
            ret = -1;
            goto FINISHED;
        }

        /* Read the SEQUENCE tag and first DER length byte */
        target = 2;
        for (skip = 0; skip < target; skip += len) {
            len = read(sd, buf + skip, target - skip);
            if (len < 0) {
                warn("read");
                ret = -1;
                goto FINISHED;
            }
            if (len == 0) {
                if (skip == 0) {
                    ret = -2;
                } else {
                    warnx("connection lost");
                    ret = -1;
                }
                goto FINISHED;
            }
        }


        /* Expect a SEQUENCE tag */
	if (buf[0] != BER_SEQUENCE) {
            warnx("protocol error (buf[0] = %02x)", buf[0]);
            ret = -1;
            goto FINISHED;
        }

        /* If the length has the msb set, then a length word follows */
	if (buf[1] & 0x80) {
		int n, i;

		n = buf[1] & 0x7F;
                if (n > sizeof vlen) {
                    warnx("LDAPMessage length too long or corrupted");
                    ret = -1;
                    goto FINISHED;
                }

                /* Read in the n-byte length word */
                for (target += n; skip < target; skip += len) {
                    len = read(sd, buf + skip, target - skip);
                    if (len < 0) {
                        warn("read");
                        ret = -1;
                        goto FINISHED;
                    }
                    if (len == 0) {
                        warnx("connection lost");
                        ret = -1;
                        goto FINISHED;
                    }
                }

                /* Convert the word into a native integer */
		vlen = 0;
                for (i = 0; i < n; i++) {
                    vlen = (vlen << 8) | buf[i+2];
		}
                if (vlen < 0) { /* Check for overflow */
                    warnx("LDAPMessage length too long or corrupted");
                    ret = -1;
                    goto FINISHED;
                }

                /* Resize the buffer before we read in the value part */
                if (vlen + skip > SHORT_MSG_SIZE) {
                    newbuf = (unsigned char *)realloc(buf, skip + vlen);
                    if (newbuf == NULL) {
                        warnx("realloc: could not allocate %u bytes", 
                                skip + vlen);
                        ret = -1;
                        goto FINISHED;
                    }
                    buf = newbuf;
		}
	} else { /* simple length */
		vlen = buf[1];
	}

        /* Read the value part of the TLV */
        for (target += vlen; skip < target; skip += len) {
            len = read(sd, buf + skip, target - skip);
            if (len < 0) {
                warn("read");
                ret = -1;
                goto FINISHED;
            }
            if (len == 0) {
                warnx("connection lost");
                ret = -1;
                goto FINISHED;
            }
        }

	query->bv_val = (char *)buf;
	query->bv_len = skip;
        ret = 0;

FINISHED:
        if (buf && ret != 0)
            free(buf);
	return ret;
}

/* Writes a berval onto the wire */
static int vmapd_send(int sd, struct berval *reply)
{
	ssize_t wlen, s = 0;

        for (s = 0; s < reply->bv_len; s += wlen) {
		wlen = write(sd, (char *)reply->bv_val + s, 
                        reply->bv_len - s);
		if (wlen < 0) {
                        warn("write");
                        return -1;
		}
		s += wlen;
	}
	return 0;
}

/* Services one LDAP query. Returns 0 on success */
static int vmapd_server(int sd)
{
	vas_ctx_t *vasctx = NULL;
	vas_id_t *vasid = NULL;
	struct berval query;
	struct berval *reply;
	int opt, ret = 0;
        vas_err_t error;

	query.bv_val = NULL;
	reply = NULL;

	opt = 1;
	if (setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (const void *)&opt, sizeof opt) < 0)
            warn("setsockopt TCP_NODELAY");

	if ((error = vas_ctx_alloc(&vasctx))) {
                warnx("vas_ctx_alloc: error %d%s", error,
                    error == VAS_ERR_NO_MEMORY ? ": no memory" :
                    error == VAS_ERR_INVALID_PARAM ? ": invalid param" : "");
		goto FINISHED;
	}

        if ((vas_id_alloc(vasctx, service_name, &vasid))) {
                warnx("vas_id_alloc %s: %s", service_name,
                        vas_err_get_string(vasctx, 1));
		goto FINISHED;
        }

        if ((vas_id_establish_cred_keytab(vasctx, vasid,
                                VAS_ID_FLAG_USE_MEMORY_CCACHE |
                                VAS_ID_FLAG_KEEP_COPY_OF_CRED,
				NULL))) {
                warnx("vas_id_establish_cred_keytab %s: %s", service_name,
			vas_err_get_string(vasctx, 1));
		goto FINISHED;
        }

	while (1) {

		ret = vmapd_recv(sd, &query);
		if (ret != 0) {
			goto FINISHED;
		}
		DEBUG(2, "QUERY successfully received\n");

		ret = vmapd_query(vasctx, vasid, &query, &reply);
		if (ret != 0) {
			goto FINISHED;
		}

		DEBUG(2, "REPLY successfully delivered\n");
		ret = vmapd_send(sd, reply);
		if (ret != 0) {
			goto FINISHED;
		}
	}

FINISHED:
	if (query.bv_val) free(query.bv_val);
	if (reply) ber_bvfree(reply);
	if (vasid) vas_id_free(vasctx, vasid);
	if (vasctx) vas_ctx_free(vasctx);
	return ret;
}

/* Double fork to become a daemon */
static void become_daemon () {
        switch (fork()) {
            case -1: err(1, "fork");
            case 0: break;
            default: _exit(0);
        }
        switch (fork()) {
            case -1: err(1, "fork");
            case 0: break;
            default: _exit(0);
        }
}

int main (int argc, char *argv[])
{
	int sd;
	struct sockaddr_in sockin;
	int len, ret;
        int ch, error = 0;
        int daemonize = 1;
        int port = 389;
        const char *bindaddr = "127.0.0.1";
        extern int optind;
        extern char *optarg;
#if defined(SO_REUSEADDR)
        int opt;
#endif

        /* Process command line arguments */
        while ((ch = getopt(argc, argv, "A:d:DFp:s:V")) != -1) {
            switch (ch) {
                case 'A': bindaddr = optarg; break;
                case 'd': debug = atoi(optarg); break;
                case 'p': port = atoi(optarg); break;
                case 'D': daemonize = 1; break;
                case 'F': daemonize = 0; break;
                case 's': service_name = optarg; break;
		case 'V':
		    printf("vasidmapd %s VAS %s\n",
			    PACKAGE_VERSION,
			    vas_library_version(0,0,0));
		    exit(0);
                default: error = 1;
            }
        }
        if (optind < argc) {
            error = 1;
        }
        if (error) {
            usage(argv[0]);
            exit(1);
        }

#if HAVE_SYSLOG
        openlog("vasidmapd", daemonize ? LOG_CONS | LOG_PID : 0, LOG_DAEMON);
#endif

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
                err(5, "socket");
	}

#if defined(SO_REUSEADDR)
	opt = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, 
                    (const void *)&opt, sizeof opt) < 0)
        {
            warn("setsockopt SO_REUSEADDR");
        }
#endif

        /* Construct a listening server socket at port 389 LDAP */
        memset(&sockin, 0, sizeof sockin);
	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(port);
        if (inet_pton(AF_INET, bindaddr, &sockin.sin_addr) <= 0) {
            errx(1, "bad IP address '%s'", bindaddr);
        }

	len = sizeof(sockin);
	ret = bind(sd, (struct sockaddr *)&sockin, len);
	if (ret == -1) {
                err(6, "bind");
	}

	ret = listen(sd, 5);
	if (ret == -1) {
                err(6, "listen");
	}

	if (daemonize) {
                become_daemon();
        }

        /* Ignore child exit signals to avoid zombie processes */
        if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
            err(1, "signal");
        }

	while (1) {
		int new, ret;
		struct sockaddr addr;
		socklen_t addrlen = sizeof addr;
		pid_t pid;

                addrlen = sizeof addr;
		new = accept(sd, (struct sockaddr *)&addr, &addrlen);
		if (new == -1) {
                        warn("accept");
			continue;
		}

		pid = fork();
                switch (pid) {
                    case -1: /* error */
                        warn("fork");
			close(new);
			continue;
                    case 0: /* child */
                        close(sd);
			ret = vmapd_server(new);
			close(new);
			_exit(ret);
                    default: /* parent */
			close(new);
		}
	}
}
