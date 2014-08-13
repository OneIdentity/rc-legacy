/* (c) 2014 Dell Software, Inc. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Dell Software, Inc. nor the names of its
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
#include <sys/stat.h>
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
#include <time.h>

#include <vas.h>
#include <ber.h>
#include <ldap.h>

#include <signal.h>
#include <fcntl.h>
#include <string.h>

#define VAS_API_VERSION_SUPPORTS(major,minor) \
            (VAS_API_VERSION_MAJOR == major && VAS_API_VERSION_MINOR >= minor)

#if !VAS_API_VERSION_SUPPORTS(4,2)
# error "Requires VAS 3.0.2 or later"
#endif

#if SIZEOF_GID_T == SIZEOF_LONG && SIZEOF_LONG != SIZEOF_INT
# define GID_T_FMT    "%ld"
#elif SIZEOF_GID_T == SIZEOF_INT
# define GID_T_FMT    "%d"
#endif

#if SIZEOF_UID_T == SIZEOF_LONG && SIZEOF_LONG != SIZEOF_INT
# define UID_T_FMT    "%ld"
#elif SIZEOF_UID_T == SIZEOF_INT
# define UID_T_FMT    "%d"
#endif

#if SIZEOF_PID_T == SIZEOF_LONG && SIZEOF_LONG != SIZEOF_INT
# define PID_T_FMT    "%ld"
#elif SIZEOF_PID_T == SIZEOF_INT
# define PID_T_FMT    "%d"
#endif

#if HAVE_SYSLOG
# include <syslog.h>

# define LOG(level, fmt, va...) do { \
  if (debug != VLMAPD_NOT_DEFINED) { \
    if (debug >= level) \
      fprintf(stderr, fmt, ##va); \
  } else \
      syslog(LOG_DAEMON | level, fmt, ## va); \
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
# define LOG(level, fmt, va...)  \
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

typedef enum vlmapd_err {
       VLMAPD_NOT_DEFINED      = -2,
       VLMAPD_ERROR            = -1,
       VLMAPD_SUCCESS          =  0,
       VLMAPD_FAILURE      =  1,
       VLMAPD_SUCCESS_EXIT =  2,
       VLMAPD_FAILURE_EXIT =  3
} vlmapd_err_t;

/* Prototypes */
static void usage(const char *prog);
static int search_result_ok(ber_int_t msgid, struct berval **reply);
static int vlmapd_sid_to_id(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *sid, BerElement *berep);
static int vlmapd_uid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *val, BerElement *berep);
static int vlmapd_gid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *val, BerElement *berep);
static int vlmapd_search_idpool(ber_int_t msgid, struct berval **reply);
static int vlmapd_search(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, BerElement *be, struct berval **reply);
static int vlmapd_bind(ber_int_t msgid, struct berval **reply);
static int vlmapd_generic_error(ber_int_t msgid, ber_tag_t msgtype, struct berval **reply);
static int vmapd_query(vas_ctx_t *vasctx, vas_id_t *vasid, struct berval *query, struct berval **reply);
static int vmapd_recv(int sd, struct berval *query);
static int vmapd_send(int sd, struct berval *reply);
static int vmapd_server(int sd);

static int vlmapd_write_pidfile_with_lock(pid_t pid);
static int vlmapd_open_pid_file(const char* pidfile);

static vlmapd_err_t become_daemon(void);
static vlmapd_err_t vlmapd_check_for_lock(int fd, pid_t pid, const char* pidfile);
static vlmapd_err_t vlmapd_set_lock(int fd, pid_t pid, const char *pidfile);
static vlmapd_err_t vlmapd_stat_file(const char* pidfile);

static void vlmapd_signal_handler(int);
static void vlmapd_cleanup(int socket_fd, int pid_fd);

void vlmapd_init_signals(void);

int debug = VLMAPD_NOT_DEFINED;                          /* Set by the -d option */
const char *service_name = "host/";                      /* Set by the -s option */
const char *pidfile = "/var/run/vasidmapd.pid";  /* Set by the -P option */

/* If set to > 0 then we created the pidfile and need to clean it up */
int remove_pidfile = 0;

/* Flag set by the signal handler when an signal is caught */
int VLMAPD_SIGNAL = VLMAPD_NOT_DEFINED;

/* Displays command line usage message */
static void usage(const char *prog) 
{
        fprintf(stderr, "usage: %s"
               " [-hDFV]"
               " [-A ipaddr] [-d level] [-p port]"
               " [-s spn]"
               " [-P pidfile]\n", prog);

        fprintf(stderr, 
               "-h             Display usage\n"
               "-D             Run in daemon mode: fork-and-detach from the controlling terminal\n"
               "-F             Don't fork-and-detach from the controlling terminal\n"
			   "-V             Causes the daemon to print its version number and exit immediately\n"
               "-A ipaddr      Address to listen for idmap requests\n"
               "-d level       Prints debug to stderr, otherwise logging goes\n"
			   "               through syslog if available. Valid debug levels are 0 - 7\n"
               "-p port        Port to listen for idmap requests on\n"
               "-s spn         Service name to be used when establishing creds. Default is host/\n"
               "-P pidfile     The pid file to use. Default is: /var/run/vasidmapd.pid\n"
               );
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
        LOG(level, fmt , ## va); \
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
    LOG(LOG_INFO, "libvas major: %d, minor: %d\n", major, minor);

    LOG(LOG_INFO, "Look up Unix ID for sid: %s\n", sid);

	if( strcmp(sid, "S-1-1-0") == 0 || strcmp(sid, "S-1-5-2") == 0 || strcmp(sid, "S-1-5-11") == 0 ) {
		LOG(LOG_INFO, "%s is a well known sid. Ignoring the request\n", sid);
		goto FINISHED;
	}

    /* check to see if the SID is a Group */
    LOG(LOG_DEBUG, "Looking up as group...\n");

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
                    LOG(LOG_DEBUG, "Memberhip empty! Looking up as a user...\n");
                
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

            LOG(LOG_WARNING, "   WARNING: no grinfo. %s\n",
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
                    FAIL(LOG_ERR, "ERROR: Could not map SID to a GID\n");
                }

                LOG(LOG_WARNING, "   WARNING: may not be a group.\n" );
            }
            else { /* VAS 3.1 and later */
                FAIL(LOG_ERR, "ERROR: Could not map SID to a Unix ID\n");
	    }
        }
    }
    else {
        LOG(LOG_WARNING,
              "   WARNING: Unable to initialize VAS group. %s\n",
              vas_err_get_string(vasctx, 1));
    }

    /* check to see if the SID is a User */
    LOG(LOG_DEBUG, "Looking up as a user...\n");

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
            FAIL(LOG_ERR, 
                  "   ERROR: no pwinfo. %s\n",
                  vas_err_get_string(vasctx, 1));
        }
    }
    else {
        FAIL(LOG_ERR, 
              "   ERROR: Unable to initalize VAS user. %s\n", 
              vas_err_get_string(vasctx, 1));
    }

SUCCESS:
    LOG(LOG_INFO, 
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
		LOG(LOG_ERR, "ERROR Conversion to uid_t failed.\n"
                         "            (val=[%s],errno=%d)\n", 
                         val, errno);
		return 0;
	}

	if (uid == 0) {
		LOG(LOG_ERR, "ERROR: not handling request for uid 0\n");
		return 0;
	}

	if ((pwent = getpwuid(uid)) == NULL) {
		LOG(LOG_ERR, "ERROR: uid (%d) not found!\n", uid);
		return 0;
	}

	if (strcmp(pwent->pw_passwd, "VAS") != 0) {
	    LOG(LOG_ERR, "ERROR: uid " UID_T_FMT " not from VAS\n", uid);
	    return 0;
	}

	if ((vas_user_init(vasctx, vasid, pwent->pw_name,
				   VAS_NAME_FLAG_FOREST_SCOPE,
				   &vasuser)) != VAS_ERR_SUCCESS) {
		LOG(LOG_ERR, "ERROR Unable to initalize VAS user:%s.\n"
                         "            [%s]\n",
                         pwent->pw_name,
                         vas_err_get_string(vasctx, 1));
		return 0;
	}

	if ((vas_user_get_sid(vasctx, vasid, vasuser, &sid)) != VAS_ERR_SUCCESS) {
		LOG(LOG_ERR, "ERROR Unable to get the SID of user %s.\n"
                         "            [%s]\n",
			 sid,
			 vas_err_get_string(vasctx, 1));
		vas_user_free(vasctx, vasuser);
		return 0;
	}

	vas_user_free(vasctx, vasuser);

	LOG(LOG_INFO, "SUCCESS: converted UID " UID_T_FMT " to SID %s.\n", uid, sid);

        ret = ber_printf(berep, "{it{s{{s{s}}{s{s}}{s{s}}}}}",
		        msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			"uidNumber", val);

    if(sid) free(sid);

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
		LOG(LOG_ERR, "ERROR Conversion to gid_t failed.\n"
                         "            (val=[%s],errno=%d)\n", 
                         val, errno);
		return 0;
	}

	if (gid == 0) {
	    LOG(LOG_ERR, "ERROR: not handling request for gid 0\n");
	    return 0;
	}

	if ((grent = getgrgid(gid)) == NULL) {
		LOG(LOG_ERR, "ERROR: gid " GID_T_FMT " not found!\n", gid);
		return 0;
	}

	if ((vas_group_init(vasctx, vasid, grent->gr_name,
				    VAS_NAME_FLAG_FOREST_SCOPE,
				    &vasgrp)) != VAS_ERR_SUCCESS) {
		LOG(LOG_ERR, "ERROR Unable to initalize VAS group:%s.\n"
                         "            [%s]\n",
                         grent->gr_name,
                         vas_err_get_string(vasctx, 1));
		return 0;
	}

	if ((vas_group_get_sid(vasctx, vasid, vasgrp, &sid)) != VAS_ERR_SUCCESS) {
		LOG(LOG_ERR, "ERROR Unable to get the SID"
                         " of group %s.\n"
                         "            [%s]\n",
			 sid,
			 vas_err_get_string(vasctx, 1));
		vas_group_free(vasctx, vasgrp);
		return 0;
	}

	vas_group_free(vasctx, vasgrp);

        LOG(LOG_INFO, "SUCCESS: converted GID " GID_T_FMT " to SID %s.\n", gid, sid);

        ret = ber_printf(berep, "{it{s{{s{s}}{s{s}}{s{s}}}}}",
		        msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			"gidNumber", val);

    if(sid) free(sid);

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
		return ret;
	}

        LOG(LOG_DEBUG, "search filter tag %02x\n", ft);

	switch (ft) {

	case FILTER_TAG_PRESENT: /* 87 */
		nl = sizeof name;
		ret = ber_scanf(be, "s", name, &nl);
		if (ret == -1) {
                        warnx("malformed AttributeDescription");
			return ret;
		}
                LOG(LOG_DEBUG, "(%.*s=*)\n", nl, name);
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
			return ret;
		}
                LOG(LOG_DEBUG, "(%.*s=%.*s)\n", nl, name, vl, val);
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
			return ret;
		}

                LOG(LOG_DEBUG, "(&(%.*s=%.*s)...)\n", nl, name, vl, val);

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
                        LOG(LOG_DEBUG, "(&...(%.*s=%.*s))\n", nl, name, vl, val);

                        if (strncasecmp(name, "sambaSID", nl) == 0) {
                                vlmapd_sid_to_id(vasctx, vasid, msgid, val, berep);

                        } else if (strncasecmp(name, "uidNumber", nl) == 0) {
                                vlmapd_uid_to_sid(vasctx, vasid, msgid, val, berep);

                        } else if (strncasecmp(name, "gidNumber", nl) == 0) {
                                vlmapd_gid_to_sid(vasctx, vasid, msgid, val, berep);

                        } else {
                                LOG(LOG_NOTICE, "skipping unexpected attribute request: [%s]\n", name);
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
			return ret;
		}
		if (multi) {
			ret = ber_scanf(be, "}");
			if (ret == -1) {
				warnx("expected filter end");
				ber_free(berep, 1);
				return ret;
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
			return ret;
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

        LOG(LOG_NOTICE, "returning success to a BindRequest\n");

	BERVAL_PRINTF(reply, "{it{eoo}}", msgid, LDAP_RES_BIND, 
                LDAP_SUCCESS, NULL, 0, NULL, 0);
FINISHED:
	return ret;
}

static int vlmapd_generic_error(ber_int_t msgid, ber_tag_t msgtype, 
        struct berval **reply)
{
	int ret;

	LOG(LOG_NOTICE, "returning error on non-search request\n");

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
            fd_set                  readfds;
            struct timeval          tv;

            FD_ZERO( &readfds );
            FD_SET( sd, &readfds );

            tv.tv_sec = 300;
            tv.tv_usec = 0;
            ret = select( sd + 1, &readfds, NULL, NULL, &tv );
            /* Handle both error and timeout */
            if( ret < 1 )
                goto FINISHED;

		    ret = vmapd_recv(sd, &query);
    		if (ret != 0) {
    			goto FINISHED;
		}
		LOG(LOG_NOTICE, "QUERY successfully received\n");

		ret = vmapd_query(vasctx, vasid, &query, &reply);
		if (ret != 0) {
			goto FINISHED;
		}

		LOG(LOG_NOTICE, "REPLY successfully delivered\n");
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

/**
* Code to "daemonize" this process.
* complete with double-fork
* @RETURN Returns vlmapd_err_t: 
*      Possible return values include: VLMAPD_SUCCESS, VLMAPD_SUCCESS_EXIT, VLMAPD_FAILURE_EXIT
*/
static vlmapd_err_t become_daemon() {

     /* Our process ID and Session ID */
        pid_t pid, sid;
        
        /* Fork off the parent process */
        pid = fork();
        LOG(LOG_DEBUG, "%s: Daemon process pid %d\n", __FUNCTION__, pid);
        if (pid < 0) {
                LOG(LOG_CRIT, "%s: Failed to fork child process %d\n", __func__, pid);
                               return(VLMAPD_FAILURE_EXIT);

        }
        /* If we got a good PID, then
           we can exit the parent process. */
        if (pid > 0) {
               LOG(LOG_INFO, "%s: Exit the parent process, child process pid %d\n", __func__, pid);
                   return(VLMAPD_SUCCESS_EXIT);
        }

        /* Change the file mode mask */
        umask(0);
                
        /* Open any logs here */        

        LOG(LOG_INFO, "%s: Parent process sid %d\n", __func__, getsid(0));
                
        /* Create a new SID for the child process */

        sid = setsid();
        if (sid < 0) {
                /* Log the failure */
                LOG(LOG_CRIT, "%s: FAILED to create a new sid for child process\n", __func__); 
                               return(VLMAPD_FAILURE_EXIT);
        }
        
        LOG(LOG_DEBUG, "%s: Child process sid %d\n", __func__, sid);

        /* double-fork to prevent zombie children */
        pid = fork();
        LOG(LOG_DEBUG, "%s: Second Fork pid %d\n", __func__, pid);
        if (pid < 0) {
                LOG(LOG_CRIT, "%s: Failed to fork child process %d\n", __func__, pid);
                               return(VLMAPD_FAILURE_EXIT);
        }else if (pid != 0) {
        /* If we got a good PID, then we can exit the parent process. */
                LOG(LOG_INFO, "%s: Exit the parent process, child process pid %d\n", __func__, pid);
                               return(VLMAPD_SUCCESS_EXIT);
        }

        /* Change the current working directory */
        if ((chdir("/")) < 0) {
                /* Log the failure */
                LOG(LOG_ERR, "%s: FAILED to change directory to /\n", __func__);
                               return(VLMAPD_FAILURE_EXIT);
        }
    /* Debug was set on the command line */ 
    if(debug == VLMAPD_NOT_DEFINED) {
        /* Close out the standard file descriptors */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

       if (open("/dev/null",O_RDONLY) == -1) {
               err(LOG_ERR, "failed to reopen stdin while daemonising: %s", strerror(errno));
                   return(VLMAPD_FAILURE_EXIT);
       }
           if (open("/dev/null",O_WRONLY) == -1) {
               err(LOG_ERR, "failed to reopen stdout while daemonising: %s)",strerror(errno));
               return(VLMAPD_FAILURE_EXIT);
       }
       if (open("/dev/null",O_RDWR) == -1) {
               err(LOG_ERR, "failed to reopen stderr while daemonising: %s)",strerror(errno));
               return(VLMAPD_FAILURE_EXIT);
       }
    }

    LOG(LOG_DEBUG, "%s: We are now a daemon\n", __func__);
    return(VLMAPD_SUCCESS);
}

/**
* Open the lock file and save the PID of the daemon into it.
* @param pid_t pid of deamon
* @return  non-negative file descriptor or -1 on failure
*/
static int vlmapd_write_pidfile_with_lock(pid_t pid)
{
       int lfp, ret = -1;
       umask(0);
       if(pid == -1)
       { 
               pid = getpid();
       }

    LOG(LOG_INFO, "%s: Attempting to write pid "PID_T_FMT" to pidfile %s\n", __func__, pid, pidfile);
       /* The file descriptor gets closed in the vlmapd_cleanup method */
       lfp = open(pidfile, O_RDWR | O_CREAT, 0644);

       if(lfp != -1) {
        remove_pidfile = 1;
       LOG(LOG_DEBUG, "%s: pidfile %s opened with file descriptor %i\n", __func__, pidfile, lfp);
        if( vlmapd_set_lock(lfp, pid, pidfile) == VLMAPD_SUCCESS ) {
               char pidtext[10];
                       snprintf(pidtext, sizeof(pidtext), PID_T_FMT"\n", pid);
                       ret = write(lfp, pidtext, strlen(pidtext));
                       if( ret == 0 ) {
                               err(LOG_ERR, "%s: Failed to write "PID_T_FMT" to pidfile: %s: %s", __func__, pid, pidfile, strerror(errno));
                               ret = -1;
                       }
               }else ret = -1;
       }
       if(ret == -1)
       {
       errx(LOG_ERR, "%s: ERROR Failed to set lock on pidfile %s: %s. Process may already be running", __func__, pidfile, strerror(errno));
               return -1;
       }
       LOG(LOG_INFO, "%s: Successfully wrote pid "PID_T_FMT" to and set lock on pidfile %s\n", __func__, pid, pidfile);
       return lfp;

}

/**
* Checks if there is a lock on the pidfile.  If the file exists but
* the lock does not exist, re-create the lock. If the file does not exist
* re-create the file and lock it.
* 
* @PARAM   lfp file descriptor of currently opened pidfile
* @PARAM   pid pid of currently running process
* @PARAM   pidfile pidfile to check for lock
* @RETURN  non-negative file descriptor or -1 on failure 
*/
static int vlmapd_check_running_status(int lfp, pid_t pid, const char* pidfile)
{
    int ret = VLMAPD_SUCCESS;
    int ld = lfp;

    LOG(LOG_DEBUG, "%s: Checking our status\n", __func__);


    /* Does the pidfile already exists? */
    if( vlmapd_stat_file(pidfile) != VLMAPD_SUCCESS ) {
        /* The pidfile no longer exists, close our file descriptor to it if set */
        LOG(LOG_DEBUG, "%s: The file %s does not exists\n", __func__, pidfile);
        if(ld != -1) {
            LOG(LOG_DEBUG, "%s: Closing file descriptor %d\n", __func__, ld);
            if(close(ld) == -1)
                LOG(LOG_WARNING, "%s: Could not close file descriptor %d : %s\n", __func__, ld, strerror(errno));
        }
        /* Re-create the pidfile, set the pid and lock the file */
        LOG(LOG_DEBUG, "%s: Recreating file %s and setting a lock on it\n", __func__, pidfile);
        ld = vlmapd_write_pidfile_with_lock(pid);
        LOG(LOG_DEBUG, "%s: Returning file descriptor %d for %s\n", __func__, ld, pidfile);
        return ld;
    }else {
        /* File exists, now check for a lock */
        if( ld == -1 ) /* We just started up and the pidfile already exists. We don't have a valid file descriptor yet. */
        {
            /* Get a valid file descriptor , open read only, do not create because it already exists at this point */
            ld = vlmapd_open_pid_file( pidfile ); 
        }
        if( (ret = vlmapd_check_for_lock(ld, pid, pidfile)) != VLMAPD_SUCCESS ) {
          /* File is locked by another process */
          LOG(LOG_DEBUG, "%s: File is locked by another vasidmapd process\n", __func__);
          LOG(LOG_DEBUG, "%s: Closing file descriptor %d\n", __func__, ld);
          if(close(ld) == -1)
              LOG(LOG_WARNING, "%s: Could not close file descriptor %d : %s\n", __func__, ld, strerror(errno));
          remove_pidfile = 0; 
          return -1;
        }else {
          /* File is not locked, set the lock if pid != -1 */
          LOG(LOG_DEBUG, "%s: File is not locked by another vasidmapd process, set the lock for pid "PID_T_FMT"\n" , __func__, pid);
          if( pid != -1 ) {
            if( vlmapd_set_lock(ld, pid, pidfile) != VLMAPD_SUCCESS ) {
              LOG(LOG_DEBUG, "%s: Could not set lock on %s\n", __func__, pidfile);
            }
          }
        }
    }    

    return ld;
}

static vlmapd_err_t vlmapd_stat_file(const char* pidfile)
{
  struct stat sb;
  if( stat( pidfile, &sb ) ) return VLMAPD_FAILURE;
  return VLMAPD_SUCCESS;
}

/**
*
* @PARAM const char *pidfile
* @RETURN vlmapd_err_t 
*/
static int vlmapd_open_pid_file(const char* pidfile)
{
  LOG(LOG_DEBUG, "%s: Opening pidfile %s\n", __FUNCTION__, pidfile);

  int fd = open(pidfile, O_RDONLY);

  if(fd != -1) /* File opened with success */
  {
    LOG(LOG_DEBUG, "%s: Successfully opened pidfile %s with file descriptor %i\n", __FUNCTION__, pidfile, fd);
  } else 
  {
    LOG(LOG_ERR, "%s: Open failed: %s\n", __FUNCTION__, strerror(errno));
  }

  LOG(LOG_DEBUG, "%s: File desctriptor %i\n", __FUNCTION__, fd);
  
  return fd;
}

/**
*
* @PARAM int fd
* @PARAM pid_t pid
* @PARAM const char *pidfile
*
* @RETURN vlmapd_err_t
*/
static vlmapd_err_t vlmapd_set_lock(int fd, pid_t pid, const char *pidfile)
{
    struct flock f1;
    struct stat s1;

    int ret = VLMAPD_SUCCESS;

    if(fd < 0) {
        LOG(LOG_ERR, "%s: Invalid file handle\n", __FUNCTION__);
        return VLMAPD_FAILURE;
    }

    if(pid < 0) {
        LOG(LOG_ERR, "%s: Invalid pid\n", __FUNCTION__);
        return VLMAPD_FAILURE;
    }

    f1.l_type = F_WRLCK;
    f1.l_whence = SEEK_SET;
    f1.l_start = 0;
    f1.l_len = 0;
    f1.l_pid = pid;

    ret = fcntl( fd, F_SETLK, &f1 );
    if( ret != -1 ) {
        LOG(LOG_DEBUG, "%s: Lock was successfully set on %s for process with pid "PID_T_FMT"\n", __FUNCTION__, pidfile, pid);
    }else {
        ret = vlmapd_check_for_lock(fd, pid, pidfile);
    }

    return ret;
}


/**
* Checks for a lock on the specified file descriptor
*
* @PARAM int fd:                File descriptor to check for a lock on
* @PARAM pid_t pid;             pid to associate to this lock
* @PARAM const char * pidfile:  Name of the file associated to the file descriptor
* @RETURNS vlmapd_err_t         VLMAPD_FAILURE or VLMAPD_SUCCESS
*/
static vlmapd_err_t vlmapd_check_for_lock(int fd, pid_t pid, const char* pidfile)
{

    LOG(LOG_DEBUG, "%s: checking for lock on file %s\n", __FUNCTION__, pidfile);

    struct flock f1;
    int ret = VLMAPD_SUCCESS;
    int lfd = fd;
    lfd = open(pidfile, O_RDONLY);

    if(lfd < 0) {
        LOG(LOG_ERR, "%s: Invalid file handle\n", __FUNCTION__);
        return VLMAPD_FAILURE;
    }

    f1.l_type = F_WRLCK;
    f1.l_whence = SEEK_SET;
    f1.l_start = 0;
    f1.l_len = 0;
    f1.l_pid = -1;

    ret = fcntl(lfd, F_GETLK, &f1);

    close(lfd);
    
    if (ret == -1) {
        LOG(LOG_ERR, "%s: ERROR: Failed to check lock for %s: %s\n", __FUNCTION__, pidfile, strerror(errno));
        ret = VLMAPD_FAILURE;
    }else {
        if( f1.l_type != F_UNLCK ){
            //errx(LOG_ERR, "%s: ERROR: Cannot set write lock on file %s. The file is already locked by Process id %d", __FUNCTION__, pidfile, f1.l_pid);
            LOG(LOG_ERR, "%s: ERROR: Cannot set write lock on file %s. The file is already locked by Process id %d\n", __FUNCTION__, pidfile, f1.l_pid);
            ret = VLMAPD_FAILURE;
        }
    } 
    return ret;
}

/**
*  Setup for signal events.
*/
void vlmapd_init_signals(void){

    struct sigaction sigact, ignore_sigact; 
 
    ignore_sigact.sa_handler = SIG_IGN;
    sigemptyset(&ignore_sigact.sa_mask);
    ignore_sigact.sa_flags = 0;

    sigact.sa_handler = vlmapd_signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;

    sigaction(SIGINT,  &sigact, (struct sigaction *)NULL);
    sigaction(SIGTERM, &sigact, (struct sigaction *)NULL);
    sigaction(SIGTRAP, &sigact, (struct sigaction *)NULL);
    sigaction(SIGPIPE, &sigact, (struct sigaction *)NULL);
    sigaction(SIGQUIT, &sigact, (struct sigaction *)NULL);

    /* Ignore child and hup signals */
    sigaction(SIGCHLD, &ignore_sigact, (struct sigaction *)NULL);
    sigaction(SIGHUP,  &ignore_sigact, (struct sigaction *)NULL);
}

/**
* Handle signals from the OS.
* @param sig The signal to the process
*/
static void vlmapd_signal_handler(int sig)
{
       LOG(LOG_NOTICE, "Caught signal %d, setting sig flag\n", sig);
       VLMAPD_SIGNAL = sig;
}

static void vlmapd_cleanup(int socket_fd, int pid_fd)
{
       int local_lfp = pid_fd;
       int sd = socket_fd;

    LOG(LOG_INFO, "Daemon shutting down, cleaning up\n");

    if(local_lfp != -1) {
        LOG(LOG_DEBUG, "Closing file descriptor %d\n", local_lfp);
        if(close(local_lfp) == -1)
            LOG(LOG_WARNING, "Warning: Could not close file descriptor %d", local_lfp);
    }
    if(sd != -1) {
        LOG(LOG_DEBUG, "Closing socket descriptor %d\n", sd);
        if(close(sd) == -1)
            LOG(LOG_WARNING, "Warning: Could not close socket descriptor %d", sd);
    }
    
    LOG(LOG_DEBUG, "remove_pid %i\n", remove_pidfile);
    if( remove_pidfile )
        if( remove(pidfile) == -1 )
            LOG(LOG_WARNING, "Warning: Could not remove pidfile %s: %m\n", pidfile);
        else
            LOG(LOG_INFO, "Removed pidfile %s\n",pidfile);

#if HAVE_SYSLOG
    closelog();
#endif

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

/**
*  main
*/
int main (int argc, char *argv[])
{
        int sd = -1;
        int local_lfp = -1;
        int local_pid = -1;
	    struct sockaddr_in sockin;
	    int len, ret;
        int ch, error = 0;
        int daemonize = 1;
        int port = 389;
        int use_default_pidfile = 1;
        int exit_code = EXIT_SUCCESS;
        const char *bindaddr = "127.0.0.1";
        extern int optind;
        extern char *optarg;
       char *progname = *(argv);
#if defined(SO_REUSEADDR)
        int opt;
#endif

    struct timeval timeout;
    fd_set fds;

    vlmapd_init_signals();

        /* Process command line arguments */
        while ((ch = getopt(argc, argv, "hA:d:DFp:s:P:V")) != -1) {
            switch (ch) {
                case 'h': usage(argv[0]); exit(EXIT_SUCCESS);
                case 'A': bindaddr = optarg; break;
                case 'd': debug = atoi(optarg); break;
                case 'p': port = atoi(optarg); if(port == 0) error=1; break;
                case 'D': daemonize = 1; use_default_pidfile = 1; break;
                case 'F': daemonize = 0; use_default_pidfile = 0; break;
                case 's': service_name = optarg; break;
                case 'P': pidfile = optarg; use_default_pidfile = 1; break;
		case 'V':
		    printf("vasidmapd %s VAS %s\n",
			    PACKAGE_VERSION,
			    vas_library_version(0,0,0));
                   exit(EXIT_SUCCESS);
                case '?':
                   if(optopt == 'd' || optopt == 'p' || optopt == 'A' || optopt == 's' || optopt == 'P' )
                     printf( "Option -%c requires an argument.\n", optopt);
                   else if (isprint (optopt))
                     printf( "Unkown option `-%c'.\n", optopt);
                   else
                     printf( "Unknown option character `\\x%x'.\n", optopt);
                   error = 1;
                default: error = 1;
            }
        }
        if (optind < argc) {
            error = 1;
        }
        if (error) {
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }

#if HAVE_SYSLOG
        openlog("vasidmapd", daemonize ? LOG_CONS | LOG_PID : 0, LOG_DAEMON);
#endif

    LOG(LOG_INFO, "%s: Attempting to start up daemon\n", __func__);

    if( use_default_pidfile  == 0 ) {
               errx(LOG_ERR, "ERROR: Location of pidfile must be provided when running in non-daemon mode");
       }
    int lfp = -1;
    if(( lfp = vlmapd_check_running_status(-1, -1, pidfile)) == -1) {
        LOG(LOG_ERR, "ERROR: Could not start %s it seems to be already running\n", argv[0]);
        goto CLEANUP;
    }else {     
        if(close(lfp) == -1) {
            /* Not being able to close a single file descriptor does not warrant exiting the daemon */
            warnx("%s: Warning: Could not close file descriptor %d", __FUNCTION__, lfp);
        }
        else
            LOG(LOG_DEBUG, "%s: Closing file descriptor %d\n", __FUNCTION__, lfp);
    }

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
        LOG(LOG_ERR, "socket");
        goto CLEANUP;
    } else
        LOG(LOG_DEBUG, "Opened socket with file descriptor %d\n", sd);

#if defined(SO_REUSEADDR)
	opt = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof opt) < 0)
    {
        warn("setsockopt SO_REUSEADDR");
    }
#endif

        /* Construct a listening server socket at port 389 LDAP */
        memset(&sockin, 0, sizeof sockin);
	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(port);
    if (inet_pton(AF_INET, bindaddr, &sockin.sin_addr) <= 0) {
        LOG(LOG_ERR, "bad IP address '%s' : %s\n", bindaddr, strerror(errno));
        goto CLEANUP;
    }

	len = sizeof(sockin);
	ret = bind(sd, (struct sockaddr *)&sockin, len);
	if (ret == -1) {
        LOG(LOG_ERR, "bind : %s\n", strerror(errno));
        goto CLEANUP;
	}

	ret = listen(sd, 5);
	if (ret == -1) {
        LOG(LOG_ERR, "listen : %s\n", strerror(errno));
        goto CLEANUP;
    } 

	if (daemonize) {
        ret = become_daemon();
        if(ret != VLMAPD_SUCCESS) {
            LOG(LOG_DEBUG, "%s: Become_daemon returned %d\n", __func__, ret);
            if(ret == VLMAPD_SUCCESS_EXIT)
                exit_code = EXIT_SUCCESS;
            else if(ret == VLMAPD_FAILURE_EXIT)
                exit_code = EXIT_FAILURE;
            else
                exit_code = ret;
            goto CLEANUP;
        }
    }

    local_pid = getpid();
    LOG(LOG_INFO, "%s: %s process (PID %d)\n", __func__, progname, local_pid);
    local_lfp = vlmapd_write_pidfile_with_lock(local_pid);
    if(local_lfp < 0) {
        exit_code = EXIT_FAILURE;
        goto CLEANUP;
    }

	while (1) {
		int new, ret;
		struct sockaddr addr;
		socklen_t addrlen = sizeof addr;
		pid_t pid;

        if( VLMAPD_SIGNAL != VLMAPD_NOT_DEFINED ) {
            LOG(LOG_DEBUG, "%s: Signal flag set, cleanup and exit\n", __func__);
            close(new);
            break;
        }

        FD_ZERO(&fds);
        FD_SET(sd, &fds);

        timeout.tv_sec = 30;
        timeout.tv_usec = 0;

        ret = select(sizeof(fds)*8, &fds, NULL, NULL, &timeout);
        if( ret == -1 ) {
            perror("select failed");
            exit_code = EXIT_FAILURE;
            goto CLEANUP;
        }
        if (ret > 0)
        {
            if (FD_ISSET(sd, &fds)) {

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
    	} else {
            local_lfp = vlmapd_check_running_status(local_lfp, local_pid, pidfile);
        }
    }

CLEANUP:
    if(exit_code != EXIT_SUCCESS)
        vlmapd_cleanup(sd, local_lfp);

FINISHED:
    exit(exit_code);
}

