/*===========================================================================
 * Project:     vlmapd - VAS ID mapping Daemon emulating a subset of the
 *		of the LDAP protocol to be used with samba idmap_ldap
 *
 *		Based on sidtouid/sidtogid utilities made by:
 *			Matt Peterson <matt.peterson@quest.com>
 *
 * Author:	Simo Sorce <simo.sorce@quest.com>
 *
 * File:        vlmapd.c
 *
 * Description: Main implementation source file
 *=========================================================================*/
/* (c) 2006 Quest Software, Inc. All rights reserved. */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>

#include <vas.h>
#include <ber.h>
#include <ldap.h>

/* Prints a message to stderr only when the debug level is 
 * at 'level' or higher */
#define DEBUG(level, fmt, va...)  \
    do { if (debug >= level) fprintf(stderr, fmt , ## va); } while (0)

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
        ber_int_t msgid, char *sid, struct berval **reply);
static int vlmapd_uid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, 
        ber_int_t msgid, char *val, struct berval **reply);
static int vlmapd_gid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid,
        ber_int_t msgid, char *val, struct berval **reply);
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


int debug;  /* Set by -d command line option */

/* Displays command line usage message */
static void usage(const char *prog) 
{
        fprintf(stderr, "usage: %s"
               " [-A ipaddr] [-d level] [-p port] [-D] [-F]\n", prog);
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

static int vlmapd_sid_to_id(vas_ctx_t *vasctx, vas_id_t *vasid,
        ber_int_t msgid, char *sid, struct berval **reply)
{
	char num[12];
	char *attr;
	vas_user_t *vasuser;
	vas_group_t *vasgrp;
	struct passwd *pwent = NULL;
	struct group *grent = NULL;
	int ret;

	/* check if it is a uid */
	if ((vas_user_init(vasctx,
			   vasid,
			   sid,
			   VAS_NAME_FLAG_FOREST_SCOPE,
			   &vasuser)) == 0) { /* success */

		if (vas_user_get_pwinfo(vasctx, vasid, vasuser, &pwent) == 0) {
			sprintf(num, "%ld", pwent->pw_uid);
			attr = "uidNumber";

			vas_user_free(vasctx, vasuser);
			free(pwent);

			goto got_an_id;
		}

		vas_user_free(vasctx, vasuser);
	
		if (debug) fprintf(stderr,
					   "ERROR: no pwinfo for sid: %s. %s\n",
					   sid,
					   vas_err_get_string(vasctx, 1));

		if (debug) fprintf(stderr, "Try with a group.\n");

	} else { /* if not an uid check if it is a gid */

		if (debug) fprintf(stderr,
				   "WARNING: Unable to initalize VAS user using sid: %s. %s\n", 
				   sid,
				   vas_err_get_string(vasctx, 1));
		if (debug) fprintf(stderr, "Try with a group.\n");
	}

	if ((vas_group_init(vasctx,
			    vasid,
			    sid,
			    VAS_NAME_FLAG_FOREST_SCOPE,
			    &vasgrp))) { /* error */
		
		if (debug) fprintf(stderr,
				   "ERROR: Unable to initialize VAS group using sid: %s. %s\n",
				   sid,
				   vas_err_get_string(vasctx, 1));
		return search_result_ok(msgid, reply);
	}

	if (vas_group_get_grinfo(vasctx, vasid, vasgrp, &grent)) {
		if (debug) fprintf(stderr,
				   "ERROR: no grinfo for sid: %s. %s\n",
				   sid,
				   vas_err_get_string(vasctx, 1));
		vas_group_free(vasctx, vasgrp);
		return search_result_ok(msgid, reply);
	}
	
	sprintf(num, "%ld", grent->gr_gid);
	attr = "gidNumber";

	vas_group_free(vasctx, vasgrp);
	free(grent);

got_an_id:
	if (debug) fprintf(stderr,
			   "SUCCESS: converted SID: %s to %s: %s.\n",
			   sid, pwent?"UID":"GID", num);

        BERVAL_PRINTF(reply, "{it{s{{s{s}}{s{s}}{s{s}}}}}{it{eoo}}",
		 msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			attr, num,
		 msgid, LDAP_RES_SEARCH_RESULT,
			LDAP_SUCCESS,
			NULL, 0,
			NULL, 0);
FINISHED:
	return ret;
}

static int vlmapd_uid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *val, struct berval **reply)
{
	vas_user_t *vasuser;
	struct passwd *pwent = NULL;
	char *sid;
	uid_t uid;
	int ret;

	errno = 0;
	uid = (uid_t)strtol(val, NULL, 10);
	if (errno != 0) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR Conversion to uid_t failed.\n"
					   "            (val=[%s],errno=%d)\n", getpid(), val, errno);
	}
	if ((pwent = getpwuid(uid)) == NULL) {
		if (debug) fprintf(stderr, "ERROR: uid (%d) not found!\n", uid);
		return search_result_ok(msgid, reply);
	}

	if ((vas_user_init(vasctx, vasid, pwent->pw_name,
				   VAS_NAME_FLAG_FOREST_SCOPE,
				   &vasuser)) != VAS_ERR_SUCCESS) {
		if (debug) fprintf(stderr,
				   "vlmapd(%d): ERROR Unable to initalize VAS user:%s.\n"
				   "            [%s]\n",
				   getpid(),
				   pwent->pw_name,
				   vas_err_get_string(vasctx, 1));
		return search_result_ok(msgid, reply);
	}

	if ((vas_user_get_sid(vasctx, vasid, vasuser, &sid)) != VAS_ERR_SUCCESS) {
		if (debug) fprintf(stderr,
				   "vlmapd(%d): ERROR Unable to get the SID of user %s.\n"
				   "            [%s]\n",
				   getpid(), sid,
				   vas_err_get_string(vasctx, 1));
		vas_user_free(vasctx, vasuser);
		return search_result_ok(msgid, reply);
	}

	vas_user_free(vasctx, vasuser);

	if (debug) fprintf(stderr,
			   "SUCCESS: converted UID: %ld to SID: %s.\n",
			   uid, sid);

	BERVAL_PRINTF(reply, "{it{s{{s{s}}{s{s}}{s{s}}}}}{it{eoo}}",
		 msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			"uidNumber", val,
		 msgid, LDAP_RES_SEARCH_RESULT,
			LDAP_SUCCESS,
			NULL, 0,
			NULL, 0);
FINISHED:
	return ret;
}

static int vlmapd_gid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *val, struct berval **reply)
{
	vas_group_t *vasgrp;
	struct group *grent = NULL;
	char *sid;
	gid_t gid;
	int ret;

	errno = 0;
	gid = (gid_t)strtol(val, NULL, 10);
	if (errno != 0) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR Conversion to gid_t failed.\n"
					   "            (val=[%s],errno=%d)\n", getpid(), val, errno);
	}
	if ((grent = getgrgid(gid)) == NULL) {
		if (debug) fprintf(stderr, "ERROR: gid (%d) not found!\n", gid);
		return search_result_ok(msgid, reply);
	}

	if ((vas_group_init(vasctx, vasid, grent->gr_name,
				    VAS_NAME_FLAG_FOREST_SCOPE,
				    &vasgrp)) != VAS_ERR_SUCCESS) {
		if (debug) fprintf(stderr,
				   "vlmapd(%d): ERROR Unable to initalize VAS group:%s.\n"
				   "            [%s]\n",
				   getpid(),
				   grent->gr_name,
				   vas_err_get_string(vasctx, 1));
		return search_result_ok(msgid, reply);
	}

	if ((vas_group_get_sid(vasctx, vasid, vasgrp, &sid)) != VAS_ERR_SUCCESS) {
		if (debug) fprintf(stderr,
				   "vlmapd(%d): ERROR Unable to get the SID of group %s.\n"
				   "            [%s]\n",
				   getpid(), sid,
				   vas_err_get_string(vasctx, 1));
		vas_group_free(vasctx, vasgrp);
		return search_result_ok(msgid, reply);
	}

	vas_group_free(vasctx, vasgrp);

	if (debug) fprintf(stderr,
			   "SUCCESS: converted GID: %ld to SID: %s.\n",
			   gid, sid);

	BERVAL_PRINTF(reply, "{it{s{{s{s}}{s{s}}{s{s}}}}}{it{eoo}}",
		 msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			"gidNumber", val,
		 msgid, LDAP_RES_SEARCH_RESULT,
			LDAP_SUCCESS,
			NULL, 0,
			NULL, 0);
FINISHED:
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
#define FILTER_TAG_EQUALITY_MATCH   0xA3

/* Handles an LDAP search request, and constructs a reply. */
static int vlmapd_search(vas_ctx_t *vasctx, vas_id_t *vasid, 
        ber_int_t msgid, BerElement *be, struct berval **reply)
{
	ber_tag_t ft;
	char name[4096], val[4096];
	int nl, vl;
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
	case FILTER_TAG_EQUALITY_MATCH:
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

	case FILTER_TAG_AND:
		/* and filter we need further investigation */
		nl = sizeof name;
                vl = sizeof val;
		ret = ber_scanf(be, "{{ss}", name, &nl, val, &vl);
		if (ret == -1) {
                        warnx("expected filter (&(=)...)");
			return -1;
		}

                DEBUG(3, "(&(%.*s=%.*s)...)\n", nl, name, vl, val);

		if (strncasecmp(name, "objectclass", nl) == 0 &&
                    strncasecmp(val, "sambaIdmapEntry", vl) == 0) {
                        nl = sizeof name;
                        vl = sizeof val;
                        ret = ber_scanf(be, "{ss}}", name, &nl, val, &vl);
                        if (ret == -1) {
                                warnx("expected filter (&(=)(=))");
                                return -1;
                        }
                        DEBUG(3, "(&...(%.*s=%.*s))\n", nl, name, vl, val);

                        if (strncasecmp(name, "sambaSID", nl) == 0) {
                                ret = vlmapd_sid_to_id(vasctx, vasid, msgid, val, reply);
                        } else if (strncasecmp(name, "uidNumber", nl) == 0) {
                                ret = vlmapd_uid_to_sid(vasctx, vasid, msgid, val, reply);
                        } else if (strncasecmp(name, "gidNumber", nl) == 0) {
                                ret = vlmapd_gid_to_sid(vasctx, vasid, msgid, val, reply);
                        } else {
                                ret = search_result_ok(msgid, reply);
                        }
                        break;
		}


		/* return nothing for everything else */
		ret = search_result_ok(msgid, reply);
		break;
		
	default:
		/* answer we found nothing */
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
	int ret = 0;
        vas_err_t error;

	query.bv_val = NULL;
	reply = NULL;

	if ((error = vas_ctx_alloc(&vasctx))) {
                warnx("vas_ctx_alloc: error %d%s", error,
                    error == VAS_ERR_NO_MEMORY ? ": no memory" :
                    error == VAS_ERR_INVALID_PARAM ? ": invalid param" : "");
		goto FINISHED;
	}

        if ((vas_id_alloc(vasctx, "host/", &vasid))) {
                warnx("vas_id_alloc host/: %s", vas_err_get_string(vasctx, 1));
		goto FINISHED;
        }

        if ((vas_id_establish_cred_keytab(vasctx, vasid,
						   VAS_ID_FLAG_USE_MEMORY_CCACHE |
						     VAS_ID_FLAG_KEEP_COPY_OF_CRED,
						   NULL))) {
                warnx("vas_id_establish_cred_keytab host/: %s", 
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

int main (int argc, char *argv[])
{
	int sd;
	struct sockaddr_in sockin;
	char *query = NULL;
	char *err_msg;
	int count, len, ret, opt, child;
        int ch, error = 0;
        int daemonize = 1;
        int port = 389;
        const char *bindaddr = NULL;
        extern int optind;
        extern char *optarg;

        while ((ch = getopt(argc, argv, "A:d:DFp:")) != -1) {
            switch (ch) {
                case 'A': bindaddr = optarg; break;
                case 'd': debug = atoi(optarg); break;
                case 'p': port = atoi(optarg); break;
                case 'D': daemonize = 1; break;
                case 'F': daemonize = 0; break;
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

        /* Check that VAS version is suitable */
	if (vas_library_version_check(VAS_API_VERSION_MAJOR, 
				      VAS_API_VERSION_MINOR,
				      VAS_API_VERSION_MICRO)) {
            errx(1, "bad VAS version; need " VAS_API_VERSION_STR " or newer");
	}

        /* Construct a server socket at port 389 LDAP */
	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(port);
        if (!bindaddr) {
            bindaddr = "127.0.0.1";
        }
        if (inet_pton(AF_INET, bindaddr, &sockin.sin_addr) <= 0) {
            errx(1, "bad IP address '%s'", bindaddr);
        }

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
                err(5, "socket");
	}

#if defined(SO_REUSEADDR)
	opt = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof opt) < 0)
            warn("setsockopt SO_REUSEADDR");
#endif

	len = sizeof(sockin);
	ret = bind(sd, (struct sockaddr *)&sockin, len);
	if (ret == -1) {
                err(6, "bind");
	}

	ret = listen(sd, 5);
	if (ret == -1) {
                err(6, "listen");
	}

	/* Double-fork to daemonize */
	if (daemonize) {
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

	child = 0;

	while (1) {
		int new, state, ret;
		struct sockaddr addr;
		socklen_t addrlen;
		pid_t pid;
		struct timeval tv;
		fd_set r_fds;

                /* FIXME: use sigchld/signign to reap children */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&r_fds);
		FD_SET(sd, &r_fds);

		ret = select(sd+1, &r_fds, NULL, NULL, &tv);
		if (ret == 0) {
			int i;
			/* select has timed out let's just clean out pending
			 * children and continue */
			for (i = child; i > 0; i--) {
				if (waitpid(-1, &state, WNOHANG) > 0) {
					child--;
				} else {
					break;
				}
			}
			continue;
		}
		if (ret < 0) {
                        if (errno == EINTR)
                            continue;
                        err(1, "select");
		}

                addrlen = sizeof addr;
		new = accept(sd, (struct sockaddr *)&addr, &addrlen);
		if (new == -1) {
                        warn("accept");
			continue;
		}

		pid = fork();
		if (pid == -1) {
                        warn("fork");
			close(new);
			continue;
		}

		if (pid) {
                        /* parent */
			close(new);
			child++;
		} else {
                        /* child */
			int ret;

			ret = vmapd_server(new);
			close(new);
			exit(ret);
		}
	}
}
