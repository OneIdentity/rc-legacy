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
#include <pwd.h>
#include <grp.h>
#include <err.h>

#include <vas.h>
#include <ber.h>
#include <ldap.h>

#if !HAVE_SOCKLEN_T
# undef socklen_t
# define socklen_t int
#endif

int debug;

void usage(const char *prog) 
{
        fprintf(stderr, "usage: %s [-A ipaddr] [-d level] [-p port] [-D] [-F]\n", prog);
}

int search_result_ok(ber_int_t msgid, struct berval **reply)
{
	BerElement *be;
	int ret;

	be = ber_alloc_t(BER_USE_DER);
	if (be == NULL) return -1;

	ret = ber_printf(be, "{it{eoo}}", msgid, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS, NULL, 0, NULL, 0);
	if (ret == -1) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR unable to create result ok reply\n", getpid());
		return -1;
	}

	ret = ber_flatten(be, reply);
	ber_free(be, 1);
	return ret;
}

int vlmapd_sid_to_id(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *sid, struct berval **reply)
{
	BerElement *be;
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

		if (vas_user_get_pwinfo(vasctx, vasid, vasuser, &pwent)) {
			if (debug) fprintf(stderr,
					   "ERROR: no pwinfo for sid: %s. %s\n",
					   sid,
					   vas_err_get_string(vasctx, 1));
			vas_user_free(vasctx, vasuser);
			return search_result_ok(msgid, reply);
		}

		sprintf(num, "%ld", pwent->pw_uid);
		attr = "uidNumber";

		vas_user_free(vasctx, vasuser);
		free(pwent);

	} else { /* if not an uid check if it is a gid */

		if (debug) fprintf(stderr,
				   "WARNING: Unable to initalize VAS user using sid: %s. %s\n", 
				   sid,
				   vas_err_get_string(vasctx, 1));
		if (debug) fprintf(stderr, "Try with a group.\n");

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
	}

	if (debug) fprintf(stderr,
			   "SUCCESS: converted SID: %s to %s: %s.\n",
			   sid, pwent?"UID":"GID", num);

	if ((be = ber_alloc_t(BER_USE_DER)) == NULL) {
		if (debug) fprintf(stderr, "ERROR: Memory allocation failed!\n");
		return -1;
	}

	if ((ret = ber_printf(be, "{it{s{{s{s}}{s{s}}{s{s}}}}}{it{eoo}}",
		 msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			attr, num,
		 msgid, LDAP_RES_SEARCH_RESULT,
			LDAP_SUCCESS,
			NULL, 0,
			NULL, 0)
	    ) == -1) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR unable to berprintf search entry\n", getpid());
		return -1;
	}

	ret = ber_flatten(be, reply);
	ber_free(be, 1);
	return ret;
}

int vlmapd_uid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *val, struct berval **reply)
{
	BerElement *be;
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

	if ((be = ber_alloc_t(BER_USE_DER)) == NULL) {
		if (debug) fprintf(stderr, "ERROR: Memory allocation failed!\n");
		return -1;
	}

	if ((ret = ber_printf(be, "{it{s{{s{s}}{s{s}}{s{s}}}}}{it{eoo}}",
		 msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			"uidnumber", val,
		 msgid, LDAP_RES_SEARCH_RESULT,
			LDAP_SUCCESS,
			NULL, 0,
			NULL, 0)
	    ) == -1) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR unable to berprintf search entry\n", getpid());
		return -1;
	}

	ret = ber_flatten(be, reply);
	ber_free(be, 1);
	return ret;
}

int vlmapd_gid_to_sid(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, char *val, struct berval **reply)
{
	BerElement *be;
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

	if ((be = ber_alloc_t(BER_USE_DER)) == NULL) {
		if (debug) fprintf(stderr, "ERROR: Memory allocation failed!\n");
		return -1;
	}

	if ((ret = ber_printf(be, "{it{s{{s{s}}{s{s}}{s{s}}}}}{it{eoo}}",
		 msgid, LDAP_RES_SEARCH_ENTRY,
			"CN=VAS-Idmapper",
			"sambaSID", sid,
			"objectClass", "sambaIdmapEntry",
			"gidNumber", val,
		 msgid, LDAP_RES_SEARCH_RESULT,
			LDAP_SUCCESS,
			NULL, 0,
			NULL, 0)
	    ) == -1) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR unable to berprintf search entry\n", getpid());
		return -1;
	}

	ret = ber_flatten(be, reply);
	ber_free(be, 1);
	return ret;
}

int vlmapd_search_idpool(ber_int_t msgid, struct berval **reply)
{
	BerElement *be;
	int ret;

	be = ber_alloc_t(BER_USE_DER);

	/* return a face unixidpool entry with uidNumber, gidNumber and objectclass */

	if ((ret = ber_printf(be, "{it{s{{s{s}}{s{s}}{s{s}}}}}{it{eoo}}",
			 msgid, LDAP_RES_SEARCH_ENTRY,
				"CN=VAS-Idmapper",
				"objectClass", "sambaUnixIdPool",
				"uidnumber", "1000",
				"gidNumber", "1000",
			 msgid, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS, NULL, 0, NULL, 0))
	    == -1) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR unable to berprintf bind reply\n", getpid());
		return -1;
	}

	ret = ber_flatten(be, reply);
	ber_free(be, 1);
	return ret;
}

int vlmapd_search(vas_ctx_t *vasctx, vas_id_t *vasid, ber_int_t msgid, BerElement *be, struct berval **reply)
{
	ber_tag_t ft;
	char name[128], val[128];
	int nl, vl;
	int ret;

	/* skip everything up to the filter (seeiib -> dn, deref, sizel, timel, typesb) */
	ret = ber_scanf(be, "xxxxxxt", &ft);
	if (ret == -1) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR malformed search request\n");
		return -1;
	}

	switch (ft) {
	case 0xA3:
		/* equality check what is it about */
		nl = vl = 128;
		ret = ber_scanf(be, "{ss}", name, &nl, val, &vl);
		if (ret == -1) {
			if (debug) fprintf(stderr, "vlmapd(%d): ERROR malformed search request(A3)\n");
			return -1;
		}
		if (strncasecmp(name, "objectclass", nl) == 0) {
			if (strncasecmp(val, "sambaUnixIdPool", vl) == 0) {
				ret = vlmapd_search_idpool(msgid, reply);
				break;
			}	
		}

		/* return nothing for everything else */
		ret = search_result_ok(msgid, reply);
		break;

	case 0xA0:
		/* and filter we need further investigation */
		nl = vl = 128;
		ret = ber_scanf(be, "{{ss}", name, &nl, val, &vl);
		if (ret == -1) {
			if (debug) fprintf(stderr, "vlmapd(%d): ERROR malformed search request (A0)\n");
			return -1;
		}

		if (strncasecmp(name, "objectclass", nl) == 0) {
			if (strncasecmp(val, "sambaIdmapEntry", vl) == 0) {
				nl = vl = 128;
				ret = ber_scanf(be, "{ss}}", name, &nl, val, &vl);
				if (ret == -1) {
					if (debug) fprintf(stderr, "vlmapd(%d): ERROR malformed search request (A0)\n");
					return -1;
				}

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
		}

		/* return nothing for everything else */
		ret = search_result_ok(msgid, reply);
		break;
		
	case 0x87:
		/* 99% it is (objectclass=*) */
	default:
		/* answer we found nothing */
		ret = search_result_ok(msgid, reply);
		break;
	}

	ber_free(be, 1);
	return ret;
}

int vlmapd_bind(ber_int_t msgid, struct berval **reply)
{
	BerElement *be;
	int ret;

	if (debug) fprintf(stderr, "vlmapd(%d): return success to a bind request\n", getpid());

	be = ber_alloc_t(BER_USE_DER);

	ret = ber_printf(be, "{it{eoo}}", msgid, LDAP_RES_BIND, LDAP_SUCCESS, NULL, 0, NULL, 0);
	if (ret == -1) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR unable to berprintf bind reply\n", getpid());
		return -1;
	}

	ret = ber_flatten(be, reply);
	ber_free(be, 1);
	return ret;
}

int vlmapd_generic_error(ber_int_t msgid, ber_tag_t msgtype, struct berval **reply)
{
	BerElement *be;
	int ret;

	if (debug) fprintf(stderr, "vlmapd(%d): return error on any non search request\n", getpid());

	be = ber_alloc_t(BER_USE_DER);

	ret = ber_printf(be, "{it{eoo}}", msgid, msgtype+1, LDAP_INSUFFICIENT_ACCESS, NULL, 0, NULL, 0);
	if (ret == -1) {
		if (debug) fprintf(stderr, "vlmapd(%d): ERROR unable to berprintf bind reply\n", getpid());
		return -1;
	}

	ret = ber_flatten(be, reply);
	ber_free(be, 1);
	return ret;
}

int vmapd_query(vas_ctx_t *vasctx, vas_id_t *vasid, struct berval *query, struct berval **reply)
{
	ber_tag_t ret;
	BerElement *be;
	ber_int_t msgid;
	ber_tag_t msgtype;

	be = ber_init(query);
	if (be == NULL) {
		if (debug) fprintf (stderr, "vlmapd(%d): ERROR Invalid ber string\n");
		ber_free(be, 1);
		return -1;
	}

	ret = ber_scanf(be, "{it{", &msgid, &msgtype);

	switch (msgtype) {
	case LDAP_REQ_BIND:
		ber_free(be, 1);
		return vlmapd_bind(msgid, reply);
	case LDAP_REQ_SEARCH:
		return vlmapd_search(vasctx, vasid, msgid, be, reply);
	default:
		ber_free(be, 1);
		return vlmapd_generic_error(msgid, msgtype, reply);
	}

	return -1;
}

#define SHORT_MSG_SIZE 129

int vmapd_recv(int sd, struct berval *query)
{
	ssize_t ret;
	ssize_t len;
	unsigned char *buf;
	int skip;

	buf = (unsigned char *)malloc(SHORT_MSG_SIZE);

	ret = read(sd, buf, 2);
	if (ret != 2) {
		if (debug) {
			if (ret == -1) {
				fprintf(stderr, "vmapd(%d): ERROR (%d) while reading from socket\n", getpid(), errno);
			} else {
				fprintf(stderr, "vmapd(%d): ERROR short read from socket reading first bytes\n", getpid());
			}
		}
		return -2;
	}

	if (buf[0] != 0x30) {
		if (debug) {
			fprintf(stderr, "vmapd(%d): ERROR protocol Error invalid first byte signature (%x)\n", getpid(), buf[0]);
		}
		return -2;
	}

	skip = 2; /* Let's skip at least the SEQUENCE tag and the Simple lenght byte */

	if (buf[1] & 0x80) {
		/* not a simple length short message */
		/* lets retrieve the contents length */
		int n, i;

		n = (buf[1] & 0x7F);
		skip += n; /* on the packet read skip also the laready retrieved length bytes */

		if (n > 4) {
			/* more than 4 bytes for the length ?! */
			if (debug) fprintf(stderr, "vmapd(%d): ERROR, we do not support more than 4 length bytes sequences\n");
			return -2;
		}

		ret = read(sd, &(buf[2]), n);
		if (ret != n) {
			if (debug) {
				if (ret == -1) {
					fprintf(stderr, "vmapd(%d): ERROR (%d) while reading from socket\n", getpid(), errno);
				} else {
					fprintf(stderr, "vmapd(%d): ERROR short read from socket reading length\n", getpid());
				}
			}
			return -2;
		}

		len = 0;
		i = 0;
		switch (n) {
		case 4:
			len += buf[2+i] << 24;
			i++;
		case 3:
			len += buf[2+i] << 16;
			i++;
		case 2:
			len += buf[2+i] << 8;
			i++;
		case 1:
			len += buf[2+i];
			break;
		default:
			if (debug) fprintf(stderr, "vmapd(%d): ERROR Internal operation failed for unkown reasons\n", getpid());
		}

		buf = (unsigned char *)realloc(buf, skip + len);
		if (buf == NULL) {
			 if (debug) fprintf(stderr, "vmapd(%d): ERROR Memory allocation failed (realloc)\n", getpid());
			return -2;
		}
	} else { /* simple lenght */
		len = buf[1];
	}

	ret = read(sd, &(buf[skip]), len);
	if (ret != len) {
		if (debug) {
			if (ret == -1) {
				fprintf(stderr, "vmapd(%d): ERROR (%d) while reading from socket\n", getpid(), errno);
			} else {
				fprintf(stderr, "vmapd(%d): ERROR short read from socket reading payload\n", getpid());
			}
		}
		return -2;
	}

	query->bv_val = (char *)buf;
	query->bv_len = skip+len;

	return 0;
}

int vmapd_send(int sd, struct berval *reply)
{
	ssize_t len = reply->bv_len;
	ssize_t ret, s = 0;

	while (s < len) {
		ret = write(sd, &(reply->bv_val[s]), len-s);
		if (ret == -1) {
			 if (debug) fprintf(stderr, "ERROR: Sending reply (errno=%d)\n", errno);
			return -1;
		}
		s += ret;
	}

	return 0;
}

int vmapd_server(int sd)
{
	vas_ctx_t *vasctx = NULL;
	vas_id_t *vasid = NULL;
	struct berval query;
	struct berval *reply;
	int ret = 0;

	query.bv_val = NULL;
	reply = NULL;

	if(vas_library_version_check(VAS_API_VERSION_MAJOR, 
				     VAS_API_VERSION_MINOR,
				     VAS_API_VERSION_MICRO)) {
		if (debug) fprintf(stderr, 
				   "ERROR: Version of VAS API library is too old."
				   "This program needs"VAS_API_VERSION_STR" or newer.\n");

		ret = -1;
		goto FINISHED;          
	}

	if ((ret = vas_ctx_alloc(&vasctx))) {
		fprintf(stderr,
			"ERROR: Unable to allocate VAS CTX. %s\n",
			vas_err_get_string(vasctx, 1));
		goto FINISHED;
	}

        if ((vas_id_alloc( vasctx, "host/", &vasid ))) {
		fprintf(stderr, 
			"ERROR: Unable to allocate VAS ID for 'host/'. %s\n",
			vas_err_get_string(vasctx, 1));
		goto FINISHED;
        }

        if ((vas_id_establish_cred_keytab(vasctx, vasid,
						   VAS_ID_FLAG_USE_MEMORY_CCACHE |
						     VAS_ID_FLAG_KEEP_COPY_OF_CRED,
						   NULL))) {
		fprintf(stderr,
			"ERROR: Unable to establish credentials for 'host/'. %s\n",
			vas_err_get_string(vasctx, 1));
		goto FINISHED;
        }

	while (1) {

		ret = vmapd_recv(sd, &query);
		if (ret != 0) {
			goto FINISHED;
		}
		 if (debug == 2) fprintf(stderr, "QUERY Successfully Received\n");

		ret = vmapd_query(vasctx, vasid, &query, &reply);
		if (ret != 0) {
			goto FINISHED;
		}

		 if (debug == 2) fprintf(stderr, "REPLY Successfully Delivered\n");
		ret = vmapd_send(sd, reply);
		if (ret != 0) {
			goto FINISHED;
		}

		free(query.bv_val);
		ber_bvfree(reply);
		query.bv_val = NULL;
		reply = NULL;
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

        while ((ch = getopt(argc, argv, "A:d:DFp:")) != -1)
            switch (ch) {
                case 'A': bindaddr = optarg; break;
                case 'd': debug = atoi(optarg); break;
                case 'p': port = atoi(optarg); break;
                case 'D': daemonize = 1; break;
                case 'F': daemonize = 0; break;
                default: error = 1;
            }

        /* Backward compat: old way of providing debug */
        if (optind < argc && strcmp(argv[optind], "debug") == 0) {
            debug = 1;
            optind++;
        }

        if (optind < argc)
            error = 1;
        if (error) {
            usage(argv[0]);
            exit(1);
        }

        /* Construct a server socket at port 389 LDAP */
	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(port);
        if (!bindaddr)
            bindaddr = debug ? "0.0.0.0" : "127.0.0.1";
        if (inet_pton(AF_INET, bindaddr, &(sockin.sin_addr.s_addr) <= 0))
            errx(1, "bad IP address '%s'", bindaddr);

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
	if (!daemonize) {
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
			close(new);
			child++;
		} else {
			int ret;

			ret = vmapd_server(new);
			close(new);
			exit(ret);
		}
	}
}
