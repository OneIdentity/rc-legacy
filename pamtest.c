/* (c) 2006 Quest Software, Inc. All rights reserved. */
/*
 * Pam testing tool
 * David Leonard
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include "authtest.h"

#define HAVE_SYSLOG_H
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

int cflag = 0;	    /* -c: set credentials flag */
int oflag = 0;	    /* -o: leave session open */
int pflag = 0;	    /* -p: privsep uid */
int privsep_uid = -1;
int rflag = 0;	    /* -r: use responses instead of prompting */
char **responses;
int sflag = 0;	    /* -s: skip pam_authenticate */

/*-----------------------------------
 * PEM error codes
 */
#define ERRDECL(n) { n, #n }
static struct err { 
    int error; const char *desc; 
} errors[] = {
    ERRDECL(PAM_SUCCESS),
    ERRDECL(PAM_OPEN_ERR),
    ERRDECL(PAM_SYMBOL_ERR),
    ERRDECL(PAM_SERVICE_ERR),
    ERRDECL(PAM_SYSTEM_ERR),
    ERRDECL(PAM_BUF_ERR),
    ERRDECL(PAM_CONV_ERR),
    ERRDECL(PAM_PERM_DENIED),
    ERRDECL(PAM_MAXTRIES),
    ERRDECL(PAM_AUTH_ERR),
    ERRDECL(PAM_NEW_AUTHTOK_REQD),
    ERRDECL(PAM_CRED_INSUFFICIENT),
    ERRDECL(PAM_AUTHINFO_UNAVAIL),
    ERRDECL(PAM_USER_UNKNOWN),
    ERRDECL(PAM_CRED_UNAVAIL),
    ERRDECL(PAM_CRED_EXPIRED),
    ERRDECL(PAM_CRED_ERR),
    ERRDECL(PAM_ACCT_EXPIRED),
    ERRDECL(PAM_AUTHTOK_EXPIRED),
    ERRDECL(PAM_SESSION_ERR),
    ERRDECL(PAM_AUTHTOK_ERR),
    ERRDECL(PAM_AUTHTOK_LOCK_BUSY),
    ERRDECL(PAM_AUTHTOK_DISABLE_AGING),
    ERRDECL(PAM_NO_MODULE_DATA),
    ERRDECL(PAM_IGNORE),
    ERRDECL(PAM_ABORT),
    ERRDECL(PAM_TRY_AGAIN),
    { -1, NULL }
};

/*------------------------------------------------------------
 * PAM logging and error printing
 */

/* Returns the string representation of a PAM error code */
static const char *
mypam_strerror(pam_handle_t *pamh, int error) {
    static char namebuf[128];
    struct err *err;
    const char *name = NULL;

    for (err = errors; err->desc; err++)
	if (err->error == error) {
	    name = err->desc;
	    break;
	}
    if (!name) {
	snprintf(namebuf, sizeof namebuf, "error %d", error);
	name = namebuf;
    }
    if (error == PAM_SUCCESS)
	return name;
#if HAVE_PAM_STRERROR
    if (pamh) {
	static char sbuf[128];
	const char *pe = pam_strerror(pamh, error);
	int pelen;

	if (!pe)
	    pe = "(null)";
	pelen = strlen(pe);
	while (pelen > 0 && pe[pelen - 1] == '\n')  /* Strip \n */
	    pelen--;
	snprintf(sbuf, sizeof sbuf, "%s: \"%.*s\"", name, pelen, pe);
	name = sbuf;
    }
#endif
    return name;
}

static void
mypam_log1(const char *expr)
{
    fprintf(stderr, "%s[%s: %s", col_SO, expr, col_SE);
}
static int
mypam_log2(pam_handle_t *pamh, int result)
{
    fprintf(stderr, "%s-> %s]%s\n", col_SO,
            mypam_strerror(pamh, result), col_SE);
    return result;
}

#define LOG(pamh, pamexpr) (mypam_log1(#pamexpr), mypam_log2(pamh, pamexpr))

/* Invoke a PAM function, and die unless it is the expected result */
#define CHECK_EXPECT(pamh, pamexpr, expectedresult) do { \
    int pam_err; \
    pam_err = LOG(pamh, pamexpr); \
    if (pam_err != (expectedresult)) { \
	debug_err("[" __FILE__ ":%d: " #pamexpr \
		" did not return %s]", __LINE__, \
                mypam_strerror(0, expectedresult)); \
	exit(1); \
    } \
} while(0)

#define CHECK(pamh, pamexpr) CHECK_EXPECT(pamh, pamexpr, PAM_SUCCESS)

#if __sun__ || __hpux
# define ITEM_TYPE void **
#else
# define ITEM_TYPE const void **
#endif

#define GETITEM(pamh, item_type) do { \
    char *value = NULL; \
    int pam_err; \
    fprintf(stderr, "%s[pam_getitem(pamh, %s) = ", col_SO, #item_type); \
    pam_err = pam_get_item(pamh, item_type, (ITEM_TYPE)&value); \
    if (pam_err == PAM_SUCCESS) { \
       if (value) \
           fprintf(stderr, "'%s'", value); \
       else \
           fprintf(stderr, "(null)"); \
    } else \
       fprintf(stderr, "error: %s", mypam_strerror(pamh, pam_err)); \
    fprintf(stderr, "]%s\n", col_SE); \
} while (0)

#define SETITEM(pamh, item_type, valuestr) do { \
    int pam_err; \
    char *value = valuestr; \
    fprintf(stderr, "%s[pam_setitem(pamh, %s, ", col_SO, #item_type); \
    if (value) \
        fprintf(stderr, "'%s')", value); \
    else \
        fprintf(stderr, "(null)"); \
    pam_err = pam_set_item(pamh, item_type, (ITEM_TYPE)value); \
    if (pam_err != PAM_SUCCESS) \
       fprintf(stderr, "error: %s", mypam_strerror(pamh, pam_err)); \
    fprintf(stderr, "]%s\n", col_SE); \
} while (0)

/*------------------------------------------------------------
 * Generalised PAM conversation function
 */
int
convfn(int n, struct pam_message **m, struct pam_response **r, void *data)
{
    int i, l;
    char buf[1024], *s;

    /* fprintf(stderr, "conv: m=%p r=%p *r=%p\n", m, r, r?*r:0); */
    debug("[conversation start, %d message%s]",  n, n == 1 ? "" : "s");

    if (!n)
	debug_err("zero messages passed to conversation function");

    /* I hope someone frees this */
    *r = (struct pam_response *)malloc(n * sizeof (struct pam_response));

    for (i = 0; i < n; i++) {
	const char *msg = m[i]->msg;
	if (msg == NULL) {
	    debug_err("  NULL pam_message field #%d", i);
	    msg = "(null)";
	}
	switch (m[i]->msg_style) {
	    case PAM_PROMPT_ECHO_OFF:
		debug_nonl("  {style=prompt_echo_off}");
		if (responses && *responses) {
		    s = *responses++;
		    printf("%s%s%s%s\n", msg, col_SO_INP, s, col_SE);
		} else
		    s = getpass(m[i]->msg);
		if (!s) { fprintf(stderr, "  eof from getpass()\n"); exit(1); }
		r[i]->resp = strdup(s);
		break;
	    case PAM_PROMPT_ECHO_ON:
		debug_nonl("  {style=prompt_echo_on}");
		printf("%s", msg);
		if (responses && *responses) {
		    s = *responses++;
		    printf("%s%s%s\n", col_SO_INP, s, col_SE);
		} else
		    s = fgets(buf, sizeof buf, stdin);
		if (!s) { debug_err("  eof from fgets()"); exit(1); }
		l = strlen(s);
		r[i]->resp = strdup(s);
		if (l > 0 && s[l-1] == '\n')
		    r[i]->resp[l-1] = '\0';
		break;
	    case PAM_ERROR_MSG:
		debug_nonl("  {style=error_msg}");
                printf("%s\n", msg);
		break;
	    case PAM_TEXT_INFO:
		debug_nonl("  {style=text_info}");
                printf("%s\n", msg);
		break;
	    default:
		debug_err("  Bad conversation message style %d, (msg=%s)",
				m[i]->msg_style, msg);
		exit(1);
	}
    }
    debug("[conversation end]");
    return PAM_SUCCESS;
}

/*------------------------------------------------------------
 * main
 */

int
main(int argc, char *argv[])
{
    int ch;
    int error = 0;
    static const char *DEFAULT = "_DEFAULT";
    const char *svcname = "pamtest";
    const char *user = NULL;
    const char *ttyn = DEFAULT;
    const char *rhost = DEFAULT;
    pam_handle_t *pamh;
    struct pam_conv conv = { convfn,  NULL };
    char *name = NULL;

#ifdef HAVE_SYSLOG_H
    openlog("pamtest", 0, LOG_USER);
#endif

    authtest_init();

    /* Process command line args */
    while ((ch = getopt(argc, argv, "cn:op:rR:st:u:")) != -1) 
	switch (ch) {
	    case 'c': cflag = 1; break;
	    case 'n': svcname = optarg; break;
	    case 'o': oflag = 1; break;
	    case 'p': privsep_uid = strtouid(optarg); 
		      pflag = 1; break;
	    case 'r': rflag = 1; break;
	    case 'R': rhost = optarg; break;
	    case 's': sflag = 1; break;  /* skip authentication */
	    case 't': ttyn = optarg; break;
	    case 'u': user = optarg; break;
	    default: error = 1;
	}
    if (!rflag && argc != optind)
	error = 1;
    if (error) {
	fprintf(stderr, 
		"usage: %s [-cso] [-n svcname] [-p privsep_uid] [-u user] "
		"[-t tty] [-R rhost] [-r response ...]\n",
		argv[0]);
	exit(1);
    }
    if (rflag)
	responses = argv + optind;

    if (ttyn == DEFAULT)
	ttyn = strdup(ttyname(0));
    else if (!*ttyn)	    /* empty string means don't set */
	ttyn = NULL;

    if (rhost == DEFAULT)
	rhost = "localhost";
    else if (!*rhost)	    /* empty string means don't set */
	rhost = NULL;

    /* We should be running privileged */
    if (geteuid() != 0)
	debug("Warning: running unprivileged (euid=%d)", geteuid());

    debug(user ? "[user = '%s']" : "[user = (null)]", user);
    debug(svcname ? "[svcname = '%s']" : "[svcname = (null)]", svcname);

    /* pam_start() */
    pamh = NULL;
    CHECK(pamh, pam_start(svcname, user, &conv, &pamh));

    /* run as unprivileged if -p is given */
    if (pflag && privsep_fork(privsep_uid) == PRIVSEP_PARENT) {
	/* Forked. Now we wait for the privsep_exit() call below */
	int ret = privsep_wait();
	if (ret != 1) {
	    debug_err("unprivileged child failed: %d", ret);
	    exit(1);
	}
	goto end_privsep;
    }

    /* (START UNPRIVILEGED) */

    /* pam_authenticate() */
    if (sflag)
	debug("[-s: skipping pam_authenticate]");
    else
	CHECK(pamh, pam_authenticate(pamh, 0));

    name = NULL;
    CHECK(pamh, pam_get_item(pamh, PAM_USER, &name));
    if (name == NULL) {
	debug_err("PAM_USER is NULL?");
	exit(1);
    }
    if (!user || strcmp(name, user) != 0)
	debug("[user name is now '%s']", name);

    /* pam_acct_mgmt() */
    error = LOG(pamh, pam_acct_mgmt(pamh, 0));

    /* pam_chauthtok */
    if (error == PAM_NEW_AUTHTOK_REQD)
	CHECK(pamh, pam_chauthtok(pamh, 0));
    else if (error != PAM_SUCCESS)
	exit(1);

    if (pflag)
	privsep_exit(1);	     /* Terminates privsep child, ret=1 */
end_privsep:

    /* (END PRIVILEGED) */

    if (ttyn)
	SETITEM(pamh, PAM_TTY, ttyn);
    GETITEM(pamh, PAM_TTY);

    if (rhost)
    	SETITEM(pamh, PAM_RHOST, rhost);
    GETITEM(pamh, PAM_RHOST);

    GETITEM(pamh, PAM_USER);
    GETITEM(pamh, PAM_SERVICE);


    /* pam_set_cred() */
    if (cflag) {
	struct passwd *passwd;

	CHECK(pamh, pam_get_item(pamh, PAM_USER, &name));
	if (name == NULL) {
	    debug_err("PAM_USER is NULL?");
	    exit(1);
	}

	debug("[setting credentials for '%s']", name);

	if ((passwd = getpwnam(name)) == NULL) {
	    debug_err("getpwnam(%s) failed", name);
	    perror(name);
	    exit(1);
	}
	if (initgroups(name, passwd->pw_gid) != 0)
	    perror("initgroups");
	if (setuid(passwd->pw_uid) != 0)
	    perror("setuid");

	CHECK(pamh, pam_setcred(pamh, PAM_ESTABLISH_CRED));
    }

    /* pam_open_session() */
    CHECK(pamh, pam_open_session(pamh, 0));

    debug("session opened");

    GETITEM(pamh, PAM_USER);
    GETITEM(pamh, PAM_SERVICE);
    GETITEM(pamh, PAM_TTY);
    GETITEM(pamh, PAM_RHOST);

    if (!oflag) {
	debug("[closing session]");
	if (cflag)
	    CHECK(pamh, pam_setcred(pamh, PAM_DELETE_CRED));
	CHECK(pamh, pam_close_session(pamh, 0));
	CHECK(pamh, pam_end(pamh, PAM_SUCCESS));
    } else
	debug("[-o: leaving session open]\n");

    exit(0);
}
