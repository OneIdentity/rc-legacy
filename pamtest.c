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
    struct err *err;
    static char sbuf[128];
    for (err = errors; err->desc; err++)
	if (err->error == error)
	    return err->desc;
    snprintf(sbuf, sizeof sbuf, "error %d\n", error);
    return sbuf;
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
                mypam_strerror(pamh, expectedresult)); \
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
    fprintf(stderr, "%s item %s = ", col_SO, #item_type); \
    pam_err = pam_get_item(pamh, item_type, (ITEM_TYPE)&value); \
    if (pam_err == PAM_SUCCESS) { \
       if (value) \
           fprintf(stderr, "'%s'%s\n", value, col_SE); \
       else \
           fprintf(stderr, "(null)%s\n", col_SE); \
    } else \
       fprintf(stderr, "error: %s%s\n", mypam_strerror(pamh, pam_err), \
               col_SE); \
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
    const char *svcname = "pamtest";
    const char *user = NULL;
    pam_handle_t *pamh;
    struct pam_conv conv = { convfn,  NULL };

    authtest_init();

    /* Process command line args */
    while ((ch = getopt(argc, argv, "n:p:rsu:")) != -1) 
	switch (ch) {
	    case 'n': svcname = optarg; break;
	    case 'p': privsep_uid = strtouid(optarg); 
		      pflag = 1; break;
	    case 's': sflag = 1; break;  /* skip authentication */
	    case 'u': user = optarg; break;
	    case 'r': rflag = 1; break;
	    default: error = 1;
	}
    if (!rflag && argc != optind)
	error = 1;
    if (error) {
	fprintf(stderr, 
		"usage: %s [-s] [-n svcname] [-p privsep_uid] [-u user] "
		"[-r response ...]\n",
		argv[0]);
	exit(1);
    }
    if (rflag)
	responses = argv + optind;

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
	/* Forked. Now we wait for the privsep_return() call below */
	int ret = privsep_wait();
	if (ret != 1) {
	    fprintf(stderr, "[unpriv child failed: %d]\n", ret);
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

    /* pam_open_session() */
    CHECK(pamh, pam_open_session(pamh, 0));

    debug("session opened");

    GETITEM(pamh, PAM_USER);
    GETITEM(pamh, PAM_SERVICE);
    GETITEM(pamh, PAM_TTY);
    GETITEM(pamh, PAM_RHOST);

    /* pam_close_session() */
    CHECK(pamh, pam_close_session(pamh, 0));
    CHECK(pamh, pam_end(pamh, PAM_SUCCESS));

    exit(0);
}
