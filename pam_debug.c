/*
 * A debugging module. Arguments are in the form:
 *
 * References:
 *   http://www.opengroup.org/onlinepubs/008329799/toc.htm
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
# include <security/pam_modules.h>
#endif

#if HAVE_SYSLOG_H
# include <syslog.h>
#else
void syslog(int, const char *, ...);
# define LOG_DEBUG 7
#endif

#define BIT(v,F) ((((v) & PAM_##F) == PAM_##F) ? #F " " : "")

char g_label[256];

/* Log all the important items in the pam stack */
static void
log_items(pamh)
    struct pam_handle_t *pamh;
{
    struct { const char *name; int item_type; } items[] = {
	{ "SERVICE", PAM_SERVICE },
	{ "USER", PAM_USER },
	{ "AUTHTOK", PAM_AUTHTOK },
	{ "OLDAUTHTOK", PAM_OLDAUTHTOK },
	{ "TTY", PAM_TTY },
	{ "RHOST", PAM_RHOST },
	{ "RUSER", PAM_RUSER },
	{ "CONV", PAM_CONV },
	{ "USER_PROMPT", PAM_USER_PROMPT }
    };
    int i;
    char *p, *b, buf[1024];

    syslog(LOG_DEBUG, "%sPAM items follow:", g_label);
    for (i = 0; i < sizeof items / sizeof items[0]; i++) {
	p = NULL;
	if (pam_get_item(pamh, items[i].item_type, (void **)&p) == PAM_SUCCESS 
		&& p != NULL)  
	{
	    char *b;
	    for (b = buf; *p && b < buf + sizeof buf - 5; p++) {
		if (*p == '\\' || *p == '"')
		    *b++ = '\\';
		if (*p >= ' ' && *p < 0x7f)
		    *b++ = *p;
		else {
		    *b++ = '\\';
		    *b++ = 'x';
		    *b++ = "0123456789abcdef"[(*p & 0xf0) >> 4];
		    *b++ = "0123456789abcdef"[(*p & 0x0f) >> 4];
		}
	    }
	    *b = 0;
	    syslog(LOG_DEBUG, "%sgetitem(%s) = \"%s\"", 
			g_label, items[i].name, buf);
	}
    }
}

static void
process_args(pamh, argc, argv)
    struct pam_handle_t *pamh;
    int argc;
    const char **argv;
{
    int i;

    for (i = 0; i < argc; i++) {
	/* syslog(LOG_DEBUG, "process arg %d '%s'", i, argv[i]); */
	if (memcmp(argv[i], "label=", 6) == 0) 
	    snprintf(g_label, sizeof g_label - 1, "[%s] ", argv[i]+6);
    }
}

/*============================================================
 * Service Provider Interface
 */

/*
 * In response to a call to pam_authenticate(), the PAM framework
 * calls pam_sm_authenticate() from the modules listed in the PAM
 * configuration. The authentication provider supplies the back-end
 * functionality for this interface function.
 *
 * The function, pam_sm_authenticate(), is called to verify the identity
 * of the current user. The user is usually required to enter a password
 * or similar authentication token depending upon the authentication scheme
 * configured within the system. The user in question is typically specified
 * by a prior call to pam_start(), and is referenced by the authentication
 * handle, pamh.
 *
 * If the user is unknown to the authentication service, the service
 * module should mask this error and continue to prompt the user for a
 * password. It should then return the error, [PAM_USER_UNKNOWN].
 *
 * Before returning, pam_sm_authenticate() should call pam_get_item()
 * and retrieve PAM_AUTHTOK. If it has not been set before (that is, the
 * value is NULL), pam_sm_authenticate() should set it to the password
 * entered by the user using pam_set_item().
 *
 * An authentication module may save the authentication status (success
 * or reason for failure) as state in the authentication handle using
 * pam_set_data(). This information is intended for use by pam_setcred().
 *
 * Note:
 *     Modules should not retry the authentication in the event of a
 * failure. Applications handle authentication retries. To limit the number
 * of retries, modules may maintain an internal retry count and return a
 * [PAM_MAXTRIES] error.
 *
 * Returns: SUCCESS, AUTH_ERR, USER_UNKNOWN, CRED_INSUFFICIENT,
 * AUTHINFO_UNAVAIL, IGNORE, CONV_ERR, SERVICE_ERR, MAXTRIES, 
 * PERM_DENIED, SYSTEM_ERR, BUF_ERR
 */
int
pam_sm_authenticate(pamh, flags, argc, argv)
    pam_handle_t *pamh;
    int flags;		/* SILENT | DISALLOW_NULL_AUTHTOK */
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_authenticate flags<%s%s>", g_label,
	    BIT(flags, SILENT), BIT(flags, DISALLOW_NULL_AUTHTOK));
    log_items(pamh);
    return PAM_IGNORE;
}

/*
 * In response to a call to pam_authenticate_secondary(), the PAM
 * framework calls pam_sm_authenticate_secondary() from the modules listed
 * in the PAM configuration. The authentication provider supplies the
 * back-end functionality for this interface function.
 *
 * The function, pam_sm_authenticate_secondary(), is called to verify
 * the identity of the current user to a further domain.
 *
 * If PAM_DISALLOW_NULL_AUTHTOK is specified and target_module_authtok
 * is NULL then the authentication will fail.
 *
 * Returns: SUCCESS, AUTH_ERR, CRED_INSUFFICIENT, USER_UKNOWN,
 * SYMBOL_ERR, SERVICE_ERR, SYSTEM_ERR, BUF_ERR, CONV_ERR, PERM_DENIED
 */
int
pam_authenticate_secondary(pamh, target_username, target_module_type,
	target_authn_domain, target_supp_data, target_module_authtok, flags)
    pam_handle_t *pamh;
    char *target_username;
    char *target_module_type;
    char *target_authn_domain;
    char *target_supp_data;
    unsigned char  *target_module_authtok;
    int flags;		/* SILENT | DISALLOW_NULL_AUTHTOK */
{
    syslog(LOG_DEBUG, "%spam_sm_authenticate_secondary", g_label);
    return PAM_IGNORE;
}

/*
 * In response to a call to pam_set_cred(), the PAM framework calls
 * pam_sm_setcred() from the modules listed in the PAM configuration. The
 * authentication provider supplies the back-end functionality for this
 * interface function.
 *
 * pam_sm_setcred() is called to set the credentials of the current user
 * associated with the authentication handle, pamh.
 *
 * The authentication status (success or reason for failure) is
 * typically saved as module-specific state in the authentication handle
 * by the authentication module. The status should be retrieved using
 * pam_get_data(), and used to determine if user credentials should be set.
 * 
 * Returns: SUCCESS, CRED_UNAVAIL, CRED_EXPIRED, USER_UNKNOWN, 
 * CRED_ERR, IGNORE, PERM_DENIED, SERVICE_ERR, SYSTEM_ERR, BUF_ERR,
 * CONV_ERR
 */
int
pam_sm_setcred(pamh, flags, argc, argv)
    pam_handle_t *pamh;
    int flags;	/* ESTABLISH_CRED | DELETE_CRED | REINITIALIZE_CRED |
		   REFRESH_CRED | SILENT */
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_authenticate <%s%s%s%s%s>", g_label,
	    BIT(flags, ESTABLISH_CRED), 
	    BIT(flags, DELETE_CRED), 
	    BIT(flags, REINITIALIZE_CRED), 
	    BIT(flags, REFRESH_CRED), 
	    BIT(flags, SILENT));
    log_items(pamh);
    return PAM_IGNORE;
}


/*
 * In response to a call to pam_chauthtok() the PAM framework calls
 * pam_sm_chauthtok() from the modules listed in the PAM configuration. The
 * password management provider supplies the back-end functionality for
 * this interface function.
 *
 * pam_sm_chauthtok() changes the authentication token associated with
 * a particular user referenced by the authentication handle, pamh.
 *
 * Upon successful completion of the call, the authentication token of
 * the user will be ready for change or will be changed (depending upon
 * the flag) in accordance with the authentication scheme configured within
 * the system.
 *
 * It is the responsibility of pam_sm_chauthtok() to determine if the
 * new password meets certain strength requirements. pam_sm_chauthtok()
 * may continue to re-prompt the user (for a limited number of times)
 * using the conversation functions for a new password until the password
 * entered meets the strength requirements.
 *
 * Before returning, pam_sm_chauthtok() should call pam_get_item()
 * and retrieve both PAM_AUTHTOK and PAM_OLDAUTHTOK. If both are NULL,
 * pam_sm_chauthtok() should set them to the new and old passwords as
 * entered by the user.
 *
 * Note that the framework invokes the password services twice. The first
 * time the modules are invoked with the flag, PAM_PRELIM_CHECK. During
 * this stage, the password modules should only perform preliminary checks
 * (ping remote name services to see if they are ready for updates, for
 * example). If a password module detects a transient error (remote name
 * service temporarily down, for example) it should return PAM_TRY_AGAIN
 * to the PAM framework, which will immediately return the error back to
 * the application. If all password modules pass the preliminary check,
 * the PAM framework invokes the password services again with the flag,
 * PAM_UPDATE_AUTHTOK. During this stage, each password module should
 * proceed to update the appropriate password. Any error will again be
 * reported back to application.
 *
 * If a service module receives the flag, PAM_CHANGE_EXPIRED_AUTHTOK, it
 * should check whether the password has aged or expired. If the password
 * has aged or expired, then the service module should proceed to update
 * the password. If the status indicates that the password has not yet
 * aged/expired, then the password module should return PAM_IGNORE.
 *
 * If a user's password has aged or expired, a PAM account module could
 * save this information as state in the authentication handle, pamh, using
 * pam_set_data(). The related password management module could retrieve
 * this information using pam_get_data() to determine whether or not it
 * should prompt the user to update the password for this particular module.
 *
 * Returns: SUCCESS, AUTHTOK_ERR, AUTHTOK_RECOVERY_ERR, AUTHTOK_LOCK_BUSY,
 * AUTHTOK_DISABLE_AGING, USER_UNKNOWN, TRY_AGAIN, IGNORE, PERM_DENIED,
 * SERVICE_ERR, SYSTEM_ERR, BUF_ERR, CONV_ERR
 */
int
pam_sm_chauthtok(pamh, flags, argc, argv)
    pam_handle_t *pamh;
    int flags;	/* SILENT | CHANGE_EXPIRED_AUTHTOK | 
		   PRELIM_CHECK | UPDATE_AUTHTOK */
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_chauthtok flags<%s%s%s%s>", g_label,
	    BIT(flags, SILENT),
	    BIT(flags, CHANGE_EXPIRED_AUTHTOK),
	    BIT(flags, PRELIM_CHECK),
	    BIT(flags, UPDATE_AUTHTOK));
    return PAM_IGNORE;
}

/*
 * Performs account management actions.
 *
 * In response to a call to pam_acct_mgmt(), the PAM framework calls
 * pam_sm_acct_mgmt() from the modules listed in the PAM configuration. The
 * authentication provider supplies the back-end functionality for this
 * interface function.
 *
 * The function pam_sm_acct_mgmt(), is called to determine if the
 * current user's account is valid. This includes checking for password and
 * account expiration, as well as verifying access hour restrictions. This
 * function is typically called after the user has been authenticated
 * with pam_authenticate().
 * 
 * Returns: SUCCESS, ACCT_EXPIRED, NEW_AUTHTOKEN_REQD, USER_UNKNOWN,
 * OPEN_ERR, SYMBOL_ERR, SERVICE_ERR,  SYSTEM_ERR, BUF_ERR, CONV_ERR, 
 * PERM_DENIED, AUTHTOK_EXPIRED
 */
int
pam_sm_acct_mgmt(pamh, flags, argc, argv)
    pam_handle_t *pamh;
    int flags;		/* SILENT, DISALLOW_NULL_AUTHTOK */
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_acct_mgmt flags<%s%s>", g_label,
	    BIT(flags, SILENT),
	    BIT(flags, DISALLOW_NULL_AUTHTOK));
    return PAM_IGNORE;
}

/*
 * Gets a password for a username.
 * 
 * The pam_sm_get_mapped_authtok() function is used to obtain a password
 * for the username supplied. Any authorization data required by the
 * implementation of this interface must be present in the PAM handle. The
 * function checks the authorization data provided in the PAM handle to
 * ensure that the caller is authorized to retrieve the password for the
 * target_module_username.
 *
 * The caller should clear memory containing the returned password
 * immediately after using the password.
 *
 * Returns: SUCCESS, USER_UNKNOWN, MODULE_UNKNOWN, DOMAIN_UNKNOWN,
 * SERVICE_ERR, IGNORE, PERM_DENIED, SYSTEM_ERR, BUF_ERR, CONV_ERR
 */

int
pam_sm_get_mapped_authtok(pamh, target_module_username,
	target_module_type, target_authn_domain,
	target_authtok_len, target_module_authtok, argc, argv)
    pam_handle_t *pamh;
    char *target_module_username;
    char *target_module_type;
    char *target_authn_domain;
    size_t *target_authtok_len;
    unsigned char **target_module_authtok;
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_get_mapped_authtok", g_label);
    return PAM_IGNORE;
}

/* 
 * Gets a valid matched identity in a new domain.
 *
 * The pam_sm_get_mapped_username() function is used to
 * obtain a valid identity in a new domain that matches the input
 * identity. target_module_type and target_authn_domain are used to query
 * the mapping database and extract the target_username.
 *
 * Returns: SUCCESS, USER_UNKNOWN, MODULE_UNKNOWN, DOMAIN_UNKNOWN,
 * SERVICE_ERR, IGNORE, PERM_DENIED, SYSTEM_ERR, BUF_ERR, CONV_ERR
 */
int
pam_sm_get_mapped_username(pamh, src_username, src_module_type,
	src_authn_domain, target_module_type, target_authn_domain,
	target_module_username, argc, argv)
    pam_handle_t *pamh;
    char *src_username;
    char *src_module_type;
    char *src_authn_domain;
    char *target_module_type;
    char *target_authn_domain;
    char **target_module_username;
    int  argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_get_mapped_username", g_label);
    return PAM_IGNORE;
}

/*
 * Stores the password for the username supplied
 *
 * Returns: SUCCESS, USER_UNKNOWN, MODULE_UNKNOWN, DOMAIN_UNKNOWN,
 * SERVICE_ERR, IGNORE, PERM_DENIED, SERVICE_ERR, SYSTEM_ERR, 
 * BUF_ERR, CONV_ERR
 */
int
pam_sm_set_mapped_authtok (pamh, target_module_username,
	target_authtok_len, target_module_authtok, target_module_type,
	target_authn_domain, argc, argv)
    pam_handle_t *pamh;
    char *target_module_username;
    size_t *target_authtok_len;
    unsigned char *target_module_authtok;
    char *target_module_type;
    char *target_authn_domain;
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_get_mapped_authtok", g_label);
    return PAM_IGNORE;
}

/*
 * Stores a username.
 * The pam_sm_set_mapped_username() function stores a username using
 * the target_module_type and target_authn_domain parameters supplied. 
 *
 * Returns: SUCCESS, USER_UNKNOWN, MODULE_UNKNOWN, DOMAIN_UNKNOWN,
 * SERVICE_ERR, IGNORE, PERM_DENIED, SYSTEM_ERR, BUF_ERR, CONV_ERR
 */
int
pam_sm_set_mapped_username(pamh, target_module_username,
	target_module_type, target_authn_domain, argc, argv)
    pam_handle_t *pamh;
    char *target_module_username;
    char *target_module_type;
    char *target_authn_domain;
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_set_mapped_username", g_label);
    return PAM_IGNORE;
}

/*
 * Initiates session management.
 * Called by PAM framework in response to pam_open_session() 
 *
 * Returns: SUCCESS, SESSION_ERR, IGNORE, PERM_DENIED, SERVICE_ERR,
 * SYSTEM_ERR, BUF_ERR, CONV_ERR
 */
int
pam_sm_open_session(pamh, flags, argc, argv)
    pam_handle_t *pamh;
    int flags;		/* SILENT */
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_open_session flags<%s>", g_label,
	    BIT(flags, SILENT));
    return PAM_IGNORE;
}

/* 
 * Terminates session management.
 * Called by PAM framework in response to pam_close_session()
 *
 * Returns: SUCCESS, SESSION_ERR, IGNORE, PERM_DENIED,
 * SERVICE_ERR, SYSTEM_ERR, BUF_ERR, CONV_ERR
 */
int
pam_sm_close_session(pamh, flags, argc, argv)
    pam_handle_t *pamh;
    int flags;		/* SILENT */
    int argc;
    const char **argv;
{
    process_args(pamh, argc, argv);
    syslog(LOG_DEBUG, "%spam_sm_close_session flags<%s>", g_label,
	    BIT(flags, SILENT));
    return PAM_IGNORE;
}

