/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "login_locl.h"
#ifdef HAVE_CAPABILITY_H
#include <capability.h>
#endif
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

RCSID("$Id: login.c,v 1.65.2.1 2006/01/09 16:29:49 joda Exp $");


#if 0
#ifdef SOLARIS
    #include <crypt.h>
#endif
#endif

#ifdef AIX
   struct aud_rec;
   #include <usersec.h>
#endif

/* for Merging, UID conflict checks, etc. */
#include <libvascache_auth.h>
#include <libvasauth/libvasauth.h>
#include <libvascache_merge.h>
#include <libvas.h>

#include <vers.h>

/* For the crypt stuff to make sure we get the renamed symbols,
 * this is probably not the best thing... */
#include <des.h>

static int login_timeout = 60;

static RETSIGTYPE
sig_handler(int sig)
{
    if (sig == SIGALRM)
    {
        fprintf(stderr,
                "Login timed out after %d seconds\n",
                login_timeout);
    }
    else
    {
        fprintf(stderr, "Login received signal, exiting\n");
    }

    exit(0);
}

static int
start_login_process(void)
{
    char *prog, *argv0;
    prog = login_conf_get_string("login_program");
    if(prog == NULL)
	return 0;
    argv0 = strrchr(prog, '/');

    if(argv0)
	argv0++;
    else
	argv0 = prog;

    return simple_execle(prog, argv0, NULL, env);
}

static int
start_logout_process(void)
{
    char *prog, *argv0;
    pid_t pid;

    prog = login_conf_get_string("logout_program");
    if(prog == NULL)
	return 0;
    argv0 = strrchr(prog, '/');

    if(argv0)
	argv0++;
    else
	argv0 = prog;

    pid = fork();
    if(pid == 0) {
	/* avoid getting signals sent to the shell */
	setpgid(0, getpid());
	return 0;
    }
    if(pid == -1)
	err(1, "fork");
    /* wait for the real login process to exit */
#ifdef HAVE_SETPROCTITLE
    setproctitle("waitpid %d", pid);
#endif
    while(1) {
	int status;
	int ret;
	ret = waitpid(pid, &status, 0);
	if(ret > 0) {
	    if(WIFEXITED(status) || WIFSIGNALED(status)) {
		execle(prog, argv0, NULL, env);
		err(1, "exec %s", prog);
	    }
	} else if(ret < 0) 
	    err(1, "waitpid");
    }
}

static void
exec_shell(const char *shell, int fallback)
{
    char *sh;
    const char *p;
    
    extend_env(NULL);
    if(start_login_process() < 0)
	warn("login process");
    start_logout_process();

    p = strrchr(shell, '/');
    if(p)
	p++;
    else
	p = shell;
    asprintf(&sh, "-%s", p);
    execle(shell, sh, NULL, env);
    if(fallback){
	warnx("Can't exec %s, trying %s", 
	      shell, _PATH_BSHELL);
	execle(_PATH_BSHELL, "-sh", NULL, env);
	err(1, "%s", _PATH_BSHELL);
    }
    err(1, "%s", shell);
}

static enum {
    NONE = 0, AUTH_KRB4 = 1, AUTH_KRB5 = 2, AUTH_OTP = 3
} auth;

#ifdef OTP
static OtpContext otp_ctx;

static int
otp_verify(struct passwd *pwd, const char *password)
{
   return (otp_verify_user (&otp_ctx, password));
}
#endif /* OTP */


#ifdef KRB4
static int pag_set = 0;
#endif

#ifdef KRB5
static krb5_context context;
static krb5_ccache  id, id2;

/* not used for now... */
#if 0
static int
krb5_verify(struct passwd *pwd, const char *password)
{
    krb5_error_code ret;
    krb5_principal princ;

    ret = krb5_parse_name(context, pwd->pw_name, &princ);
    if(ret)
	return 1;
    ret = krb5_cc_gen_new(context, &krb5_mcc_ops, &id);
    if(ret) {
	krb5_free_principal(context, princ);
	return 1;
    }
    ret = krb5_verify_user_lrealm(context,
				  princ, 
				  id,
				  password, 
				  1,
				  NULL);
    krb5_free_principal(context, princ);
    return ret;
}
#endif


#define DBGLOG(x,va...) syslog(LOG_INFO,x,##va)
#define ERRLOG(x,va...) syslog(LOG_ERR,x,##va)


/* This is similar to the pam_vas handle_expired_password code */
static int
vas_authhelper_new_password( vascache_userinfo_t *info,
                             const char *password,
                             char **new_password_ptr )
{
    int                     result = 0;
    char                    new_password[128] = {'\0'},
                            *helper_input[] = { NULL, NULL, NULL },
                            verify_password[128] = {'\0'};
    vasauth_helperinfo_t    helper_info;
    vasauth_helperopts_t    helper_opts;

    memset( &helper_info, 0, sizeof(helper_info) );
    memset( &helper_opts, 0, sizeof(helper_opts) );

    /* Prompt for new password */
#ifdef UW7
    fprintf( stderr,
             "UX:in.login: ERROR: Your password has expired\n" );
#else
    fprintf( stdout, 
             "Your password has expired, please follow the "
             "prompts to change it.\n" );
#endif

    switch( read_string( "New Password: ", 
                         new_password, 
                         sizeof(new_password), 
                         0 ) )
    {
        case -3:
            exit( 0 );
            break;
        case -2:
            sig_handler( 0 );
            break;
        default:
            break;
    }

    switch( read_string( "Verify New Password: ", 
                         verify_password, 
                         sizeof(verify_password), 
                         0 ) )
    {
        case -3:
            exit( 0 );
            break;
        case -2:
            sig_handler( 0 );
            break;
        default:
            break;
    }

    if( strcmp( new_password, verify_password ) )
    {
        fprintf( stderr,
                 "Sorry, entered passwords do not match.\n" );
        return( 1 );
    }
    
    helper_input[0] = (char *)password;
    helper_input[1] = new_password;

    if( (result = libvasauth_launch_helper( &helper_info,
                                            &helper_opts,
                                            VASAUTH_HELPER_CMD_CHANGEPW,
                                            info->krb5PrincipalName,
                                            0,
                                            0,
                                            (const char **) helper_input ))
          == VASAUTH_HELPER_OPEN_FAILED )
    {
        ERRLOG( "Could not execute vasauth_helper" );
        result = 1;
        return( result );
    }

    result = libvasauth_waitfor_helper( &helper_info );

    if( new_password_ptr )
        *new_password_ptr = strdup( new_password );

    return( result );
}

/* This function replaces vas_verify --- it passes off all of the
 * vas authentication, account management( expired passwords, etc )
 * to the auth_helper application
 */
static int
vas_helper_verify( vascache_t *vascache,
                   vascache_userinfo_t *info,
                   const char *password,
                   int *did_disconnected_auth )
{
    char                        *helper_input[] = { NULL, NULL },
                                *new_password = NULL,
                                *spn_name = "host/";
    int                         do_disconnected_auth = 0,
                                result = 1,         /* Assume failure */
                                rval = 0;
    vasauth_helperinfo_t        helper_info;
    vasauth_helperopts_t        helper_opts;

    memset( &helper_info, 0, sizeof(helper_info) );
    memset( &helper_opts, 0, sizeof(helper_opts) );

    /* Basically allow the helper to do what it needs to do...*/
    helper_input[0] = (char *)password;

    /* Set some default values */
    helper_opts.auth_ad_service_principal = spn_name;
    helper_opts.auth_ad_write_expiration_days = 1;
    
    /* This needs to be cleaned up a bit....Probably need to scan through
     * the pam settings to set things up properly as far as timeouts,
     * options, and such....
     */
    helper_opts.auth_ad_get_tgt = 1;
    helper_opts.auth_ad_check_pwdLastSet = 0;

    if( (rval = libvasauth_launch_helper( &helper_info,
                                           &helper_opts,
                                           VASAUTH_HELPER_CMD_AUTH,
                                           info->userPrincipalName,
                                           0,
                                           0,
                                           (const char **) helper_input ))
          == VASAUTH_HELPER_OPEN_FAILED )
    {
        ERRLOG( "%s: could not execute vasauth_helper, error=%d",
                __FUNCTION__, 
                rval );
    }
    else
    {
        /* Let it finish */
        switch( (rval = libvasauth_waitfor_helper( &helper_info )) )
        {
            case VASAUTH_HELPER_KDC_UNREACHABLE:
            case VASAUTH_HELPER_TIMED_OUT:
                /* Do a disconnected authication */
                do_disconnected_auth = 1;
                break;
            case VASAUTH_HELPER_TIME_SYNC_ERR:
                /* Output the message */
                fprintf( stderr,
                         "Your system's internal clock is not "
                         "synchronized with your authentication "
                         "server.\nPlease notify the system "
                         "administrator.\n" );
                break;
            case VASAUTH_HELPER_POLICY_DENIED:
            case VASAUTH_HELPER_PERM_DENIED:
                /* Output message */
                fprintf( stderr,
                         "The authentication server policy does "
                         "not allow you to login at this time.\n" );
                break;
            case VASAUTH_HELPER_ACCOUNT_EXPIRED:
                /* Displaying info here could be a security risk, so don't */
                ERRLOG( "Account %s: is expired", info->userPrincipalName );
                break;
            case VASAUTH_HELPER_NEED_NEW_PASSWORD:
                /* Allow the user to change their password */
                if( vas_authhelper_new_password( info,
                                                 password,
                                                 &new_password ) == 0)
                {
                    result = vas_helper_verify( vascache,
                                                info,
                                                new_password,
                                                did_disconnected_auth );
                    if( new_password )
                    {
                        int         len = strlen( new_password );

                        memset( new_password, 0, len );
                        free( new_password );
                    }
                }
                else
                {
                    ERRLOG( "vas_authhelper_new_password failed." );
                }
                break;
            case VASAUTH_HELPER_AUTH_ERROR:
                ERRLOG( "Failed authentication attempt for Active "
                        "Directory user: %s for service login, err = bad password",
                        info->userPrincipalName );
                break;
            case VASAUTH_HELPER_SUCCESS:
                result = 0;
                break;
            case VASAUTH_HELPER_INTERNAL_ERR:
            default:
                ERRLOG( "Failed authentication attempt for Active "
                        "Directory user: %s for service login, "
                        "err = vas_auth_helper internal failure", 
                        info->userPrincipalName );
                break;
        }

        if( do_disconnected_auth )
        {
            if( libvascache_user_disconnected_auth( vascache, info, password ) )
            {
                if( errno == EPERM )
                {
                }
                else
                {
                }
            }
            else
            {
               if( did_disconnected_auth )
                   *did_disconnected_auth = 1;
               result = 0;
            }
        }
    }

    return( result );
}

#if 0
static int
vas_verify( vascache_t* vascache,
            vascache_userinfo_t* info, 
            const char* password, 
            int no_disconnected_mode,
            int timed_out )
{
    int             rval = 1; /* Assume failure */
    libvas_t*       libvas = NULL;
    int             vas_ret;
    char            current_password[128];
    char            new_password[128];
    char            verify_password[128];
    char            *pretty_name = NULL;
    libvas_ticket_t ticket;

    /* Initialize locals */
    memset(&ticket,0,sizeof(ticket));

    /* Quick check up front for disconnected mode */
    if( !no_disconnected_mode && 
        (timed_out || !vascache_is_daemon_running( vascache )) )
    {
        /* do disconnected authentication */
        if( libvascache_user_disconnected_auth( vascache, 
                                                info, 
                                                password ) )
        {
            /* bad password */
            goto CLEANUP;
        }
        else
        {
            /* SUCCESS! It's authenticated */
            goto CLEANUP;  
        }
    }
    
    /* use a memory ccache until we're finished and we can copy
     * the tickets to the real creds cache */
    if( (vas_ret = vas_alloc( (vas_t**) &libvas, 
                              info->krb5PrincipalName )) )
    {
        DBGLOG( "could not allocate libvas structure" );
        goto CLEANUP;
    }
    vas_opt_set( libvas, VAS_OPT_KRB5_USE_MEMCACHE, "1" );
    
    /* try to get the TGT */
    if( (vas_ret = libvas_ticket_get(libvas, NULL, password, 1, NULL )) )
    {
        /* do disconnected authentication */
        if( libvas->err.krb5_err.err == KRB5_KDC_UNREACH )
        {
            if( !no_disconnected_mode )
            {
                DBGLOG( "vas_verify: trying disconnected auth" );
                if( (vas_ret = libvascache_user_disconnected_auth( vascache,
                                                                   info,
                                                                   password )) )
                {
                    DBGLOG( "vas_verify: disconnected authentication failed, "
                            "err = %d", 
                            vas_ret );
                }
            }
            else
            {
                DBGLOG( "krb5 ticket request timed out, but disconnected "
                        "mode is disabled" );
            }

            goto CLEANUP;
        }
        else 
        if( libvas->err.krb5_err.err == KRB5KDC_ERR_KEY_EXPIRED )
        {
            /* password is expired, so we ought to try and change it,
             * prompt for the new password and prompt again to verify
             * it */
            DBGLOG( "vas_verify: password has expired, change it!" );

            memset( current_password, 0, sizeof(current_password) );
            memset( new_password, 0, sizeof(new_password) );
            memset( verify_password, 0, sizeof(verify_password) );

#ifdef UW7
            fprintf( stderr,
                     "UX:in.login: ERROR: Your password has expired\n" );
#else
            fprintf( stdout, 
                     "Your password has expired, please follow the "
                     "prompts to change it.\n" );
#endif

            switch( read_string( "Current Password: ", 
                                 current_password, 
                                 sizeof(current_password), 
                                 0 ) )
            {
                case -3:
                    exit( 0 );
                    break;
                case -2:
                    sig_handler( 0 );
                    break;
                default:
                    break;
            }

            switch( read_string( "New Password: ", 
                                 new_password, 
                                 sizeof(new_password), 
                                 0 ) )
            {
                case -3:
                    exit( 0 );
                    break;
                case -2:
                    sig_handler( 0 );
                    break;
                default:
                    break;
            }

            switch( read_string( "Verify New Password: ", 
                                 verify_password, 
                                 sizeof(verify_password), 
                                 0 ) )
            {
                case -3:
                    exit( 0 );
                    break;
                case -2:
                    sig_handler( 0 );
                    break;
                default:
                    break;
            }

            if( strcmp( new_password, verify_password ) )
            {
                fprintf( stderr,
                         "Sorry, entered passwords do not match.\n" );
                goto CLEANUP;
            }

            vas_ret = vas_change_password( libvas, 
                                           current_password, 
                                           new_password );
            switch( vas_ret )
            {
            case 0:
                fprintf( stdout, 
                         "Your password was successfully changed.\n" );
                if( (vas_ret = libvas_ticket_get( libvas, 
                                                  NULL,
                                                  new_password,
                                                  1,
                                                  NULL )) )
                {
                    DBGLOG( "couldn't get tgt with new changed password, "
                            "err = %d", 
                            libvas->err.krb5_err.err );
                    goto CLEANUP;
                }
                break;

            case EACCES:
                fprintf( stderr,
                         "You are not allowed to change your password "
                         "at this time.\n" );
                goto CLEANUP;
                break;

            case EFAULT:
                fprintf( stderr,
                         "This new password does not meet your "
                         "domain's password policy requirements.\n"
                         "Contact your Administrator for information "
                         "on the minimum password length,\n"
                         "password complexity, "
                         "and password history requirements.\n" );
                goto CLEANUP;
                break;

            default:
                fprintf( stderr,
                         "Password change failed.\n" );
                DBGLOG( "couldn't change password, err = %d",
                        vas_ret );
                goto CLEANUP;
                break;
            }
        }
        else
        {
            DBGLOG( "couldn't get tgt, error = %d", 
                    libvas->err.krb5_err.err );
            goto CLEANUP;
        }
    }

    /* try to get the host ticket */
    if( (vas_ret = libvas_beautify_pname( libvas, "host/", 1, &pretty_name )) )
    {
        DBGLOG( "could not beautify \"host/\", error = %s",
                vas_error_str( libvas ) );
        goto CLEANUP;
    }

    if( (vas_ret = libvas_ticket_get( libvas, pretty_name, NULL, 1, &ticket )) )
    {
        DBGLOG( "could not get a ticket for %s, error = %s, krb5 code = %d", 
                pretty_name,
                vas_error_str( libvas ), 
                libvas->err.krb5_err.err );
        goto CLEANUP;
    }

    /* Validate the host ticket */
    if( (vas_ret = libvas_ticket_validate(libvas,&ticket)) )
    {
        DBGLOG( "could not validate ticket for %s, error = %s",
                pretty_name,
                vas_error_str( libvas ) );
    }

    /* Copy the cred cache to the global "id" variable so that it
     * can be saved upon successful login 
     */
    if( krb5_cc_gen_new(context, &krb5_mcc_ops, &id) )
        goto CLEANUP;
    
    krb5_cc_copy_cache(libvas->krb5ctx,libvas->krb5cc,id);

    /* cache the disconnected password */
    if( !no_disconnected_mode )
        libvascache_user_store_password( info, password, 1 );

    /* set this so we do the krb5 ticket stuff later */
    auth = AUTH_KRB5;

    /* SUCCESS */
    rval = 0;

CLEANUP:
    memset( new_password, 0, sizeof(new_password) );
    memset( verify_password, 0, sizeof(verify_password) );
    libvas_ticket_free(&ticket);
    
    if( pretty_name )   free( pretty_name );
    if( libvas)         vas_free( libvas );

    return rval;
}
#endif

#ifdef KRB4
static krb5_error_code
krb5_to4 (krb5_ccache id)
{
    krb5_error_code ret;
    krb5_principal princ;

    int get_v4_tgt;

    get_v4_tgt = krb5_config_get_bool(context, NULL,
                                      "libdefaults",
                                      "krb4_get_tickets",
                                      NULL);

    ret = krb5_cc_get_principal(context, id, &princ);
    if(ret == 0) {
        get_v4_tgt = krb5_config_get_bool_default(context, NULL,
                                                  get_v4_tgt,
                                                  "realms",
                                                  *krb5_princ_realm(context,
                                                                    princ),
                                                  "krb4_get_tickets",
                                                  NULL);
	krb5_free_principal(context, princ);
    }

    if (get_v4_tgt) {
        CREDENTIALS c;
        krb5_creds mcred, cred;
        char krb4tkfile[MAXPATHLEN];
	krb5_error_code ret;
	krb5_principal princ;

	krb5_cc_clear_mcred(&mcred);

	ret = krb5_cc_get_principal (context, id, &princ);
	if (ret)
	    return ret;

	ret = krb5_make_principal(context, &mcred.server,
				  princ->realm,
				  "krbtgt",
				  princ->realm,
				  NULL);
	if (ret) {
	    krb5_free_principal(context, princ);
	    return ret;
	}
	mcred.client = princ;

	ret = krb5_cc_retrieve_cred(context, id, 0, &mcred, &cred);
	if(ret == 0) {
	    ret = krb524_convert_creds_kdc_ccache(context, id, &cred, &c);
	    if(ret == 0) {
		snprintf(krb4tkfile,sizeof(krb4tkfile),"%s%d",TKT_ROOT,
			 getuid());
		krb_set_tkt_string(krb4tkfile);
		tf_setup(&c, c.pname, c.pinst);
	    }
	    memset(&c, 0, sizeof(c));
	    krb5_free_cred_contents(context, &cred);
	}
	krb5_free_principal(context, mcred.server);
	krb5_free_principal(context, mcred.client);
    }
    return 0;
}
#endif /* KRB4 */

static int
krb5_start_session (const struct passwd *pwd)
{
    krb5_error_code ret;
    char residual[64];

    /* copy credentials to file cache */
    snprintf(residual, sizeof(residual), "FILE:/tmp/krb5cc_%u", 
	     (unsigned)pwd->pw_uid);
    krb5_cc_resolve(context, residual, &id2);
    ret = krb5_cc_copy_cache(context, id, id2);
    if (ret == 0)
	add_env("KRB5CCNAME", residual);
    else {
	krb5_cc_destroy (context, id2);
	return ret;
    }
#ifdef KRB4
    krb5_to4 (id2);
#endif
    krb5_cc_close(context, id2);
    krb5_cc_destroy(context, id);
    return 0;
}

static void
krb5_finish (void)
{
    krb5_free_context(context);
}

#ifdef KRB4
static void
krb5_get_afs_tokens (const struct passwd *pwd)
{
    char cell[64];
    char *pw_dir;
    krb5_error_code ret;

    if (!k_hasafs ())
	return;

    ret = krb5_cc_default(context, &id2);
 
    if (ret == 0) {
	pw_dir = pwd->pw_dir;

	if (!pag_set) {
	    k_setpag();
	    pag_set = 1;
	}

	if(k_afs_cell_of_file(pw_dir, cell, sizeof(cell)) == 0)
	    krb5_afslog_uid_home (context, id2,
				  cell, NULL, pwd->pw_uid, pwd->pw_dir);
	krb5_afslog_uid_home (context, id2, NULL, NULL,
			      pwd->pw_uid, pwd->pw_dir);
	krb5_cc_close (context, id2);
    }
}
#endif /* KRB4 */

#endif /* KRB5 */

#ifdef KRB4

static int
krb4_verify(struct passwd *pwd, const char *password)
{
    char lrealm[REALM_SZ];
    int ret;
    char ticket_file[MaxPathLen];

    ret = krb_get_lrealm (lrealm, 1);
    if (ret)
	return 1;

    snprintf (ticket_file, sizeof(ticket_file),
	      "%s%u_%u",
	      TKT_ROOT, (unsigned)pwd->pw_uid, (unsigned)getpid());

    krb_set_tkt_string (ticket_file);

    ret = krb_verify_user (pwd->pw_name, "", lrealm, (char *)password,
			   KRB_VERIFY_SECURE_FAIL, NULL);
    if (ret)
	return 1;

    if (chown (ticket_file, pwd->pw_uid, pwd->pw_gid) < 0) {
	dest_tkt();
	return 1;
    }
	
    add_env ("KRBTKFILE", ticket_file);
    return 0;
}

static void
krb4_get_afs_tokens (const struct passwd *pwd)
{
    char cell[64];
    char *pw_dir;

    if (!k_hasafs ())
	return;

    pw_dir = pwd->pw_dir;

    if (!pag_set) {
	k_setpag();
	pag_set = 1;
    }

    if(k_afs_cell_of_file(pw_dir, cell, sizeof(cell)) == 0)
	krb_afslog_uid_home (cell, NULL, pwd->pw_uid, pwd->pw_dir);

    krb_afslog_uid_home (NULL, NULL, pwd->pw_uid, pwd->pw_dir);
}

#endif /* KRB4 */

static int f_flag;
static int p_flag;
#if 0
static int r_flag;
#endif
static int version_flag;
static int help_flag;
static char *remote_host;
static char *auth_level = NULL;

struct getargs args[] = {
    { NULL, 'a', arg_string,    &auth_level,    "authentication mode", NULL, },
#if 0
    { NULL, 'd', 0, NULL, NULL, NULL, NULL},
#endif
    { NULL, 'f', arg_flag,  &f_flag,    "pre-authenticated", NULL },
    { NULL, 'h', arg_string,	&remote_host,	"remote host", "hostname" },
    { NULL, 'p', arg_flag,  &p_flag,    "don't purge environment", NULL },
#if 0
    { NULL, 'r', arg_flag,  &r_flag,    "rlogin protocol", NULL },
#endif
    { "version", 0,  arg_flag,  &version_flag, NULL, NULL },
    { "help",    0,  arg_flag,&help_flag, NULL, NULL }
};

int nargs = sizeof(args) / sizeof(args[0]);

static void
update_utmp(const char *username, const char *hostname,
	    char *tty, char *ttyn)
{
    /*
     * Update the utmp files, both BSD and SYSV style.
     */
    if (utmpx_login(tty, username, hostname) != 0 && !f_flag) {
	printf("No utmpx entry.  You must exec \"login\" from the "
	       "lowest level shell.\n");
	exit(1);
    }
    utmp_login(ttyn, username, hostname);
}

static void
checknologin(void)
{
    FILE *f;
    char buf[1024];

    f = fopen(_PATH_NOLOGIN, "r");
    if(f == NULL)
	return;
    while(fgets(buf, sizeof(buf), f))
	fputs(buf, stdout);
    fclose(f);
    exit(0);
}

/* print contents of a file */
static void
show_file(const char *file)
{
    FILE *f;
    char buf[BUFSIZ];
    if((f = fopen(file, "r")) == NULL)
	return;
    while (fgets(buf, sizeof(buf), f))
	fputs(buf, stdout);
    fclose(f);
}

/* 
 * Actually log in the user.  `pwd' contains all the relevant
 * information about the user.  `ttyn' is the complete name of the tty
 * and `tty' the short name.
 */

static void
do_login(const struct passwd *pwd, char *tty, char *ttyn)
{
#ifdef HAVE_GETSPNAM
    struct spwd *sp;
#endif
    int rootlogin = (pwd->pw_uid == 0);
    gid_t tty_gid;
    struct group *gr;
    const char *home_dir;
    int i;

    if(!rootlogin)
	checknologin();
    
#ifdef HAVE_GETSPNAM
    sp = getspnam(pwd->pw_name);
#endif

    update_utmp(pwd->pw_name, remote_host ? remote_host : "",
		tty, ttyn);

    gr = getgrnam ("tty");
    if (gr != NULL)
	tty_gid = gr->gr_gid;
    else
	tty_gid = pwd->pw_gid;

    if (chown (ttyn, pwd->pw_uid, tty_gid) < 0) {
	warn("chown %s", ttyn);
	if (rootlogin == 0)
	    exit (1);
    }

    if (chmod (ttyn, S_IRUSR | S_IWUSR | S_IWGRP) < 0) {
	warn("chmod %s", ttyn);
	if (rootlogin == 0)
	    exit (1);
    }

#ifdef HAVE_SETLOGIN
    if(setlogin(pwd->pw_name)){
	warn("setlogin(%s)", pwd->pw_name);
	if(rootlogin == 0)
	    exit(1);
    }
#endif
    if(rootlogin == 0) {
	const char *file = login_conf_get_string("limits");
	if(file == NULL)
	    file = _PATH_LIMITS_CONF;

	read_limits_conf(file, pwd);
    }
	    
#ifdef HAVE_SETPCRED
    if (setpcred (pwd->pw_name, NULL) == -1)
	warn("setpcred(%s)", pwd->pw_name);
#endif /* HAVE_SETPCRED */
#ifdef HAVE_INITGROUPS
    if(initgroups(pwd->pw_name, pwd->pw_gid)){
	warn("initgroups(%s, %u)", pwd->pw_name, (unsigned)pwd->pw_gid);
	if(rootlogin == 0)
	    exit(1);
    }
#endif
    if(do_osfc2_magic(pwd->pw_uid))
	exit(1);
    if(setgid(pwd->pw_gid)){
	warn("setgid(%u)", (unsigned)pwd->pw_gid);
	if(rootlogin == 0)
	    exit(1);
    }
    if(setuid(pwd->pw_uid) || (pwd->pw_uid != 0 && setuid(0) == 0)) {
	warn("setuid(%u)", (unsigned)pwd->pw_uid);
	if(rootlogin == 0)
	    exit(1);
    }

    /* make sure signals are set to default actions, apparently some
       OS:es like to ignore SIGINT, which is not very convenient */
    
    for (i = 1; i < NSIG; ++i)
	signal(i, SIG_DFL);

    /* all kinds of different magic */

#ifdef HAVE_GETSPNAM
    check_shadow(pwd, sp);
#endif

#if defined(HAVE_GETUDBNAM) && defined(HAVE_SETLIM)
    {
	struct udb *udb;
	long t;
	const long maxcpu = 46116860184; /* some random constant */
	udb = getudbnam(pwd->pw_name);
	if(udb == UDB_NULL)
	    errx(1, "Failed to get UDB entry.");
	t = udb->ue_pcpulim[UDBRC_INTER];
	if(t == 0 || t > maxcpu)
	    t = CPUUNLIM;
	else
	    t *= 100 * CLOCKS_PER_SEC;

	if(limit(C_PROC, 0, L_CPU, t) < 0)
	    warn("limit C_PROC");

	t = udb->ue_jcpulim[UDBRC_INTER];
	if(t == 0 || t > maxcpu)
	    t = CPUUNLIM;
	else
	    t *= 100 * CLOCKS_PER_SEC;

	if(limit(C_JOBPROCS, 0, L_CPU, t) < 0)
	    warn("limit C_JOBPROCS");

	nice(udb->ue_nice[UDBRC_INTER]);
    }
#endif
#if defined(HAVE_SGI_GETCAPABILITYBYNAME) && defined(HAVE_CAP_SET_PROC)
	/* XXX SGI capability hack IRIX 6.x (x >= 0?) has something
	   called capabilities, that allow you to give away
	   permissions (such as chown) to specific processes. From 6.5
	   this is default on, and the default capability set seems to
	   not always be the empty set. The problem is that the
	   runtime linker refuses to do just about anything if the
	   process has *any* capabilities set, so we have to remove
	   them here (unless otherwise instructed by /etc/capability).
	   In IRIX < 6.5, these functions was called sgi_cap_setproc,
	   etc, but we ignore this fact (it works anyway). */
	{
	    struct user_cap *ucap = sgi_getcapabilitybyname(pwd->pw_name);
	    cap_t cap;
	    if(ucap == NULL)
		cap = cap_from_text("all=");
	    else
		cap = cap_from_text(ucap->ca_default);
	    if(cap == NULL)
		err(1, "cap_from_text");
	    if(cap_set_proc(cap) < 0)
		err(1, "cap_set_proc");
	    cap_free(cap);
	    free(ucap);
	}
#endif
    home_dir = pwd->pw_dir;
    if (chdir(home_dir) < 0) {
	fprintf(stderr, "No home directory \"%s\"!\n", pwd->pw_dir);
	if (chdir("/"))
	    exit(0);
	home_dir = "/";
	fprintf(stderr, "Logging in with home = \"/\".\n");
    }
#ifdef KRB5
    if (auth == AUTH_KRB5) {
	krb5_start_session (pwd);
    }
#ifdef KRB4
    else if (auth == 0) {
	krb5_error_code ret;
	krb5_ccache id;

	ret = krb5_cc_default (context, &id);
	if (ret == 0) {
	    krb5_to4 (id);
	    krb5_cc_close (context, id);
	}
    }

    krb5_get_afs_tokens (pwd);
#endif /* KRB4 */
    krb5_finish ();
#endif /* KRB5 */

#ifdef KRB4
    krb4_get_afs_tokens (pwd);
#endif /* KRB4 */

    add_env("PATH", _PATH_DEFPATH);

    {
	const char *str = login_conf_get_string("environment");
	char buf[MAXPATHLEN];

	if(str == NULL) {
	    login_read_env(_PATH_ETC_ENVIRONMENT);
	} else {
	    while(strsep_copy(&str, ",", buf, sizeof(buf)) != -1) {
		if(buf[0] == '\0')
		    continue;
		login_read_env(buf);
	    }
	}
    }
    {
	const char *str = login_conf_get_string("motd");
	char buf[MAXPATHLEN];

	if(str != NULL) {
	    while(strsep_copy(&str, ",", buf, sizeof(buf)) != -1) {
		if(buf[0] == '\0')
		    continue;
		show_file(buf);
	    }
	}
    }
    add_env("HOME", home_dir);
    add_env("USER", pwd->pw_name);
    add_env("LOGNAME", pwd->pw_name);
    add_env("SHELL", pwd->pw_shell);
    exec_shell(pwd->pw_shell, rootlogin);
}


static int
check_password(struct passwd *pwd, const char *password)
{
    if (pwd == NULL || pwd->pw_passwd == NULL)
	return 1;

    if(pwd->pw_passwd[0] == '\0'){
#ifdef ALLOW_NULL_PASSWORD
	return password[0] != '\0';
#else
	return 1;
#endif
    }

    /* the shadow password is filled in by k_getpwnam from libroken */
    if(strcmp(pwd->pw_passwd, crypt(password, pwd->pw_passwd)) == 0)
	return 0;


/* disable the rest of these since we handle krb5 and we'll do
 * that before doing the local check */
#if 0
#ifdef KRB5
    if(krb5_verify(pwd, password) == 0) {
	auth = AUTH_KRB5;
	return 0;
    }
#endif
#ifdef KRB4
    if (krb4_verify (pwd, password) == 0) {
	auth = AUTH_KRB4;
	return 0;
    }
#endif
#ifdef OTP
    if (otp_verify (pwd, password) == 0) {
       auth = AUTH_OTP;
       return 0;
    }
#endif
#endif
    
    return 1;
}


static void
usage(int status)
{
    arg_printusage(args, nargs, NULL, "[username]");
    exit(status);
}


int
main(int argc, char **argv)
{
    int max_tries = 5;
    int  curr_try = 0;
    char *bad_group = NULL;
    char username[32];
    int optind = 0;
    int ask = 1;
    int     did_disconnected_auth = 0,
            result;
    struct sigaction sa;
    
    /* VAS variables used */
    vascache_t*          vascache = NULL;
    vascache_userinfo_t  vas_userinfo;
    int                  vas_disconnected_mode = 0; 

    /* options loaded out of config file */
    int                  vas_show_realm_prompt = 0;
    int                  vas_create_homedir = 0;
    int                  vas_nodisconnected_auth = 0;
    int                  vas_nouid_conflict_check = 0;
    int                  vas_noaccess_check = 0;
    int                  vas_do_merge = 0;
    

    memset( &vas_userinfo, 0, sizeof(vas_userinfo) );
    setprogname(argv[0]);

#ifdef KRB5
    {
	krb5_error_code ret;

	ret = krb5_init_context(&context);
	if (ret)
	    errx (1, "krb5_init_context failed: %d", ret);

        /* now load the login options specified in vas.conf */
        vas_show_realm_prompt =
            krb5_config_get_bool_default( context,
                                          NULL,
                                          FALSE,
                                          "login",
                                          "realm_prompt",
                                          NULL );
        vas_create_homedir =
            krb5_config_get_bool_default( context,
                                          NULL,
                                          TRUE,
                                          "login",
                                          "create_homedir",
                                          NULL );
        vas_nodisconnected_auth =
            krb5_config_get_bool_default( context,
                                          NULL,
                                          FALSE,
                                          "login",
                                          "no_disconnected",
                                          NULL );
        vas_nouid_conflict_check =
            krb5_config_get_bool_default( context,
                                          NULL,
                                          FALSE,
                                          "login",
                                          "no_uidconflict_check",
                                          NULL );
        vas_noaccess_check =
            krb5_config_get_bool_default( context,
                                          NULL,
                                          FALSE,
                                          "login",
                                          "no_access_check",
                                          NULL );
        vas_do_merge =
            krb5_config_get_bool_default( context,
                                          NULL,
                                          FALSE,
                                          "login",
                                          "do_merge",
                                          NULL );
 
    }
#endif

    openlog("login", LOG_ODELAY | LOG_PID, LOG_AUTH);

    if (getarg (args, sizeof(args) / sizeof(args[0]), argc, argv,
		&optind))
	usage (1);
    argc -= optind;
    argv += optind;

    if(help_flag)
	usage(0);
    if (version_flag) {
	print_version (NULL);
	return 0;
    }
	
    if (geteuid() != 0)
	errx(1, "only root may use login, use su");

    /* Default tty settings. */
    stty_default();

    if(p_flag)
	copy_env();
    else {
	/* this set of variables is always preserved by BSD login */
	if(getenv("TERM"))
	    add_env("TERM", getenv("TERM"));
	if(getenv("TZ"))
	    add_env("TZ", getenv("TZ"));
    }

    if(*argv){
	if(strchr(*argv, '=') == NULL && strcmp(*argv, "-") != 0){
	    strlcpy (username, *argv, sizeof(username));
	    ask = 0;
	}
    }

#if defined(DCE) && defined(AIX)
    esetenv("AUTHSTATE", "DCE", 1);
#endif

    /* XXX should we care about environment on the command line? */

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);
/*    alarm(login_timeout); */

    for (curr_try = 0; curr_try < max_tries; curr_try++) {
        
        /* VAS vars we need */
        int                  is_vas_user = 0;
        int                  merge_failed = 0;

        struct passwd*       pwd = NULL;
	char password[128];
	int ret;
	char ttname[32];
        char*                tty = NULL;
        char*                ttyn = NULL;
        char prompt[128];
#ifdef OTP
        char otp_str[256];
#endif

	if(ask){
	    f_flag = 0;
#if 0
	    r_flag = 0;
#endif
	    ret = read_string("login: ", username, sizeof(username), 1);
	    if(ret == -3)
		exit(0);
	    if(ret == -2)
		sig_handler(0); /* exit */
        } else {
            DBGLOG( "Not prompting for user: %s", username );
        }
        
        vascache_userinfo_free( &vas_userinfo );
        if( vascache == NULL ) 
        {
            if( vascache_init( &vascache, NULL, 0 ) ) {
                break;
	}
        }
            
        if( vascache )
        {
            is_vas_user = vascache_is_vas_user( vascache, 
                                                username, 
                                                VASCACHE_FORCE_UPDATE, 
                                                &vas_userinfo,
                                                &vas_disconnected_mode,
                                                NULL,
                                                0 );
        }

        /* If merging is turned on, we want to make sure we merge in this 
         * user, or get him deleted. We don't need to update the cache 
         * since we already did it in the vascache_is_vas_user function.
         * Also- we force the groups to update to make sure we get any group
         * changes for this user.
         *
         * Note -- we want to recommend using vasypserv over merging though! */
        if( vas_do_merge )
        {
            if( is_vas_user )
            {
                if( (merge_failed = libvascache_merge_user( vascache,
                                                            &vas_userinfo,
                                                            NULL,
                                                            NULL )) == 0 )
                    libvascache_merge_groups( vascache, VASCACHE_FORCE_UPDATE );
            }
            else
            {
                /* make sure this user gets deleted */
                libvascache_unmerge_user( vascache, username );
            }
        }

        /* note that on NSS platforms this will send the update IPC from
         * the NSS module :) */
        pwd = k_getpwnam(username);
#ifdef ALLOW_NULL_PASSWORD
        if (pwd != NULL && (pwd->pw_passwd[0] == '\0')) {
            strcpy(password,"");
        } else
#endif
        {
#ifdef OTP
           if(auth_level && strcmp(auth_level, "otp") == 0 &&
                 otp_challenge(&otp_ctx, username,
                            otp_str, sizeof(otp_str)) == 0)
                 snprintf (prompt, sizeof(prompt), "%s's %s Password: ",
                            username, otp_str);
            else
#endif
                 strncpy(prompt, "Password: ", sizeof(prompt));

	    if (f_flag == 0) {
                if( is_vas_user && vas_show_realm_prompt ) {
                    snprintf( prompt,
                              sizeof(prompt),
                              "Password for %s: ",
                              vas_userinfo.userPrincipalName );
                    ret = read_string( prompt, 
                                       password, 
                                       sizeof(password), 
                                       0 );
                }
                else
	       ret = read_string(prompt, password, sizeof(password), 0);

               if (ret == -3) {
                  ask = 1;
                  continue;
               }

               if (ret == -2)
                  sig_handler(0);
            }
         }
	
	if(pwd == NULL){
#ifdef UW7
                fprintf(stderr, "UX:in.login: ERROR: Login incorrect\n");
#else
                fprintf(stderr, "Login incorrect\n");
#endif
            if( is_vas_user && merge_failed )
                DBGLOG( "Could not merge user: %s", username );
            else
                DBGLOG( "could not get passwd entry for user: %s", username );
            ask = 1;
            continue;
        }

        if( f_flag == 0 ) {
            if( (is_vas_user && vas_helper_verify( vascache,
                                                   &vas_userinfo, 
                                                   password, 
                                                   &did_disconnected_auth )) ||
                (!is_vas_user && check_password( pwd, password )) ) 
            {
#ifdef UW7
                fprintf(stderr, "UX:in.login: ERROR: Login incorrect\n");
#else
                fprintf(stderr, "Login incorrect\n");
#endif
	    ask = 1;
	    continue;
	}
        }

        /* check these things here in case we've got a kerberized login with no
         * password prompt */
        if( is_vas_user )
        {
            /* check these things after we successfully validate
             * the password, just so we know it's them, so we don't
             * reveal info we shouldn't */
            if( !vas_nouid_conflict_check && 
                libvascache_user_has_uidconflict( vascache, 
                                                  &vas_userinfo ) ) {
                syslog( LOG_ALERT, 
                        "Login was rejected for %s due to UID conflict", 
                        pwd->pw_name );

                /* try to use the same string as what's in the PAM module */
                fprintf( stderr,
                         "Your UID conflicts with another user. "
                        "Please contact your administrator.\n " );

            ask = 1;
	    continue;
	}

            /* Need to perform the group conflict checking.... */
            if( !did_disconnected_auth )
            {
                vascache_send_groups_for_user_update( vascache,
                                                      vas_userinfo.userPrincipalName,
                                                      VASCACHE_FORCE_UPDATE, 
                                                      1,
                                                      NULL );

                if( !libvascache_group_gid_is_cached( vascache, 
                                                      vas_userinfo.gidNumberStr ) )
                {
                    char* user_domain = strchr( vas_userinfo.krb5PrincipalName, '@' );
                    user_domain ++;

                    libvascache_send_group_gid_realm_request( vascache,
                                                              vas_userinfo.gidNumber,
                                                              user_domain,
                                                              VASCACHE_FORCE_UPDATE,
                                                              NULL );
                }
            }
            if( (result = libvascache_user_has_group_gid_conflict( vascache,
                                                                   &vas_userinfo,
                                                                   &bad_group )) )
            {
                if( result == -1 )
                {
                    syslog( LOG_ALERT,
                            "group conflict check for user: %s "
                            "failed due to an internal error, errno=%d.",
                            vas_userinfo.userPrincipalName,
                            errno );
                    ask = 1;
                    continue;
                }
                else
                {
                    syslog( LOG_ALERT,
                            "User: %s belongs to group %s which has a "
                            "GID conflict.  Login was denied.",
                            vas_userinfo.userPrincipalName,
                            bad_group );
                    fprintf( stderr,
                             "You belong to a group that has a conflicting "
                             "gid with another group.\n"
                             "Please contact your administrator.\n" );
                    ask = 1;
                    continue;
                }
            }
                            
            /* reset this since there was no uid_conflict but we probably
             * messed up the passwd ptr */
            pwd = k_getpwnam( username );

            /* Don't authenticate the user if their shell is set to the
             * magic value we consider disabled. */
            if( strcmp( pwd->pw_shell, VASCACHE_DISABLED_SHELL ) == 0 )
            {
                syslog( LOG_INFO, 
                        "Attempted login by %s whose shell is /bin/false", 
                        pwd->pw_name );
                fprintf( stderr, "Permission denied\n" );
                ask = 1;
                continue;
            }

            /* do users.[allow,deny] check for vas users */
            if( !vas_noaccess_check &&
                vascache_user_check_access( vascache, 
                                            &vas_userinfo,
                                            NULL ) ) {
                syslog( LOG_INFO, 
                        "Attempted login by %s who does not have access", 
                        pwd->pw_name );
                fprintf( stderr, "Permission denied\n" );
                ask = 1;
                continue;
            }

            /* make sure the user's home directory exists- we don't care about
             * return values here */
            libvascache_create_homedir( &vas_userinfo );
        }

	ttyn = ttyname(STDIN_FILENO);
	if(ttyn == NULL){
	    snprintf(ttname, sizeof(ttname), "%s??", _PATH_TTY);
	    ttyn = ttname;
	}
	if (strncmp (ttyn, _PATH_DEV, strlen(_PATH_DEV)) == 0)
	    tty = ttyn + strlen(_PATH_DEV);
	else
	    tty = ttyn;
    
	if (login_access (pwd, remote_host ? remote_host : tty) == 0) {
	    fprintf(stderr, "Permission denied\n");
	    if (remote_host)
		syslog(LOG_NOTICE, "%s LOGIN REFUSED FROM %s",
		       pwd->pw_name, remote_host);
	    else
		syslog(LOG_NOTICE, "%s LOGIN REFUSED ON %s",
		       pwd->pw_name, tty);
	    exit (1);
	} else {
	    if (remote_host)
		syslog(LOG_NOTICE, "%s LOGIN ACCEPTED FROM %s ppid=%d",
		       pwd->pw_name, remote_host, (int) getppid());
	    else
		syslog(LOG_NOTICE, "%s LOGIN ACCEPTED ON %s ppid=%d",
		       pwd->pw_name, tty, (int) getppid());
	}
        alarm(0);
	do_login(pwd, tty, ttyn);
    }
    exit(1);
}

