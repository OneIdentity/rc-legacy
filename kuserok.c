/* (c) 2006 Quest Software, Inc. All rights reserved. */
#include <krb5.h>
#include <stdio.h>
#include <pwd.h>
#include "authtest.h"

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_principal principal;
    const char *luser;
    char *pname;
    krb5_error_code error;
    krb5_boolean kuserok;
    struct passwd *princ_pw, *luser_pw;
    uid_t princ_uid, luser_uid;

    authtest_init();

    /* Obtain an initial krb5 context */
    error = krb5_init_context(&context);
    if (error) {
        fprintf(stderr, "krb5_init_context: error %d\n", error);
        exit(1);
    }

    /* Parse the command line arguments */
    if (argc != 3) {
        fprintf(stderr, "usage: %s principal unix-user\n", argv[0]);
        exit(1);
    }

    luser = argv[2];

    error = krb5_parse_name(context, argv[1], &principal);
    if (error) 
        krb5_err(context, 1, error, "krb5_parse_name '%s'", argv[1]);

    pname = NULL;
    error = krb5_unparse_name(context, principal, &pname);
    if (error)
        krb5_err(context, 1, error, "krb5_parse_name '%s'", argv[1]);
    debug("principal: %s", pname);

    /* Verify that the local (unix) user exists */
    luser_pw = getpwnam(luser);
    if (!luser_pw) {
        debug("unknown unix user '%s'", luser);
        exit(1);
    }
    luser_uid = luser_pw->pw_uid;
    debug("NSS uid for '%s': %d", luser, luser_uid);

    /* Try the kuserok call */
    kuserok = krb5_kuserok(context, principal, luser);
    if (kuserok) {
        debug("krb5_kuserok() returned OK");
        exit(0);
    } else
        debug_err("krb5_kuserok() denied access");

    /*
     * kuserok returned false, but now we try a getpwnam() and check
     * uids. If VAS is installed, it will resolve UPN to a synthetic 
     * password entry and then we can compare uids. This is what
     * happens in cross-realm environments.
     */

    princ_pw = getpwnam(pname);
    if (princ_pw) {
        princ_uid = princ_pw->pw_uid;

        debug("NSS uid for %s: %d", pname, princ_uid);
        if (princ_uid == luser_uid)  {
            debug("principal '%s' and unix user '%s' resolve to same uid",
                    pname, luser);
            debug("uid match OK");
            exit(0);
        } else {
            debug_err("principal '%s' has different uid to unix user '%s'",
                    pname, luser);
        }
    } else
        debug_err("principal '%s' was not resolved by NSS", pname);

    debug_err("permission denied");
    exit(1);
}
