/*
 * vasidmap client test tool (a cut down ldapsearch)
 *   Usage:
 *     vasidmapc [-h host] [-p port] [-b base] [-D binddn] [-w password] filter
 *   Performs an LDAP search given the filter and prints all responses.
 */
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

#include <ldap.h>

#undef LDAP_SASL_SIMPLE
#define LDAP_SASL_SIMPLE    ""

static char *
ldap_err2string(int errcode)
{
    static char buf[2048];
    char *s;
    void libldap_get_default_errmsg( int errcode, char** errmsg );

    libldap_get_default_errmsg(errcode, &s);
    snprintf(buf, sizeof buf, "%s", s);
    free(s);
    return buf;
}

static int
ldap_simple_bind_s(LDAP *ld, char *dn, char *passwd)
{
    struct berval cred;
    cred.bv_len = passwd ? strlen(passwd) : 0;
    cred.bv_val = passwd;

    return ldap_sasl_bind_s(ld, dn, LDAP_SASL_SIMPLE, &cred, 
            NULL, NULL, NULL);
}

int
main(int argc, char **argv)
{
    LDAP *ld;
    LDAPMessage *result, *e;
    BerElement *ber;
    int version, ret, pret, rc, i;
    char *dn, *a;
    char **vals, **referrals;
    char *matched_msg, *error_msg;
    int scope = LDAP_SCOPE_SUBTREE;
    int msgid;
    int ch, error = 0;
    const char *host = "127.0.0.1";
    int port = LDAP_PORT;
    const char *basedn = NULL;
    const char *binddn = NULL;
    const char *bindpw = "";
    const char *filter;

    while ((ch = getopt(argc, argv, "h:p:b:D:w:")) != -1)
        switch (ch) {
            case 'h': host = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 'D': binddn = optarg; break;
            case 'w': bindpw = optarg; break;
            default: error = 1;
        }
    if (optind < argc)
        filter = argv[optind++];
    else
        error = 1;
    if (optind < argc)
        error = 1;
    if (error) {
        fprintf(stderr, "usage: %s [-h host] [-p port] "
                "[-b base] [-D binddn] [-w password] filter\n", argv[0]);
        exit(1);
    }

    if ((ld = ldap_init(host, port)) == NULL)
        err(1, "ldap_init: %s:%d", host, port);

    version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    if ((ret = ldap_simple_bind_s(ld, (char *)binddn, (char *)bindpw)) 
            != LDAP_SUCCESS)
        errx(1, "ldap_simple_bind_s: %s", ldap_err2string(ret));

    if ((ret = ldap_search_ext(ld, basedn, scope, filter, NULL, 0,
                    NULL, NULL, NULL, LDAP_NO_LIMIT, &msgid)) != LDAP_SUCCESS)
        errx(1, "ldap_search: %s", ldap_err2string(ret));

    do
        switch (ret = ldap_result(ld, msgid, LDAP_MSG_ONE, NULL, &result)) {
        case -1:
            ret = ldap_get_lderrno(ld, NULL, NULL);
            errx(1, "ldap_result: %s", ldap_err2string(ret));
        case LDAP_RES_SEARCH_ENTRY:
            if ((dn = ldap_get_dn(ld, result)) != NULL) {
                printf("dn: %s\n", dn);
                ldap_memfree(dn);
            }
            for (a = ldap_first_attribute(ld, result, &ber); a;
                 a = ldap_next_attribute(ld, result, ber))
            {
                if ((vals = ldap_get_values(ld, result, a, NULL)) != NULL) {
                    for (i = 0; vals[i]; i++)
                        printf("%s: %s\n", a, vals[i]);
                    ldap_value_free(vals);
                }
                ldap_memfree(a);
            }
            if (ber)
                ber_free(ber, 0);
            printf("\n");
            ldap_msgfree(result);
            break;
        case LDAP_RES_SEARCH_REFERENCE:
            if ((pret = ldap_parse_reference(ld, result, &referrals, NULL, 1))
                    != LDAP_SUCCESS)
                errx(1, "ldap_parse_reference: %s", ldap_err2string(pret));
            if (referrals) {
                for (i = 0; referrals[i] != NULL; i++)
                    printf("# Search reference: %s\n\n", referrals[i]);
                ldap_value_free(referrals);
            }
            break;
        case LDAP_RES_SEARCH_RESULT:
            if ((pret = ldap_parse_result(ld, result, &rc, NULL, 
                    NULL, NULL, NULL, 1)) != LDAP_SUCCESS)
                    errx(1, "ldap_parse_result: %s", ldap_err2string(pret));
            if (rc != LDAP_SUCCESS)
                warnx("ldap_search_ext: %s", ldap_err2string(rc));
            break;
        default:
            break;
    } while (ret != LDAP_RES_SEARCH_RESULT);

    if ((ret = ldap_unbind(ld)) != LDAP_SUCCESS)
        errx(1, "ldap_unbind: %s", ldap_err2string(ret));

    exit(0);
}
