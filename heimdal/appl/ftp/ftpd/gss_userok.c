/*
 * Copyright (c) 1998 - 2001 Kungliga Tekniska Högskolan
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

#include "ftpd_locl.h"
#include <gssapi.h>
#include <krb5.h>

RCSID("$Id: gss_userok.c,v 1.12 2003/05/21 15:08:48 lha Exp $");

/* XXX a bit too much of krb5 dependency here... 
   What is the correct way to do this? 
   */

extern krb5_context gssapi_krb5_context;

/* XXX sync with gssapi.c */
struct gss_data {
    gss_ctx_id_t context_hdl;
    char *client_name;
    gss_cred_id_t delegated_cred_handle;
};

/* XXX Dodgy import from Heimdal source. Assumes underlying GSSAPI is
 * Heimdal or compatible */
typedef struct gss_cred_id_t_desc_struct {
  gss_name_t principal;
  struct krb5_keytab_data *keytab;
  OM_uint32 lifetime;
  gss_cred_usage_t usage;
  gss_OID_set mechanisms;
  struct krb5_ccache_data *ccache;
} gss_cred_id_t_desc;


/* Nabbed from openssh/gss-serv-krb5.c:72
 *
 * Tests that the user principal name yields a VAS account UID
 * the same as the local user account.
 *
 * Workaround for bug 5894: The krb5_kuserok() function did not
 * always recognise foreign realm users who have valid VAS local user
 * accounts. This is because it made the assumption that only UPNs
 * of the form luser@LOCALREALM were allowed access.
 */

static int
vas_userok(char *upn, char *luser)
{
    uid_t upn_uid, luser_uid;
    struct passwd *pw;

    if ((pw = getpwnam(upn)) == NULL)
	return 0;
    upn_uid = pw->pw_uid;

    if ((pw = getpwnam(luser)) == NULL)
	return 0;
    luser_uid = pw->pw_uid;

    return upn_uid == luser_uid;
}


int gss_userok(void*, char*); /* to keep gcc happy */

/* XXX Review what this function does. It plays hard and fast with heimdal
 * internals */

int
gss_userok(void *app_data, char *username)
{
    struct gss_data *data = app_data;
    if(gssapi_krb5_context) {
	krb5_principal client;
	krb5_error_code ret;
/* tedp: Start by pretending these are both valid. They can be removed later. */
        gss_cred_id_t_desc *delegated_cred_handle; // working
	OM_uint32 minor_status; // merge-right.r14
        
	ret = krb5_parse_name(gssapi_krb5_context, data->client_name, &client);
	if(ret)
	    return 1;
	ret = krb5_kuserok(gssapi_krb5_context, client, username);
	if (!ret && !vas_userok(username, data->client_name)) {
	    krb5_free_principal(gssapi_krb5_context, client);
	    return 1;
	}
        
        ret = 0;
        
        /* more of krb-depend stuff :-( */
	/* gss_add_cred() ? */
        delegated_cred_handle = data->delegated_cred_handle;
        if (delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
           krb5_ccache ccache = NULL; 
           char* ticketfile;
           struct passwd *pw;
           
           pw = getpwnam(username);
           
	   if (pw == NULL) {
	       ret = 1;
	       goto fail;
	   }

           asprintf (&ticketfile, "%s%u", KRB5_DEFAULT_CCROOT,
		     (unsigned)pw->pw_uid);
        
           ret = krb5_cc_resolve(gssapi_krb5_context, ticketfile, &ccache);
           if (ret)
              goto fail;
           
           ret = gss_krb5_copy_ccache(&minor_status,
				      delegated_cred_handle,
				      ccache);
           if (ret) {
	      ret = 0;
              goto fail;
	   }
           
           chown (ticketfile+5, pw->pw_uid, pw->pw_gid);
           
           if (k_hasafs()) {
	       krb5_afslog(gssapi_krb5_context, ccache, 0, 0);
           }
           esetenv ("KRB5CCNAME", ticketfile, 1);
           
fail:
           if (ccache)
              krb5_cc_close(gssapi_krb5_context, ccache); 
           free(ticketfile);
        }
           
	gss_release_cred(&minor_status, &data->delegated_cred_handle);
	krb5_free_principal(gssapi_krb5_context, client);
        return ret;
    }
    return 1;
}

/*
 * vim:tabstop=8
 */
