/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Companion program to gss-client/gss-server, but using the Windows SSPI interface.
 * David Leonard, 2009.
 */

#include <stdio.h>
#include "common.h"
#include "wsspi.h"
#include "errmsg.h"

/* Lists the SSPI security packages available */
void
list_pkgs()
{
    SECURITY_STATUS status;
    PSecPkgInfo pkgs;
    ULONG count;
    int i;

    status = EnumerateSecurityPackages(&count, &pkgs);
    if (status != SEC_E_OK) {
	errmsg("EnumerateSecurityPackages", status);
	exit(1);
    }

    for (i = 0; i < count; i++) {
	printf("\t%s\n", pkgs[i].Name);
	if (pkgs[i].Comment)
	    printf("\t\t- %s\n", pkgs[i].Comment);
    }
}

static const char *
TimeStamp_to_string(TimeStamp *ts)
{
    SYSTEMTIME st;
    static char buf[1024];

    FileTimeToSystemTime((FILETIME *)ts, &st);
    snprintf(buf, sizeof buf, "%05u-%02u-%02u %02u:%02u:%02u.%03u",
	    st.wYear, st.wMonth, st.wDay,
	    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

/* Prints information about context attributes */
void print_context_attrs(CtxtHandle *context)
{
    SecPkgContext_Sizes sizes;
    SecPkgContext_StreamSizes stream_sizes;
    SecPkgContext_Authority authority;
    SecPkgContext_KeyInfo key_info;
    SecPkgContext_Lifespan life_span;
    SECURITY_STATUS status;

    status = QueryContextAttributes(context, SECPKG_ATTR_AUTHORITY, 
	   &authority);
    if (status == SEC_E_OK)
	printf("authority.name          = %s\n", authority.sAuthorityName);
    else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes AUTHORITY", status);

    status = QueryContextAttributes(context, SECPKG_ATTR_KEY_INFO, 
	   &key_info);
    if (status == SEC_E_OK) {
	printf("key_info.sig_algorithm  = %s\n",
		key_info.sSignatureAlgorithmName);
	printf("key_info.enc_algorithm  = %s\n",
		key_info.sEncryptAlgorithmName);
	printf("key_info.key_size    m  = %ld bits\n", key_info.KeySize);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes KEY_INFO", status);

    status = QueryContextAttributes(context, SECPKG_ATTR_LIFESPAN, 
	   &life_span);
    if (status == SEC_E_OK) {
	printf("life_span.start         = %s\n",
		TimeStamp_to_string(&life_span.tsStart));
	printf("life_span.expiry        = %s\n",
		TimeStamp_to_string(&life_span.tsExpiry));
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes LIFESPAN", status);

    status = QueryContextAttributes(context, SECPKG_ATTR_SIZES, &sizes);
    if (status == SEC_E_OK) {
	printf("sizes.cbMaxToken        = %10ld\n", sizes.cbMaxToken);
	printf("sizes.cbMaxSignature    = %10ld\n", sizes.cbMaxSignature);
	printf("sizes.cbBlockSize       = %10ld\n", sizes.cbBlockSize);
	printf("sizes.cbSecurityTrailer = %10ld\n", sizes.cbSecurityTrailer);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes SIZES", status);

    status = QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, 
	    &stream_sizes);
    if (status == SEC_E_OK) {
	printf("stream_sizes.cbHeader   = %10ld\n", 
		stream_sizes.cbHeader);
	printf("stream_sizes.cbTrailer  = %10ld\n", 
		stream_sizes.cbTrailer);
/*	printf("stream_sizes.cbMaximumMessage = %10ld\n", 
		stream_sizes.cbMaximumMessage);
	printf("stream_sizes.cbBuffers  = %10ld\n", 
		stream_sizes.cbBuffers);
*/	printf("stream_sizes.cbBlockSize= %10ld\n", 
		stream_sizes.cbBlockSize);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes STREAM_SIZES", status);
}

/* Prints information about the credentials */
void
print_cred_attrs(CredHandle *credentials)
{
    SecPkgCredentials_Names names;
    SECURITY_STATUS status;

    status = QueryCredentialsAttributes(credentials, 
	    SECPKG_CRED_ATTR_NAMES, &names);
    if (status != SEC_E_OK)
	errmsg("QueryCredentialsAttributes", status);
    else
	printf("credential.userName: %s\n", names.sUserName);
}
