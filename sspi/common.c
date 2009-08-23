/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Companion program to gss-client/gss-server, but using the Windows SSPI interface.
 * David Leonard, 2009.
 */

#include <stdio.h>
#include "common.h"
#include "wsspi.h"
#include "errmsg.h"

PSecurityFunctionTable sspi;

/* Guarantees a string is not NULL by replacing NULL with "(null)" */
static const char *
protect_null(char *s)
{
    return s ? s : "(null)";
}

/* Lists the SSPI security packages available */
void
list_pkgs()
{
    SECURITY_STATUS status;
    PSecPkgInfo pkgs;
    ULONG count;
    int i;

    status = sspi->EnumerateSecurityPackages(&count, &pkgs);
    if (status != SEC_E_OK) {
	errmsg("EnumerateSecurityPackages", status);
	exit(1);
    }
    for (i = 0; i < count; i++)
	print_package_info(pkgs + i);
}

void
print_package_info(SecPkgInfo *pkg)
{
    int j, first;
    static struct {
	ULONG flag;
	const char *desc;
    } map[] = {
	{ SECPKG_FLAG_INTEGRITY, "integ" },	/* Make/VeirfySignature */
	{ SECPKG_FLAG_PRIVACY, "privacy" },	/* Encrypt/DecryptMessage */
	{ SECPKG_FLAG_TOKEN_ONLY, "token-only" },
	{ SECPKG_FLAG_DATAGRAM, "datagram" },
	{ SECPKG_FLAG_CONNECTION, "connection" },
	{ SECPKG_FLAG_MULTI_REQUIRED, "multi" },
	{ SECPKG_FLAG_CLIENT_ONLY, "client-only" },
	{ SECPKG_FLAG_EXTENDED_ERROR, "ext-err" },
	{ SECPKG_FLAG_IMPERSONATION, "impersonation" },
	{ SECPKG_FLAG_ACCEPT_WIN32_NAME, "win32-names" },
	{ SECPKG_FLAG_STREAM, "stream" },
#ifdef SECPKG_FLAG_NEGOTIABLE
	{ SECPKG_FLAG_NEGOTIABLE, "negotiable" },
	{ SECPKG_FLAG_GSS_COMPATIBLE, "gss-compat" },
	{ SECPKG_FLAG_LOGON, "logon" },		/* LSALogonUser */
	{ SECPKG_FLAG_ASCII_BUFFERS, "ascii" },
	{ SECPKG_FLAG_FRAGMENT, "fragment" },	/* ISC/ASC */
	{ SECPKG_FLAG_MUTUAL_AUTH, "mutual" },
	{ SECPKG_FLAG_DELEGATION, "deleg" },
	{ SECPKG_FLAG_READONLY_WITH_CHECKSUM, "ro-cksum" },  /*EncryptMessage*/
# ifdef SECPKG_FLAG_RESTRICTED_TOKENS
	{ SECPKG_FLAG_RESTRICTED_TOKENS, "r-tokens" },
	{ SECPKG_FLAG_NEGOTIABLE2, "nego2" },
# endif
#endif
    };

    printf(" \"%s\" {\n", pkg->Name);
    printf("    capabilities: ");
    first = 0;
    for (j = 0; j < sizeof map / sizeof map[0]; j++)
	if (pkg->fCapabilities & map[j].flag)
	    printf("%s%s", first++ ? ",": "<", map[j].desc);
    printf("%s\n", first ? ">": "<>");
    if (pkg->wVersion != 1)
	printf("    version:      %d\n", pkg->wVersion);
    printf("    max token:    %ld bytes\n", pkg->cbMaxToken);
    if (pkg->wRPCID != SECPKG_ID_NONE)
	printf("    RPC ID:       %d\n", pkg->wRPCID);
    if (pkg->Comment)
	printf("    comment:      %s\n", pkg->Comment);
    printf("}\n");
}

const char *
TimeStamp_to_string(TimeStamp *ts)
{
    SYSTEMTIME st;
    static char buf[1024];

    FileTimeToSystemTime((FILETIME *)ts, &st);
    snprintf(buf, sizeof buf, "%5u-%02u-%02u %02u:%02u:%02u.%03u",
	    st.wYear, st.wMonth, st.wDay,
	    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

/* Prints information about context attributes */
void
print_context_attrs(CtxtHandle *context)
{
    SecPkgContext_Sizes sizes;
    SecPkgContext_StreamSizes stream_sizes;
    SecPkgContext_Authority authority;
    SecPkgContext_KeyInfo key_info;
    SecPkgContext_Lifespan life_span;
    SecPkgContext_PackageInfo pkg_info;
    SecPkgContext_NegotiationInfo nego_info;
    SecPkgContext_NativeNames native_names;
    SECURITY_STATUS status;

    printf("Context attributes:\n");

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_AUTHORITY, 
	   &authority);
    if (status == SEC_E_OK)
	printf(" authority.name          = %s\n", authority.sAuthorityName);
    else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes AUTHORITY", status);

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_KEY_INFO, 
	   &key_info);
    if (status == SEC_E_OK) {
	printf(" key_info.sig_algorithm  = \"%s\"\n",
		protect_null(key_info.sSignatureAlgorithmName));
	printf(" key_info.enc_algorithm  = \"%s\"\n",
		protect_null(key_info.sEncryptAlgorithmName));
	printf(" key_info.key_size       = %ld bits\n", key_info.KeySize);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes KEY_INFO", status);

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_LIFESPAN, 
	   &life_span);
    if (status == SEC_E_OK) {
	printf(" life_span.start         = %s\n",
		TimeStamp_to_string(&life_span.tsStart));
	printf(" life_span.expiry        = %s\n",
		TimeStamp_to_string(&life_span.tsExpiry));
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes LIFESPAN", status);

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_PACKAGE_INFO, 
	   &pkg_info);
    if (status == SEC_E_OK) {
	printf(" package_info            = ");
	print_package_info(pkg_info.PackageInfo);
	status = FreeContextBuffer(pkg_info.PackageInfo);
	if (status != SEC_E_OK)
	    errmsg("FreeContextBuffer NEGOTIATION_INFO", status);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes PACKAGE_INFO", status);

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_NEGOTIATION_INFO, &nego_info);
    if (status == SEC_E_OK) {
	printf(" nego.package.state      = %s\n",
	    nego_info.NegotiationState == SECPKG_NEGOTIATION_COMPLETE ? 
	    					"complete" :
	    nego_info.NegotiationState == SECPKG_NEGOTIATION_OPTIMISTIC ? 
	    					"optimistic" :
	    nego_info.NegotiationState == SECPKG_NEGOTIATION_IN_PROGRESS ? 
	    					"in-progress" :
#ifdef SECPKG_NEGOTIATION_DIRECT
	    nego_info.NegotiationState == SECPKG_NEGOTIATION_DIRECT ? 
	    					"direct" :
#endif
#ifdef SECPKG_NEGOTIATION_TRY_MULTICRED
	    nego_info.NegotiationState == SECPKG_NEGOTIATION_TRY_MULTICRED ? 
	    					"try-multicred" :
#endif
	    "?");
	printf(" nego.package.name       = \"%s\"\n",
		nego_info.PackageInfo->Name);

	status = sspi->FreeContextBuffer(nego_info.PackageInfo);
	if (status != SEC_E_OK)
	    errmsg("FreeContextBuffer NEGOTIATION_INFO", status);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes NEGOTIATION_INFO", status);

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_SIZES, &sizes);
    if (status == SEC_E_OK) {
	printf(" sizes.cbMaxToken        = %10ld\n", sizes.cbMaxToken);
	printf(" sizes.cbMaxSignature    = %10ld\n", sizes.cbMaxSignature);
	printf(" sizes.cbBlockSize       = %10ld\n", sizes.cbBlockSize);
	printf(" sizes.cbSecurityTrailer = %10ld\n", sizes.cbSecurityTrailer);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes SIZES", status);

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, 
	    &stream_sizes);
    if (status == SEC_E_OK) {
	printf(" stream_sizes.cbHeader   = %10ld\n", 
		stream_sizes.cbHeader);
	printf(" stream_sizes.cbTrailer  = %10ld\n", 
		stream_sizes.cbTrailer);
/*	printf(" stream_sizes.cbMaximumMessage = %10ld\n", 
		stream_sizes.cbMaximumMessage);
	printf(" stream_sizes.cbBuffers  = %10ld\n", 
		stream_sizes.cbBuffers);
*/	printf(" stream_sizes.cbBlockSize= %10ld\n", 
		stream_sizes.cbBlockSize);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes STREAM_SIZES", status);

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_NATIVE_NAMES, 
	   &native_names);
    if (status == SEC_E_OK) {
	printf(" native_names.client     = %s\n",
		protect_null(native_names.sClientName));
	printf(" native_names.server     = %s\n",
		protect_null(native_names.sServerName));
	status = sspi->FreeContextBuffer(native_names.sClientName);
	if (status != SEC_E_OK)
	    errmsg("FreeContextBuffer sClientName", status);
	status = sspi->FreeContextBuffer(native_names.sServerName);
	if (status != SEC_E_OK)
	    errmsg("FreeContextBuffer sServerName", status);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes NATIVE_NAMES", status);

    printf("\n");
}

/* Prints information about the credentials */
void
print_cred_attrs(CredHandle *credentials)
{
    SecPkgCredentials_Names names;
    SECURITY_STATUS status;

    status = sspi->QueryCredentialsAttributes(credentials, 
	    SECPKG_CRED_ATTR_NAMES, &names);
    if (status != SEC_E_OK)
	errmsg("QueryCredentialsAttributes", status);
    else
	printf("credential.userName: %s\n", names.sUserName);
}

/* Converts principals called "NULL" into the NULL pointer */
char *
null_principal(char *principal)
{
    if (!principal || strcmp(principal, "NULL") == 0)
	return NULL;
    else
	return principal;
}
