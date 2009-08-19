/* (c) 2009, Quest Sofwtare, Inc. All rights reserved. */
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include "errmsg.h"
#include "deleg.h"

/* Requires -ladvapi32 */

/* Returns a SID's use-type as a string. */
static const char *
use_to_string(SID_NAME_USE use)
{
    static struct {
	SID_NAME_USE use;
	const char *desc;
    } usemap[] = {
	{ SidTypeUser, "user" },
	{ SidTypeGroup, "group" },
	{ SidTypeDomain, "domain" },
	{ SidTypeAlias, "alias" },
	{ SidTypeWellKnownGroup, "well-known-group" },
	{ SidTypeDeletedAccount, "deleted-account" },
	{ SidTypeInvalid, "invalid" },
	{ SidTypeUnknown, "unknown" },
	{ SidTypeComputer, "computer" },
	// { SidTypeLabel, "label" },
    };
    int i;

    for (i = 0; i < sizeof usemap / sizeof usemap[0]; i++)
	if (usemap[i].use == use)
	    return usemap[i].desc;
    return "?";
}

/* Prints the comma-delimited list of SID group attributes */
static void
print_sid_attrs(DWORD attrs)
{
    int first = 0;
    static struct {
	DWORD attr;
	const char *desc;
    } map[] = {
	{ SE_GROUP_ENABLED, "en" },
	{ SE_GROUP_ENABLED_BY_DEFAULT, "def" },
	{ SE_GROUP_INTEGRITY, "int" },
	{ SE_GROUP_INTEGRITY_ENABLED, "int-en" },
	{ SE_GROUP_LOGON_ID, "logon" },
	{ SE_GROUP_MANDATORY, "mand" },
	{ SE_GROUP_OWNER, "owner" },
	{ SE_GROUP_RESOURCE, "resource" },
	{ SE_GROUP_USE_FOR_DENY_ONLY, "use-for-deny-only" },
    };
    int i;

    for (i = 0; i < sizeof map / sizeof map[0]; i++)
	if (attrs & map[i].attr)
	    printf("%s%s", first++ ? "," : "", map[i].desc);
}

/* Prints a SID in a readable way */
static void
print_sid(SID *sid)
{
    TCHAR name[1024], domain[1024];
    DWORD name_sz = sizeof name;
    DWORD domain_sz = sizeof domain;
    SID_NAME_USE use;
    DWORD error;

    if (!LookupAccountSid(NULL, sid, name, &name_sz,
	    domain, &domain_sz, &use))
	printf("%s\\%s(%s)", domain, name, use_to_string(use));
    else {
	TCHAR *sidstr;
	if ((error = GetLastError()) != ERROR_NONE_MAPPED &&
	    error != ERROR_IO_PENDING /* !!!??? */)
	    errmsg("LookupAccountSid", error);
	if (!ConvertSidToStringSid(sid, &sidstr)) {
	    errmsg("ConvertSidToStringSid", GetLastError());
	} else {
	    printf("%s", sidstr);
	    LocalFree(sidstr);
	}
    }
}

/* Prints an indented array of SIDs and their attributes */
static void
print_sidattrs(const char *indent, int count, SID_AND_ATTRIBUTES *sids)
{
    int i;

    if (count == 0) {
	printf("[]");
	return;
    }

    printf("[\n");
    for (i = 0; i < count; i++) {
	printf("%s  ", indent);
	print_sid(sids[i].Sid);
	printf(" <");
	print_sid_attrs(sids[i].Attributes);
	printf(">\n");
    }
    printf("%s]", indent);
}

/*
 * Prints some diagnostic information about a security token.
 * Token must have been opened with QUERY and QUERY_SOURCE mode bits.
 */
void
print_token_info(HANDLE token_handle)
{
    union {
	char _pad[8192];
	TOKEN_SOURCE token_source;
	TOKEN_GROUPS token_groups;
	SECURITY_IMPERSONATION_LEVEL imp_level;
	TOKEN_OWNER token_owner;
    } u;
    DWORD len;
    TOKEN_GROUPS *token_groups;
    DWORD error;

    if (GetTokenInformation(token_handle, TokenSource, &u.token_source, 
		sizeof u, &len))
	printf("  source.name = %.*s\n", 
		sizeof u.token_source.SourceName,
		u.token_source.SourceName);
    else
	errmsg("GetTokenInformation source", GetLastError());

    len = 0;
    GetTokenInformation(token_handle, TokenGroups, NULL, 0, &len);
    if (len != 0) {
	token_groups = malloc(len);
	if (!token_groups) {
	    errmsg("malloc", GetLastError());
	    exit(1);
	}
	if (GetTokenInformation(token_handle, TokenGroups, 
		    token_groups, len, &len))
	{
	    printf("  groups = ");
	    print_sidattrs("  ", token_groups->GroupCount, 
		    token_groups->Groups);
	    printf("\n");
	} else
	    errmsg("GetTokenInformation groups", GetLastError());
	free(token_groups);
    }

    len = 0;
    if (GetTokenInformation(token_handle, TokenImpersonationLevel, 
		&u.imp_level, sizeof u.imp_level, &len))
	printf("  impersonation_level = %s\n",
		u.imp_level == SecurityAnonymous ? "anonymous" :
		u.imp_level == SecurityIdentification ? "identification" :
		u.imp_level == SecurityImpersonation ? "impersonation" :
		u.imp_level == SecurityDelegation ? "delegation" :
		"?");
    else if ((error = GetLastError()) != ERROR_INVALID_PARAMETER)
	errmsg("GetTokenInformation impersonation", error);

    if (GetTokenInformation(token_handle, TokenOwner, 
		&u.token_owner, sizeof u, &len))
    {
	printf("  owner = ");
	print_sid(u.token_owner.Owner);
	printf("\n");
    } else
	errmsg("GetTokenInformation owner", GetLastError());
}

/* Prints information about the current process's security token. */
void
print_self_info()
{
    HANDLE handle = INVALID_HANDLE_VALUE;

    if (!OpenProcessToken(
	GetCurrentProcess(),			/* ThreadHandle */
	TOKEN_QUERY | TOKEN_QUERY_SOURCE,	/* DesiredAccess */
	&handle))				/* TokenHandle */
    {
	errmsg("OpenThreadToken", GetLastError());
	return;
    }

    printf("Current process security token:\n");
    print_token_info(handle);
    printf("\n");

    CloseHandle(handle);
}
