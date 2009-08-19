/* (c) 2009, Quest Software, Inc. All rights reserved. */

/* MinGW's headers have some missing pieces */

#include <windows.h>
#include <ntsecpkg.h>   /* Gah! */
#include <security.h>

#ifndef ISC_RET_DELEGATE
# define ISC_RET_DELEGATE 0x1
#endif

#ifndef ISC_RET_MUTUAL_AUTH
# define ISC_RET_MUTUAL_AUTH 0x2
#endif

#ifndef ISC_RET_REPLAY_DETECT
# define ISC_RET_REPLAY_DETECT 0x4
#endif

#ifndef ISC_RET_SEQUENCE_DETECT
# define ISC_RET_SEQUENCE_DETECT 0x8
#endif

#ifndef ISC_RET_CONFIDENTIALITY
# define ISC_RET_CONFIDENTIALITY 0x10
#endif

#ifndef ISC_RET_INTEGRITY
# define ISC_RET_INTEGRITY 0x10000
#endif

#ifndef ISC_RET_STREAM
# define ISC_RET_STREAM 0x8000
#endif

#ifndef ISC_RET_USE_SESSION_KEY
# define ISC_RET_USE_SESSION_KEY 0x20
#endif

#ifndef SECQOP_WRAP_NO_ENCRYPT
# define SECQOP_WRAP_NO_ENCRYPT KERB_WRAP_NO_ENCRYPT

typedef struct _SecPkgContext_Lifespan {
  TimeStamp tsStart;
  TimeStamp tsExpiry;
} SecPkgContext_Lifespan, *PSecPkgContext_Lifespan;

#endif

#ifndef InitSecurityInterface
# ifdef UNICODE
#  define InitSecurityInterface InitSecurityInterfaceW
# else
#  define InitSecurityInterface InitSecurityInterfaceA
# endif
#endif

#ifndef SECPKG_FLAG_NEGOTIABLE
# define SECPKG_FLAG_NEGOTIABLE 0x800
#endif

#ifndef SECPKG_FLAG_GSS_COMPATIBLE
# define SECPKG_FLAG_GSS_COMPATIBLE 0x1000
#endif

#ifndef SECPKG_FLAG_LOGON
# define SECPKG_FLAG_LOGON 0x2000
#endif

#ifndef SECPKG_FLAG_ASCII_BUFFERS
# define SECPKG_FLAG_ASCII_BUFFERS 0x4000
#endif

#ifndef SECPKG_FLAG_FRAGMENT
# define SECPKG_FLAG_FRAGMENT 0x8000
#endif

#ifndef SECPKG_FLAG_MUTUAL_AUTH
# define SECPKG_FLAG_MUTUAL_AUTH 0x10000
#endif

#ifndef SECPKG_FLAG_DELEGATION
# define SECPKG_FLAG_DELEGATION 0x20000
#endif

#ifndef SECPKG_FLAG_READONLY_WITH_CHECKSUM
# define SECPKG_FLAG_READONLY_WITH_CHECKSUM 0x40000
#endif

#ifndef SECPKG_ID_NONE
# define SECPKG_ID_NONE 0xffff
#endif

#ifndef SECPKG_ATTR_PACKAGE_INFO
# define SECPKG_ATTR_PACKAGE_INFO 10
#endif 

#ifndef SECPKG_ATTR_NEGOTIATION_INFO
# define SECPKG_ATTR_NEGOTIATION_INFO 12

typedef struct _SecPkgContext_NegotiationInfoA
{
    PSecPkgInfoA    PackageInfo ;
    unsigned long   NegotiationState ;
} SecPkgContext_NegotiationInfoA, SEC_FAR * PSecPkgContext_NegotiationInfoA;

// begin_ntifs
typedef struct _SecPkgContext_NegotiationInfoW
{
    PSecPkgInfoW    PackageInfo ;
    unsigned long   NegotiationState ;
} SecPkgContext_NegotiationInfoW, SEC_FAR * PSecPkgContext_NegotiationInfoW;

# ifdef UNICODE
#  define SecPkgContext_NegotiationInfo   SecPkgContext_NegotiationInfoW
#  define PSecPkgContext_NegotiationInfo  PSecPkgContext_NegotiationInfoW
# else
#  define SecPkgContext_NegotiationInfo   SecPkgContext_NegotiationInfoA
#  define PSecPkgContext_NegotiationInfo  PSecPkgContext_NegotiationInfoA
# endif
# define SECPKG_NEGOTIATION_COMPLETE             0
# define SECPKG_NEGOTIATION_OPTIMISTIC           1
# define SECPKG_NEGOTIATION_IN_PROGRESS          2
# define SECPKG_NEGOTIATION_DIRECT               3
# define SECPKG_NEGOTIATION_TRY_MULTICRED        4
#endif
