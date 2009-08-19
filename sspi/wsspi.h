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


