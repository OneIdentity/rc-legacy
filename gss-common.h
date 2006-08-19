/* (c) 2005 Quest Software, Inc. All rights reserved. */
/* David Leonard */

#include <stdio.h>
#include <gssapi.h>

/* A structure for convenient packaging of GSS results. */
struct res {
    OM_uint32 major;
    OM_uint32 minor;
};

/* Prints a message with a GSS error code to stderr and exits. */
void gssdie(int exitcode, struct res *res, const char *msg);

/* Prints GSS flags inside angle brackets to stderr. */
void fprintflags(FILE *out, OM_uint32 flags);

/* Converts a comma-separated list of flag names to a flag bitmask */
OM_uint32 names2flags(const char *names);

/* Reads and decodes base64 from stdin. Caller must free buf->value */
void readb64(gss_buffer_t buf);

/* Writes buffer as base64 to stdout, and then releases/zeros the gss buffer */
void writeb64_and_release(gss_buffer_t buf);

/* Prints an OID (or its symbolic name) */
void fprintoid(FILE *out, gss_OID oid);

