#include "wsspi.h"

void list_pkgs(void);
void print_context_attrs(CtxtHandle *context);
void print_cred_attrs(CredHandle *credentials);
const char *TimeStamp_to_string(TimeStamp *ts);

extern PSecurityFunctionTable sspi;
