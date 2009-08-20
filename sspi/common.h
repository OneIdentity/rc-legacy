#include "wsspi.h"

void list_pkgs(void);
void print_context_attrs(CtxtHandle *context);
void print_cred_attrs(CredHandle *credentials);
const char *TimeStamp_to_string(TimeStamp *ts);
void print_package_info(SecPkgInfo *pkg);
char *null_principal(char *principal);
extern PSecurityFunctionTable sspi;
