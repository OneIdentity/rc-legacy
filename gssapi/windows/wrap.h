#include "wsspi.h"
int wrap_send(CtxtHandle *context, const char *msg, int msg_len, 
		int conf_req);
int wrap_recv(CtxtHandle *context, char **msg_ret, int *msg_len_ret, 
		ULONG *qop);
void wrap_recv_free(char *msg);
