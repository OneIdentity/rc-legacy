#include "wsspi.h"
int output_encrypted(CtxtHandle *context, const char *msg, int msg_len, 
		int conf_req);
int input_encrypted(CtxtHandle *context, char **msg_ret, int *msg_len_ret, 
		ULONG *qop);
void input_encrypted_free(char *msg);
