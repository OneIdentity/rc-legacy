#include <windows.h>
#include <ntsecpkg.h>	/* Gah! */
#include <security.h>

/* Sends a token to the user */
void user_output_token(SecBufferDesc *desc);
void user_output_flush(void);
void user_input_token(SecBuffer *buf);
