#ifndef PAMCHECK_H
#define PAMCHECK_H

#include <security/pam_appl.h>

/* Empty conversation function, for apps that can't really carry out
 * a PAM conversation.
 */
int
pamcheck_conv_nothing(
    int num_msg,
    const struct pam_message **msg,
    struct pam_response **resp,
    void *appdata_ptr)
{
    return PAM_CONV_ERR;
}

#endif /* ifndef PAMCHECK_H */
