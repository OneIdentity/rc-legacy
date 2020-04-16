#ifndef PUTTY_WINXCONS
#define PUTTY_WINXCONS

/* Configuration structure for Windows console extensions */
extern struct winxcons {
    int has_console;		/* Is set to true if no console available */
    int use_gui;		/* Use dialogs for authentication prompts */
    int use_gui_passwd;		/* Use dialogs for password prompts */
    int always_store_keys;	/* Always accept server keys - XXX stupid */
    int console_was_hidden;	/* Saved initial console visibility */
} winxcons;

void winxcons_init(void);
int  winxcons_process_param(char *arg, Config *cfg);
void winxcons_print_usage(void);
void winxcons_cleanup_exit(int code);
void winxcons_printf(const char *fmt, ...);
int  winxcons_get_line(char *reply, int replysz, int is_pw);
void winxcons_console_hide(int hide);

#endif
