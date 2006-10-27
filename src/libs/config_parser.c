#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF 512

/* Get section name from a key, or NULL if a section name cannot be obtained.
 *
 * For example, the section name of the key "foo/bar" would be "foo".
 */
static const char *get_section_name(const char *key)
{
    char *buf = NULL;

    if ((buf = strdup(key)) != NULL)
    { 
        char *p = strchr(buf, '/');
        if (p != NULL) 
        {
            *p = 0;
        }
    }

    return buf;
}

/* Get property name from a key, or NULL if a property name cannot be obtained.
 *
 * For example, the property name of the key "foo/bar" would be "bar".
 */
static const char *get_property_name(const char *key)
{
    char *buf = NULL;
    char *p = strchr(key, '/');
 
    if (p != NULL && (buf = strdup(key)) != NULL)
    { 
        char *b = buf;

        p++; /* skip '/' */
        while (*p != 0)
        {
            *b = *p;
            b++;
            p++;
        }
        *b = 0;
    }

    return buf;
}

/*
 * foo/bar maps to "[foo]/bar=baz"
 */
const char *gdm_prompt_config_get_string(const char *config_file,
                                         const char *key)
{
    FILE *fp = NULL;
    char line_buf[MAX_BUF];
    char *lp = NULL;
    const char *section = NULL;
    const char *property = NULL;
    const char *value = NULL;

    /* Pre-condition checks */
    if (config_file == NULL || key == NULL)
    {
        goto FINISH;
    }

    /* Load the configuration file */
    if ((fp = fopen(config_file, "r")) == NULL)
    {
        goto FINISH;
    }

    /* Get section name from key */
    if ((section = get_section_name(key)) == NULL) 
    {
        goto FINISH;
    }

    /* Scan lines until section is found */
    while ((lp = fgets(line_buf, sizeof(line_buf), fp)) != NULL)
    {
        /* Skip leading whitespace */
	while (*lp != 0 && isspace(*lp)) { lp++; }
 
        /* Check for "[${section}]" */
        if (*lp == '[') 
        {
            size_t n = strlen(section);

            lp++; /* skip '[' */
            if (strncmp(lp, section, n) == 0 && *(lp+n) == ']')
            {
                break;
            }   
        }        
    }

    /* Check that a line exists (ie, a section was found) */
    if (lp == NULL)
    {
        goto FINISH;
    }

    /* Get the property */
    if ((property = get_property_name(key)) == NULL)
    {
        goto FINISH;
    }

    /* Scan lines until property (or next section) is found */
    while ((lp = fgets(line_buf, sizeof(line_buf), fp)) != NULL)
    {
        /* Skip white space */
        while (*lp != 0 && isspace(*lp)) { lp++; }
        
        /* Check for start of next section */
        if (*lp == '[') 
        {
            break;
        }

        /* Check if line has '=' (ie, it has property and value) */
        if (strchr(lp, '=') != NULL)
        { 
            size_t n = strlen(property);

            /* Make sure line begins with property name and is followed 
               by whitespace or '=' */
            if (strncmp(lp, property, n) == 0 && 
                (*(lp+n) == '=' || isspace(*(lp+n))))
            {
                char value_buf[MAX_BUF];
                char *vp = value_buf;

                /* Skip to '=' */
                lp += n;
                while (*lp != 0 && *lp != '=') { lp++; }
                if (*lp == 0) { goto FINISH; }
                lp++; /* skip '=' */

                /* Skip white space */
                while (*lp != 0 && isspace(*lp)) { lp++; }

                /* Get value */
                while (*lp != 0 && *lp != '\n') 
                {
                    *vp = *lp;
                    vp++;
                    lp++;
                }
                *vp = 0;

                value = strdup(value_buf);
            }
        }
    }

FINISH:
    if (fp != NULL) { fclose(fp); }
    if (section != NULL) { free((void*) section); }
    if (property != NULL) { free((void*) property); }

    return value;
}

