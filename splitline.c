/* $Vintela: splitline.c,v 1.2 2005/04/21 02:29:27 davidl Exp $ */
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#if STDC_HEADERS
# include <ctype.h>
#endif

#include "ktedit.h"

/**
 * Splits a line into components, like a shell would. Understands
 * quoting. Returns the number of words split into the word array;
 * Ignores comments after '#' sign. Sets the last word to NULL.
 *   @param line the (mutable) text to split into words
 *   @param word array of string pointers to fill in
 *   @param wordsz the length of the word array
 */
int
splitline(char *line, char *word[], int wordsz)
{
    int count = 0;
    char *p = line, *q, *start;
    char quote, ch;
    int toomanywords = 0;

    for (;;) {
	while (*p && isspace(*p)) p++;	/* skip whitespace */
	if (!*p || *p == '#')
	    break;
	quote = 0;
	start = q = p;
	while (*p) {
	    if (*p == '\\' && quote != '\'') {
		p++;
		switch (ch = *p++) {
		    case 'n': *q++ = '\n'; break;
		    case 'r': *q++ = '\r'; break;
		    case 't': *q++ = '\t'; break;
		    case '\0': 
		       fprintf(stderr, "ignored trailing backslash\n");
		       p--;
		       continue;
		    default:  
		      if (ch >= '0' && ch <= '7') {
			  ch -= '0';
			  if (*p >= '0' && *p <= '7') {
			      ch = ch << 3 | (*p++ - '0');
			      if (*p >= '0' && *p <= '7') 
				  ch = ch << 3 | (*p++ - '0');
			  }
		      } 
		      *q++ = ch;
		}
	    } else if (quote && *p == quote) {
		quote = 0; p++;
	    } else if (!quote && (*p == '\'' || *p == '\"')) {
		quote = *p++;
	    } else if (!quote && isspace(*p))
		break;
	    else if (!quote && *p == '#') {
		*p = '\0';
		break;
	    } else
		*q++ = *p++;
	}
	if (quote)
	    fprintf(stderr, "unclosed %c quote\n", quote);
	if (*p) p++;
	*q = '\0';
	if (count < wordsz - 1)
	    word[count++] = start;
	else
	    toomanywords = 1;
    }
    word[count] = NULL;
    if (toomanywords)
        fprintf(stderr, "too many words; truncating\n");
    return count;
}

#if TEST
int
main(int argc, char **argv)
{
#define NWORDS 5
    char buf[4096], *line;
    char *words[NWORDS];
    int i, count;

    for (;;) {
	printf("> ");
	fflush(stdout);
	if ((line = gets(buf)) == NULL)
	    break;
	count = splitline(line, words, NWORDS);
	printf("count=%d\n", count);
	for (i = 0; i < count; i++)
	    printf("  %3d <%s>\n", i, words[i]);
    }
    exit(0);
}
#endif
