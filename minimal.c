#include <u.h>
#include <libc.h>
#include <bio.h>
#include "httpd.h"
#include "httpsrv.h"

Hio *ho;

#define MAXHDRS 64

HSPairs *
parseheaders(char *headers)
{
	char *hdrlines[MAXHDRS];
	HSPairs *h, *t;
	int nhdr;
	int i;

	h = t = nil;

	nhdr = getfields(headers, hdrlines, MAXHDRS, 1, "\r\n");

	/* XXX I think leading whitespaces signifies a continuation line. */
	/* Skip the first line, or else getfields(..., " ") picks up the GET. */
	for(i = 1; i < nhdr; ++i){
		HSPairs *tmp;
		char *kv[2];

		if(!hdrlines[i])
			continue;

		getfields(hdrlines[i], kv, 2, 1, ": \t");

		if((tmp = malloc(sizeof(HSPairs))) == nil)
			goto cleanup;

		tmp->s = kv[0];
		tmp->t = kv[1];

		if(!h){
			h = t = tmp;
		}else{
			t->next = tmp;
			t = tmp;
		}
		tmp->next = nil;
	}

	return h;

cleanup:
	for(t = h->next; h != nil; h = t, t = h->next)
		free(h);
	return nil;
}
		
int
dostuff(HConnect *c)
{
	HSPairs *hdrs, *h;

	if(strcmp(c->req.meth, "GET"))
		return hunallowed(c, "GET");

	hokheaders(c);
	hprint(ho, "Content-type: text/html\r\n");
	hprint(ho, "\r\n");

	hprint(ho, "<html><body>\r\n"
		"<h1>whee, httpd <i>magic</i> is working!</h1>\r\n"
		"<p>Lorem ipsum and so on.  I can eat glass!\r\n");

	hprint(ho, "<pre>%s</pre>\r\n", c->header);

	hdrs = parseheaders((char *)c->header);
	hprint(ho, "<table>\n");
	for(h = hdrs; h != nil; h = h->next){
		hprint(ho, "\t<tr><td>%s</td><td>%s</td></tr>\n", h->s, h->t);
	}
	hprint(ho, "</table>\n");

	hprint(ho, "</body></html>\r\n");

/* HSPairs for headers! */


	hflush(ho);
	return 1;
}

void
main(int argc, char **argv)
{
	HConnect *c;

	c = init(argc, argv);
	ho = &c->hout;
	if(hparseheaders(c, HSTIMEOUT) >= 0)
		dostuff(c);
	exits(nil);
}
