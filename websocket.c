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

HSPairs *
getheader(HSPairs *h, const char *k)
{
	for(; h != nil; h = h->next)
		if(!cistrcmp(h->s, k))
			return h;
	return nil;
}

int
failhdr(HConnect *c, int code, const char *status, const char *message)
{
	Hio *o;
	o = &c->hout;
	hprint(o, "%s %d %s\r\n", hversion, code, status);
	hprint(o, "Server: Plan9\r\n");
	hprint(o, "Date: %D\r\n", time(nil));
	hprint(o, "Content-type: text/html\r\n");
	hprint(o, "\r\n");
	hprint(o, "<html><head><title>%d %s</title></head>\n", code, status);
	hprint(o, "<body><h1>%d %s</h1>\n", code, status);
	hprint(o, "<p>Failed to establish websocket connection: %s\n", message);
	hprint(o, "</body></html>\n");
	hflush(o);
	return 0;
}

int
dostuff(HConnect *c)
{
	HSPairs *hdrs, *h;

	if(strcmp(c->req.meth, "GET"))
		return hunallowed(c, "GET");

	//return failhdr(c, 403, "Forbidden", "my hair is on fire");

	hokheaders(c);
	hprint(ho, "Content-type: text/html\r\n");
	hprint(ho, "\r\n");

	hprint(ho, "<html><body>\r\n"
		"<h1>whee, httpd <i>magic</i> is working!</h1>\r\n"
		"<p>Lorem ipsum and so on.  I can eat glass!\r\n");

	hdrs = parseheaders((char *)c->header);
	hprint(ho, "<table>\n");
	for(h = hdrs; h != nil; h = h->next){
		hprint(ho, "\t<tr><td>%s</td><td>%s</td></tr>\n", h->s, h->t);
	}
	hprint(ho, "</table>\n");

	hprint(ho, "<b>Connection:</b> <tt>%s</tt>\n", getheader(hdrs, "connection")->t);
	hprint(ho, "</body></html>\r\n");

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
