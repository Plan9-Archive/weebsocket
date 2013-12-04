#include <u.h>
#include <libc.h>
#include <bio.h>
#include "httpd.h"
#include "httpsrv.h"

Hio *ho;

int
dostuff(HConnect *c)
{
	if(strcmp(c->req.meth, "GET"))
		return hunallowed(c, "GET");

	hokheaders(c);
	hprint(ho, "Content-type: text/html\r\n");
	hprint(ho, "\r\n");

	hprint(ho, "<html><body>\r\n"
		"<h1>whee, httpd <i>magic</i> is working!</h1>\r\n"
		"<p>Lorem ipsum and so on.  I can eat glass!\r\n");

	hprint(ho, "<pre>%s</pre>\r\n", c->header);

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
