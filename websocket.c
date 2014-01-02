#include <u.h>
#include <libc.h>
#include <thread.h>
#include <bio.h>
#include <mp.h>
#include <libsec.h>
#include "httpd.h"
#include "httpsrv.h"

/* XXX The default was not enough, but this is just a guess. */
int mainstacksize = 32768;

Hio *ho;
Biobuf bin, bout;

#define MAXHDRS 64

const char wsnoncekey[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const int wsversion = 13;

typedef struct Procio Procio;
struct Procio
{
	Channel *c;
	Biobuf *b;
	int fd;
};

enum
{
	STACKSZ = 2048,
	BUFSZ = 16384,
};

typedef struct Buf Buf;
struct Buf
{
	uchar *buf;
	long n;
};

enum Pkttype
{
	CONT = 0x0,
	TEXT = 0x1,
	BINARY = 0x2,
	/* reserved non-control frames */
	CLOSE = 0x8,
	PING = 0x9,
	PONG = 0xA,
	/* reserved control frames */
};

typedef struct Wspkt Wspkt;
struct Wspkt
{
	Buf;
	enum Pkttype type;
	int masked;
	uchar mask[4];
};

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

char *
getheader(HSPairs *h, const char *k)
{
	for(; h != nil; h = h->next)
		if(!cistrcmp(h->s, k))
			return h->t;
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

void
okhdr(HConnect *c, const char *wshashedkey, const char *proto)
{
	Hio *o;
	o = &c->hout;
	hprint(o, "%s 101 Switching Protocols\r\n", hversion);
	hprint(o, "Upgrade: websocket\r\n");
	hprint(o, "Connection: upgrade\r\n");
	hprint(o, "Sec-WebSocket-Accept: %s\r\n", wshashedkey);
	if(proto)
		hprint(o, "Sec-WebSocket-Protocol: %s\r\n", proto);
	/* we don't handle extensions */
	hprint(o, "\r\n");
	hflush(o);
}

int
testwsversion(const char *vs)
{
	int i, n;
	char *v[16];

	n = getfields(vs, v, 16, 1, "\t ,");
	for(i = 0; i < n; ++i)
		if(atoi(v[i]) == wsversion)
			return 1;
	return 0;
}

/* Assumptions: */
/* We will never be masking the data. */
/* Messages will be atomic: all frames are final. */
/* XXX convert to bio(2) */
void
sendpkt(Wspkt *pkt)
{
	uchar hdr[2+8] = {0x80 | pkt->type};
	ulong hdrsz, len;
	IOchunk ioc[2];

	len = pkt->n;

	/* XXX only supports up to 32 bits */
	if(len >= (1 << 16)){
		hdrsz = 2 + 8;
		hdr[1] = 127;
		hdr[2] = hdr[3] = hdr[4] = hdr[5] = 0;
		hdr[6] = len & (0xFF << 24);
		hdr[7] = len & (0xFF << 16);
		hdr[8] = len & (0xFF << 8);
		hdr[9] = len & (0xFF << 0);
	}else if(len >= 126){
		hdrsz = 2 + 2;
		hdr[1] = 126;
		hdr[2] = len & (0xFF << 8);
		hdr[3]= len & (0xFF << 0);
	}else{
		hdrsz = 2;
		hdr[1] = len;
	}

	ioc[0] = (IOchunk){hdr, hdrsz};
	ioc[1] = (IOchunk){pkt->buf, len};

	writev(1, ioc, 2);
}

void
wsreadproc(void *arg)
{
	Buf b;

	for(;;){
		//b.buf = malloc(BUFSZ);
		//if(!b.buf)
		//	sysfatal("wsreadproc: could not allocate: %r");
		//b.n = read(0, b.buf, BUFSZ);

		/* Bgetc header */
		/* allocate appropriate buffer */
		/* while((remaining -= Bread(remaining, buf)) > 0); */
		/* XXX allocation -> DoS if we're sent a packet with a huge size! */
		/* if(pkt.size <= MAXPKTSZ){ malloc(pkt.size) } else { close connection (see error code table) } */
		/* websocket spec allows this behaviour. (where?) */
		/* mask if appropriate */
		/* send on chan */
	}
}

void
pipereadproc(void *arg)
{
	/* read from pipe */
	/* send on chan */
}

int
dowebsock(HConnect *c)
{
	HSPairs *hdrs;
	char *s, *wsclientkey;
	char *rawproto;
	char *proto;
	char wscatkey[64];
	uchar wshashedkey[SHA1dlen];
	char wsencoded[32];

	if(strcmp(c->req.meth, "GET"))
		return hunallowed(c, "GET");

	//return failhdr(c, 403, "Forbidden", "my hair is on fire");

	hdrs = parseheaders((char *)c->header);

	s = getheader(hdrs, "upgrade");
	if(!s || !cistrstr(s, "websocket"))
		return failhdr(c, 400, "Bad Request", "no <pre>upgrade: websocket</pre> header.");
	s = getheader(hdrs, "connection");
	if(!s || !cistrstr(s, "upgrade"))
		return failhdr(c, 400, "Bad Request", "no <pre>connection: upgrade</pre> header.");
	wsclientkey = getheader(hdrs, "sec-websocket-key");
	if(!wsclientkey || strlen(wsclientkey) != 24)
		return failhdr(c, 400, "Bad Request", "invalid websocket nonce key.");
	s = getheader(hdrs, "sec-websocket-version");
	if(!s || !testwsversion(s))
		return failhdr(c, 426, "Upgrade Required", "could not match websocket version.");
	/* XXX should get resource name */
	rawproto = getheader(hdrs, "sec-websocket-protocol");
	proto = rawproto;
	/* XXX should test if proto is acceptable" */
	/* should get sec-websocket-extensions */

	/* OK, we seem to have a valid Websocket request. */

	/* Hash websocket key. */
	strcpy(wscatkey, wsclientkey);
	strcat(wscatkey, wsnoncekey);
	sha1((uchar *)wscatkey, strlen(wscatkey), wshashedkey, nil);
	enc64(wsencoded, 32, wshashedkey, SHA1dlen);

	okhdr(c, wsencoded, proto);
	hflush(ho);

	/* We should now have an open Websocket connection. */
	//sendpkt(BINARY, (uchar *)"hello world", strlen("hello world"));
	{
		/* I can't figure out how to include an array in (Wspkt){...} struct literal syntax. */
		/* I can't figure out how to use {.x=...} struct literal syntax in an expression. */
		/* I can't figure out how to initialise an anonymous substructure in a {.x=...} literal. */
		Wspkt mypkt = {
			.type = BINARY,
			.masked = 0,
		};
		mypkt.Buf = (Buf){
			(uchar *)"hello world",
			strlen("hello world"),
		};
		sendpkt(&mypkt);
	}
	return 1;
}

void
threadmain(int argc, char **argv)
{
	HConnect *c;

	c = init(argc, argv);
	ho = &c->hout;
	if(hparseheaders(c, HSTIMEOUT) >= 0)
		dowebsock(c);
	exits(nil);
}
