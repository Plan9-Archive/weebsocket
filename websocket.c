#include <u.h>
#include <libc.h>
#include <thread.h>
#include <bio.h>
#include <mp.h>
#include <libsec.h>
#include "httpd.h"
#include "httpsrv.h"

/* XXX The default was not enough, but this is just a guess. */
int mainstacksize = 65536;

Hio *ho;
Biobuf bin, bout;

#define MAXHDRS 64

const char wsnoncekey[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const char wsversion[] = "13";

typedef struct Procio Procio;
struct Procio
{
	Channel *c;
	Biobuf *b;
	int fd;
	char **argv;
};

enum
{
	STACKSZ = 32768,
	BUFSZ = 16384,
	CHANBUF = 8,
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
		if(!strcmp(v[i], wsversion))
			return 1;
	return 0;
}

/* Assumptions: */
/* We will never be masking the data. */
/* Messages will be atomic: all frames are final. */
void
sendpkt(Biobuf *b, Wspkt *pkt)
{
	uchar hdr[2+8];
	long hdrsz, len;

	hdr[0] = 0x80 | pkt->type;
	len = pkt->n;

	/* XXX should use putbe(). */
	if(len >= (1 << 16)){
		hdrsz = 2 + 8;
		hdr[1] = 127;
		hdr[2] = hdr[3] = hdr[4] = hdr[5] = 0;
		hdr[6] = len >> 24;
		hdr[7] = len >> 16;
		hdr[8] = len >> 8;
		hdr[9] = len >> 0;
	}else if(len >= 126){
		hdrsz = 2 + 2;
		hdr[1] = 126;
		hdr[2] = len >> 8;
		hdr[3]= len >> 0;
	}else{
		hdrsz = 2;
		hdr[1] = len;
	}

	Bwrite(b, hdr, hdrsz);
	Bwrite(b, pkt->buf, len);
	Bflush(b);
}

Wspkt
recvpkt(Biobuf *b)
{
	Wspkt pkt;
	long sz;

	pkt.type = Bgetc(b);
	if(pkt.type < 0){
		/* read error */
		/* XXX better error handling! */
		sysfatal("recvpkt: %r");
	}
	/* Strip FIN/continuation bit. */
	pkt.type &= 0x0F;

	pkt.n = Bgetc(b);
	if(pkt.n < 0){
		/* read error */
	}
	pkt.masked = pkt.n & 0x80;
	pkt.n &= 0x7F;
	sz = 0;
	/* XXX Get a char array in one step with Bread! */
	if(pkt.n >= 127){
		sz |= Bgetc(b) << 56;
		sz |= Bgetc(b) << 48;
		sz |= Bgetc(b) << 40;
		sz |= Bgetc(b) << 32;
		sz |= Bgetc(b) << 24;
		sz |= Bgetc(b) << 16;
	}
	if(pkt.n >= 126){
		sz |= Bgetc(b) << 8;
		sz |= Bgetc(b) << 0;
		pkt.n = sz;
	}
	if(pkt.masked){
		pkt.mask[0] = Bgetc(b);
		pkt.mask[1] = Bgetc(b);
		pkt.mask[2] = Bgetc(b);
		pkt.mask[3] = Bgetc(b);
	}
	/* allocate appropriate buffer */
	if(pkt.n > BUFSZ){
		/* buffer unacceptably large! */
		/* XXX this should close the connection with a specific error code. */
		/* See websocket spec. */
	}else if(pkt.n == 0){
		pkt.buf = nil;
	}else{
		pkt.buf = malloc(pkt.n);
		if(!pkt.buf)
			sysfatal("wsreadproc: could not allocate: %r");

		sz = pkt.n;
		/* XXX Bread returns negative on error; should use a temp variable. */
		while((sz -= Bread(b, pkt.buf + (pkt.n - sz), sz)) > 0);

		if(pkt.masked)
			for(sz = 0; sz < pkt.n; ++sz)
				pkt.buf[sz] ^= pkt.mask[sz % 4];
		pkt.masked = 0;
	}
	return pkt;
}

void
wsreadproc(void *arg)
{
	Procio *pio;
	Channel *c;
	Biobuf *b;
	Wspkt pkt;

	pio = (Procio *)arg;
	c = pio->c;
	b = pio->b;

	for(;;){
		pkt = recvpkt(b);
		send(c, &pkt);
	}
}

void
wswriteproc(void *arg)
{
	Procio *pio;
	Channel *c;
	Biobuf *b;
	Wspkt pkt;

	pio = (Procio *)arg;
	c = pio->c;
	b = pio->b;

	for(;;){
		recv(c, &pkt);
		sendpkt(b, &pkt);
		free(pkt.buf);
	}
}

void
pipereadproc(void *arg)
{
	Procio *pio;
	Channel *c;
	int fd;
	Buf b;

	pio = (Procio *)arg;
	c = pio->c;
	fd = pio->fd;

	for(;;){
		b.buf = malloc(BUFSZ);
		b.n = read(fd, b.buf, BUFSZ);
		syslog(1, "websocket", "pipereadproc: read %ld", b.n);
		if(b.n < 1){
			sleep(1000*10);
			continue;
		}
		send(c, &b);
	}
}

void
pipewriteproc(void *arg)
{
	Procio *pio;
	Channel *c;
	int fd;
	Buf b;

	pio = (Procio *)arg;
	c = pio->c;
	fd = pio->fd;

	for(;;){
		recv(c, &b);
		write(fd, b.buf, b.n);
		free(b.buf);
	}
}

void
mountproc(void *arg)
{
	Procio *pio;
	int fd;
	char **argv;

	pio = (Procio *)arg;
	fd = pio->fd;
	argv = pio->argv;

	if(mount(fd, -1, "/dev/", MBEFORE, "") == -1)
		sysfatal("mount failed: %r");

	procexec(nil, argv[0], argv);
}

void
echoproc(void *arg)
{
	Procio *pio;
	int fd;
	char buf[1024];
	int n;

	pio = (Procio *)arg;
	fd = pio->fd;

	for(;;){
		n = read(fd, buf, 1024);
		if(n > 0)
			write(fd, buf, n);
	}
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
		Biobuf bin, bout;
		Wspkt pkt;
		Buf buf;
		int p[2], fd;
		Alt a[] = {
		/*	c	v	op */
			{nil, &pkt, CHANRCV},
			{nil, &buf, CHANRCV},
			{nil, nil, CHANEND},
		};
		Procio fromws, tows, frompipe, topipe;
		Procio mountp, echop;
		char *argv[] = {"/bin/games/catclock", nil};

		fromws.c = chancreate(sizeof(Wspkt), CHANBUF);
		tows.c = chancreate(sizeof(Wspkt), CHANBUF);
		frompipe.c = chancreate(sizeof(Buf), CHANBUF);
		topipe.c = chancreate(sizeof(Buf), CHANBUF);

		syslog(1, "websocket", "created chans");

		a[0].c = fromws.c;
		a[1].c = frompipe.c;

		Binit(&bin, 0, OREAD);
		Binit(&bout, 1, OWRITE);
		fromws.b = &bin;
		tows.b = &bout;

		pipe(p);
		//fd = create("/srv/weebtest", OWRITE, 0666);
		//fprint(fd, "%d", p[0]);
		//close(fd);
		//close(p[0]);

		frompipe.fd = p[1];
		topipe.fd = p[1];

		mountp.fd = echop.fd = p[0];
		mountp.argv = argv;

		syslog(1, "websocket", "before proccreate");

		proccreate(wsreadproc, &fromws, STACKSZ);
		proccreate(wswriteproc, &tows, STACKSZ);
		proccreate(pipereadproc, &frompipe, STACKSZ);
		proccreate(pipewriteproc, &topipe, STACKSZ);

		//proccreate(echoproc, &echop, STACKSZ);
		proccreate(mountproc, &mountp, STACKSZ);

		syslog(1, "websocket", "created procs");

		for(;;){
			switch(alt(a)){
			case 0: /* from socket */
				if(pkt.type == PING){
					pkt.type = PONG;
					send(tows.c, &pkt);
				}else if(pkt.type == CLOSE){
					send(tows.c, &pkt);
					goto done;
				}else{
					send(topipe.c, &pkt.Buf);
				}
				break;
			case 1: /* from pipe */
				pkt.type = BINARY;
				pkt.Buf = buf;
				pkt.masked = 0;
				send(tows.c, &pkt);
				break;
			default:
				sysfatal("can't happen");
			}
		}
	}
done:
	return 1;
}

void
threadmain(int argc, char **argv)
{
	HConnect *c;
	int errfd;

	errfd = open("/sys/log/websocket", OWRITE);
	dup(errfd, 2);

	syslog(1, "websocket", "websocket process %d", getpid());

	c = init(argc, argv);
	ho = &c->hout;
	if(hparseheaders(c, HSTIMEOUT) >= 0)
		dowebsock(c);
	exits(nil);
}
