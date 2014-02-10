# Weebsocket

Weebsocket is a WebSocket server for Plan 9.

## Installing

Add `websocket` to `TARG` and `XTARG` in
`/sys/src/cmd/ip/httpd/mkfile`, then run `mk` in this directory.

## Using

Currently, catclock is hardcoded, which requires 9webdraw[0].

Ignore its installation instructions; all of the C and Go plumbing is
replaced by Weebsocket.  The function that chooses the websocket
address needs a slight modification; rather than
`ws://host.example/9p`, `ws://host.example/magic/websocket` is used.

[0]:
https://bitbucket.org/dhoskin/9webdraw/
