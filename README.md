# Weebsocket

Weebsocket is a WebSocket server for Plan 9.

## Installing

Add `websocket` to `TARG` and `XTARG` in
`/sys/src/cmd/ip/httpd/mkfile`, then run `mk` in this directory.

## Using

Currently, acme is hardcoded, which requires [9webdraw][0].

[0]: https://bitbucket.org/dhoskin/9webdraw/
