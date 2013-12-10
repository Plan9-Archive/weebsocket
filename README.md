# Weebsocket

Weebsocket is a WebSocket server for Plan 9.

## Installing

Currently this is a bit of a hack.

    cp websocket.c /sys/src/cmd/ip/httpd/
    cd /sys/src/cmd/ip/httpd/
    # add "websocket" to TARG in mkfile
    mk install

## Testing

Visit `http://my-server.example.com/magic/websocket` in your favourite
web browser.
