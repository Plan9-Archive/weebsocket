WEBSRC=/sys/src/cmd/ip/httpd

$WEBSRC/websocket.install: $WEBSRC/websocket.c
	cd $WEBSRC
	mk websocket.install

$WEBSRC/websocket.c: websocket.c
	cp websocket.c $WEBSRC/websocket.c
