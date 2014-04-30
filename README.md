minimalist-pcproxy
==================

Minimalist PCP proxy implementation. No client state and minimal server state.

Goals
-----

- portable C code

- small total LoC count 

- few dependencies (libubox)

- minimal state (some per-server things)

- follow the IETF specs ( such as
  http://tools.ietf.org/html/draft-ietf-pcp-proxy-05 and
  https://tools.ietf.org/html/rfc6887 ) as closely as possible

Non-goals
---------

- server selection draft; we do server selection *ENTIRELY* based on the
  client's IP address. we also don't track liveliness of servers.

Usage
-----

	cmake .
	./minimalist-pcproxy eth0 eth1 2000:db8::/32=2000:db8::1 ::ffff:0:0/96=2000:db8::2

The command line arguments may be either interfaces, or (address prefix) =
(PCP server) mappings.
