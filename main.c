/*
 * $Id: main.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 16:53:27 2014 mstenber
 * Last modified: Mon May  5 18:37:43 2014 mstenber
 * Edit time:     45 min
 *
 */


#ifdef __APPLE__

/* Haha. Got to love advanced IPv6 socket API being disabled by
 * default. */
#define __APPLE_USE_RFC_3542

#endif /* __APPLE__ */

#include <stdio.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "pcp.h"
#include "proxy.h"

int client_port, server_port;


int init_listening_socket(int port)
{
  int on = 1, off = 0;
  int s = socket(PF_INET6, SOCK_DGRAM, 0);
  struct sockaddr_in6 sin6;

  if (s < 0)
    perror("socket");
#if 0
#ifdef __linux__
  /* Linux (used to?) require this to get info on mapped sockets. */
  else if (setsockopt(s, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0)
    perror("setsockopt IP_PKTINFO");
#endif /* __linux__ */
#endif /* 0 */
  else if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
    perror("setsockopt IPV6_RECVPKTINFO");
  else if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) < 0)
    perror("setsockopt IPV6_V6ONLY");
  else if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
      perror("setsockopt SO_REUSEADDR");
  else
    {
      memset(&sin6, 0, sizeof(sin6));
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = htons(port);
      if (bind(s, (struct sockaddr *)&sin6, sizeof(sin6)) < 0)
        perror("bind");
      else
        return s;
    }
  abort();
  return -1; /* Not reached */
}

void init_ports()
{
  client_port = init_listening_socket(PCP_CLIENT_PORT);
  server_port = init_listening_socket(PCP_SERVER_PORT);
}

int main(int argc, char **argv)
{
  int c;

  if (uloop_init() < 0)
    {
      perror("uloop_init");
      abort();
    }
  init_ports();
  while ((c = getopt(argc, argv, "h"))>0)
    {
      switch (c)
        {
        case 'h':
          /* XXX display help */
          break;
        }
    }
  return 0;
}
