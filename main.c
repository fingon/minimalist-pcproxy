/*
 * $Id: main.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 16:53:27 2014 mstenber
 * Last modified: Mon May 19 13:14:03 2014 mstenber
 * Edit time:     161 min
 *
 */


#include <stdio.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>

#include "shared.h"
#include "pcp.h"
#include "pcpproxy.h"
#include "udp46.h"

int client_socket, server_socket;

struct uloop_fd ufds[4];
udp46 clients, servers;

void fd_callback(struct uloop_fd *u, unsigned int events)
{
  if (!events & ULOOP_READ)
    return;
  struct sockaddr_in6 srcsa, dstsa;
  uint8_t data[PCP_PAYLOAD_LENGTH + 1];

  int i;
  for (i = 0; i < 4; i++)
    if (u == &ufds[i])
      {
        DEBUG("fd callback for socket #%d", i);
        if (i < 2)
          {
            ssize_t l = udp46_recv(clients, &srcsa, &dstsa, data, sizeof(data));
            if (l < 0)
              perror("recvmsg");
            else
              {
                DEBUG("calling pcp_proxy_handle_from_server");
                pcp_proxy_handle_from_server(&srcsa, &dstsa, data, l);
              }
          }
        else
          {
            ssize_t l = udp46_recv(servers, &srcsa, &dstsa, data, sizeof(data));
            if (l < 0)
              perror("recvmsg");
            else
              {
                DEBUG("calling pcp_proxy_handle_from_client");
                pcp_proxy_handle_from_client(&srcsa, &dstsa, data, l);
              }
          }
        return;
      }
  DEBUG("invalid callback?!?");
}

void init_sockets(int server_port)
{
  /* Any port should work */
  clients = udp46_create(0);
  assert(clients);

  /* We insist on server port, though. */
  servers = udp46_create(server_port);
  assert(servers);

  int i;
  for (i = 0; i < 4; i++)
    {
      memset(&ufds[i], 0, sizeof(ufds[i]));
      ufds[i].cb = fd_callback;
    }
  udp46_get_fds(clients, &ufds[0].fd, &ufds[1].fd);
  udp46_get_fds(servers, &ufds[2].fd, &ufds[3].fd);
  for (i = 0; i < 4; i++)
    if (uloop_fd_add(&ufds[i], ULOOP_READ) < 0)
      {
        perror("uloop_fd_add");
        abort();
      }
}

void pcp_proxy_send_to_client(struct sockaddr_in6 *src,
                              struct sockaddr_in6 *dst,
                              void *data, int data_len)
{
  DEBUG("pcp_proxy_send_to_client %s->%s %d bytes",
        SOCKADDR_IN6_REPR(src), SOCKADDR_IN6_REPR(dst),
        data_len);
  struct iovec iov = {.iov_base = data,
                      .iov_len = data_len };
  if (udp46_send_iovec(servers, src, dst, &iov, 1) < 0)
    perror("sendmsg");
}

void pcp_proxy_send_to_server(struct sockaddr_in6 *src,
                              struct sockaddr_in6 *dst,
                              void *data, int data_len,
                              void *data2, int data_len2)
{
  struct iovec iov[2] = {
    {.iov_base = data,
     .iov_len = data_len },
    {.iov_base = data2,
     .iov_len = data_len2 }
  };
  DEBUG("pcp_proxy_send_to_server %s->%s %d+%d bytes",
        SOCKADDR_IN6_REPR(src), SOCKADDR_IN6_REPR(dst),
        data_len, data_len2);
  if (udp46_send_iovec(clients, src, dst, iov, 2) < 0)
    perror("sendmsg");
}

static void help_and_exit(const char *p, const char *reason)
{
  if (reason)
    printf("%s.\n\n", reason);
  printf("Usage: %s [-h] [-p server-port] S [S [S ..]]\n", p);
  printf(" Where S = <source prefix>/<source prefix length>=<server>\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int c;
  int server_port = PCP_SERVER_PORT;

  if (uloop_init() < 0)
    {
      perror("uloop_init");
      abort();
    }
  /* XXX - add support for parsing interfaces too and use them for
   * announces on reset_epoch */
  while ((c = getopt(argc, argv, "hp:"))>0)
    {
      switch (c)
        {
        case 'h':
          help_and_exit(argv[0], NULL);
        case 'p':
          server_port = atoi(optarg);
          break;
        }
    }
  /* Parse command leftover command line arguments. Assume they're of
   * type <source prefix>/<source prefix length>=server, all in IPv6
   * format. */
  int i;
  if (optind == argc)
    help_and_exit(argv[0], "One server is required");
  pcp_proxy_init();
  init_sockets(server_port);
  for (i = optind; i < argc; i++)
    {
      char err[1024];
      if (!pcp_proxy_add_server_string(argv[i], err, sizeof(err)))
        help_and_exit(argv[0], err);
    }
  uloop_run();
  uloop_done();
  /* Not reached, included here just for pedantism.. */
  udp46_destroy(clients);
  udp46_destroy(servers);
  return 0;
}
