/*
 * $Id: udp46.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu May 15 12:33:19 2014 mstenber
 * Last modified: Thu May 15 14:14:51 2014 mstenber
 * Edit time:     22 min
 *
 */

#include "udp46.h"
#include "shared.h"

#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>

struct udp46_t {
  int s4;
  int s6;
};

#define IN_ADDR_TO_MAPPED_IN6_ADDR(a, a6)       \
do {                                            \
  memset(a6, 0, sizeof(*(a6)));                 \
  (a6)->s6_addr[10] = 0xff;                     \
  (a6)->s6_addr[11] = 0xff;                     \
  ((uint32_t *)a6)[3] = *((uint32_t *)a);       \
 } while (0)

static int init_listening_socket(int pf, int port)
{
  int on = 1;
  int s = socket(pf, SOCK_DGRAM, 0);
  struct sockaddr_storage ss;
  int ss_len;

  if (s < 0)
    perror("socket");
  else if (fcntl(s, F_SETFL, O_NONBLOCK) < 0)
    perror("fnctl O_NONBLOCK");
#ifdef USE_IP_PKTINFO
  else if (pf == PF_INET
           && setsockopt(s, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0)
    perror("setsockopt IP_PKTINFO");
#endif /* USE_IP_PKTINFO */
#ifdef USE_IP_REVCDSTADDR
  else if (pf == PF_INET
           && setsockopt(s, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on)) < 0)
    perror("setsockopt IP_RECVDSTADDR");
#endif /* USE_IP_REVCDSTADDR */
  else if (pf == PF_INET6
           && setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
    perror("setsockopt IPV6_RECVPKTINFO");
  else if (pf == PF_INET6
           && setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0)
    perror("setsockopt IPV6_V6ONLY");
  else if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    perror("setsockopt SO_REUSEADDR");
  else
    {
      if (pf == PF_INET6)
        {
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
          memset(sin6, 0, sizeof(*sin6));
          sin6->sin6_family = AF_INET6;
          sin6->sin6_port = htons(port);
          ss_len = sizeof(*sin6);
        }
      else
        {
          struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
          memset(sin, 0, sizeof(*sin));
          sin->sin_family = AF_INET;
          sin->sin_port = htons(port);
          ss_len = sizeof(*sin);
        }

      if (bind(s, (struct sockaddr *)&ss, ss_len) < 0)
        perror("bind");
      else
        return s;
    }
  return - 1;
}

udp46 udp46_create(uint16_t port)
{
  udp46 s;
  int fd1 = -1, fd2 = -1;

  s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;
  if (port)
    {
      fd1 = init_listening_socket(PF_INET, port);
      fd2 = init_listening_socket(PF_INET6, port);
    }
  else
    {
      /*
       * XXX - correct way to do this would be to allocate one, try
       * getting similar, and then start incrementing from there. This
       * for loop is simpler and stupider, though..
       */
      for (port = 1000; port > 0 && (fd1 < 0 || fd2 < 0); port++)
        {
          if (fd1 >= 0)
            close(fd1);
          fd1 = init_listening_socket(PF_INET, port);
          if (fd1 >= 0)
            fd2 = init_listening_socket(PF_INET6, port);
        }
    }
  if (fd1 >= 0 && fd2 >= 0)
    {
      s->s4 = fd1;
      s->s6 = fd2;
      return s;
    }
  if (fd1 >= 0)
    close(fd1);
  if (fd2 >= 0)
    close(fd2);
  free(s);
  return NULL;
}

void udp46_get_fds(udp46 s, int *fd1, int *fd2)
{
  *fd1 = s->s4;
  *fd2 = s->s6;
}

ssize_t udp46_recv(udp46 s,
                   struct sockaddr_in6 *src,
                   struct sockaddr_in6 *dst,
                   void *buf, size_t buf_size)
{
  struct iovec iov[1] = {
    {.iov_base = buf,
     .iov_len = buf_size },
  };
  uint8_t c[1000];
  struct msghdr msg = {
    .msg_iov = iov,
    .msg_iovlen = sizeof(iov) / sizeof(*iov),
    .msg_name = src,
    .msg_namelen = src ? sizeof(*src) : 0,
    .msg_flags = 0,
    .msg_control = c,
    .msg_controllen = sizeof(c)
  };
  ssize_t l;

  if ((l = recvmsg(s->s6, &msg, 0)) < 0)
    if ((l = recvmsg(s->s4, &msg, 0)) < 0)
      return -1;
  if (src && src->sin6_family != AF_INET6)
    {
      /* XXX - convert */
      DEBUG("got non-AF_INET6 packet");
      return -1;
    }
  struct cmsghdr *h;
#ifdef USE_IP_REVCDSTADDR
  struct in6_addr dst_buf;
#endif /* USE_IP_REVCDSTADDR */

  if (dst)
    memset(dst, 0, sizeof(*dst));
  for (h = CMSG_FIRSTHDR(&msg); h;
       h = CMSG_NXTHDR(&msg, h))
    if (h->cmsg_level == IPPROTO_IPV6
        && h->cmsg_type == IPV6_PKTINFO)
      {
        struct in6_pktinfo *ipi6 = (struct in6_pktinfo *)CMSG_DATA(h);
        dst->sin6_family = AF_INET6;
        dst->sin6_addr = ipi6->ipi6_addr;
        dst->sin6_scope_id = ipi6->ipi6_ifindex;
      }
#ifdef USE_IP_REVCDSTADDR
    else if (h->cmsg_level == IPPROTO_IP
             && h->cmsg_type == IP_RECVDSTADDR)
      {
        struct in_addr *a = (struct in_addr *)CMSG_DATA(h);
        IN_ADDR_TO_MAPPED_IN6_ADDR(a, dst);
      }
#endif /* USE_IP_REVCDSTADDR */
  if (dst->sin6_family != AF_INET6)
    {
      /* By default, nothing happens if the option is AWOL. */
      DEBUG("unknown destination");
      return -1;
    }
  return l;
}

int udp46_send_iovec(udp46 s,
                     const struct sockaddr_in6 *src,
                     const struct sockaddr_in6 *dst,
                     struct iovec *iov, int iov_len)
{
  /* XXX - IPv4 path */
  struct in6_pktinfo ipi6 = {.ipi6_addr = src->sin6_addr,
                              .ipi6_ifindex = src->sin6_scope_id };
  uint8_t c[CMSG_SPACE(sizeof(ipi6))];
  struct msghdr msg = {
    .msg_iov = iov,
    .msg_iovlen = iov_len,
    .msg_name = (void *)dst,
    .msg_namelen = sizeof(*dst),
    .msg_flags = 0,
    .msg_control = c,
    .msg_controllen = sizeof(c)
  };
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = IPPROTO_IPV6;
  cmsg->cmsg_type = IPV6_PKTINFO;
  cmsg->cmsg_len = CMSG_LEN(sizeof(ipi6));
  *((struct in6_pktinfo *)CMSG_DATA(cmsg)) = ipi6;
  return sendmsg(s->s6, &msg, 0);
}


void udp46_destroy(udp46 s)
{
  close(s->s4);
  close(s->s6);
  free(s);
}
