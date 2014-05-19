/*
 * $Id: shared.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 19:28:48 2014 mstenber
 * Last modified: Mon May 19 12:34:45 2014 mstenber
 * Edit time:     15 min
 *
 */

#ifndef SHARED_H
#define SHARED_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#ifdef __APPLE__
#include <sys/queue.h>
#ifdef LIST_HEAD
#undef LIST_HEAD
#endif /* LIST_HEAD */

#endif /* __APPLE__ */

#ifndef typeof
#define typeof __typeof
#endif

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type, member) ))
#endif

#include <libubox/list.h>

#define IN6_ADDR_REPR(a6) \
  inet_ntop(AF_INET6, a6, alloca(INET6_ADDRSTRLEN), INET6_ADDRSTRLEN)

static inline const char *_sockaddr_in6_repr(const struct sockaddr_in6 *sa,
                                             char *buf, size_t buf_len)
{
  char host[123];
  char serv[123];

  if (!buf)
    return NULL;
  if (getnameinfo((const struct sockaddr *)sa, sizeof(*sa),
                  host, sizeof(host), serv, sizeof(serv),
                  NI_NUMERICHOST|NI_NUMERICSERV))
    {
      perror("getnameinfo");
      return NULL;
    }
  snprintf(buf, buf_len, "%s:%s", host, serv);
  return buf;
}

#define SOCKADDR_IN6_REPR(sin6) _sockaddr_in6_repr(sin6, alloca(123), 123)

static inline void sockaddr_in6_set(struct sockaddr_in6 *sin6,
                                    struct in6_addr *a6,
                                    uint16_t port)
{
  memset(sin6, 0, sizeof(*sin6));
#ifdef SIN6_LEN
  sin6->sin6_len = sizeof(*sin6);
#endif /* SIN6_LEN */
  sin6->sin6_family = AF_INET6;
  if (a6)
    sin6->sin6_addr = *a6;
  sin6->sin6_port = htons(port);
}

#define IN_ADDR_TO_MAPPED_IN6_ADDR(a, a6)       \
do {                                            \
  memset(a6, 0, sizeof(*(a6)));                 \
  (a6)->s6_addr[10] = 0xff;                     \
  (a6)->s6_addr[11] = 0xff;                     \
  ((uint32_t *)a6)[3] = *((uint32_t *)a);       \
 } while (0)

#define MAPPED_IN6_ADDR_TO_IN_ADDR(a6, a)       \
do {                                            \
  *((uint32_t *)a) = ((uint32_t *)a6)[3];       \
 } while (0)

#ifndef NDEBUG

#include <stdio.h>

#define DEBUG(...) do {                                 \
  fprintf(stderr, "[%s:%d]", __FILE__, __LINE__);       \
  fprintf(stderr, __VA_ARGS__);                         \
  fprintf(stderr, "\n");                                \
  fflush(stdout);                                       \
} while(0)

#else

#define DEBUG(...) do { } while(0)

#endif /* !NDEBUG */

#endif /* SHARED_H */
