/*
 * $Id: shared.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 19:28:48 2014 mstenber
 * Last modified: Thu May 15 19:17:32 2014 mstenber
 * Edit time:     13 min
 *
 */

#ifndef SHARED_H
#define SHARED_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>

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
