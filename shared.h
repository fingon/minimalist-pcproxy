/*
 * $Id: shared.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 19:28:48 2014 mstenber
 * Last modified: Mon May  5 23:48:57 2014 mstenber
 * Edit time:     3 min
 *
 */

#ifndef SHARED_H
#define SHARED_H


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
