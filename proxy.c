/*
 * $Id: proxy.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 18:37:03 2014 mstenber
 * Last modified: Mon May  5 20:02:54 2014 mstenber
 * Edit time:     44 min
 *
 */

#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "proxy.h"
#include "pcp.h"

typedef struct {
  struct list_head lh;
  struct in6_addr prefix;
  int plen;
  struct in6_addr address;
} proxy_server_s, *proxy_server;

int determine_local_address(const struct in6_addr *dst,
                            struct in6_addr *result)
{
  int s = socket(PF_INET6, SOCK_DGRAM, 0);
  struct sockaddr_in6 sin6;
  socklen_t sin6_len = sizeof(sin6);

  if (s < 0)
    return -1;
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = 123; /* random */
  sin6.sin6_addr = *dst;
  if (connect(s, (struct sockaddr *)&sin6, sizeof(sin6))
      && errno != EINPROGRESS)
    goto err;
  if (getsockname(s, (struct sockaddr *)&sin6, &sin6_len))
    goto err;
  if (sin6.sin6_family == AF_INET6)
    {
      *result = sin6.sin6_addr;
      close(s);
      return 0;
    }
 err:
  close(s);
  return -1;
}

static struct list_head servers = LIST_HEAD_INIT(servers);

void proxy_init(void)
{
}

void proxy_add_server(struct in6_addr *prefix, int plen,
                      struct in6_addr *address)
{
  proxy_server s = calloc(1, sizeof(*s));
  assert(s);
  s->prefix = *prefix;
  s->plen = plen;
  s->address = *address;
  list_add(&s->lh, &servers);
}

static proxy_server determine_server_for_source(struct in6_addr *src)
{
  proxy_server s;

  list_for_each_entry(s, &servers, lh)
    {
      int whole = s->plen / 8;

      /* Consider whole bytes */
      if (memcmp(s->prefix.s6_addr, src->s6_addr, whole))
        continue;

      /* Consider leftover bits */
      int bits = s->plen % 8;
      if (bits
          && s->prefix.s6_addr[whole] >> (8 - bits) !=
             src->s6_addr[whole] >> (8 - bits))
        continue;

      /* Yay, match */
      return s;
    }
  return NULL;
}

void proxy_handle_from_client(struct in6_addr *src,
                              struct in6_addr *dst,
                              void *data, int data_len)
{
  pcp_common_header h = (pcp_common_header) data;

  if (data_len < sizeof(*h))
    return;
  if (memcmp(src, &h->address, sizeof(*src)))
    return;
  if (h->version != PCP_VERSION_RFC)
    return;
  proxy_server s = determine_server_for_source(src);
  if (!s)
    return;
#if 0
  /* Hmm. This would be correct, but unfortunately we have to use
   * 'dst' to store server client side expects.. */
  struct in6_addr my_src;
  if (determine_local_address(&s->address,
                              &my_src) < 0)
    return;
#endif /* 0 */

  pcp_thirdparty_option_s tpo = {
    .po = {
      .option_code = PCP_OPTION_THIRD_PARTY,
      .reserved = 0,
      .len = ntohs(16)
    },
    .address = *src
  };

  h->address = *dst;
  proxy_send_to_server(dst, &s->address,
                       data, data_len,
                       &tpo, sizeof(tpo));
}

void proxy_handle_from_server(struct in6_addr *src,
                              struct in6_addr *dst,
                              void *data, int data_len)
{
  pcp_common_header h = (pcp_common_header) data;

  if (data_len < sizeof(*h))
    return;

  proxy_server s;
  bool found = false;

  /* Verify we know about the server */
  list_for_each_entry(s, &servers, lh)
    if (!memcmp(&s->address, src, sizeof(*src)))
      {
        found = true;
        break;
      }
  if (!found)
    return;

  if (h->version != PCP_VERSION_RFC)
    return;

  /* XXX - insert real option parsing here. */
  pcp_option_s po = {
      .option_code = PCP_OPTION_THIRD_PARTY,
      .reserved = 0,
      .len = ntohs(16)
  };

  pcp_thirdparty_option tpo = data + data_len - sizeof(pcp_thirdparty_option_s);

  /* No third party in the end => skip */
  if (memcmp(&tpo->po, &po, sizeof(po)) != 0)
    return;

  /* XXX - how can we find client address? we can't, currently. */
}
