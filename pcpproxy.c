/*
 * $Id: pcpproxy.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 18:37:03 2014 mstenber
 * Last modified: Thu May 15 10:24:24 2014 mstenber
 * Edit time:     64 min
 *
 */

#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "pcp.h"
#include "pcpproxy.h"

typedef struct {
  struct list_head lh;

  /* Source address to match */
  struct in6_addr prefix;
  int plen;

  /* Server to contact */
  struct in6_addr address;

  /* Server epoch tracking */
  time_t server_time;
  time_t client_time;
} proxy_server_s, *proxy_server;

time_t our_epoch;

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
  return - 1;
}

static struct list_head servers = LIST_HEAD_INIT(servers);

static uint32_t get_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec;
}

static void reset_epoch(void)
{
  our_epoch = get_time();
  /* XXX - send ANNOUNCEs all over the place! */
  DEBUG("resetting epoch to %d", (int)our_epoch);
}

void proxy_init(void)
{
  reset_epoch();
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

  if (data_len < (int)sizeof(*h))
    {
      DEBUG("too short input from client (%d<%d)", data_len, (int)sizeof(*h));
      return;
    }
  if (memcmp(src, &h->address, sizeof(*src)))
    {
      DEBUG("source address and internal address mismatch");
      return;
    }
  if (h->version != PCP_VERSION_RFC)
    {
      DEBUG("wrong PCP version:%d", h->version);
      return;
    }
  /* XXX - handle client-originated ANNOUNCE locally */

  proxy_server s = determine_server_for_source(src);
  if (!s)
    {
      DEBUG("no PCP server found");
      return;
    }
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

  if (data_len < (int)sizeof(*h))
    {
      DEBUG("too short input from server (%d<%d)", data_len, (int)sizeof(*h));
      return;
    }

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
    {
      DEBUG("reply from unknown PCP server");
      return;
    }

  if (h->version != PCP_VERSION_RFC)
    {
      DEBUG("wrong PCP version:%d", h->version);
      return;
    }

  /* XXX - insert real option parsing here. */
  pcp_option_s po = {
      .option_code = PCP_OPTION_THIRD_PARTY,
      .reserved = 0,
      .len = ntohs(16)
  };

  pcp_thirdparty_option tpo;
  tpo = data + data_len - sizeof(*tpo);

  /* No third party in the end => skip */
  if (memcmp(&tpo->po, &po, sizeof(po)) != 0)
    {
      DEBUG("PCP THIRD_PARTY option missing, ignoring");
      return;
    }

  /* Rewrite + track epoch here */
  uint32_t *epochp = (uint32_t *)&h->address;
  uint32_t curr_server_time = ntohl(*epochp);
  uint32_t curr_client_time = get_time();
  bool valid = true;
  if (s->server_time && s->client_time)
    {
      if (curr_server_time + 1 < s->server_time)
        {
          valid = false;
          DEBUG("server time moving backwards > 1 seconds");
        }
      else
        {
          int64_t client_delta = curr_client_time - s->client_time;
          int64_t server_delta = curr_server_time - s->server_time;
          valid = !(client_delta + 2 < server_delta - server_delta / 16
                    || server_delta + 2 < client_delta - client_delta / 16);
        }
    }
  s->server_time = curr_server_time;
  s->client_time = curr_client_time;
  if (!valid)
    reset_epoch();
  *epochp = get_time() - our_epoch;

  /* XXX override lifetimes if we care to? */
  proxy_send_to_client(dst, &tpo->address,
                       data, data_len - sizeof(*tpo));
}
