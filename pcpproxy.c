/*
 * $Id: pcpproxy.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 18:37:03 2014 mstenber
 * Last modified: Tue Sep  2 12:31:38 2014 mstenber
 * Edit time:     155 min
 *
 */

#include "shared.h"
#include "pcpproxy.h"
#include "pcp.h"

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

typedef struct {
  struct sockaddr_in6 src;
  struct sockaddr_in6 dst;
  bool third_party; /* was the original request third party too? */
  uint8_t nonce[PCP_NONCE_LENGTH];
  time_t t;
} pcp_proxy_request_s, *pcp_proxy_request;

typedef struct {
  struct list_head lh;

  /* Source address to match */
  struct in6_addr prefix;
  int plen;

  /* Server to contact */
  struct sockaddr_in6 address;

  /* Server epoch tracking */
  time_t server_time;
  time_t client_time;
} pcp_proxy_server_s, *pcp_proxy_server;

/* This is the global state proxy has */
time_t our_epoch;
static struct list_head servers = LIST_HEAD_INIT(servers);
pcp_proxy_request_s requests[PCP_PROXY_ASSUMED_REQUEST_ROUNDTRIP_SECONDS *
                             PCP_PROXY_ASSUMED_REQUESTS_PER_SECOND + 1];

#define NUM_REQUESTS ((int) (sizeof(requests)/sizeof(requests[0])))

/************************************************************* Time handling */

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

/********************************************************** Request handling */

static pcp_proxy_request get_request(pcp_common_header h)
{
  int i;
  void *nonce = h+1;

  for (i = 0; i < NUM_REQUESTS; i++)
    {
      pcp_proxy_request req = &requests[i];
      if (memcmp(req->nonce, nonce, PCP_NONCE_LENGTH) == 0 && req->t)
        return req;
    }
  return NULL;
}

static pcp_proxy_request allocate_request(struct sockaddr_in6 *src,
                                          struct sockaddr_in6 *dst,
                                          pcp_common_header h)
{
  int i;
  time_t now = get_time();
  time_t old_time = now - PCP_PROXY_ASSUMED_REQUESTS_PER_SECOND;
  time_t t;
  pcp_proxy_request req, breq = NULL;
  void *nonce = h+1;

  if (get_request(h))
    return NULL;

  for (i = 0; i < NUM_REQUESTS; i++)
    {
      req = &requests[i];
      if ((t = req->t) < old_time)
        {
          if (!t)
            {
              breq = req;
              break;
            }
          if (!breq || breq->t > req->t)
            breq = req;
        }
    }
  if (i == NUM_REQUESTS && !breq)
    return NULL;
  breq->t = now;
  breq->src = *src;
  breq->dst = *dst;
  memcpy(breq->nonce, nonce, PCP_NONCE_LENGTH);
  return breq;
}


/************************************************************ Public methods */


void pcp_proxy_init(void)
{
  memset(requests, 0, sizeof(requests));
  reset_epoch();
}

void pcp_proxy_add_server(struct in6_addr *prefix, int plen,
                          struct sockaddr_in6 *address)
{
  pcp_proxy_server s = calloc(1, sizeof(*s));
  assert(s);
  s->prefix = *prefix;
  s->plen = plen;
  s->address = *address;
  list_add(&s->lh, &servers);
  DEBUG("added server %s for %s/%d",
        SOCKADDR_IN6_REPR(&s->address), IN6_ADDR_REPR(&s->prefix), s->plen);
}

/* Linux strchr doesn't like NULL argument. Some others do. */
#define STRCHRISH(haystack,needle) \
  ((haystack) ? strchr(haystack, needle) : NULL)

static int in6_pton(const char *p, struct in6_addr *in6)
{
  if (inet_pton(AF_INET6, p, in6) < 1)
    {
      /* Automatically map IPv4 address too */
      struct in_addr a;
      if (inet_pton(AF_INET, p, &a) < 1)
        return -1;
      IN_ADDR_TO_MAPPED_IN6_ADDR(&a, in6);
    }
  return 1;
}

static int parse_sockaddr_in6(char *c,
                              struct sockaddr_in6 *sin6, uint16_t dport)
{
  /* (Destructively) parse the address or [address]:port in c to
   * sin6. Do not touch anything except sin6_addr and sin6_port (if
   * available). */
  char *p1 = STRCHRISH(c, '[');
  char *p2 = STRCHRISH(p1, ']');
  char *p3 = STRCHRISH(p2, ':');
  const char *host = NULL;
  const char *port = NULL;
  int p = 0;

  if (p3)
    {
      p1++;
      *p2 = 0;
      p3++;
      host = p1;
      port = p3;
    }
  else
    {
      host = c;
      port = NULL;
    }
  if (port)
    {
      p = atoi(port);
      if (!p)
        return 0;
    }
  sockaddr_in6_set(sin6, NULL, p ? p : dport);
  return in6_pton(host, &sin6->sin6_addr);
}

bool pcp_proxy_add_server_string(const char *string,
                                 char *err, size_t err_len)
{
  char *bases = strdup(string);

  if (!bases)
    {
      snprintf(err, err_len, "OOM (strdup)");
      return false;
    }
  char *prefix = bases;
  char *d = STRCHRISH(prefix, '/');
  char *c = STRCHRISH(d, '=');
  if (!c)
    {
      snprintf(err, err_len, "Invalid server format (no X/Y=Z)");
    err:
      free(bases);
      return false;
    }
  *d = 0;
  d++;
  *c = 0;
  c++;
  struct sockaddr_in6 sin6;
  struct in6_addr p;
  DEBUG("converting to IPv6: %s / %s", prefix, c);
  if (in6_pton(prefix, &p) < 1
      || parse_sockaddr_in6(c, &sin6, PCP_SERVER_PORT) < 1)
    {
      snprintf(err, err_len, "Unable to parse the addresses: %s",
               strerror(errno));
      goto err;
    }
  long plen = strtol(d, NULL, 10);
  if (IN6_IS_ADDR_V4MAPPED(&p))
    plen += 96;
  if (plen < 0  || plen > 128)
    {
      snprintf(err, err_len, "Invalid prefix length");
      goto err;
    }
  pcp_proxy_add_server(&p, plen, &sin6);
  free(bases);
  return true;
}


static int determine_local_address(const struct sockaddr_in6 *dst,
                                   struct in6_addr *result)
{
  int s = socket(PF_INET6, SOCK_DGRAM, 0);
  struct sockaddr_in6 sin6;
  socklen_t sin6_len = sizeof(sin6);

  if (s < 0)
    return -1;
  if (connect(s, (struct sockaddr *)dst, sizeof(*dst)) && errno != EINPROGRESS)
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


static pcp_proxy_server determine_server_for_source(struct in6_addr *src)
{
  pcp_proxy_server s;

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

#define for_each_pcp_option(o, data, data_len)          \
for (o = data ;                                         \
     ((void *)o + sizeof(*o)) <= (data + data_len)      \
       && ((void *)o + sizeof(*o) + htons(o->len))      \
           <= (data + data_len) ;                       \
     o = o + sizeof(*o) + ntohs(o->len))

static pcp_option_s tpo_header = {
  .option_code = PCP_OPTION_THIRD_PARTY,
  .reserved = 0,
  .len = ntohs(16)
};

pcp_thirdparty_option find_third_party_option(void *data, int data_len)
{
  pcp_common_header ch = data;
  int opcode = ch->opcode & ~PCP_OPCODE_RESPONSE;
  void *ptr = data +
    (opcode == PCP_OPCODE_MAP ? sizeof(pcp_map_header_s) :
     sizeof(pcp_peer_header_s));
  pcp_option o;
  for_each_pcp_option(o, ptr, data_len - (ptr - data))
    if (memcmp(o, &tpo_header, sizeof(tpo_header)) == 0)
      return (pcp_thirdparty_option)o;
  return NULL;
}

void send_error(struct sockaddr_in6 *src, struct sockaddr_in6 *dst,
                int rc, void *data, int data_len)
{
  pcp_common_header h = (pcp_common_header) data;

  /* Modify the payload according to RFC6887 section 8.2 */
  if (data_len > 1100)
    data_len = 1100;
  h->opcode |= PCP_OPCODE_RESPONSE;
  h->result_code = rc;
  h->lifetime = htonl(30 * 60); /* Recommended long lifetime */
  h->reserved = 0;
  memset(&h->int_address, 0, sizeof(h->int_address));
  *((uint32_t *)&h->int_address) = htonl(get_time() - our_epoch);
  pcp_proxy_send_to_client(dst, src, data, data_len);
}

void pcp_proxy_handle_from_client(struct sockaddr_in6 *src,
                                  struct sockaddr_in6 *dst,
                                  void *data, int data_len)
{
  pcp_common_header h = (pcp_common_header) data;

  DEBUG("pcp_proxy_handle_from_client: %s->%s %d bytes",
        SOCKADDR_IN6_REPR(src), SOCKADDR_IN6_REPR(dst), data_len);
  if (data_len < (int)sizeof(*h))
    {
      DEBUG("too short input from client (%d<%d)", data_len, (int)sizeof(*h));
      /* XXX - what to respond? clearly broken client */
      return;
    }
  if (memcmp(&src->sin6_addr, &h->int_address, sizeof(src->sin6_addr)))
    {
      DEBUG("source address and internal address mismatch: %s<>%s",
            SOCKADDR_IN6_REPR(src), IN6_ADDR_REPR(&h->int_address));
      send_error(src, dst, PCP_RC_ADDRESS_MISMATCH, data, data_len);
      return;
    }
  if (h->version != PCP_VERSION_RFC)
    {
      DEBUG("wrong PCP version:%d", h->version);
      send_error(src, dst, PCP_RC_UNSUPP_VERSION, data, data_len);
      return;
    }
  switch (h->opcode)
    {
    case PCP_OPCODE_ANNOUNCE:
      /* Check that there are no mandatory-to-understand options */
      {
        pcp_option o;
        for_each_pcp_option(o, data + sizeof(*h), data_len - sizeof(*h))
          {
            if (o->option_code < PCP_OPTION_MANDATORY_BELOW)
              {
                send_error(src, dst, PCP_RC_UNSUPP_OPTION, data, data_len);
                return;
              }
          }
        send_error(src, dst, PCP_RC_SUCCESS, data, data_len);
        return;
      }
    case PCP_OPCODE_PEER:
    case PCP_OPCODE_MAP:
      if (data_len < (int)(sizeof(*h) + PCP_NONCE_LENGTH))
        {
          DEBUG("too short peer/map");
          return;
        }
      break;
    default:
      DEBUG("unknown opcode:%d", h->opcode);
      send_error(src, dst, PCP_RC_UNSUPP_OPCODE, data, data_len);
      return;
    }

  pcp_thirdparty_option tpop = find_third_party_option(data, data_len);
  struct in6_addr *osrc = tpop ? &tpop->tp_address : &src->sin6_addr;
  pcp_proxy_server s = determine_server_for_source(osrc);
  if (!s)
    {
      DEBUG("no PCP server found");
      return;
    }

  pcp_proxy_request req = allocate_request(src, dst, h);
  if (!req)
    {
      DEBUG("too busy or resend -> ignoring");
      return;
    }

  int tpop_len = 0;
  pcp_thirdparty_option_s tpo = {
    .po = {
      .option_code = PCP_OPTION_THIRD_PARTY,
      .reserved = 0,
      .len = ntohs(16)
    },
    .tp_address = src->sin6_addr
  };
  if (!tpop)
    {
      tpop = &tpo;
      tpop_len = sizeof(*tpop);
    }
  else
    {
      req->third_party = true;
    }

  /* Determine whether our current source address is acceptable, or if
   * we should do SA for the server address and pick new one. For the
   * time being, only linklocal source address is considered
   * non-reusable (XXX: can we do this just always?) */
  struct in6_addr nsrc = dst->sin6_addr;
  if (IN6_IS_ADDR_LINKLOCAL(&nsrc))
    if (determine_local_address(&s->address, &nsrc))
      {
        DEBUG("no route found to generate source address");
        return;
      }

  h->int_address = nsrc;
  struct sockaddr_in6 sin6;
  sockaddr_in6_set(&sin6, &nsrc, 0); /* port ignored in send */
  pcp_proxy_send_to_server(&sin6, &s->address,
                           data, data_len,
                           tpop, tpop_len);
}


void pcp_proxy_handle_from_server(struct sockaddr_in6 *src,
                                  struct sockaddr_in6 *dst,
                                  void *data, int data_len)
{
  pcp_common_header h = (pcp_common_header) data;

  DEBUG("pcp_proxy_handle_from_server: %s->%s %d bytes",
        SOCKADDR_IN6_REPR(src), SOCKADDR_IN6_REPR(dst), data_len);
  if (data_len < (int)sizeof(*h))
    {
      DEBUG("too short input from server (%d<%d)", data_len, (int)sizeof(*h));
      return;
    }

  pcp_proxy_server s;
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

  if (h->opcode != (PCP_OPCODE_PEER | PCP_OPCODE_RESPONSE)
      && h->opcode != (PCP_OPCODE_MAP | PCP_OPCODE_RESPONSE))
    {
      DEBUG("ignored opcode %d from server", h->opcode);
      return;
    }

  pcp_proxy_request req = get_request(h);
  if (!req)
    {
      DEBUG("no request found");
      return;
    }

  if (data_len < (int)(sizeof(*h) + PCP_NONCE_LENGTH))
    {
      DEBUG("too short peer/map from server");
      return;
    }

  pcp_thirdparty_option tpo = find_third_party_option(data, data_len);

  if (!tpo)
    {
      DEBUG("PCP THIRD_PARTY option missing, ignoring");
      return;
    }

  if (!req->third_party)
    {
      /* Original request wasn't third party, we added it. Let's get
       * rid of it. */
      memcpy(tpo, tpo+1,
             data_len - ((void *)tpo - data) - sizeof(*tpo));
      data_len -= sizeof(*tpo);
    }
  /* Rewrite + track epoch here */
  uint32_t *epochp = (uint32_t *)&h->int_address;
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
  *epochp = htonl(get_time() - our_epoch);

  /* XXX override lifetimes if we care to? */
  pcp_proxy_send_to_client(&req->dst, &req->src, data, data_len);

  /* No longer needed request */
  req->t = 0;
}
