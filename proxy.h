/*
 * $Id: proxy.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 18:28:00 2014 mstenber
 * Last modified: Mon May  5 18:39:27 2014 mstenber
 * Edit time:     9 min
 *
 */

#ifndef PROXY_H
#define PROXY_H

#include <netinet/in.h>

/*
 * (Relatively) event loop free PCP proxy implementation.  The
 * assumption is that configuration is set from somewhere. And that
 * the receiving functions are called as needed, and that the sending
 * functions are available.
 */

void proxy_init(void);
void proxy_add_server(struct in6_addr *prefix, int plen,
                      struct in6_addr *address);
void proxy_handle_from_client(struct in6_addr *src,
                              struct in6_addr *dst,
                              void *data, int data_len);
void proxy_handle_from_server(struct in6_addr *src,
                              struct in6_addr *dst,
                              void *data, int data_len);
void proxy_send_to_client(struct in6_addr *src,
                          struct in6_addr *dst,
                          void *data, int data_len);
void proxy_send_to_server(struct in6_addr *src,
                          struct in6_addr *dst,
                          void *data, int data_len,
                          void *data2, int data_len2);

#endif /* PROXY_H */
