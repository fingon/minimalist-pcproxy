/*
 * $Id: pcpproxy.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 18:28:00 2014 mstenber
 * Last modified: Thu May 15 13:14:29 2014 mstenber
 * Edit time:     22 min
 *
 */

#ifndef PCP_PROXY_H
#define PCP_PROXY_H

#include <netinet/in.h>

/*
 * (Relatively) event loop free PCP proxy implementation.  The
 * assumption is that configuration is set from somewhere. And that
 * the receiving functions are called as needed, and that the sending
 * functions are available.
 *
 * (= sockets are mostly someone else's problem, and they behave like
 * correct dual-stack IPv6 sockets do; such things do not exist in the
 * API-land, but hopefully someone wraps them so we can live
 * blissfully unaware of the fact).
 */

/* For how long a time, we _won't_ override old requests */
#define PCP_PROXY_ASSUMED_REQUEST_ROUNDTRIP_SECONDS 10

/* What sort of load we assume to be under at most, under sane conditions */
#define PCP_PROXY_ASSUMED_REQUESTS_PER_SECOND 10

/******************************************************* Init/configuration  */

void pcp_proxy_init(void);
/*
 * Add a new server.
 */
void pcp_proxy_add_server(struct in6_addr *prefix, int plen,
                          struct sockaddr_in6 *server_address);
/*
 * Utility method with built-in parsing.
 *
 * The string is expected to be in format prefix/plen=address The
 * return value is whether the add succeeded or not.
 */
bool pcp_proxy_add_server_string(const char *string,
                                 char *err, size_t err_len);

/******************************************************** Input to the proxy */

void pcp_proxy_handle_from_client(struct sockaddr_in6 *src,
                                  struct sockaddr_in6 *dst,
                                  void *data, int data_len);
void pcp_proxy_handle_from_server(struct sockaddr_in6 *src,
                                  struct sockaddr_in6 *dst,
                                  void *data, int data_len);

/************* Output from the proxy (client implementation responsibility)  */

void pcp_proxy_send_to_client(struct sockaddr_in6 *src,
                              struct sockaddr_in6 *dst,
                              void *data, int data_len);
void pcp_proxy_send_to_server(struct sockaddr_in6 *src,
                              struct sockaddr_in6 *dst,
                              void *data, int data_len,
                              void *data2, int data_len2);

#endif /* PCP_PROXY_H */
