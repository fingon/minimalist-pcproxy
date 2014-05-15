/*
 * $Id: pcp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Mon May  5 17:22:26 2014 mstenber
 * Last modified: Thu May 15 20:21:06 2014 mstenber
 * Edit time:     11 min
 *
 */

#ifndef PCP_H
#define PCP_H

#include <libubox/utils.h>
#include <netinet/in.h>


/* From RFC6887 */

#define PCP_CLIENT_PORT 5350
#define PCP_SERVER_PORT 5351

#define PCP_VERSION_RFC 2

#define PCP_PAYLOAD_LENGTH 1100

#define PCP_NONCE_LENGTH 12

#define PCP_OPCODE_ANNOUNCE 0
#define PCP_OPCODE_MAP 1
#define PCP_OPCODE_PEER 2
#define PCP_OPCODE_RESPONSE 128

typedef struct __packed {
  uint8_t version;
  uint8_t opcode;
  uint16_t reserved;
  uint32_t lifetime;
  struct in6_addr address;
  char data[];
} pcp_common_header_s, *pcp_common_header;

typedef struct __packed {
  uint8_t option_code;
  uint8_t reserved;
  uint16_t len;
} pcp_option_s, *pcp_option;

#define PCP_OPTION_THIRD_PARTY 1

typedef struct __packed {
  pcp_option_s po;
  struct in6_addr address;
} pcp_thirdparty_option_s, *pcp_thirdparty_option;

typedef struct __packed {
  pcp_common_header_s pch;
  uint8_t nonce[PCP_NONCE_LENGTH];
  uint8_t protocol;
  uint8_t reserved[3];
  uint16_t int_port, ext_port;
  struct in6_addr ext_address;
} pcp_map_header_s;

typedef struct __packed {
  pcp_common_header_s pch;
  uint8_t nonce[PCP_NONCE_LENGTH];
  uint8_t protocol;
  uint8_t reserved[3];
  uint16_t int_port, ext_port;
  struct in6_addr ext_address;
  uint16_t peer_port, reserved2;
  struct in6_addr peer_address;
} pcp_peer_header_s;

#endif /* PCP_H */
