/* Copyright (c) 2017 Shawn Webb <shawn.webb@hardenedbsd.org> */
/* See LICENSE for licensing information */

/**
 * \file sandbox.h
 * \brief Header file for sandbox.c.
 **/

#ifndef SANDBOX_FREEBSD_H_
#define SANDBOX_FREEBSD_H_

#include "orconfig.h"
#include "torint.h"

#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>

struct sandbox_impl;

struct sandbox_cfg_elem {
  unsigned int unused;
};

/** Typedef to structure used to manage a sandbox configuration. */
typedef struct sandbox_cfg_elem sandbox_cfg_t;

struct sandbox_impl *sandbox_freebsd_get_impl(void);
void fork_backend(void);

#include <uuid.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#define F_NONE     0
#define F_SHUTDOWN   1

#define F_FEATURE_NONE   0
#define F_FEATURE_CAP  1

#define F_GETADDRINFO_NONE   0
#define F_GETADDRINFO_HINTS  1

#define STATUSSZ   33
#define CONTROLSZ  (sizeof(struct cmsghdr) + sizeof(int) + 16)

typedef enum _request_type {
  ADD_FILE_PATH = 0,
  SHUTDOWN  = 1,
  CLOSE_FD  = 2,
  CREATE_SOCKET = 3,
  UNLINK_PATH = 4,
  GETADDRINFO = 5,
  CONNECT_SOCKET  = 6,
  MKDIR   = 7,
  STAT    = 8,
  RENAME    = 9,
} request_type;

typedef enum _response_code {
  ERROR_NONE  = 0,
  ERROR_FAIL  = 1,
} response_code;

struct request_add_file_path {
  char     r_path[1024];
  int    r_flags;
  mode_t     r_mode;
  uint64_t   r_features;
  cap_rights_t   r_rights;
};

struct request_close_fd {
  uuid_t   r_uuid;
};

struct request_mkdir {
  char   r_path[1024];
  mode_t   r_mode;
};

struct request_open_socket {
  int    r_domain;
  int    r_type;
  int    r_protocol;
  uint64_t   r_features;
  cap_rights_t   r_rights;
};

struct request_connect_socket {
  uuid_t     r_uuid;
  socklen_t  r_socklen;
  union {
    struct sockaddr_in   addr4;
    struct sockaddr_in6  addr6;
  }    r_sock;
};

struct request_unlink {
  char   r_path[1024];
};

struct request_getaddrinfo {
  char     r_hostname[256];
  char     r_servname[256];
  struct addrinfo  r_hints;
  uint64_t   r_features;
};

struct request_stat {
  char   r_path[1024];
};

struct request_rename {
  char   r_from_path[512];
  char   r_to_path[512];
};

struct request {
  request_type   r_type;
  union {
    struct request_add_file_path   u_add_file_path;
    struct request_open_socket   u_open_socket;
    struct request_close_fd    u_close_fd;
    struct request_unlink    u_unlink_path;
    struct request_getaddrinfo   u_getaddrinfo;
    struct request_connect_socket  u_connect;
    struct request_mkdir     u_mkdir;
    struct request_stat    u_stat;
    struct request_rename    u_rename;
  }    r_payload;
};

struct response_addrinfo {
  int  ra_flags;
  int  ra_family;
  int  ra_socktype;
  int  ra_protocol;
  union {
    struct sockaddr_in   addr4;
    struct sockaddr_in6  addr6;
  }  ra_sockaddr;
};

struct response_stat {
  response_code  rs_code;
  int    rs_errno;
  struct stat  rs_sb;
};

struct generic_response {
  response_code  r_code;
  int    r_errno;
};

struct response {
  response_code  r_code;
  int    r_errno;
  uuid_t     r_uuid;
};

extern int backend_fd;
extern int sandboxpid;

/* END FREEBSD SANDBOX API */

#endif /* SANDBOX_FREEBSD_H_ */

