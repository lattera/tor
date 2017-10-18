#ifndef SANDBOX_H_
#define SANDBOX_H_

#include "orconfig.h"

#ifdef HAVE_SYS_CAPSICUM_H
#include <sys/capsicum.h>
#include "sandbox_freebsd.h"
#else
#include "sandbox_dummy.h"
typedef char cap_rights_t;
#endif

typedef struct sandbox_impl {
  int (*sandbox_init)(sandbox_cfg_t *);
  void (*sandbox_fini)(void);
  sandbox_cfg_t *(*sandbox_cfg_new)(void);
  int (*sandbox_is_active)(void);
  int (*sandbox_open)(const char *, int, mode_t, cap_rights_t *);
  int (*sandbox_mkdir)(const char *, mode_t);
  int (*sandbox_unlink)(const char *);
  int (*sandbox_socket)(int, int, int, cap_rights_t *);
  int (*sandbox_getaddrinfo)(const char *, const char *,
        const struct addrinfo *, struct addrinfo **);
  void (*sandbox_freeaddrinfo)(struct addrinfo *);
  int (*sandbox_connect)(int, const struct sockaddr *, socklen_t);
  int (*sandbox_stat)(const char *, struct stat *);
  int (*sandbox_rename)(const char *, const char *);
  int (*sandbox_close)(int);
  const char *(*sandbox_intern_string)(const char *);
  int (*sandbox_add_addrinfo)(const char *);
  void (*sandbox_free_getaddrinfo_cache)(void);
  void (*sandbox_disable_getaddrinfo_cache)(void);
  int (*sandbox_cfg_allow_open_filename)(sandbox_cfg_t **, char *);
  int (*sandbox_cfg_allow_openat_filename)(sandbox_cfg_t **, char *);
  int (*sandbox_cfg_allow_stat_filename)(sandbox_cfg_t **, char *);
  int (*sandbox_cfg_allow_chown_filename)(sandbox_cfg_t **, char *);
  int (*sandbox_cfg_allow_chmod_filename)(sandbox_cfg_t **, char *);
  int (*sandbox_cfg_allow_rename)(sandbox_cfg_t **, char *, char *);
} sandbox_impl_t;

extern sandbox_impl_t *sandbox;

sandbox_impl_t *sandbox_get_impl(void);

#endif

