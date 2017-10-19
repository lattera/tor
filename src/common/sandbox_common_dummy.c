 /* Copyright (c) 2017 Shawn Webb. */
/* See LICENSE for licensing information */

/**
 * \file sandbox_common_tor_freebsd.c
 * \brief Code to enable sandboxing with Capsicum.
 **/

#include "orconfig.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "orconfig.h"
#include "sandbox.h"

static int
sandbox_dummy_open(const char *path, int flags, mode_t mode,
    cap_rights_t *rights)
{
  return open(path, flags, mode);
}

static int
sandbox_dummy_unlink(const char *path)
{
  return unlink(path);
}

static int
sandbox_dummy_socket(int domain, int type, int protocol,
    cap_rights_t *rights)
{
  return socket(domain, type, protocol);
}

static int
sandbox_dummy_getaddrinfo(const char *name, const char *servname,
    const struct addrinfo *hints,
    struct addrinfo **res)
{
  return getaddrinfo(name, servname, hints, res);
}
static void
sandbox_dummy_freeaddrinfo(struct addrinfo *ai)
{
  freeaddrinfo(ai);
}

static int
sandbox_dummy_connect(int sockfd, const struct sockaddr *name, socklen_t namelen)
{
  return connect(sockfd, name, namelen);
}

static int
sandbox_dummy_mkdir(const char *path, mode_t mode)
{
  return mkdir(path, mode);
}

static int
sandbox_dummy_stat(const char *path, struct stat *sb)
{
  return stat(path, sb);
}

static int
sandbox_dummy_rename(const char *from, const char *to)
{
  return rename(from, to);
}

static int
sandbox_dummy_close(int fd)
{
  return close(fd);
}

static int
sandbox_dummy_cfg_allow_open_filename(sandbox_cfg_t **cfg, char *file)
{
  return 0;
}

static int
sandbox_dummy_cfg_allow_openat_filename(sandbox_cfg_t **cfg, char *file)
{
  return 0;
}

static int
sandbox_dummy_cfg_allow_stat_filename(sandbox_cfg_t **cfg, char *file)
{
  return 0;
}

static int
sandbox_dummy_cfg_allow_chown_filename(sandbox_cfg_t **cfg, char *file)
{

  return 0;
}

static int
sandbox_dummy_cfg_allow_chmod_filename(sandbox_cfg_t **cfg, char *file)
{

  return 0;
}

static int
sandbox_dummy_cfg_allow_rename(sandbox_cfg_t **cfg, char *file1, char *file2)
{
  return 0;
}

static int
sandbox_dummy_is_active(void)
{
  return 0;
}

static const char *
sandbox_dummy_intern_string(const char *str)
{
  return str;
}

static int
sandbox_dummy_init(sandbox_cfg_t *cfg)
{
  return 0;
}

static sandbox_cfg_t *
sandbox_dummy_cfg_new(void)
{
    return NULL;
}

static sandbox_impl_t sandbox_dummy_impl = {
  .sandbox_init = sandbox_dummy_init,
  .sandbox_is_active = sandbox_dummy_is_active,
  .sandbox_open = sandbox_dummy_open,
  .sandbox_mkdir = sandbox_dummy_mkdir,
  .sandbox_unlink = sandbox_dummy_unlink,
  .sandbox_socket = sandbox_dummy_socket,
  .sandbox_getaddrinfo = sandbox_dummy_getaddrinfo,
  .sandbox_freeaddrinfo = sandbox_dummy_freeaddrinfo,
  .sandbox_connect = sandbox_dummy_connect,
  .sandbox_stat = sandbox_dummy_stat,
  .sandbox_rename = sandbox_dummy_rename,
  .sandbox_close = sandbox_dummy_close,
  .sandbox_cfg_new = sandbox_dummy_cfg_new,
  .sandbox_cfg_allow_open_filename = sandbox_dummy_cfg_allow_open_filename,
  .sandbox_cfg_allow_openat_filename = sandbox_dummy_cfg_allow_openat_filename,
  .sandbox_cfg_allow_stat_filename = sandbox_dummy_cfg_allow_stat_filename,
  .sandbox_cfg_allow_chown_filename = sandbox_dummy_cfg_allow_chown_filename,
  .sandbox_cfg_allow_chmod_filename = sandbox_dummy_cfg_allow_chmod_filename,
  .sandbox_cfg_allow_rename = sandbox_dummy_cfg_allow_rename,
  .sandbox_intern_string = sandbox_dummy_intern_string,
};

sandbox_impl_t *
sandbox_dummy_get_impl(void)
{
  return &sandbox_dummy_impl;
}

