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
#include "container.h"
#include "torlog.h"
#include "torint.h"
#include "util.h"
#include "tor_queue.h"

#include <fcntl.h>

#if HAVE_SYS_CAPSICUM_H

#include <sys/procdesc.h>

#define SANDBOX_ENABLED 1

struct response_wrapper {
  int fd;
  struct response response;
};

static struct uuids {
  int active;
  int fd;
  uuid_t uuid;
} *uuids;

static struct dirfd {
  int fd;
  char *path;
} *dirfds;

static pthread_mutex_t sandbox_mtx;
int backend_fd;

static size_t nuuids, ndirs;

static int
sandbox_freebsd_is_active(void)
{
  unsigned int mode;

  mode = 0;
  cap_getmode(&mode);

  return mode;
}

static struct dirfd *
lookup_directory(char *file)
{
  size_t i;

  for (i = 0; i < ndirs; i++) {
    if (!strncmp(file, dirfds[i].path, strlen(dirfds[i].path)))
      return &(dirfds[i]);
  }

  return NULL;
}

static void
add_directory_descriptor(int fd, char *path)
{
  void *p;

  if (sandbox_freebsd_is_active())
    return;

  p = tor_reallocarray(dirfds, sizeof(*dirfds), ndirs + 1);
  if (p == NULL)
    return;

  dirfds = p;

  dirfds[ndirs].fd = fd;
  dirfds[ndirs].path = tor_strdup(path);
  ndirs++;
}

static int
lookup_directory_descriptor(char *file)
{
  struct dirfd *entry;

  entry = lookup_directory(file);

  if (entry != NULL)
    return entry->fd;

  return -1;
}

static struct uuids *
lookup_uuid(int fd)
{
  size_t i;

  for (i = 0; i < nuuids; i++) {
    if (uuids[i].active == 0)
      continue;

    if (uuids[i].fd == fd)
      return (&(uuids[i]));
  }

  return (NULL);
}

static struct uuids *
add_uuid(int fd, uuid_t *uuid)
{
  struct uuids *u;
  size_t i;
  void *p;

  u = lookup_uuid(fd);
  if (u != NULL)
    return (u);

  for (i = 0; i < nuuids; i++) {
    if (uuids[i].active == 0) {
      uuids[i].active = 1;
      uuids[i].fd = fd;
      memmove(&(uuids[i].uuid), uuid,
          sizeof(uuids[i].uuid));
      return (&(uuids[i]));
    }
  }

  p = tor_reallocarray(uuids, sizeof(struct uuids),
      (nuuids + 1));
  if (p == NULL)
    return (NULL);

  uuids = p;
  uuids[nuuids].active = 1;
  uuids[nuuids].fd = fd;
  memmove(&(uuids[i].uuid), uuid, sizeof(uuids[i].uuid));
  nuuids++;

  return (&(uuids[nuuids-1]));
}

static struct response_wrapper *
send_request(struct request *request)
{
  struct response_wrapper *wrapper;
  char control[CONTROLSZ];
  struct cmsghdr *cmsg;
  struct msghdr msg;
  struct iovec iov;
  ssize_t nrecv;

  wrapper = tor_calloc(1, sizeof(*wrapper));
  if (wrapper == NULL)
    return (NULL);

  memset(&iov, 0, sizeof(iov));
  memset(&msg, 0, sizeof(msg));
  memset(&control, 0, sizeof(control));

  if (send(backend_fd, request, sizeof(*request), 0) != sizeof(*request)) {
    perror("write");
    return (NULL);
  }

  switch (request->r_type) {
  case GETADDRINFO:
    tor_free(wrapper);
    return (NULL);
  case CONNECT_SOCKET:
  case UNLINK_PATH:
    nrecv = recv(backend_fd, &(wrapper->response),
        sizeof(wrapper->response), 0);
    if (nrecv != sizeof(wrapper->response)) {
      tor_free(wrapper);
      return (NULL);
    }
    return (wrapper);
  case CLOSE_FD:
  case SHUTDOWN:
    tor_free(wrapper);
    return (NULL);
  case ADD_FILE_PATH:
  case CREATE_SOCKET:
  case MKDIR:
  case STAT:
  case RENAME:
  default:
    break;
  }

  iov.iov_base = &(wrapper->response);
  iov.iov_len = sizeof(wrapper->response);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  if (recvmsg(backend_fd, &msg, 0) < 0) {
    perror("recvmsg");
    return (NULL);
  }

  cmsg = CMSG_FIRSTHDR(&msg);
  while (cmsg != NULL) {
    if (cmsg->cmsg_level == SOL_SOCKET && \
        cmsg->cmsg_type == SCM_RIGHTS) {
      memmove(&(wrapper->fd), CMSG_DATA(cmsg),
          sizeof(wrapper->fd));
      return (wrapper);
    }
  }

  tor_free(wrapper);
  return (NULL);
}

static struct response_wrapper *
create_socket(int domain, int type, int protocol,
    cap_rights_t *rights)
{
  struct response_wrapper *wrapper;
  struct request request;

  memset(&request, 0, sizeof(request));

  request.r_type = CREATE_SOCKET;
  request.r_payload.u_open_socket.r_domain = domain;
  request.r_payload.u_open_socket.r_type = type;
  request.r_payload.u_open_socket.r_protocol = protocol;
  if (rights != NULL) {
    request.r_payload.u_open_socket.r_features |= F_FEATURE_CAP;
    memcpy(&(request.r_payload.u_open_socket.r_rights), rights,
        sizeof(request.r_payload.u_open_socket.r_rights));
  }

  wrapper = send_request(&request);
  if (wrapper != NULL && wrapper->response.r_code == ERROR_NONE)
    add_uuid(wrapper->fd, &(wrapper->response.r_uuid));
  return (wrapper);
}

static void
close_fd(uuid_t *uuid)
{
  struct request request;

  memset(&request, 0, sizeof(request));
  request.r_type = CLOSE_FD;
  memmove(&(request.r_payload.u_close_fd.r_uuid), uuid,
      sizeof(request.r_payload.u_close_fd.r_uuid));

  send_request(&request);
}

static void
shutdown_backend(void)
{
  struct request request;

  pthread_mutex_lock(&sandbox_mtx);

  memset(&request, 0, sizeof(request));
  request.r_type = SHUTDOWN;
  send_request(&request);

  pdkill(sandboxpid, SIGINT);

  pthread_mutex_unlock(&sandbox_mtx);

  return;
}

static int
sandbox_freebsd_open(const char *path, int flags, mode_t mode,
    cap_rights_t *rights)
{
  const char *relpath;
  struct dirfd *dirfd;
  int fd;

  if (!sandbox_freebsd_is_active())
    return open(path, flags, mode);

  /* The path passed in must be the fully-qualified path */
  if (path[0] != '/') {
    errno = EPERM;
    return -1;
  }

  dirfd = lookup_directory(path);
  if (dirfd == NULL) {
    errno = EPERM;
    return -1;
  }

  /* The following logic assumes that strlen(path) >
   * strlen(dirfd->path) + 1. */
  if (strlen(path) < strlen(dirfd->path) + 1) {
    errno = EPERM;
    return -1;
  }

  relpath = path;
  relpath += strlen(dirfd->path) + 1;

  fd = openat(dirfd->fd, relpath, flags, mode);
  if (fd != -1 && rights != NULL)
    cap_rights_limit(fd, rights);

  return (fd);
}

static int
sandbox_freebsd_unlink(const char *path)
{
  const char *relpath;
  struct dirfd *dirfd;
  int fd;

  if (!sandbox_freebsd_is_active())
    return unlink(path);

  /* The path passed in must be the fully-qualified path */
  if (path[0] != '/') {
    errno = EPERM;
    return -1;
  }

  dirfd = lookup_directory(path);
  if (dirfd == NULL) {
    errno = EPERM;
    return -1;
  }

  /* The following logic assumes that strlen(path) >
   * strlen(dirfd->path) + 1. */
  if (strlen(path) < strlen(dirfd->path) + 1) {
    errno = EPERM;
    return -1;
  }

  relpath = path;
  relpath += strlen(dirfd->path) + 1;

  return unlinkat(dirfd->fd, relpath, 0);
}

static int
sandbox_freebsd_socket(int domain, int type, int protocol,
    cap_rights_t *rights)
{
  struct response_wrapper *wrapper;
  int fd;

  if (!sandbox_freebsd_is_active())
    return (socket(domain, type, protocol));

  pthread_mutex_lock(&sandbox_mtx);

  wrapper = create_socket(domain, type, protocol, rights);
  if (wrapper == NULL) {
    pthread_mutex_unlock(&sandbox_mtx);
    return (-1);
  }

  fd = wrapper->fd;

  if (wrapper->response.r_code != ERROR_NONE) {
    fd = -1;
    errno = wrapper->response.r_errno;
  }

  pthread_mutex_unlock(&sandbox_mtx);
  tor_free(wrapper);
  return (fd);
}

static void
sandbox_freebsd_freeaddrinfo(struct addrinfo *ai)
{
  struct addrinfo *next;

  if (!sandbox_freebsd_is_active()) {
    freeaddrinfo(ai);
    return;
  }

  while (ai != NULL) {
    next = ai->ai_next;
    if (ai->ai_addr != NULL) {
      memset(ai->ai_addr, 0, ai->ai_addrlen);
      tor_free(ai->ai_addr);
    }
    memset(ai, 0, sizeof(*ai));
    tor_free(ai);
    ai = next;
  }
}

static int
sandbox_freebsd_getaddrinfo(const char *name, const char *servname,
    const struct addrinfo *hints,
    struct addrinfo **res)
{
  struct response_addrinfo *responses;
  struct request request;
  struct addrinfo *next, *p;
  size_t i, nresults;
  int retval;

  if (!sandbox_freebsd_is_active())
    return (getaddrinfo(name, servname, hints, res));

  if ((name == NULL && servname == NULL) || res == NULL)
    return (-1);

  *res = NULL;
  responses = NULL;

  pthread_mutex_lock(&sandbox_mtx);

  retval = 0;
  memset(&request, 0, sizeof(request));
  request.r_type = GETADDRINFO;
  if (hints != NULL) {
    memmove(&(request.r_payload.u_getaddrinfo.r_hints),
        hints,
        sizeof(request.r_payload.u_getaddrinfo.r_hints));
    request.r_payload.u_getaddrinfo.r_features |= F_GETADDRINFO_HINTS;
  }

  if (name != NULL) {
    strlcpy(request.r_payload.u_getaddrinfo.r_hostname,
        name,
        sizeof(request.r_payload.u_getaddrinfo.r_hostname));
  }

  if (servname != NULL) {
    strlcpy(request.r_payload.u_getaddrinfo.r_servname,
        servname,
        sizeof(request.r_payload.u_getaddrinfo.r_servname));
  }

  if (send(backend_fd, &request, sizeof(request), 0) != sizeof(request)) {
    retval = -1;
    goto end;
  }

  nresults = 0;
  if (recv(backend_fd, &nresults, sizeof(nresults), 0) != sizeof(nresults)) {
    retval = -1;
    goto end;
  }

  if (nresults == 0) {
    retval = -1;
    goto end;
  }

  responses = tor_calloc(nresults, sizeof(*responses));
  if (responses == NULL) {
    /*
     * We still have data to receive. However, we don't
     * have any available memory. Receive one byte a time
     * until we've read all the data, then return -1.
     *
     * We'll intentionally discard the data.
     */
    for (i = 0; i < sizeof(*responses) * nresults; i++)
      recv(backend_fd, &retval, 1, 0);
    retval = -1;
    goto end;
  }

  if (recv(backend_fd, responses, sizeof(*responses) * nresults, 0)
      != (ssize_t)(sizeof(*responses) * nresults)) {
    retval = -1;
    goto end;
  }

  *res = tor_calloc(1, sizeof(struct addrinfo));
  if (*res == NULL) {
    retval = -1;
    goto end;
  }

  p = *res;
  for (i=0; i < nresults; i++) {
    p->ai_flags = responses[i].ra_flags;
    p->ai_family = responses[i].ra_family;
    p->ai_socktype = responses[i].ra_socktype;
    p->ai_protocol = responses[i].ra_protocol;

    switch (p->ai_family) {
    case AF_INET:
      p->ai_addrlen = sizeof(struct sockaddr_in);
      p->ai_addr = tor_malloc(p->ai_addrlen);
      if (p->ai_addr == NULL) {
        retval = -1;
        goto end;
      }
      memmove(p->ai_addr, &(responses[i].ra_sockaddr.addr4),
        p->ai_addrlen);
      break;
    case AF_INET6:
      p->ai_addrlen = sizeof(struct sockaddr_in6);
      p->ai_addr = tor_malloc(p->ai_addrlen);
      if (p->ai_addr == NULL) {
        retval = -1;
        goto end;
      }
      memmove(p->ai_addr, &(responses[i].ra_sockaddr.addr6),
        p->ai_addrlen);
      break;
    }

    next = tor_calloc(1, sizeof(struct addrinfo));
    if (next == NULL) {
      retval = -1;
      goto end;
    }

    p->ai_next = next;
    p = next;
  }

 end:
  if (retval == -1 && *res != NULL) {
    sandbox_freebsd_freeaddrinfo(*res);
    *res = NULL;
  }
  if (responses != NULL) {
    memset(responses, 0, sizeof(*responses) * nresults);
    tor_free(responses);
  }
  pthread_mutex_unlock(&sandbox_mtx);
  return (retval);
}

static int
sandbox_freebsd_connect(int sockfd, const struct sockaddr *name, socklen_t namelen)
{
  struct response_wrapper *wrapper;
  struct request request;
  struct uuids *uuid;

  if (!sandbox_freebsd_is_active())
    return (connect(sockfd, name, namelen));

  pthread_mutex_lock(&sandbox_mtx);

  uuid = lookup_uuid(sockfd);
  if (uuid == NULL) {
    errno = EBADF;
    pthread_mutex_unlock(&sandbox_mtx);
    return (-1);
  }

  memset(&request, 0, sizeof(request));
  request.r_type = CONNECT_SOCKET;
  request.r_payload.u_connect.r_socklen = namelen;
  switch (namelen) {
  case sizeof(struct sockaddr_in):
    memmove(&(request.r_payload.u_connect.r_sock.addr4),
        name,
        sizeof(request.r_payload.u_connect.r_sock.addr4));
    break;
  case sizeof(struct sockaddr_in6):
    memmove(&(request.r_payload.u_connect.r_sock.addr6),
        name,
        sizeof(request.r_payload.u_connect.r_sock.addr6));
    break;
  default:
    errno = EOVERFLOW;
    pthread_mutex_unlock(&sandbox_mtx);
    return (-1);
  }
  memmove(&(request.r_payload.u_connect.r_uuid),
      &(uuid->uuid),
      sizeof(request.r_payload.u_connect.r_uuid));

  wrapper = send_request(&request);
  if (wrapper == NULL) {
    errno = EBADF;
    pthread_mutex_unlock(&sandbox_mtx);
    return (-1);
  }

  if (wrapper->response.r_code != ERROR_NONE) {
    errno = wrapper->response.r_errno;
    tor_free(wrapper);
    pthread_mutex_unlock(&sandbox_mtx);
    return (-1);
  }

  pthread_mutex_unlock(&sandbox_mtx);
  tor_free(wrapper);
  return (0);
}

static int
sandbox_freebsd_mkdir(const char *path, mode_t mode)
{
  struct request request;
  struct response response;

  if (!sandbox_freebsd_is_active())
    return (mkdir(path, mode));

  pthread_mutex_lock(&sandbox_mtx);

  memset(&request, 0, sizeof(request));
  memset(&response, 0, sizeof(response));

  request.r_type = MKDIR;
  request.r_payload.u_mkdir.r_mode = mode;
  strlcpy(request.r_payload.u_mkdir.r_path, path,
      sizeof(request.r_payload.u_mkdir.r_path));

  send(backend_fd, &request, sizeof(request), 0);
  recv(backend_fd, &response, sizeof(response), 0);

  if (response.r_code != ERROR_NONE)
    errno = response.r_errno;

  pthread_mutex_unlock(&sandbox_mtx);

  return (response.r_code == ERROR_NONE ? 0 : -1);
}

static int
sandbox_freebsd_stat(const char *path, struct stat *sb)
{
  struct response_stat response;
  struct request request;

  if (!sandbox_freebsd_is_active())
    return (stat(path, sb));

  memset(&request, 0, sizeof(request));
  memset(&response, 0, sizeof(response));

  pthread_mutex_lock(&sandbox_mtx);

  request.r_type = STAT;
  strlcpy(request.r_payload.u_stat.r_path,
      path,
      sizeof(request.r_payload.u_stat.r_path));

  if (send(backend_fd, &request, sizeof(request), 0) != sizeof(request)) {
    perror("send");
    pthread_mutex_unlock(&sandbox_mtx);
    return (-1);
  }

  if (recv(backend_fd, &response, sizeof(response), 0) != sizeof(response)) {
    perror("recv");
    pthread_mutex_unlock(&sandbox_mtx);
    return (-1);
  }

  pthread_mutex_unlock(&sandbox_mtx);

  if (response.rs_code != ERROR_NONE) {
    errno = response.rs_errno;
    return (-1);
  }

  memmove(sb, &(response.rs_sb), sizeof(*sb));
  return (0);
}

static int
sandbox_freebsd_rename(const char *from, const char *to)
{
  struct dirfd *fromfd, *tofd;
  const char *relfrom, *relto;

  if (!sandbox_freebsd_is_active())
    return (rename(from, to));

  /* The path passed in must be the fully-qualified path */
  if (from[0] != '/' || to[0] != '/') {
    errno = EPERM;
    return -1;
  }

  fromfd = lookup_directory(from);
  if (fromfd == NULL) {
    errno = EPERM;
    return -1;
  }

  /* The following logic assumes that strlen(path) >
   * strlen(dirfd->path) + 1. */
  if (strlen(from) < strlen(fromfd->path) + 1) {
    errno = EPERM;
    return -1;
  }

  relfrom = from;
  relfrom += strlen(fromfd->path) + 1;

  tofd = lookup_directory(to);
  if (tofd == NULL) {
    errno = EPERM;
    return -1;
  }

  /* The following logic assumes that strlen(path) >
   * strlen(dirfd->path) + 1. */
  if (strlen(to) < strlen(tofd->path) + 1) {
    errno = EPERM;
    return -1;
  }

  relto = to;
  relto += strlen(tofd->path) + 1;

  return renameat(fromfd->fd, relfrom, tofd->fd, relto);
}

static int
sandbox_freebsd_close(int fd)
{
  struct uuids *u;
  int res;

  if (!sandbox_freebsd_is_active())
    return (close(fd));

  pthread_mutex_lock(&sandbox_mtx);

  res = 0;

  u = lookup_uuid(fd);
  if (u != NULL) {
    u->active = 0;
    close_fd(&(u->uuid));
    memset(&(u->uuid), 0, sizeof(u->uuid));
  }

  res = close(fd);

  pthread_mutex_unlock(&sandbox_mtx);

  return (res);
}

static int
sandbox_freebsd_init(sandbox_cfg_t *cfg)
{
  time_t clock;
  (void)cfg;

#if SANDBOX_ENABLED
  /* Cache timezone data */
  clock = time(NULL);
  if (gmtime(&clock) == NULL) {
    return -1;
  }

  pthread_mutex_init(&sandbox_mtx, NULL);
  fork_backend();

  if (cap_enter() == ENOSYS)
    return -1;
#endif

  return 0;
}

static int
sandbox_freebsd_cfg_allow_open_filename(sandbox_cfg_t **cfg, char *file)
{
  char **p;
  int fd;
  struct stat sb;

  (void)cfg;

  if (sandbox_freebsd_is_active())
	  return -1;

  if (file == NULL || file[0] != '/')
	  return 0;

  fd = open(file, O_RDONLY);
  if (fd != -1) {
    if (fstat(fd, &sb)) {
      close(fd);
      return -1;
    }

    if (!S_ISDIR(sb.st_mode)) {
      close(fd);
      return 0;
    }

    add_directory_descriptor(fd, file);
  }

  return 0;
}

static int
sandbox_freebsd_cfg_allow_openat_filename(sandbox_cfg_t **cfg, char *file)
{

  return sandbox_freebsd_cfg_allow_open_filename(cfg, file);
}

static int
sandbox_freebsd_cfg_allow_stat_filename(sandbox_cfg_t **cfg, char *file)
{

  return sandbox_freebsd_cfg_allow_open_filename(cfg, file);
}

static int
sandbox_freebsd_cfg_allow_chown_filename(sandbox_cfg_t **cfg, char *file)
{

  return sandbox_freebsd_cfg_allow_open_filename(cfg, file);
}

static int
sandbox_freebsd_cfg_allow_chmod_filename(sandbox_cfg_t **cfg, char *file)
{

  return sandbox_freebsd_cfg_allow_open_filename(cfg, file);
}

static int
sandbox_freebsd_cfg_allow_rename(sandbox_cfg_t **cfg, char *file1, char *file2)
{
  int res;

  res = sandbox_freebsd_cfg_allow_open_filename(cfg, file1);
  if (res == 0)
    res = sandbox_freebsd_cfg_allow_open_filename(cfg, file2);

  return res;
}

static const char *
sandbox_freebsd_intern_string(const char *str)
{
  return str;
}

static void
sandbox_freebsd_cleanup(void)
{
  if (sandbox_freebsd_is_active()) {
    shutdown_backend();
    pthread_mutex_destroy(&sandbox_mtx);
  }
}

static sandbox_cfg_t *
sandbox_freebsd_cfg_new(void)
{
  return NULL;
}

static sandbox_impl_t sandbox_freebsd_impl = {
  .sandbox_init = sandbox_freebsd_init,
  .sandbox_fini = sandbox_freebsd_cleanup,
  .sandbox_cfg_new = sandbox_freebsd_cfg_new,
  .sandbox_is_active = sandbox_freebsd_is_active,
  .sandbox_open = sandbox_freebsd_open,
  .sandbox_mkdir = sandbox_freebsd_mkdir,
  .sandbox_unlink = sandbox_freebsd_unlink,
  .sandbox_socket = sandbox_freebsd_socket,
  .sandbox_getaddrinfo = sandbox_freebsd_getaddrinfo,
  .sandbox_freeaddrinfo = sandbox_freebsd_freeaddrinfo,
  .sandbox_connect = sandbox_freebsd_connect,
  .sandbox_stat = sandbox_freebsd_stat,
  .sandbox_rename = sandbox_freebsd_rename,
  .sandbox_close = sandbox_freebsd_close,
  .sandbox_cfg_allow_open_filename = sandbox_freebsd_cfg_allow_open_filename,
  .sandbox_cfg_allow_openat_filename = sandbox_freebsd_cfg_allow_openat_filename,
  .sandbox_cfg_allow_stat_filename = sandbox_freebsd_cfg_allow_stat_filename,
  .sandbox_cfg_allow_chown_filename = sandbox_freebsd_cfg_allow_chown_filename,
  .sandbox_cfg_allow_chmod_filename = sandbox_freebsd_cfg_allow_chmod_filename,
  .sandbox_cfg_allow_rename = sandbox_freebsd_cfg_allow_rename,
  .sandbox_intern_string = sandbox_freebsd_intern_string,
};

sandbox_impl_t *
sandbox_freebsd_get_impl(void)
{
  return &sandbox_freebsd_impl;
}

#endif /* HAVE_SYS_CAPSICUM_H */

