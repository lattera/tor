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

static pthread_mutex_t sandbox_mtx;
static int active;
static char **whitelist;
int backend_fd;

static size_t nuuids, nwhitelist;

static ssize_t
whitelist_index(const char *file)
{
  size_t i;

  if (file == NULL)
    return -1;

  for (i = 0; i < nwhitelist; i++)
    if (whitelist[i] != NULL && strcmp(whitelist[i], file) == 0)
      return i;

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
open_file(const char *path, int flags, mode_t mode, cap_rights_t *rights)
{
  struct response_wrapper *wrapper;
  struct request request;

  memset(&request, 0, sizeof(request));

  strlcpy(request.r_payload.u_add_file_path.r_path, path,
      sizeof(request.r_payload.u_add_file_path.r_path));
  request.r_payload.u_add_file_path.r_flags = flags;
  request.r_payload.u_add_file_path.r_mode = mode;
  if (rights != NULL) {
    request.r_payload.u_add_file_path.r_features |= F_FEATURE_CAP;
    memcpy(&(request.r_payload.u_add_file_path.r_rights), rights,
        sizeof(request.r_payload.u_add_file_path.r_rights));
  }

  wrapper = send_request(&request);
  if (wrapper != NULL && wrapper->response.r_code == ERROR_NONE)
    add_uuid(wrapper->fd, &(wrapper->response.r_uuid));
  return (wrapper);
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

int
sandbox_open(const char *path, int flags, mode_t mode,
    cap_rights_t *rights)
{
  struct response_wrapper *wrapper;
  int fd;

  if (!active)
    return (open(path, flags, mode));

  if (whitelist_index(path) == -1) {
    errno = EPERM;
    return -1;
  }

  pthread_mutex_lock(&sandbox_mtx);

  fd = -1;
  wrapper = open_file(path, flags, mode, rights);
  if (wrapper == NULL)
    goto end;
  fd = wrapper->fd;

  if (wrapper->response.r_code != ERROR_NONE) {
    fd = -1;
    errno = wrapper->response.r_errno;
  }

 end:
  pthread_mutex_unlock(&sandbox_mtx);

  return (fd);
}

int
sandbox_unlink(const char *path)
{
  struct response_wrapper *wrapper;
  struct request request;
  int res;

  if (!active)
    return (unlink(path));

  if (whitelist_index(path) == -1) {
    errno = EPERM;
    return -1;
  }

  pthread_mutex_lock(&sandbox_mtx);

  memset(&request, 0, sizeof(request));

  request.r_type = UNLINK_PATH;
  strlcpy(request.r_payload.u_unlink_path.r_path, path,
      sizeof(request.r_payload.u_unlink_path.r_path));

  wrapper = send_request(&request);
  if (wrapper == NULL) {
    pthread_mutex_unlock(&sandbox_mtx);
    return (0);
  }

  res = wrapper->response.r_code;
  if (res == ERROR_FAIL)
    errno = wrapper->response.r_errno;

  pthread_mutex_unlock(&sandbox_mtx);
  tor_free(wrapper);
  return (res == ERROR_FAIL ? -1 : 0);
}

int
sandbox_socket(int domain, int type, int protocol,
    cap_rights_t *rights)
{
  struct response_wrapper *wrapper;
  int fd;

  if (!active)
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

int
sandbox_getaddrinfo(const char *name, const char *servname,
    const struct addrinfo *hints,
    struct addrinfo **res)
{
  struct response_addrinfo *responses;
  struct request request;
  struct addrinfo *next, *p;
  size_t i, nresults;
  int retval;

  if (!active)
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
    sandbox_freeaddrinfo(*res);
    *res = NULL;
  }
  if (responses != NULL) {
    memset(responses, 0, sizeof(*responses) * nresults);
    tor_free(responses);
  }
  pthread_mutex_unlock(&sandbox_mtx);
  return (retval);
}

void
sandbox_freeaddrinfo(struct addrinfo *ai)
{
  struct addrinfo *next;

  if (!active) {
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

int
sandbox_connect(int sockfd, const struct sockaddr *name, socklen_t namelen)
{
  struct response_wrapper *wrapper;
  struct request request;
  struct uuids *uuid;

  if (!active)
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

int
sandbox_mkdir(const char *path, mode_t mode)
{
  struct request request;
  struct response response;

  if (!active)
    return (mkdir(path, mode));

  if (whitelist_index(path) == -1) {
    errno = EPERM;
    return -1;
  }

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

int
sandbox_stat(const char *path, struct stat *sb)
{
  struct response_stat response;
  struct request request;

  if (!active)
    return (stat(path, sb));

  if (whitelist_index(path) == -1) {
    errno = EPERM;
    return -1;
  }

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

int
sandbox_rename(const char *from, const char *to)
{
  struct generic_response response;
  struct request request;

  if (!active)
    return (rename(from, to));

  if (whitelist_index(from) == -1) {
    errno = EPERM;
    return -1;
  }

  if (whitelist_index(to) == -1) {
    errno =  EPERM;
    return -1;
  }

  memset(&request, 0, sizeof(request));
  memset(&response, 0, sizeof(response));

  pthread_mutex_lock(&sandbox_mtx);

  request.r_type = RENAME;
  strlcpy(request.r_payload.u_rename.r_from_path,
      from,
      sizeof(request.r_payload.u_rename.r_from_path));
  strlcpy(request.r_payload.u_rename.r_to_path,
      to,
      sizeof(request.r_payload.u_rename.r_to_path));

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

  if (response.r_code != ERROR_NONE) {
    errno = response.r_errno;
    return (-1);
  }

  return (0);
}

int
sandbox_close(int fd)
{
  struct uuids *u;
  int res;

  if (!active)
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

sandbox_cfg_t*
sandbox_cfg_new(void)
{
  return NULL;
}

int
sandbox_init(sandbox_cfg_t *cfg)
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

  active = 1;
#endif

  return 0;
}

int
sandbox_cfg_allow_open_filename(sandbox_cfg_t **cfg, char *file)
{
  char **p;

  (void)cfg;

  /* Whitelist is read-only when sandbox is active */
  if (active)
	  return -1;

  if (file == NULL || file[0] != '/')
	  return 0;

  if (whitelist_index(file) != -1)
    return 0;

  p = tor_reallocarray(whitelist, sizeof(char **), nwhitelist + 1);
  if (p == NULL)
    return (-1);

  whitelist = p;
  whitelist[nwhitelist++] = tor_strdup(file);

  return 0;
}

int
sandbox_cfg_allow_openat_filename(sandbox_cfg_t **cfg, char *file)
{

  return sandbox_cfg_allow_open_filename(cfg, file);
}

int
sandbox_cfg_allow_stat_filename(sandbox_cfg_t **cfg, char *file)
{

  return sandbox_cfg_allow_open_filename(cfg, file);
}

int
sandbox_cfg_allow_chown_filename(sandbox_cfg_t **cfg, char *file)
{

  return sandbox_cfg_allow_open_filename(cfg, file);
}

int
sandbox_cfg_allow_chmod_filename(sandbox_cfg_t **cfg, char *file)
{

  return sandbox_cfg_allow_open_filename(cfg, file);
}

int
sandbox_cfg_allow_rename(sandbox_cfg_t **cfg, char *file1, char *file2)
{
  int res;

  res = sandbox_cfg_allow_open_filename(cfg, file1);
  if (res == 0)
    res = sandbox_cfg_allow_open_filename(cfg, file2);

  return res;
}

int
sandbox_is_active(void)
{
  return active;
}

void
sandbox_disable_getaddrinfo_cache(void)
{
}

void
sandbox_cleanup(void)
{
  if (active) {
    shutdown_backend();
    pthread_mutex_destroy(&sandbox_mtx);
  }
}
#endif /* HAVE_SYS_CAPSICUM_H */

