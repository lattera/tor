/*-
 * Copyright (c) 2017 Shawn Webb <shawn.webb@hardenedbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "orconfig.h"
#include "util.h"

#if HAVE_SYS_CAPSICUM_H

#include "sandbox.h"

typedef enum _callback_result {
	CB_TERMINATE	= 0,
	CB_CONTINUE	= 1,
} callback_result;

typedef callback_result (*callback)(int, struct request *);

static callback_result do_add_file_path(int, struct request *);
static callback_result do_getaddrinfo(int, struct request *);
static callback_result do_unlink_path(int, struct request *);
static callback_result do_socket_create(int, struct request *);
static callback_result do_connect(int, struct request *);
static callback_result do_shutdown(int, struct request *);
static callback_result do_close(int, struct request *);
static callback_result do_mkdir(int, struct request *);
static callback_result do_stat(int, struct request *);
static callback_result do_rename(int, struct request *);

/*
 * Order of callbacks is semi-important. The way the callback system
 * is currently designed allows a developer to write callbacks
 * specifically for auditing. An audit callback would return
 * CB_CONTINUE rather than CB_TERMINATE and must be placed before any
 * callback for that type that returns CB_TERMINATE.
 */
static struct callback {
	request_type	c_type;
	callback	c_callback;
} callbacks[] = {
	{
		ADD_FILE_PATH,
		do_add_file_path
	},
	{
		GETADDRINFO,
		do_getaddrinfo
	},
	{
		UNLINK_PATH,
		do_unlink_path
	},
	{
		CREATE_SOCKET,
		do_socket_create
	},
	{
		CONNECT_SOCKET,
		do_connect
	},
	{
		SHUTDOWN,
		do_shutdown
	},
	{
		CLOSE_FD,
		do_close
	},
	{
		MKDIR,
		do_mkdir
	},
	{
		STAT,
		do_stat
	},
	{
		RENAME,
		do_rename
	}
};

static struct responses {
	int active;
	int fd;
	struct response *response;
} *responses;

static size_t nresponses;
static int badf;
int sandboxpid;

static struct responses *
lookup_response(uuid_t *uuid)
{
	size_t i;

	for (i = 0; i < nresponses; i++) {
		if (responses[i].active == 0)
			continue;

		if (uuid_equal(uuid, &(responses[i].response->r_uuid), NULL))
			return (&responses[i]);
	}

	return (NULL);
}

static struct responses *
add_response(int fd, struct response *response)
{
	struct responses *r;
	size_t i;
	void *p;

	r = lookup_response(&(response->r_uuid));
	if (r != NULL)
		return (r);

	for (i = 0; i < nresponses; i++) {
		if (responses[i].active == 0) {
			responses[i].active = 1;
			responses[i].response = response;
			responses[i].fd = fd;
			return (&(responses[i]));
		}
	}

	p = tor_reallocarray(responses, sizeof(struct responses), (nresponses + 1));
	if (p == NULL)
		return (NULL);

	responses = p;
	responses[nresponses].active = 1;
	responses[nresponses].fd = fd;
	responses[nresponses].response = response;
	nresponses++;

	return (&(responses[nresponses-1]));
}

static uuid_t *
new_uuid(void)
{
	uuid_t *uuid;
	uint32_t status;

	uuid = tor_calloc(1, sizeof(*uuid));
	if (uuid == NULL)
		return (NULL);

	do {
		status = 0;
		uuid_create(uuid, &status);
		if (status != uuid_s_ok) {
			tor_free(uuid);
			return (NULL);
		}
	} while (lookup_response(uuid));

	return (uuid);
}

static void
close_resource(uuid_t *uuid)
{
	struct responses *r;
	char *str;

	r = lookup_response(uuid);
	if (r != NULL) {
		str = NULL;
		uuid_to_string(uuid, &str, NULL);
		if (r->fd != badf)
			close(r->fd);
		memset(r->response, 0, sizeof(*(r->response)));
		tor_free(r->response);
		memset(r, 0, sizeof(*r));
	}
}

void
fork_backend(void)
{
	int breakout, fd, fdpair[2];
	struct request request;
	cap_rights_t rights;
	pid_t pid;
	size_t i;

	if (socketpair(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fdpair)) {
		perror("socketpair");
		exit(1);
	}

	pid = pdfork(&sandboxpid, PD_CLOEXEC);
	switch (pid) {
	case -1:
		perror("pdfork");
		exit(1);
	case 0:
		/*
		 * Not ignoring in the child the signals Tor cares
		 * about can cause conflicts between the non-capmode
		 * child and its capmode parent.
		 */
		signal(SIGINT, SIG_IGN);
		signal(SIGTERM, SIG_IGN);

		/*
		 * sendmsg(2) won't allow us to send -1 as a file
		 * descriptor (in case of error). Instead, open
		 * /dev/null and use that as our -1 descriptor. Ensure
		 * it has no capabilities.
		 */
		badf = open("/dev/null", O_RDONLY);
		cap_rights_init(&rights);
		cap_rights_limit(badf, &rights);

		close(fdpair[0]);
		fd = fdpair[1];
		break;
	default:
		/*
		 * Make sure that the IPC file descriptor is limited
		 * to the very basics.
		 */
		cap_rights_init(&rights, CAP_READ, CAP_WRITE);
		backend_fd = fdpair[0];
		cap_rights_limit(backend_fd, &rights);
		close(fdpair[1]);
		return;
	}

	while (1) {
		memset(&request, 0, sizeof(request));
		if (recv(fd, &request, sizeof(request), 0) != sizeof(request))
			break;

		breakout = 0;
		for (i = 0; i < sizeof(callbacks) / sizeof(struct callback); i++) {
			if (callbacks[i].c_type == request.r_type) {
				switch (callbacks[i].c_callback(fd, &request)) {
				case CB_TERMINATE:
					breakout = 1;
					break;
				case CB_CONTINUE:
				default:
					break;
				}
			}

			if (breakout)
				break;
		}
	}

	close(fd);
	_exit(0);
}

static void
send_file_descriptor(int fd, struct responses *res)
{
	char control[CONTROLSZ];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;

	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));

	iov.iov_base = res->response;
	iov.iov_len = sizeof(*(res->response));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(res->fd));
	memmove(CMSG_DATA(cmsg), &(res->fd), sizeof(res->fd));
	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(fd, &msg, 0) < 0) {
		perror("sendmsg");
		_exit(0);
	}
}

static callback_result
do_add_file_path(int commfd, struct request *request)
{
	struct response *response;
	struct responses *res;
	uuid_t *uuid;
	int fd, flags;
	mode_t mode;

	response = tor_calloc(1, sizeof(*response));
	if (response == NULL)
		return (CB_TERMINATE);

	flags = request->r_payload.u_add_file_path.r_flags;
	mode = request->r_payload.u_add_file_path.r_mode;

	if ((flags & O_CREAT) == O_CREAT) {
		fd = open(request->r_payload.u_add_file_path.r_path,
		    flags, mode);
	} else {
		fd = open(request->r_payload.u_add_file_path.r_path,
		    flags);
	}

	if (fd != -1 &&
	    (request->r_payload.u_add_file_path.r_features & F_FEATURE_CAP)) {
		cap_rights_limit(fd,
		    &(request->r_payload.u_add_file_path.r_rights));
	}

	if (fd == -1) {
		fd = badf;
		response->r_code = ERROR_FAIL;
		response->r_errno = errno;
	}

	uuid = new_uuid();
	if (uuid == NULL) {
		close(fd);
		memset(response, 0, sizeof(*response));
		tor_free(response);
		return (CB_TERMINATE);
	}
	memmove(&(response->r_uuid), uuid, sizeof(response->r_uuid));
	tor_free(uuid);

	res = add_response(fd, response);
	if (res == NULL) {
		close(fd);
		memset(response, 0, sizeof(*response));
		tor_free(response);
		return (CB_TERMINATE);
	}

	send_file_descriptor(commfd, res);

	return (CB_TERMINATE);
}

static callback_result
do_unlink_path(int fd, struct request *request)
{
	struct response response;
	int res;

	memset(&response, 0, sizeof(response));

	res = unlink(request->r_payload.u_unlink_path.r_path);
	if (res) {
		response.r_code = ERROR_FAIL;
		response.r_errno = errno;
	}

	send(fd, &response, sizeof(response), 0);

	return (CB_TERMINATE);
}

static callback_result
do_getaddrinfo(int fd, struct request *request)
{
	struct addrinfo *hints, *iter, *res;
	struct response_addrinfo *addrinfo_responses;
	char *host, *servname;
	size_t i, nresults;
	int err;

	nresults = 0;
	host = servname = NULL;
	hints = NULL;
	res = NULL;

	if (strlen(request->r_payload.u_getaddrinfo.r_hostname))
		host = request->r_payload.u_getaddrinfo.r_hostname;
	if (strlen(request->r_payload.u_getaddrinfo.r_servname))
		servname = request->r_payload.u_getaddrinfo.r_servname;
	if ((request->r_payload.u_getaddrinfo.r_features & F_GETADDRINFO_HINTS))
		hints = &(request->r_payload.u_getaddrinfo.r_hints);

	if (host == NULL && servname == NULL) {
		send(fd, &nresults, sizeof(nresults), 0);
		goto err;
	}

	err = getaddrinfo(host, servname, hints, &res);
	if (err) {
		send(fd, &nresults, sizeof(nresults), 0);
		goto err;
	}

	iter = res;
	nresults = 0;
	while (iter != NULL) {
		iter = iter->ai_next;
		nresults++;
	}

	addrinfo_responses = tor_calloc(nresults, sizeof(*responses));
	if (addrinfo_responses == NULL) {
		nresults = 0;
		send(fd, &nresults, sizeof(nresults), 0);
		goto err;
	}

	if (send(fd, &nresults, sizeof(nresults), 0) != sizeof(nresults)) {
		freeaddrinfo(res);
		nresults = 0;
		send(fd, &nresults, sizeof(nresults), 0);
		goto err;
	}

	for (i=0, iter = res; iter != NULL; iter = iter->ai_next, i++) {
		addrinfo_responses[i].ra_flags = iter->ai_flags;
		addrinfo_responses[i].ra_family = iter->ai_family;
		addrinfo_responses[i].ra_socktype = iter->ai_socktype;
		addrinfo_responses[i].ra_protocol = iter->ai_protocol;

		switch (iter->ai_family) {
		case AF_INET:
			memmove(&(addrinfo_responses[i].ra_sockaddr.addr4),
			    iter->ai_addr,
			    sizeof(addrinfo_responses[i].ra_sockaddr.addr4));
			break;
		case AF_INET6:
			memmove(&(addrinfo_responses[i].ra_sockaddr.addr6),
			    iter->ai_addr,
			    sizeof(addrinfo_responses[i].ra_sockaddr.addr6));
			break;
		}
	}

	send(fd, addrinfo_responses, sizeof(*addrinfo_responses) * nresults, 0);

err:
	if (res != NULL)
		freeaddrinfo(res);

	return (CB_TERMINATE);
}

static callback_result
do_socket_create(int commfd, struct request *request)
{
	struct response *response;
	struct responses *res;
	uuid_t *uuid;
	int fd;

	response = tor_calloc(1, sizeof(*response));
	if (response == NULL)
		return (CB_TERMINATE);

	fd = socket(request->r_payload.u_open_socket.r_domain,
	    request->r_payload.u_open_socket.r_type,
	    request->r_payload.u_open_socket.r_protocol);

	if (fd != -1 &&
	    (request->r_payload.u_open_socket.r_features & F_FEATURE_CAP)) {
		cap_rights_limit(fd,
		    &(request->r_payload.u_open_socket.r_rights));
	}

	if (fd == -1) {
		fd = badf;
		response->r_code = ERROR_FAIL;
		response->r_errno = errno;
	}

	uuid = new_uuid();
	if (uuid == NULL) {
		close(fd);
		memset(response, 0, sizeof(*response));
		tor_free(response);
		return (CB_TERMINATE);
	}
	memmove(&(response->r_uuid), uuid, sizeof(response->r_uuid));
	tor_free(uuid);

	res = add_response(fd, response);
	if (res == NULL) {
		close(fd);
		memset(response, 0, sizeof(*response));
		tor_free(response);
		return (CB_TERMINATE);
	}

	send_file_descriptor(commfd, res);

	return (CB_TERMINATE);
}

static callback_result
do_connect(int fd, struct request *request)
{
	struct response res;
	struct responses *r;
	int conres;
	char *str;
	void *p;

	conres = -1;

	memset(&res, 0, sizeof(res));

	r = lookup_response(&(request->r_payload.u_connect.r_uuid));
	if (r == NULL) {
		str = NULL;
		uuid_to_string(&(request->r_payload.u_connect.r_uuid),
		    &str, NULL);
		printf("Child: Could not find UUID %s\n", str);
		goto err;
	}

	/*
	 * Technically, p should end up pointing to the same address.
	 * Splitting this out into a switch allows us to do sanity
	 * checking, though.
	 */
	switch (request->r_payload.u_connect.r_socklen) {
	case sizeof(struct sockaddr_in):
		p = &(request->r_payload.u_connect.r_sock.addr4);
		break;
	case sizeof(struct sockaddr_in6):
		p = &(request->r_payload.u_connect.r_sock.addr6);
		break;
	default:
		/* Only IPv4 and IPv6 is supported right now. */
		res.r_errno = EBADF;
		break;
	}

	if (res.r_errno == 0)
		conres = connect(r->fd, (const struct sockaddr *)p,
		    request->r_payload.u_connect.r_socklen);

err:
	if (conres == -1) {
		res.r_code = ERROR_FAIL;
		res.r_errno = errno;
	}

	send(fd, &res, sizeof(res), 0);

	return (CB_TERMINATE);
}

static callback_result
do_close(int fd, struct request *request)
{
	close_resource(&(request->r_payload.u_close_fd.r_uuid));
	return (CB_TERMINATE);
}

static callback_result
do_mkdir(int fd, struct request *request)
{
	struct response response;
	int res;

	memset(&response, 0, sizeof(response));
	res = mkdir(request->r_payload.u_mkdir.r_path,
	    request->r_payload.u_mkdir.r_mode);
	if (res) {
		response.r_code = ERROR_FAIL;
		response.r_errno = errno;
	}

	send(fd, &response, sizeof(response), 0);

	return (CB_TERMINATE);
}

static callback_result
do_stat(int fd, struct request *request)
{
	struct response_stat response;

	memset(&response, 0, sizeof(response));

	if (stat(request->r_payload.u_stat.r_path, &(response.rs_sb))) {
		response.rs_code = ERROR_FAIL;
		response.rs_errno = errno;
	}

	send(fd, &response, sizeof(response), 0);

	return (CB_TERMINATE);
}

static callback_result
do_rename(int fd, struct request *request)
{
	struct generic_response response;
	int res;

	memset(&response, 0, sizeof(response));

	res = rename(request->r_payload.u_rename.r_from_path,
	    request->r_payload.u_rename.r_to_path);

	if (res) {
		response.r_code = ERROR_FAIL;
		response.r_errno = errno;
	}

	send(fd, &response, sizeof(response), 0);

	return (CB_TERMINATE);
}

static callback_result
do_shutdown(int fd, struct request *request)
{
	close(fd);
	_exit(0);
}
#endif /* HAVE_SYS_CAPSICUM_H */
