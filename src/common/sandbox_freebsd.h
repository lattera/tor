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

/* BEGIN UNUSED SANDBOX API */
struct sandbox_cfg_elem {
	unsigned int unused;
};

/** Typedef to structure used to manage a sandbox configuration. */
typedef struct sandbox_cfg_elem sandbox_cfg_t;

/** Creates an empty sandbox configuration file.*/
sandbox_cfg_t * sandbox_cfg_new(void);

/**
 * Function used to add a open allowed filename to a supplied configuration.
 * The (char*) specifies the path to the allowed file; we take ownership
 * of the pointer.
 */
int sandbox_cfg_allow_open_filename(sandbox_cfg_t **cfg, char *file);
int sandbox_cfg_allow_chmod_filename(sandbox_cfg_t **cfg, char *file);
int sandbox_cfg_allow_chown_filename(sandbox_cfg_t **cfg, char *file);

/* DOCDOC */
int sandbox_cfg_allow_rename(sandbox_cfg_t **cfg, char *file1, char *file2);

/**
 * Function used to add a openat allowed filename to a supplied configuration.
 * The (char*) specifies the path to the allowed file; we steal the pointer to
 * that file.
 */
int sandbox_cfg_allow_openat_filename(sandbox_cfg_t **cfg, char *file);

/**
 * Function used to add a stat/stat64 allowed filename to a configuration.
 * The (char*) specifies the path to the allowed file; that pointer is stolen.
 */
int sandbox_cfg_allow_stat_filename(sandbox_cfg_t **cfg, char *file);

/** Function used to initialise a sandbox configuration.*/
int sandbox_init(sandbox_cfg_t* cfg);

/** Return true iff the sandbox is turned on. */
int sandbox_is_active(void);

void sandbox_disable_getaddrinfo_cache(void);

sandbox_cfg_t *sandbox_init_filter(void);

/* XXX TODO */
#define sandbox_intern_string(s) (s)
#define sandbox_add_addrinfo(name) \
  ((void)(name))
#define sandbox_freeaddrinfo(res)
#define sandbox_free_getaddrinfo_cache()

/* END UNUSED SANDBOX API */

/* BEGIN FREEBSD SANDBOX API */


#include <uuid.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#define	F_NONE		 0
#define	F_SHUTDOWN	 1

#define	F_FEATURE_NONE	 0
#define	F_FEATURE_CAP	 1

#define	F_GETADDRINFO_NONE	 0
#define	F_GETADDRINFO_HINTS	 1

#define	STATUSSZ	 33
#define	CONTROLSZ	 (sizeof(struct cmsghdr) + sizeof(int) + 16)

typedef enum _request_type {
	ADD_FILE_PATH	= 0,
	SHUTDOWN	= 1,
	CLOSE_FD	= 2,
	CREATE_SOCKET	= 3,
	UNLINK_PATH	= 4,
	GETADDRINFO	= 5,
	CONNECT_SOCKET	= 6,
	MKDIR		= 7,
	STAT		= 8,
	RENAME		= 9,
	GMTIME		= 10,
} request_type;

typedef enum _response_code {
	ERROR_NONE	= 0,
	ERROR_FAIL	= 1,
} response_code;

struct request_add_file_path {
	char		 r_path[1024];
	int		 r_flags;
	mode_t		 r_mode;
	uint64_t	 r_features;
	cap_rights_t	 r_rights;
};

struct request_close_fd {
	uuid_t	 r_uuid;
};

struct request_mkdir {
	char	 r_path[1024];
	mode_t	 r_mode;
};

struct request_open_socket {
	int		 r_domain;
	int		 r_type;
	int		 r_protocol;
	uint64_t	 r_features;
	cap_rights_t	 r_rights;
};

struct request_connect_socket {
	uuid_t		 r_uuid;
	socklen_t	 r_socklen;
	union {
		struct sockaddr_in	 addr4;
		struct sockaddr_in6	 addr6;
	}		 r_sock;
};

struct request_unlink {
	char	 r_path[1024];
};

struct request_getaddrinfo {
	char		 r_hostname[256];
	char		 r_servname[256];
	struct addrinfo	 r_hints;
	uint64_t	 r_features;
};

struct request_stat {
	char	 r_path[1024];
};

struct request_rename {
	char	 r_from_path[512];
	char	 r_to_path[512];
};

struct request_gmtime {
	time_t	 r_clock;
};

struct request {
	request_type	 r_type;
	union {
		struct request_add_file_path	 u_add_file_path;
		struct request_open_socket	 u_open_socket;
		struct request_close_fd		 u_close_fd;
		struct request_unlink		 u_unlink_path;
		struct request_getaddrinfo	 u_getaddrinfo;
		struct request_connect_socket	 u_connect;
		struct request_mkdir		 u_mkdir;
		struct request_stat		 u_stat;
		struct request_rename		 u_rename;
		struct request_gmtime		 u_gmtime;
	}		 r_payload;
};

struct response_addrinfo {
	int	 ra_flags;
	int	 ra_family;
	int	 ra_socktype;
	int	 ra_protocol;
	union {
		struct sockaddr_in	 addr4;
		struct sockaddr_in6	 addr6;
	}	 ra_sockaddr;
};

struct response_stat {
	response_code	 rs_code;
	int		 rs_errno;
	struct stat	 rs_sb;
};

struct generic_response {
	response_code	 r_code;
	int		 r_errno;
};

struct response {
	response_code	 r_code;
	int		 r_errno;
	uuid_t		 r_uuid;
};

extern int backend_fd;
extern int sandboxpid;

int sandbox_open(const char *, int, mode_t, cap_rights_t *);
int sandbox_mkdir(const char *, mode_t);
int sandbox_unlink(const char *);
int sandbox_socket(int, int, int, cap_rights_t *);
int sandbox_getaddrinfo(const char *, const char *,
    const struct addrinfo *, struct addrinfo **);
int sandbox_connect(int, struct sockaddr *, socklen_t);
int sandbox_stat(const char *, struct stat *);
int sandbox_rename(const char *, const char *);
struct tm *sandbox_gmtime(const time_t *);
struct tm *sandbox_gmtime_r(const time_t *, struct tm *);
int sandbox_close(int);

void fork_backend(void);
void sandbox_cleanup(void);

/* END FREEBSD SANDBOX API */

#endif /* SANDBOX_FREEBSD_H_ */

