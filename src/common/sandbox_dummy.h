/* Copyright (c) 2017 Shawn Webb <shawn.webb@hardenedbsd.org> */
/* See LICENSE for licensing information */

/**
 * \file sandbox_dummy.h
 * \brief Header file for sandbox_common_dummy.c.
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

struct sandbox_impl *sandbox_dummy_get_impl(void);


#endif /* SANDBOX_DUMMY_H_ */

