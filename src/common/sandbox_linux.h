#include "torint.h"

#ifndef SANDBOX_LINUX_H_
#define SANDBOX_LINUX_H_

#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

struct sandbox_impl;
typedef char cap_rights_t;

#ifndef SYS_SECCOMP

/**
 * Used by SIGSYS signal handler to check if the signal was issued due to a
 * seccomp2 filter violation.
 */
#define SYS_SECCOMP 1

#endif /* !defined(SYS_SECCOMP) */

#if defined(HAVE_SECCOMP_H) && defined(__linux__)
#define USE_LIBSECCOMP
#endif

struct sandbox_cfg_elem;

/** Typedef to structure used to manage a sandbox configuration. */
typedef struct sandbox_cfg_elem sandbox_cfg_t;

/**
 * Linux definitions
 */
#ifdef USE_LIBSECCOMP

#include <sys/ucontext.h>
#include <seccomp.h>
#include <netdb.h>

#define PARAM_PTR 0
#define PARAM_NUM 1

/**
 * Enum used to manage the type of the implementation for general purpose.
 */
typedef enum {
  /** Libseccomp implementation based on seccomp2*/
  LIBSECCOMP2 = 0
} SB_IMPL;

/**
 *  Configuration parameter structure associated with the LIBSECCOMP2
 *  implementation.
 */
typedef struct smp_param {
  /** syscall associated with parameter. */
  int syscall;

  /** parameter value. */
  char *value;
  /** parameter value, second argument. */
  char *value2;

  /**  parameter flag (0 = not protected, 1 = protected). */
  int prot;
} smp_param_t;

/**
 * Structure used to manage a sandbox configuration.
 *
 * It is implemented as a linked list of parameters. Currently only controls
 * parameters for open, openat, execve, stat64.
 */
struct sandbox_cfg_elem {
  /** Sandbox implementation which dictates the parameter type. */
  SB_IMPL implem;

  /** Configuration parameter. */
  smp_param_t *param;

  /** Next element of the configuration*/
  struct sandbox_cfg_elem *next;
};

/** Function pointer defining the prototype of a filter function.*/
typedef int (*sandbox_filter_func_t)(scmp_filter_ctx ctx,
    sandbox_cfg_t *filter);

/** Type that will be used in step 3 in order to manage multiple sandboxes.*/
typedef struct {
  /** function pointers associated with the filter */
  sandbox_filter_func_t *filter_func;

  /** filter function pointer parameters */
  sandbox_cfg_t *filter_dynamic;
} sandbox_t;

#endif /* defined(USE_LIBSECCOMP) */

struct sandbox_impl *sandbox_seccomp_get_impl(void);

#endif /* !defined(SANDBOX_LINUX_H_) */

