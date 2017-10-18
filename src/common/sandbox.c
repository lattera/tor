#include "orconfig.h"
#include "sandbox.h"

sandbox_impl_t *sandbox;

sandbox_impl_t *
sandbox_get_impl(void)
{
  if (sandbox != NULL)
    return sandbox;

#ifdef HAVE_SYS_CAPSICUM_H
  sandbox = sandbox_freebsd_get_impl();
#else
  sandbox = sandbox_dummy_get_impl();
#endif

  return sandbox;
}

__attribute__((constructor)) void
sandbox_preinit(void)
{
  sandbox_get_impl();
}
