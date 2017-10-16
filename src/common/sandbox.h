#include "orconfig.h"

#ifdef HAVE_SYS_CAPSICUM_H
#include "sandbox_freebsd.h"
#else
#include "sandbox_linux.h"
#endif

