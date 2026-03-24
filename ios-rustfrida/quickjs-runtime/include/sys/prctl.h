#ifndef IOS_RUSTFRIDA_SYS_PRCTL_H
#define IOS_RUSTFRIDA_SYS_PRCTL_H

#include <errno.h>
#include <stdarg.h>

static inline int prctl(int option, ...) {
    (void) option;
    errno = ENOTSUP;
    return -1;
}

#endif
