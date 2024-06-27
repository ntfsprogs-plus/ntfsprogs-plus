#ifndef _LIB_UTILS_H_
#define _LIB_UTILS_H_

#include "config.h"

#include "types.h"
#include "layout.h"
#include "volume.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

int utils_is_metadata(ntfs_inode *inode);
ATTR_RECORD * find_attribute(const ATTR_TYPES type, ntfs_attr_search_ctx *ctx);
ATTR_RECORD * find_first_attribute(const ATTR_TYPES type, MFT_RECORD *mft);

#endif	/* _LIB_UTILS_H_ */
