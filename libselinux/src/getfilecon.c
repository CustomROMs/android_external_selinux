#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "selinux_internal.h"
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "policy.h"

int getfilecon_raw(const char *path, char ** context)
{
	char *buf;
	ssize_t size;
	ssize_t ret = 0;

	size = INITCONTEXTLEN + 1;
	buf = malloc(size);
	if (!buf)
		return -1;
#if defined(__ANDROID__)
	if (is_selinux_enabled() > 0) {
#endif

	memset(buf, 0, size);
	ret = getxattr(path, XATTR_NAME_SELINUX, buf, size - 1);
	if (ret < 0 && errno == ERANGE) {
		char *newbuf;

		size = getxattr(path, XATTR_NAME_SELINUX, NULL, 0);
		if (size < 0)
			goto out;

		size++;
		newbuf = realloc(buf, size);
		if (!newbuf)
			goto out;

		buf = newbuf;
		memset(buf, 0, size);
		ret = getxattr(path, XATTR_NAME_SELINUX, buf, size - 1);
	}
      out:
	if (ret == 0) {
		/* Re-map empty attribute values to errors. */
		errno = ENOTSUP;
		ret = -1;
	}
	if (ret < 0)
		free(buf);
	else
		*context = buf;
#if defined(__ANDROID__)
} else {
	memset(buf, 0xff, size);
	*context = buf;
}
#endif
	return ret;
}

hidden_def(getfilecon_raw)

int getfilecon(const char *path, char ** context)
{
	int ret;
	char * rcontext = NULL;

	*context = NULL;

	ret = getfilecon_raw(path, &rcontext);

	if (ret > 0) {
#if defined(__ANDROID__)
		if (is_selinux_enabled() > 0)
#endif
			ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}
	if (ret >= 0 && *context)
		return strlen(*context) + 1;

	return ret;
}

hidden_def(getfilecon)
