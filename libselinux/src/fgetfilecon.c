#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int fgetfilecon_raw(int fd, char ** context)
{
	int ret = 0;
	char *buf;
	ssize_t size;

#if defined(__ANDROID__)
	if (is_selinux_enabled() > 0) {
#endif
		size = INITCONTEXTLEN + 1;
		buf = malloc(size);
		if (!buf)
			return -1;
		memset(buf, 0, size);

		ret = fgetxattr(fd, XATTR_NAME_SELINUX, buf, size - 1);
		if (ret < 0 && errno == ERANGE) {
			char *newbuf;

			size = fgetxattr(fd, XATTR_NAME_SELINUX, NULL, 0);
			if (size < 0)
				goto out;

			size++;
			newbuf = realloc(buf, size);
			if (!newbuf)
				goto out;

			buf = newbuf;
			memset(buf, 0, size);
			ret = fgetxattr(fd, XATTR_NAME_SELINUX, buf, size - 1);
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
		size = INITCONTEXTLEN + 1;
		buf = malloc(size);
		if (!buf)
			return -1;

		memset(buf, 0xff, size);

		*context = buf;
		return 0;
	}
#endif
	return ret;
}

hidden_def(fgetfilecon_raw)

static int fgetfilecon_dummy(int fd, char ** context)
{
	char * rcontext = NULL;
	int ret;

	*context = NULL;

	ret = fgetfilecon_raw(fd, &rcontext);

	return ret;
}

int fgetfilecon(int fd, char ** context)
{
	char * rcontext = NULL;
	int ret;

#if defined(__ANDROID__)
	if (is_selinux_enabled() <= 0)
		return fgetfilecon_dummy(fd, context);
#endif

	*context = NULL;

	ret = fgetfilecon_raw(fd, &rcontext);

	if (ret > 0) {
		ret = selinux_raw_to_trans_context(rcontext, context);
		freecon(rcontext);
	}

	if (ret >= 0 && *context)
		return strlen(*context) + 1;

	return ret;
}
