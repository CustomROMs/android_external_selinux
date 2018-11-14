#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int fsetfilecon_raw(int fd, const char * context)
{
	int rc = 0;
#if defined(__ANDROID__)
	if (is_selinux_enabled() > 0) {
#endif
		rc = fsetxattr(fd, XATTR_NAME_SELINUX, context, strlen(context) + 1,
				 0);
		if (rc < 0 && errno == ENOTSUP) {
			char * ccontext = NULL;
			int err = errno;
			if ((fgetfilecon_raw(fd, &ccontext) >= 0) &&
			    (strcmp(context,ccontext) == 0)) {
				rc = 0;
			} else {
				errno = err;
			}
			freecon(ccontext);
		}
#if defined(__ANDROID__)
	} else
		return 0;
#endif
	return rc;
}

hidden_def(fsetfilecon_raw)

int fsetfilecon(int fd, const char *context)
{
	int ret = 0;
	char * rcontext;

#if defined(__ANDROID__)
	if (is_selinux_enabled() > 0) {
#endif
		if (selinux_trans_to_raw_context(context, &rcontext))
			return -1;

		ret = fsetfilecon_raw(fd, rcontext);

		freecon(rcontext);
#if defined(__ANDROID__)
	}
#endif

	return ret;
}
