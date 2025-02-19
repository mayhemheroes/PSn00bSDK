/*
 * PSn00bSDK assert macro and internal logging
 * (C) 2022 spicyjpeg - MPL licensed
 */

#undef SDK_LIBRARY_NAME

#include <assert.h>
#include <psxapi.h>

/* Internal function used by assert() macro */

void _assert_abort(const char *file, int line, const char *expr) {
	_sdk_log("%s:%d: assert(%s)\n", file, line, expr);

	for (;;)
		__asm__ volatile("");
}

/* Standard abort */

void abort(void) {
	_sdk_log("abort()\n");

	for (;;)
		__asm__ volatile("");
}

/* Pure virtual function call (C++) */

void __cxa_pure_virtual(void) {
	_sdk_log("__cxa_pure_virtual()\n");

	for (;;)
		__asm__ volatile("");
}
