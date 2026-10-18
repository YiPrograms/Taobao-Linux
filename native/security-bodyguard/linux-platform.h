#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Returned strings are malloc-owned. Unknown SDK field IDs return ENOTSUP.
int tb_linux_collection(int index, char **output, size_t *length);
char *tb_linux_platform_snapshot(void);
void tb_linux_platform_free(void *memory);
#ifdef __cplusplus
}
#endif
