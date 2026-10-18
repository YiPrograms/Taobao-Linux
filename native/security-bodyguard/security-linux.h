#pragma once
#ifdef __cplusplus
extern "C" {
#endif
// C ABI v1. Requests and responses are UTF-8 JSON. Requests return 0 on
// success and -1 on error. Release each allocated response with tb_security_free.
typedef struct tb_security_context tb_security_context;
#define TB_SECURITY_API __attribute__((visibility("default")))
TB_SECURITY_API unsigned tb_security_abi_version(void);
TB_SECURITY_API tb_security_context *tb_security_create(const char *storage_namespace);
TB_SECURITY_API void tb_security_destroy(tb_security_context *context);
TB_SECURITY_API int tb_security_request(tb_security_context *context, const char *request,
                                        char **response);
TB_SECURITY_API void tb_security_free(void *memory);
#ifdef __cplusplus
}
#endif
