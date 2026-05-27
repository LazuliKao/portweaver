/*
 * Minimal libnftables.h for PortWeaver integration
 * Based on the official nftables libnftables API
 * Reference: https://github.com/zevenet/nftlb/blob/master/include/nftables/libnftables.h
 */

#ifndef _LIBNFTABLES_H_
#define _LIBNFTABLES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Possible flags to pass to nft_ctx_new()
 */
#define NFT_CTX_DEFAULT  0

/*
 * Possible output flags
 */
enum {
    NFT_CTX_OUTPUT_REVERSE_DNS = (1 << 0),
    NFT_CTX_OUTPUT_SERVICE_NAME = (1 << 1),
    NFT_CTX_OUTPUT_STATELESS = (1 << 2),
    NFT_CTX_OUTPUT_HANDLE = (1 << 3),
    NFT_CTX_OUTPUT_JSON = (1 << 4),
    NFT_CTX_OUTPUT_ECHO = (1 << 5),
    NFT_CTX_OUTPUT_GUID = (1 << 6),
    NFT_CTX_OUTPUT_NUMERIC_PROTO = (1 << 7),
    NFT_CTX_OUTPUT_NUMERIC_TIME = (1 << 8),
    NFT_CTX_OUTPUT_NUMERIC_PRIO = (1 << 9),
    NFT_CTX_OUTPUT_NUMERIC_SYMBOL = (1 << 10),
};

/*
 * Debug flags
 */
enum {
    NFT_DEBUG_SCANNER = 0x1,
    NFT_DEBUG_PARSER = 0x2,
    NFT_DEBUG_EVALUATION = 0x4,
    NFT_DEBUG_NETLINK = 0x8,
    NFT_DEBUG_MNL = 0x10,
    NFT_DEBUG_PROTO_CTX = 0x20,
    NFT_DEBUG_SEGTREE = 0x40,
};

/*
 * Opaque context structure
 */
struct nft_ctx;

/*
 * Core context management
 */
struct nft_ctx *nft_ctx_new(uint32_t flags);
void nft_ctx_free(struct nft_ctx *ctx);

/*
 * Command execution
 */
int nft_run_cmd_from_buffer(struct nft_ctx *ctx, const char *buf);
int nft_run_cmd_from_filename(struct nft_ctx *ctx, const char *filename);

/*
 * Output/error buffering
 */
int nft_ctx_buffer_output(struct nft_ctx *ctx);
int nft_ctx_buffer_error(struct nft_ctx *ctx);
const char *nft_ctx_get_output_buffer(struct nft_ctx *ctx);
const char *nft_ctx_get_error_buffer(struct nft_ctx *ctx);

/*
 * Dry run mode
 */
bool nft_ctx_get_dry_run(struct nft_ctx *ctx);
void nft_ctx_set_dry_run(struct nft_ctx *ctx, bool dry);

/*
 * Output flags
 */
unsigned int nft_ctx_output_get_flags(struct nft_ctx *ctx);
void nft_ctx_output_set_flags(struct nft_ctx *ctx, unsigned int flags);

/*
 * Debug level
 */
int nft_ctx_get_debug(struct nft_ctx *ctx);
void nft_ctx_set_debug(struct nft_ctx *ctx, uint32_t level);

/*
 * Max errors
 */
unsigned int nft_ctx_get_max_errors(struct nft_ctx *ctx);
void nft_ctx_set_max_errors(struct nft_ctx *ctx, unsigned int max);

/*
 * Output file
 */
int nft_ctx_set_output(struct nft_ctx *ctx, FILE *fp);
int nft_ctx_set_error(struct nft_ctx *ctx, FILE *fp);

/*
 * Statistics
 */
int nft_ctx_output_json_schema(struct nft_ctx *ctx, const char *json_schema);

#ifdef __cplusplus
}
#endif

#endif /* _LIBNFTABLES_H_ */
