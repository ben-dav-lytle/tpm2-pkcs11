/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_PKCS11_TPM_H_
#define SRC_PKCS11_TPM_H_

#include <stdbool.h>
#include <stdint.h>

#include <tss2/tss2_esys.h>

#include "attrs.h"
#include "debug.h"
#include "object.h"
#include "twist.h"
#include "utils.h"

/* config env var for TCTI context */
#define TPM2_PKCS11_TCTI "TPM2_PKCS11_TCTI"

typedef struct tpm_ctx tpm_ctx;

typedef struct tpm_op_data tpm_op_data;

/* forward references */
typedef union crypto_op_data crypto_op_data;
typedef struct mdetail mdetail;
typedef struct pobject pobject;


/**
 * Destroys the system API context, and when the refcnt
 * hits 0 for the tcti context, destroys it as well.
 * @param ctx
 *  The tpm context
 * @note: NOT THREAD SAFE: Assumes session table lock held
 */
void tpm_ctx_free(tpm_ctx *ctx);

/**
 * Creates a new tpm_ctx with it's own ESAPI
 * and TCTI contexts internally.
 * @param tcti
 *  An optional (can be null) tcti config string.
 * @param tctx
 *  The tpm_ctx to create.
 * @return
 *  CJR_OK on success, anything else is a failure.
 */
CK_RV tpm_ctx_new(const char *tcti, tpm_ctx **tctx);

CK_RV tpm_ctx_new_fromtcti(void *tcti, tpm_ctx **tctx);

/**
 * Retrieves Spec Version, FW Version, Manufacturer and Model from TPM
 * and populates the provided CK_TOKEN_INFO structure.
 *
 * If the manufacturer id is specified in TPM2_MANUFACTURER_MAP it will be
 * extended with a human readable form of the manufacturer
 * @param ctx
 *  The tpm api context.
 * @param info
 *  The CK_TOKEN_INFO structure where the data is written to
 * @return
 *  CKR_OK on success, CKR_ARGUMENTS_BAD, or CKR_GENERAL_ERROR otherwise
 */
CK_RV tpm_get_token_info (tpm_ctx *ctx, CK_TOKEN_INFO *info);

CK_RV tpm_is_rsa_keysize_supported(tpm_ctx *tctx, CK_ULONG test_size);

CK_RV tpm_find_max_rsa_keysize(tpm_ctx *tctx, CK_ULONG_PTR min, CK_ULONG_PTR max);

CK_RV tpm_find_ecc_keysizes(tpm_ctx *tctx, CK_ULONG_PTR min, CK_ULONG_PTR max);

CK_RV tpm_find_aes_keysizes(tpm_ctx *tctx, CK_ULONG_PTR min, CK_ULONG_PTR max);

CK_RV tpm_is_ecc_curve_supported(tpm_ctx *tctx, int nid);

/**
 * Generates random bytes from the TPM
 * @param ctx
 *  The tpm api context.
 * @param data
 *  The date to write the random bytes into.
 * @param size
 *  The number of random bytes to generate.
 * @return
 *  true on success, false otherwise.
 */
bool tpm_getrandom(tpm_ctx *ctx, uint8_t *data, size_t size);

CK_RV tpm_stirrandom(tpm_ctx *ctx, unsigned char *seed, unsigned long seed_len);

CK_RV tpm_loadobj(tpm_ctx *ctx, uint32_t phandle, twist auth,
        twist pub_path, twist priv_path, uint32_t *handle);

bool tpm_flushcontext(tpm_ctx *ctx, uint32_t handle);

twist tpm_unseal(tpm_ctx *ctx, uint32_t handle, twist objauth);

WEAK bool tpm_deserialize_handle(tpm_ctx *ctx, twist handle_blob, uint32_t *handle);

bool tpm_contextload_handle(tpm_ctx *ctx, twist handle_blob, uint32_t *handle);

CK_RV tpm_sign(tpm_op_data *opdata, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen);
CK_RV tpm_verify(tpm_op_data *opdata, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig, CK_ULONG siglen);

CK_RV tpm_rsa_pkcs_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_rsa_oaep_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_rsa_pss_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata);
CK_RV tpm_rsa_pss_sha1_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_rsa_pss_sha256_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_rsa_pss_sha384_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_rsa_pss_sha512_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);

CK_RV tpm_rsa_pkcs_sha1_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_rsa_pkcs_sha256_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_rsa_pkcs_sha384_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_rsa_pkcs_sha512_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);

CK_RV tpm_ec_ecdsa_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_ec_ecdsa_sha1_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_ec_ecdsa_sha256_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_ec_ecdsa_sha384_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_ec_ecdsa_sha512_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_ec_ecdh1_derive(tpm_ctx *tctx, tobject *tobj, unsigned char *pubkey, size_t pubkey_len, unsigned char **psec, size_t *pseclen);

CK_RV tpm_aes_cbc_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_aes_cfb_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_aes_ecb_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **opdata);
CK_RV tpm_aes_ctr_get_opdata(mdetail *m, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata);

CK_RV tpm_hmac_sha1_get_opdata(mdetail *mdtl, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata);
CK_RV tpm_hmac_sha256_get_opdata(mdetail *mdtl, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata);
CK_RV tpm_hmac_sha384_get_opdata(mdetail *mdtl, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata);
CK_RV tpm_hmac_sha512_get_opdata(mdetail *mdtl, tpm_ctx *tctx, CK_MECHANISM_PTR mech, tobject *tobj, tpm_op_data **outdata);

void tpm_opdata_reset(tpm_op_data *opdata);
void tpm_opdata_free(tpm_op_data **opdata);

CK_RV tpm_encrypt(crypto_op_data *opdata, CK_OBJECT_CLASS clazz, CK_BYTE_PTR ptext, CK_ULONG ptextlen, CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen);

CK_RV tpm_final_encrypt(crypto_op_data *opdata, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len);

CK_RV tpm_decrypt(crypto_op_data *opdata, CK_OBJECT_CLASS clazz, CK_BYTE_PTR ctext, CK_ULONG ctextlen, CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen);

CK_RV tpm_final_decrypt(crypto_op_data *opdata, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len);

CK_RV tpm_changeauth(tpm_ctx *ctx, uint32_t parent_handle, uint32_t object_handle,
        twist oldauth, twist newauth,
        twist *newblob);

CK_RV tpm2_create_seal_obj(tpm_ctx *ctx, twist parentauth, uint32_t parent_handle, twist objauth, twist oldpubblob, twist sealdata, twist *newpubblob, twist *newprivblob);

bool tpm_session_active(tpm_ctx *ctx);

CK_RV tpm_session_start(tpm_ctx *ctx, twist auth, uint32_t handle);

CK_RV tpm_session_stop(tpm_ctx *ctx);

typedef struct tpm_object_data tpm_object_data;
struct tpm_object_data {

    uint32_t privhandle;
    uint32_t pubhandle;

    attr_list *attrs;

    twist pubblob;
    twist privblob;
};

void tpm_objdata_free(tpm_object_data *objdata);

CK_RV tpm2_generate_key(
        tpm_ctx *tpm,

        uint32_t parent,
        twist parentauth,

        twist newauthbin,

        CK_MECHANISM_PTR mechanism,

        attr_list *pubattrs,

        attr_list *privattrs,

        tpm_object_data *objdata);

CK_RV tpm2_getmechanisms(tpm_ctx *ctx, CK_MECHANISM_TYPE *mechanism_list, CK_ULONG_PTR count);

CK_RV tpm_get_existing_primary(tpm_ctx *tpm, uint32_t *primary_handle, twist *primary_blob);

CK_RV tpm_create_persistent_primary(tpm_ctx *tpm, uint32_t *primary_handle, twist *primary_blob);

CK_RV tpm_create_transient_primary_from_template(tpm_ctx *tpm,
        const char *template_name, const char *pobj_auth,
        uint32_t *primary_handle);

CK_RV tpm_get_pss_sig_state(tpm_ctx *tctx, tobject *tobj, bool *pss_sigs_good);

/**
 * Retrieve the associated ESYS_TR from the given TPM2_HANDLE.
 *
 * @param ctx
 *  The TPM API context.
 * @param persistent_handle
 *  The TPM persistent handle (TPM2_HANDLE).
 * @param esys_tr
 *  An optional output (can be NULL).
 *  The associated ESYS_TR is returned here.
 * @param esys_tr_pub
 *  An optional output (can be NULL).
 *  A new key is created with only the public component from the
 *  persistent handle. The associated ESYS_TR is returned here.
 * @return
 *  CKR_OK on success; otherwise, an error code.
 */
CK_RV tpm_get_esys_tr(
        tpm_ctx *ctx,
        uint32_t persistent_handle,
        uint32_t *esys_tr,
        uint32_t *esys_tr_pub);

bool tpm_get_name(tpm_ctx *ctx, uint32_t handle, twist *name);

/**
 * Populate the CK_ATTRIBUTE list based on the given TPM key
 *
 * @param ctx
 *  The TPM API context.
 * @param esys_tr
 *  The TPM key ESYS_TR.
 * @param mechanism
 *  The mechanism.
 * @param pub_attrs
 *  The public key's CK_ATTRIBUTE list is returned here.
 * @param priv_attrs
 *  The private key's CK_ATTRIBUTE list is returned here.
 * @param obj_data
 *  The struct tpm_object_data is returned here.
 * @return
 *  CKR_OK on success; otherwise, an error code.
 */
CK_RV tpm_parse_key_to_attrs(
        tpm_ctx *tpm,
        uint32_t esys_tr,
        CK_MECHANISM_PTR mechanism,
        attr_list *pub_attrs,
        attr_list *priv_attrs,
        tpm_object_data *obj_data);

void tpm_init(void);

void tpm_destroy(void);

#endif /* SRC_PKCS11_TPM_H_ */
