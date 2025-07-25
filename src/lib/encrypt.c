/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "checks.h"
#include "encrypt.h"
#include "mech.h"
#include "ssl_util.h"
#include "session.h"
#include "session_ctx.h"
#include "token.h"
#include "tpm.h"

struct sw_encrypt_data {
    int padding;
    RSA *key;
};

typedef CK_RV (*crypto_op)(crypto_op_data *enc_data, CK_OBJECT_CLASS, CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out, CK_ULONG_PTR outlen);

static sw_encrypt_data *sw_encrypt_data_new(void) {

    return (sw_encrypt_data *)calloc(1, sizeof(sw_encrypt_data));
}

static void sw_encrypt_data_free(sw_encrypt_data **enc_data) {
    if (!enc_data) {
        return;
    }

    if ((*enc_data)->key) {
        RSA_free((*enc_data)->key);
    }

    free(*enc_data);
    *enc_data = NULL;
}

encrypt_op_data *encrypt_op_data_new(tobject *tobj) {

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_CLASS);
    if (!a) {
        LOGE("Expected tobjects to have attribute CKA_CLASS");
        return NULL;
    }

    CK_OBJECT_CLASS clazz;
    CK_RV rv = attr_CK_OBJECT_CLASS(a, &clazz);
    if (rv != CKR_OK) {
        LOGE("Could not convert CKA_CLASS");
        return NULL;
    }

    encrypt_op_data *d = (encrypt_op_data *)calloc(1, sizeof(encrypt_op_data));
    if (!d) {
        return NULL;
    }

    d->clazz = clazz;

    return d;
}

void encrypt_op_data_free(encrypt_op_data **opdata) {

    if (opdata) {
        (*opdata)->use_sw ?
                sw_encrypt_data_free(&(*opdata)->cryptopdata.sw_enc_data) :
                tpm_opdata_free(&(*opdata)->cryptopdata.tpm_opdata);
        free(*opdata);
        *opdata = NULL;
    }
}

CK_RV sw_encrypt_data_init(CK_MECHANISM *mechanism, tobject *tobj, sw_encrypt_data **enc_data) {
    BIGNUM *e = NULL;
    BIGNUM *n = NULL;
    RSA *r = NULL;

    CK_RV rv = CKR_GENERAL_ERROR;

    /* we only support one mechanism via this path right now */
    if (mechanism->mechanism != CKM_RSA_PKCS) {
        LOGE("Cannot synthesize mechanism for key");
        return CKR_MECHANISM_INVALID;
    }

    /*
     * We know this in RSA key since we checked the mechanism,
     * create the OSSL key
     */
    r = RSA_new();
    if (!r) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    CK_ATTRIBUTE_PTR a = attr_get_attribute_by_type(tobj->attrs, CKA_MODULUS);
    if (!a) {
        LOGE("Expected RSA key to have modulus");
        goto error;
    }

    n = BN_bin2bn(a->pValue, a->ulValueLen, NULL);
    if (!n) {
        LOGE("Could not create BN from modulus");
        goto error;
    }

    a = attr_get_attribute_by_type(tobj->attrs, CKA_PUBLIC_EXPONENT);
    if (!a) {
        LOGE("Expected RSA key to have exponent");
        goto error;
    }

    e = BN_bin2bn(a->pValue, a->ulValueLen, NULL);
    if (!e) {
        LOGE("Could not create BN from exponent");
        goto error;
    }

    int rc = RSA_set0_key(r, n, e, NULL);
    if (!rc) {
        LOGE("Could not set RSA public key from parts");
        goto error;
    }

    /* ownership of memory transferred */
    n = NULL;
    e = NULL;

    sw_encrypt_data *d = sw_encrypt_data_new();
    if (!d) {
        LOGE("oom");
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    d->key = r;
    d->padding = RSA_PKCS1_PADDING;

    *enc_data = d;

    return CKR_OK;
error:
    if (n) {
        BN_free(n);
    }
    if (e) {
        BN_free(e);
    }
    return rv;
}

CK_RV sw_encrypt(crypto_op_data *opdata, CK_OBJECT_CLASS clazz,
        CK_BYTE_PTR ptext, CK_ULONG ptextlen,
        CK_BYTE_PTR ctext, CK_ULONG_PTR ctextlen) {
    UNUSED(clazz);
    assert(opdata);

    sw_encrypt_data *sw_enc_data = opdata->sw_enc_data;

    assert(sw_enc_data);
    assert(sw_enc_data->key);

    RSA *r = sw_enc_data->key;
    int padding = sw_enc_data->padding;

    /* make sure destination is big enough */
    int to_len = RSA_size(r);
    if (to_len < 0) {
        LOGE("RSA_Size cannot be 0");
        return CKR_GENERAL_ERROR;
    }

    if ((CK_ULONG)to_len > *ctextlen) {
        *ctextlen = to_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    int rc = RSA_public_encrypt(ptextlen, ptext,
        ctext, r, padding);
    if (!rc) {
        LOGE("Could not perform RSA public encrypt");
        return CKR_GENERAL_ERROR;
    }

    assert(rc > 0);

    *ctextlen = rc;

    return CKR_OK;
}

CK_RV sw_decrypt(crypto_op_data *opdata, CK_OBJECT_CLASS clazz,
        CK_BYTE_PTR ctext, CK_ULONG ctextlen,
        CK_BYTE_PTR ptext, CK_ULONG_PTR ptextlen) {
    UNUSED(clazz);
    assert(opdata);

    CK_RV rv = CKR_GENERAL_ERROR;

    sw_encrypt_data *sw_enc_data = opdata->sw_enc_data;

    assert(sw_enc_data);
    assert(sw_enc_data->key);

    RSA *r = sw_enc_data->key;
    int padding = sw_enc_data->padding;
    int to_len = RSA_size(r);
    if (to_len <= 0) {
        LOGE("Expected buffer size to be > 0, got: %d", to_len);
        return CKR_GENERAL_ERROR;
    }

    unsigned char *buffer = calloc(1, to_len);
    if (!buffer) {
        LOGE("oom");
        return CKR_HOST_MEMORY;
    }

    int rc = RSA_public_decrypt(ctextlen, ctext, buffer, r, padding);
    if (rc <= 0) {
        LOGE("Could not perform RSA public decrypt: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }
    assert(rc > 0);

    if (*ptextlen > (CK_ULONG)rc) {
        *ptextlen = rc;
        free(buffer);
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(ptext, buffer, rc);
    *ptextlen = rc;

    rv = CKR_OK;

out:
    free(buffer);
    return rv;
}

static CK_RV common_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, operation op, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {

    check_pointer(mechanism);

    LOGV("mechanism->mechanism: %lu\n"
            "mechanism->ulParameterLen: %lu\n"
            "mechanism->pParameter: %s",
            mechanism->mechanism,
            mechanism->ulParameterLen,
            mechanism->pParameter ? "set" : "(null)");

    token *tok = session_ctx_get_token(ctx);
    assert(tok);

    if (!supplied_opdata) {
        bool is_active = session_ctx_opdata_is_active(ctx);
        if (is_active) {
            return CKR_OPERATION_ACTIVE;
        }
    }

    tobject *tobj;
    CK_RV rv = token_load_object(tok, key, &tobj);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = object_mech_is_supported(tobj, mechanism);
    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        return rv;
    }

    encrypt_op_data *opdata;
    if (!supplied_opdata) {
        opdata = encrypt_op_data_new(tobj);
        if (!opdata) {
            tobject_user_decrement(tobj);
            return CKR_HOST_MEMORY;
        }
    } else {
        opdata = supplied_opdata;
    }

    /*
     * Objects that don't have a tpm pub pointer blob are things like public key
     * only object and don't go to the TPM.
     */
    if (tobj->pub) {
        rv = mech_get_tpm_opdata(tok->mdtl, tok->tctx, mechanism, tobj,
                &opdata->cryptopdata.tpm_opdata);
    } else {
        opdata->use_sw = true;
        rv = sw_encrypt_data_init(mechanism, tobj, &opdata->cryptopdata.sw_enc_data);
    }

    if (rv != CKR_OK) {
        tobject_user_decrement(tobj);
        if (!supplied_opdata) {
            encrypt_op_data_free(&opdata);
        }
        return rv;
    }

    if (!supplied_opdata) {
        session_ctx_opdata_set(ctx, op, tobj, opdata, (opdata_free_fn)encrypt_op_data_free);
    }

    return CKR_OK;
}

static CK_RV common_update_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, operation op,
        CK_BYTE_PTR part, CK_ULONG part_len,
        CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {

    check_pointer(part);
    check_pointer(encrypted_part_len);

    CK_RV rv = CKR_GENERAL_ERROR;

    encrypt_op_data *opdata = NULL;
    if (!supplied_opdata) {
        rv = session_ctx_opdata_get(ctx, op, &opdata);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = session_ctx_tobject_authenticated(ctx);
        if (rv != CKR_OK) {
            return rv;
        }
    } else {
        opdata = supplied_opdata;
    }

    crypto_op fop;
    switch(op) {
    case operation_encrypt:
        fop = opdata->use_sw ? sw_encrypt : tpm_encrypt;
        break;
    case operation_decrypt:
        fop = opdata->use_sw ? sw_decrypt : tpm_decrypt;
        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    rv = fop(&opdata->cryptopdata, opdata->clazz, part, part_len,
            encrypted_part, encrypted_part_len);

    return rv;
}

static CK_RV common_final_op(session_ctx *ctx, encrypt_op_data *supplied_opdata, operation op,
        CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len, bool is_oneshot) {

    check_pointer(last_part_len);

    bool reset_ctx = false;
    CK_RV rv = CKR_GENERAL_ERROR;

    encrypt_op_data *opdata = supplied_opdata;
    if (!opdata) {
        rv = session_ctx_opdata_get(ctx, op, &opdata);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = session_ctx_tobject_authenticated(ctx);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    assert(opdata);

    tobject *tobj = session_ctx_opdata_get_tobject(ctx);
    assert(tobj);

    /* we may have some TPM symmetric data to deal with */
    if (!opdata->use_sw) {

        rv = (op == operation_encrypt) ?
            tpm_final_encrypt(&opdata->cryptopdata, last_part, last_part_len) :
            tpm_final_decrypt(&opdata->cryptopdata, last_part, last_part_len);
        if (rv != CKR_OK) {
            goto out;
        }

    } else if (!last_part) {
        /* For all other encrypt operations deal with 5.2 style returns */
        if (last_part_len) {
            *last_part_len = 0;
        }
    }

    rv = CKR_OK;

out:
    /*
     * we're only done if last_part is specified or the buffer isn't too small
     *
     * We also don't want to decrement the tobject unless we're using session ctx
     * not internal routines.
     */
    reset_ctx = (rv == CKR_BUFFER_TOO_SMALL || !last_part);
    if (reset_ctx) {
        if (is_oneshot && !opdata->use_sw) {
            tpm_opdata_reset(opdata->cryptopdata.tpm_opdata);
        }
        /* all is well, we reset the command context */
        rv = CKR_OK;
    } else if(!supplied_opdata) {
        /* end the command context */
        tobj->is_authenticated = false;
        if (!supplied_opdata) {
            session_ctx_opdata_clear(ctx);
        }

        CK_RV tmp_rv = tobject_user_decrement(tobj);
        if (tmp_rv != CKR_OK && rv == CKR_OK) {
            rv = tmp_rv;
        }
    }

    return rv;
}

CK_RV encrypt_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init_op(ctx, supplied_opdata, operation_encrypt, mechanism, key);
}

CK_RV decrypt_init_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_MECHANISM *mechanism, CK_OBJECT_HANDLE key) {

    return common_init_op(ctx, supplied_opdata, operation_decrypt, mechanism, key);
}

CK_RV encrypt_update_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {

    return common_update_op(ctx, supplied_opdata, operation_encrypt, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV decrypt_update_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) {

    return common_update_op(ctx, supplied_opdata, operation_decrypt, part, part_len, encrypted_part, encrypted_part_len);
}

CK_RV encrypt_final_ex (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR last_encrypted_part, CK_ULONG_PTR last_encrypted_part_len, bool is_oneshot) {

    return common_final_op(ctx, supplied_opdata, operation_encrypt, last_encrypted_part, last_encrypted_part_len, is_oneshot);
}

CK_RV decrypt_final_ex (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len, bool is_oneshot) {

    return common_final_op(ctx, supplied_opdata, operation_decrypt, last_part, last_part_len, is_oneshot);
}

CK_RV decrypt_oneshot_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR encrypted_data, CK_ULONG encrypted_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {

    check_pointer(data_len);

    bool is_buffer_too_small = false;
    CK_ULONG tmp_len = *data_len;

    CK_RV rv = decrypt_update_op(ctx, supplied_opdata, encrypted_data, encrypted_data_len,
            data, &tmp_len);
    if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        return rv;
    }

    CK_ULONG update_len = tmp_len;
    if (rv == CKR_BUFFER_TOO_SMALL) {
        data = NULL;
        is_buffer_too_small = true;
    } else {
        if (data) {
            data = &data[update_len];
            assert(tmp_len <= *data_len);
        }
        tmp_len = *data_len - tmp_len;
    }

    rv = decrypt_final_ex(ctx, supplied_opdata, data, &tmp_len, true);
    *data_len = update_len + tmp_len;
    return !is_buffer_too_small ? rv : CKR_BUFFER_TOO_SMALL;
}

CK_RV encrypt_oneshot_op (session_ctx *ctx, encrypt_op_data *supplied_opdata, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len) {

    check_pointer(encrypted_data_len);

    bool is_buffer_too_small = false;
    CK_ULONG tmp_len = *encrypted_data_len;

    CK_RV rv = encrypt_update_op (ctx, supplied_opdata, data, data_len, encrypted_data, &tmp_len);
    if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
        return rv;
    }

    CK_ULONG update_len = tmp_len;
    if (rv == CKR_BUFFER_TOO_SMALL) {
        encrypted_data = NULL;
        is_buffer_too_small = true;
    } else {
        if (encrypted_data) {
            encrypted_data = &encrypted_data[update_len];
            assert(tmp_len <= *encrypted_data_len);
        }
        tmp_len = *encrypted_data_len - tmp_len;
    }

    rv = encrypt_final_ex(ctx, supplied_opdata, encrypted_data, &tmp_len, true);
    *encrypted_data_len = update_len + tmp_len;
    return !is_buffer_too_small ? rv : CKR_BUFFER_TOO_SMALL;
}
