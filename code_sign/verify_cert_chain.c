// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/cred.h>
#include <linux/key.h>
#include <linux/slab.h>
#include <linux/verification.h>
#include <crypto/pkcs7.h>
#include "objsec.h"
#include "../../security/xpm/include/dsmm_developer.h"
#include "code_sign_ioctl.h"
#include "code_sign_log.h"
#include "verify_cert_chain.h"

/*
 * Find the key (X.509 certificate) to use to verify a PKCS#7 message.  PKCS#7
 * uses the issuer's name and the issuing certificate serial number for
 * matching purposes.  These must match the certificate issuer's name (not
 * subject's name) and the certificate serial number [RFC 2315 6.7].
 */
static int pkcs7_find_key(struct pkcs7_message *pkcs7,
			  struct pkcs7_signed_info *sinfo)
{
	struct x509_certificate *cert;
	unsigned certix = 1;

	kenter("%u", sinfo->index);
	code_sign_log_info("sinfo->index %u", sinfo->index);

	cert = pkcs7->certs;
	while (cert) {
		if (asymmetric_key_id_same(cert->id, sinfo->sig->auth_ids[0])) {
			if (strcmp(cert->pub->pkey_algo, sinfo->sig->pkey_algo) != 0
					&& (strncmp(cert->pub->pkey_algo, "ecdsa-", 6) != 0
					|| strcmp(cert->sig->pkey_algo, "ecdsa") != 0)) {
				code_sign_log_warn("sig %u: X.509 algo and PKCS#7 sig algo don't match", sinfo->index);
				cert = cert->next;
				certix++;
				continue;
			}
		} else {
			code_sign_log_warn("sig %u: X.509->id and PKCS#7 sinfo->sig->auth_ids[0] don't match",
				sinfo->index, cert->id, sinfo->sig->auth_ids[0]);
			cert = cert->next;
			certix++;
			continue;
		}

		// cert is found
		sinfo->signer = cert;
		return 0;
	}

	/* The relevant X.509 cert isn't found here, but it might be found in
	 * the trust keyring.
	 */
	code_sign_log_info("Sig %u: Issuing X.509 cert not found (#%*phN)",
		 sinfo->index,
		 sinfo->sig->auth_ids[0]->len, sinfo->sig->auth_ids[0]->data);
	return 0;
}

void code_sign_verify_certchain(const void *raw_pkcs7, size_t pkcs7_len, int *ret)
{
	struct pkcs7_message *pkcs7;
	struct pkcs7_signed_info *sinfo;

	pkcs7 = pkcs7_parse_message(raw_pkcs7, pkcs7_len);
	if (IS_ERR(pkcs7)) {
		code_sign_log_error("parse pkcs7 message failed");
		*ret = PTR_ERR(pkcs7);
		return;
	}

	// no cert chain, verify by certificates in keyring
	if (!pkcs7->certs) {
		code_sign_log_warn("no certs in pkcs7, might be found in trust keyring");
		*ret = MAY_LOCAL_CODE;
		return;
	}

	if (!pkcs7->signed_infos) {
		code_sign_log_error("signed info not found in pkcs7");
		*ret = -EKEYREJECTED;
		return;
	}

	bool is_dev_mode = false, is_dev_proc = false;

	// developer mode && developer proc
	if (!strcmp(developer_mode_state(), DEVELOPER_STATUS_ON)) {
		code_sign_log_info("developer mode on");
		is_dev_mode = true;
		if (!code_sign_avc_has_perm(SECCLASS_XPM, XPM__EXEC_NO_SIGN)) {
			is_dev_proc = true;
		}
	}

	for (sinfo = pkcs7->signed_infos; sinfo; sinfo = sinfo->next) {
		/* Find the key for the signature if there is one */
		*ret = pkcs7_find_key(pkcs7, sinfo);
		if (*ret) {
			code_sign_log_error("key not find in pkcs7");
			return;
		}

		struct x509_certificate *signer = sinfo->signer;

		if (!signer) {
			code_sign_log_error("signer cert not found in pkcs7");
			*ret = -EINVAL;
			return;
		}

		struct cert_source *source = find_match(signer, is_dev_proc);
		if (source == NULL) {
			signer->subject = "ALL";
			source = find_match(signer, is_dev_proc);
			if (source == NULL) {
				code_sign_log_error("signer certificate's subject and issuer not trusted");
				*ret = -EKEYREJECTED;
				return;
			}
		} else if (source->path_type == RELEASE_BLOCK_CODE || source->path_type == DEBUG_BLOCK_CODE) {
			code_sign_log_error("signer certificate's type not trusted");
			*ret = -EKEYREJECTED;
			return;
		}

		// cal cert chain depth
		int cert_chain_depth_without_root = 1;
		char *issuer = signer->issuer;
		struct x509_certificate* cert = pkcs7->certs;
		while(cert) {
			// if issuer cert is found
			if (cert->subject && (strcmp(cert->subject, issuer) == 0)) {
				// reach root CA, end search
				if (strcmp(cert->subject, cert->issuer) == 0) {
					break;
				}
				cert_chain_depth_without_root++;
				// search again for current issuer's issuer
				issuer = cert->issuer;
				cert = pkcs7->certs;
			} else {
				// move to next certificate
				cert = cert->next;
			}
		}
		if (cert_chain_depth_without_root == (source->max_path_depth - 1)) {
			code_sign_log_info("cert subject and issuer trusted");
			*ret = source->path_type;
			return;
		} else {
			code_sign_log_error("depth mismatch: cert chain depth without root is %d, max_path_depth is %d",
				cert_chain_depth_without_root, source->max_path_depth);
		}
	}

	code_sign_log_error("cert subject and issuer verify failed");
	*ret = -EKEYREJECTED;
	return;
}
