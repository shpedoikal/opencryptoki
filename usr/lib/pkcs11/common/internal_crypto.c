/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2011 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/*
 * internal_crypto.c
 *
 * Oct 14, 2011
 *
 * Author: Kent Yoder <yoder1@us.ibm.com>
 *
 * Encryption routines for the Linux kernel's user-space crypto APIs
 *
 */


#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"


static int
_setup_tfm(int *tfm, char *type, const char *name)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_name = { 0 },
		.salg_type = { 0 }
	};

	*tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (*tfm == -1) {
		OCK_LOG_DEBUG("%s:%s: socket(): %s", type, name, strerror(errno));
		return -1;
	}

	strncpy(sa.salg_type, type, sizeof(sa.salg_type)-1);
	strncpy(sa.salg_name, name, sizeof(sa.salg_name)-1);
	if (bind(*tfm, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
		OCK_LOG_DEBUG("%s:%s: bind(): %s", type, name, strerror(errno));
		close(*tfm);
		return -1;
	}

	return 0;
}


static int
__cipher_cbc(const char *name, CK_BYTE *in_data, CK_ULONG in_data_len,
	     CK_BYTE *out_data, CK_ULONG *out_data_len,
	     CK_BYTE *key, ssize_t key_len, CK_BYTE *iv, CK_ULONG ivlen, int encrypt)
{
	uint32_t type;
	struct iovec iov;
	ssize_t len;
	char buf[CMSG_SPACE(sizeof(type)) +
		 CMSG_SPACE(offsetof(struct af_alg_iv, iv) + MAX_IV_LEN)] = { 0, };
	struct msghdr msg = { 0, };
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};
	int tfm, rc, op;

	if (*out_data_len < in_data_len) {
		OCK_LOG_DEBUG("not enough space in out_data");
		return EINVAL;
	}

	rc = _setup_tfm(&tfm, "skcipher", name);
	if (rc) {
		OCK_LOG_DEBUG("setup_tfm failed\n");
		return rc;
	}

	if (setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key, (socklen_t)key_len) == -1) {
		OCK_LOG_DEBUG("setsockopt() failed: %s\n", strerror(errno));
		rc = -1;
		goto err;
	}

	op = accept(tfm, NULL, 0);
	if (op == -1) {
		OCK_LOG_DEBUG("accept() failed: %s\n", strerror(errno));
		rc = -1;
		goto err;
	}

	type = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	/*
	 *   POSIX 1003.1g - ancillary data object information
	 *   Ancillary data consits of a sequence of pairs of
	 *   (cmsghdr, cmsg_data[])
	 */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(type));
	*(uint32_t *)CMSG_DATA(cmsg) = type;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + ivlen);

	/* get a pointer to the tail of the second cmsg */
	ivm = (void *)CMSG_DATA(cmsg);
	ivm->ivlen = ivlen;
	memcpy(ivm->iv, iv, ivlen);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	iov.iov_base = in_data;
	iov.iov_len = in_data_len;

	len = sendmsg(op, &msg, 0);
	if (len != in_data_len) {
		OCK_LOG_DEBUG("sendmsg() failed: %s. "
				"Tried to send %u bytes, only sent %zd\n",
				strerror(errno), in_data_len, len);
		close(op);
		goto err;
	}

	if (read(op, out_data, len) != in_data_len) {
		OCK_LOG_DEBUG("read() failed: %s. Tried to read %u bytes, only read %zd\n",
				strerror(errno), len, in_data_len);
		close(op);
		goto err;
	}

	return 0;
err:
	close(tfm);
	return 1;
}

int
__aes_cbc(CK_BYTE *in_data, CK_ULONG in_data_len,
	  CK_BYTE *out_data, CK_ULONG *out_data_len,
	  CK_BYTE *key, ssize_t key_len, CK_BYTE *iv, int encrypt)
{
	return __cipher_cbc("cbc(aes)", in_data, in_data_len, out_data, out_data_len, key, key_len,
			    iv, AES_IV_SIZE, encrypt);
}

int
__des3_cbc(CK_BYTE *in_data, CK_ULONG in_data_len,
	   CK_BYTE *out_data, CK_ULONG *out_data_len,
	   CK_BYTE *key, ssize_t key_len, CK_BYTE *iv, int encrypt)
{
	return __cipher_cbc("cbc(des3_ede)", in_data, in_data_len, out_data, out_data_len, key,
			    key_len, iv, DES3_IV_SIZE, encrypt);
}

static int
__digest(const char *name, CK_BYTE *data, CK_ULONG data_len, CK_BYTE *hash, CK_ULONG hash_len)
{
	int tfm, op, rc;
	struct iovec iov;
	struct msghdr msg = { 0, };
	ssize_t len;

	rc = _setup_tfm(&tfm, "hash", name);
	if (rc) {
		OCK_LOG_DEBUG("setup_tfm failed\n");
		return rc;
	}

	op = accept(tfm, NULL, 0);
	if (op == -1) {
		OCK_LOG_DEBUG("accept() failed: %s\n", strerror(errno));
		rc = -1;
		goto err;
	}

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	iov.iov_base = data;
	iov.iov_len = data_len;

	len = sendmsg(op, &msg, 0);
	if (len != data_len) {
		OCK_LOG_DEBUG("sendmsg() failed: %s. "
			      "Tried to send %u bytes, only sent %zd\n",
			      strerror(errno), data_len, len);
		close(op);
		rc = -1;
		goto err;
	}

	if ((len = read(op, hash, hash_len)) != hash_len) {
		OCK_LOG_DEBUG("read() failed: %s. Tried to read %u bytes, only read %zd\n",
				strerror(errno), hash_len, len);
		close(op);
		rc = -1;
		goto err;
	}
err:
	close(tfm);
	return rc;
}

int
__md5(CK_BYTE *in_data, CK_ULONG in_data_len, CK_BYTE *hash)
{
	return __digest("md5", in_data, in_data_len, hash, MD5_HASH_SIZE);
}

int
__sha1(CK_BYTE *in_data, CK_ULONG in_data_len, CK_BYTE *hash)
{
	return __digest("sha1", in_data, in_data_len, hash, SHA1_HASH_SIZE);
}


