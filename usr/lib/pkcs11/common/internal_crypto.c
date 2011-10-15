
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include "pkcs11types.h"
//#include "stdll.h"

#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"


int
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

	tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfm == -1) {
		OCK_LOG_DEBUG("socket() failed: %s", strerror(errno));
		return -1;
	}

	strncpy(sa.salg_name, name, strlen(name)+1);
	if (bind(tfm, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
		OCK_LOG_DEBUG("bind() failed: %s", strerror(errno));
		rc = -1;
		goto err;
	}

	if (setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key, (socklen_t)key_len) == -1) {
		OCK_LOG_DEBUG("setsockopt() failed: %s", strerror(errno));
		rc = -1;
		goto err;
	}

	op = accept(tfm, NULL, 0);
	if (op == -1) {
		OCK_LOG_DEBUG("accept() failed: %s", strerror(errno));
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

	//do {
		len = sendmsg(op, &msg, 0);
		if (len != in_data_len) {
			OCK_LOG_DEBUG("sendmsg() failed: %s. "
				      "Tried to send %u bytes, only sent %zd\n",
				      strerror(errno), in_data_len, len);
			close(op);
			goto err;
		}
	//} while (total_len < in_data_len);

	if (read(op, out_data, len) != in_data_len) {
		OCK_LOG_DEBUG("read() failed: %s. Tried to read %u bytes, only read %zd",
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
#if 0
int do_test(struct published_test_suite_info *t)
{
	int i;

	for (i = 0; i < t->tvcount; i++) {
		struct aes_test_vector *tv = &t->tv[i];
		char data[64];

		PRINT("plen = %u", tv->plen);
		PRINT("klen = %u", tv->klen);
		PRINT("clen = %u", tv->clen);

		if (aes_cbc(tv->plaintext, tv->plen, data, sizeof(data), tv->key, tv->klen,
			    tv->iv, 1)) {
			ERR("aes_cbc failed");
		}

		if (!memcmp(data, tv->ciphertext, tv->clen)) {
			PRINT("Success.");
		} else {
			ERR("Ciphertext doesn't match");
		}
		fflush(stdout);
	}

	printf("\n");
	return 0;
}
#endif

