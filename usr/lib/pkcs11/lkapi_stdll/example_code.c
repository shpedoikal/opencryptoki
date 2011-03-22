
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

int main()
{
	int tfm, i;
	char key[16];

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(aes)",
	};

	tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfm == -1 || bind(tfm, (struct sockaddr*)&sa, sizeof(sa)) == -1)
	{
		return 1;
	}

	memset(key, 0x34, sizeof(key));
	if (setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) == -1)
	{
		return 1;
	}

	for (i = 0; i < 1000; i++)
	{
		struct msghdr msg = {};
		struct cmsghdr *cmsg;
		struct af_alg_iv *ivm;
		u_int32_t type;
		struct iovec iov;
		char buf[CMSG_SPACE(sizeof(type)) +
			CMSG_SPACE(offsetof(struct af_alg_iv, iv)+16)];
		char data[64];
		ssize_t len;
		int op;

		op = accept(tfm, NULL, 0);
		if (op == -1)
		{
			return 1;
		}

		type = ALG_OP_ENCRYPT;
		memset(data, 0x12, sizeof(data));
		memset(buf, 0, sizeof(buf));

		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_OP;
		cmsg->cmsg_len = CMSG_LEN(sizeof(type));
		*(u_int32_t*)CMSG_DATA(cmsg) = type;

		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_IV;
		cmsg->cmsg_len = CMSG_LEN(
				offsetof(struct af_alg_iv, iv) + 16);
		ivm = (void*)CMSG_DATA(cmsg);
		ivm->ivlen = 16;
		memset(ivm->iv, 0x23, 16);

		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		iov.iov_base = data;
		iov.iov_len = sizeof(data);

		len = sendmsg(op, &msg, 0);
		if (len != sizeof(data))
		{
			return 1;
		}
		if (read(op, data, len) != len)
		{
			return 1;
		}
		printf(".");
		fflush(stdout);
		close(op);
	}

	close(tfm);
	printf("\n");
	return 0;
}
