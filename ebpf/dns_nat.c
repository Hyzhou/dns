// dns_nat.c

#include "common.h"

#include "dns_nat.h"

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") ip_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 3,
};

struct bpf_map_def SEC("maps") conntrack_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size  = sizeof(u32),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") host_netns_cookie_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

SEC("cgroup/sendmsg4")
int nat_sendmsg4(struct bpf_sock_addr *ctx) {
	if (ctx->protocol != 17) // IPPROTO_UDP
		return 1;

	// 获取 netns cookie
	__u64 netns_cookie = bpf_get_netns_cookie(ctx->sk);
	if (netns_cookie == 0) {
		// 不支持 bpf_get_netns_cookie
		return 1;
	}

	// 从映射中获取主机 netns cookie
	__u32 key          = 0;
	__u64 *host_cookie = bpf_map_lookup_elem(&host_netns_cookie_map, &key);
	if (!host_cookie) {
		// 未设置主机 netns cookie
		return 1;
	}

	if (netns_cookie == *host_cookie) {
		// 在主机 netns 中，不处理
		return 1;
	}

	// 从 ip_map 中获取 IP 地址
	__u32 key0 = 0, key1 = 1, key2 = 2;
	__u32 *ip1 = bpf_map_lookup_elem(&ip_map, &key0);
	__u32 *ip2 = bpf_map_lookup_elem(&ip_map, &key1);
	__u32 *ip3 = bpf_map_lookup_elem(&ip_map, &key2);

	if (!ip1 || !ip2 || !ip3) {
		// IP 地址未设置
		return 1;
	}

	__u32 dest_ip = ctx->user_ip4;

	if (dest_ip == *ip1 || dest_ip == *ip2) {
		// 记录原始目的 IP
		__u64 sk = (__u64)ctx->sk;
		bpf_map_update_elem(&conntrack_map, &sk, &dest_ip, BPF_ANY);

		// 将目的 IP 修改为 ip3
		ctx->user_ip4 = *ip3;
	}

	return 1;
}

SEC("cgroup/recvmsg4")
int nat_recvmsg4(struct bpf_sock_addr *ctx) {
	if (ctx->protocol != 17) // IPPROTO_UDP
		return 1;

	// 获取 netns cookie
	__u64 netns_cookie = bpf_get_netns_cookie(ctx->sk);
	if (netns_cookie == 0) {
		// 不支持 bpf_get_netns_cookie
		return 1;
	}

	// 从映射中获取主机 netns cookie
	__u32 key          = 0;
	__u64 *host_cookie = bpf_map_lookup_elem(&host_netns_cookie_map, &key);
	if (!host_cookie) {
		// 未设置主机 netns cookie
		return 1;
	}

	if (netns_cookie == *host_cookie) {
		// 在主机 netns 中，不处理
		return 1;
	}

	// 恢复原始源 IP
	__u64 sk       = (__u64)ctx->sk;
	__u32 *orig_ip = bpf_map_lookup_elem(&conntrack_map, &sk);

	if (orig_ip) {
		ctx->user_ip4 = *orig_ip;
		bpf_map_delete_elem(&conntrack_map, &sk);
	}

	return 1;
}