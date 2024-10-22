// main.go

//go:build amd64

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func mountCgroup2() error {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return err
	}

	if strings.Contains(string(data), "cgroup2") {
		return nil // 已挂载
	}

	// 挂载 cgroup2 到 /sys/fs/cgroup
	cmd := exec.Command("mount", "-t", "cgroup2", "none", "/sys/fs/cgroup")
	return cmd.Run()
}

func parseIP(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("无效的 IPv4 地址: %s", ipStr)
	}
	return binary.BigEndian.Uint32(ip), nil
}

func getHostNetnsCookie() (uint64, error) {
	// 打开主机 netns 文件
	fd, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	// 获取 netns ID（inode）
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, err
	}

	return uint64(st.Ino), nil
}

//func checkNetnsCookieSupport() error {
//	// 检查内核是否支持 bpf_get_netns_cookie
//	// 尝试加载一个简单的程序，如果加载失败且错误为不支持，则返回错误
//	prog := []byte{
//		// BPF_LD | BPF_IMM | BPF_DW
//		0x79, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r5 = bpf_get_netns_cookie(ctx->sk)
//		0x95, 0x00, 0x00, 0x00, // exit
//	}
//
//	spec := &ebpf.ProgramSpec{
//		Type:         ebpf.CGroupSockAddr,
//		Instructions: ebpf.RawInstructions(prog),
//		License:      "GPL",
//	}
//
//	_, err := ebpf.NewProgram(spec)
//	if err != nil {
//		if errors.Is(err, unix.EINVAL) {
//			return fmt.Errorf("内核不支持 bpf_get_netns_cookie")
//		}
//		return err
//	}
//
//	return nil
//}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf dns_nat.c -- -I../headers

func main() {
	// 移除内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("无法移除内存锁定限制: %v", err)
	}

	// 解析命令行参数
	var ip1Str, ip2Str, ip3Str string
	flag.StringVar(&ip1Str, "ip1", "", "要拦截的第一个 IP 地址")
	flag.StringVar(&ip2Str, "ip2", "", "要拦截的第二个 IP 地址")
	flag.StringVar(&ip3Str, "ip3", "", "要重定向到的 IP 地址")
	flag.Parse()

	if ip1Str == "" || ip2Str == "" || ip3Str == "" {
		log.Fatalf("用法: %s -ip1 <ip1> -ip2 <ip2> -ip3 <ip3>", os.Args[0])
	}

	// 检查内核是否支持 bpf_get_netns_cookie
	//if err := checkNetnsCookieSupport(); err != nil {
	//	log.Fatalf("检查 bpf_get_netns_cookie 支持失败: %v", err)
	//}

	// 获取主机 netns cookie
	hostNetnsCookie, err := getHostNetnsCookie()
	if err != nil {
		log.Fatalf("无法获取主机 netns cookie: %v", err)
	}

	// 转换 IP 地址为 uint32
	ip1, err := parseIP(ip1Str)
	if err != nil {
		log.Fatalf("无效的 ip1: %v", err)
	}
	ip2, err := parseIP(ip2Str)
	if err != nil {
		log.Fatalf("无效的 ip2: %v", err)
	}
	ip3, err := parseIP(ip3Str)
	if err != nil {
		log.Fatalf("无效的 ip3: %v", err)
	}

	// 挂载 cgroupv2（如果尚未挂载）
	if err := mountCgroup2(); err != nil {
		log.Fatalf("挂载 cgroupv2 失败: %v", err)
	}
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpConnect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("加载和分配 eBPF 对象失败: %v", err)
	}
	defer objs.NatSendmsg4.Close()
	defer objs.NatRecvmsg4.Close()
	defer objs.IpMap.Close()
	defer objs.ConntrackMap.Close()
	defer objs.HostNetnsCookieMap.Close()

	// 将 IP 地址加载到 ip_map 中
	var key0 uint32 = 0
	var key1 uint32 = 1
	var key2 uint32 = 2

	if err := objs.IpMap.Update(&key0, &ip1, ebpf.UpdateAny); err != nil {
		log.Fatalf("更新 ip_map[0] 失败: %v", err)
	}
	if err := objs.IpMap.Update(&key1, &ip2, ebpf.UpdateAny); err != nil {
		log.Fatalf("更新 ip_map[1] 失败: %v", err)
	}
	if err := objs.IpMap.Update(&key2, &ip3, ebpf.UpdateAny); err != nil {
		log.Fatalf("更新 ip_map[2] 失败: %v", err)
	}

	// 将主机 netns cookie 加载到 host_netns_cookie_map 中
	var netnsKey uint32 = 0
	if err := objs.HostNetnsCookieMap.Update(&netnsKey, &hostNetnsCookie, ebpf.UpdateAny); err != nil {
		log.Fatalf("更新 host_netns_cookie_map 失败: %v", err)
	}

	// 将 eBPF 程序附加到根 cgroup
	cgroupPath := "/sys/fs/cgroup"
	link1, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupUDP4Sendmsg,
		Program: objs.NatSendmsg4,
	})
	if err != nil {
		log.Fatalf("附加 sendmsg4 程序失败: %v", err)
	}

	link2, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupUDP4Recvmsg,
		Program: objs.NatRecvmsg4,
	})
	if err != nil {
		link1.Close()
		log.Fatalf("附加 recvmsg4 程序失败: %v", err)
	}

	// 在程序退出时卸载 eBPF 程序
	defer func() {
		log.Println("正在卸载 eBPF 程序")
		link1.Close()
		link2.Close()
	}()

	log.Println("eBPF 程序已成功附加，按 Ctrl+C 退出")

	// 等待中断信号以退出
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("程序退出")
}
