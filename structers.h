#pragma once
#include <WinSock2.h>

// ip 地址 (4 Bytes)
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

// MAC 地址 (6 Bytes)
typedef struct mac_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}mac_address;

// 以太网数据报头
typedef struct eth_header {
    mac_address dest_mac;   // 目的 MAC 地址 (6 bytes)
    mac_address sour_mac;   // 源 MAC 地址 (6 bytes)
    u_short eh_type;        // 类型 (16 bits): 如果上层协议是 ip，则为0x0800h，即2048d
}eth_header;

// IPv4 首部
typedef struct ip_header {
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型 (8 bits)
    u_short tlen;           // 总长度 (16 bits)
    u_short identification; // 标识 (16 bits)
    u_short flags_fo;       // 标志位 (3 bits) + 段偏移量 (13 bits)
    u_char  ttl;            // 存活时间 (8 bits)
    u_char  proto;          // 协议 (8bits)
    u_short crc;            // 首部校验和 (16 bits)
    ip_address  saddr;      // 源地址 (32 bits)
    ip_address  daddr;      // 目的地址 (32 bits)
    u_int   op_pad;         // 可选字段 + 填充 (共32 bits)
}ip_header;

// UDP 首部
typedef struct udp_header {
    u_short sport;          // 源端口 (16 bits)
    u_short dport;          // 目的端口 (16 bits)
    u_short len;            // UDP 数据包长度 (16 bits)
    u_short crc;            // 校验和 (16 bits)
}udp_header;

// TCP 首部
typedef struct tcp_header {
    u_short sport;          // 源端口 (16 bits)
    u_short dport;          // 目的端口 (16 bits)
    u_int seril_num;        // 序号 (32 bits)
    u_int acknow_num;       // 确认号 (32 bits)
    u_char offset_retain;   // 偏移量 (4 bits) + 保留 (4 bits)
    u_char flags;           // 标志 (8 bits)
    u_short window;         // 窗口 (16bits)
    u_short crc;            // 校验和 (16bits)
    u_short urgency_pt;     // 紧急指针 (16 bits)
    u_int op_pad;           // 可选字段 + 填充 (32 bits)
}tcp_header;

// ICMP 首部
typedef struct icmp_header {
    u_char type;            // 类型 (8 bits)
    u_char code;            // 代码 (8 bits)
    u_short crc;            // 校验和 (16 bits)
    u_short flags;          // 标识符 (16 bits)
    u_short seril_num;      // 序号 (16 bits)
    u_int op;               // 选项 (32 bits)
}icmp_header;

// ARP 首部
typedef struct arp_header {
    mac_address dest_mac;   // 目的主机的 MAC 地址 (6 bytes)
    mac_address source_mac; // 源 MAC 地址 (6 bytes)
    u_short et_type;        // 类型 (2 bytes)
    u_short hardware_type;  // 硬件类型 (2 bytes)
    u_short protocol_type;  // 协议类型 (2 bytes)
    u_char add_len;         // 硬件地址长度 (8 bits): MAC 地址长度为6B
    u_char pro_len;         // 协议地址长度 (8 bits): 协议地址长度为4B
    u_short op;             // 操作 (2 bytes): ARP请求为1，ARP应答为2
    mac_address sour_addr;  // 源 MAC 地址 (6 bytes): 发送方的 MAC 地址
    ip_address sour_ip;     // 源 IP 地址 (4 bytes): 发送方的 IP 地址
    mac_address dest_addr;  // 目的 MAC 地址 (6 bytes): ARP请求中该字段没有意义；ARP响应中为接收方的MAC地址
    ip_address dest_ip;     // 目的IP地址 (4 bytes): ARP请求中为请求解析的IP地址；ARP响应中为接收方的IP地址
    u_char padding[18];
}arp_header;

// 设备结构体
typedef struct alldevCho {
    pcap_if_t* alldevs;     // 查找到的所有设备
    pcap_if_t* choosed;     // 选中的设备
}alldevCho;