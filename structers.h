#pragma once
#include <WinSock2.h>

// ip ��ַ (4 Bytes)
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

// MAC ��ַ (6 Bytes)
typedef struct mac_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}mac_address;

// ��̫�����ݱ�ͷ
typedef struct eth_header {
    mac_address dest_mac;   // Ŀ�� MAC ��ַ (6 bytes)
    mac_address sour_mac;   // Դ MAC ��ַ (6 bytes)
    u_short eh_type;        // ���� (16 bits): ����ϲ�Э���� ip����Ϊ0x0800h����2048d
}eth_header;

// IPv4 �ײ�
typedef struct ip_header {
    u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
    u_char  tos;            // �������� (8 bits)
    u_short tlen;           // �ܳ��� (16 bits)
    u_short identification; // ��ʶ (16 bits)
    u_short flags_fo;       // ��־λ (3 bits) + ��ƫ���� (13 bits)
    u_char  ttl;            // ���ʱ�� (8 bits)
    u_char  proto;          // Э�� (8bits)
    u_short crc;            // �ײ�У��� (16 bits)
    ip_address  saddr;      // Դ��ַ (32 bits)
    ip_address  daddr;      // Ŀ�ĵ�ַ (32 bits)
    u_int   op_pad;         // ��ѡ�ֶ� + ��� (��32 bits)
}ip_header;

// UDP �ײ�
typedef struct udp_header {
    u_short sport;          // Դ�˿� (16 bits)
    u_short dport;          // Ŀ�Ķ˿� (16 bits)
    u_short len;            // UDP ���ݰ����� (16 bits)
    u_short crc;            // У��� (16 bits)
}udp_header;

// TCP �ײ�
typedef struct tcp_header {
    u_short sport;          // Դ�˿� (16 bits)
    u_short dport;          // Ŀ�Ķ˿� (16 bits)
    u_int seril_num;        // ��� (32 bits)
    u_int acknow_num;       // ȷ�Ϻ� (32 bits)
    u_char offset_retain;   // ƫ���� (4 bits) + ���� (4 bits)
    u_char flags;           // ��־ (8 bits)
    u_short window;         // ���� (16bits)
    u_short crc;            // У��� (16bits)
    u_short urgency_pt;     // ����ָ�� (16 bits)
    u_int op_pad;           // ��ѡ�ֶ� + ��� (32 bits)
}tcp_header;

// ICMP �ײ�
typedef struct icmp_header {
    u_char type;            // ���� (8 bits)
    u_char code;            // ���� (8 bits)
    u_short crc;            // У��� (16 bits)
    u_short flags;          // ��ʶ�� (16 bits)
    u_short seril_num;      // ��� (16 bits)
    u_int op;               // ѡ�� (32 bits)
}icmp_header;

// ARP �ײ�
typedef struct arp_header {
    mac_address dest_mac;   // Ŀ�������� MAC ��ַ (6 bytes)
    mac_address source_mac; // Դ MAC ��ַ (6 bytes)
    u_short et_type;        // ���� (2 bytes)
    u_short hardware_type;  // Ӳ������ (2 bytes)
    u_short protocol_type;  // Э������ (2 bytes)
    u_char add_len;         // Ӳ����ַ���� (8 bits): MAC ��ַ����Ϊ6B
    u_char pro_len;         // Э���ַ���� (8 bits): Э���ַ����Ϊ4B
    u_short op;             // ���� (2 bytes): ARP����Ϊ1��ARPӦ��Ϊ2
    mac_address sour_addr;  // Դ MAC ��ַ (6 bytes): ���ͷ��� MAC ��ַ
    ip_address sour_ip;     // Դ IP ��ַ (4 bytes): ���ͷ��� IP ��ַ
    mac_address dest_addr;  // Ŀ�� MAC ��ַ (6 bytes): ARP�����и��ֶ�û�����壻ARP��Ӧ��Ϊ���շ���MAC��ַ
    ip_address dest_ip;     // Ŀ��IP��ַ (4 bytes): ARP������Ϊ���������IP��ַ��ARP��Ӧ��Ϊ���շ���IP��ַ
    u_char padding[18];
}arp_header;

// �豸�ṹ��
typedef struct alldevCho {
    pcap_if_t* alldevs;     // ���ҵ��������豸
    pcap_if_t* choosed;     // ѡ�е��豸
}alldevCho;