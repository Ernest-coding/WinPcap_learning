#if 1
#define WIN32  
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
//#pragma pack(1)       // ��һ�ֽڶ���
#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <string.h>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <Windows.h>
#include <remote-ext.h>
#include "structers.h"
#pragma comment(lib,"iphlpapi.lib")

using namespace std;

// ѡ����ģʽ
void choose_work_mode(int &mode_type);
// ѡ��Э������
char* choose_protocol_type(int& protocol_type);
// ѡ��ʹ���豸
void choose_use_device(int i, int& num);
// �����豸��ѡ���豸
alldevCho find_and_choose_dev(char *errbuf);
// ���豸
pcap_t* open_device(alldevCho oper, char* errbuf, u_int &netmask, const char* packet_filter);
// ��������
void start_catch(pcap_t* adhandle, int protocol_type);

// �������ݰ�
u_char* make_packet(alldevCho oper);
// ��ȡ�����豸 IP ��ַ
ip_address* get_local_ip(pcap_if_t* dev);
// ��ȡ�����豸 MAC ��ַ
mac_address* get_local_mac(pcap_if_t* dev, u_char ucMacAddr[]);
int GetGateWayMac();
// ������̫�����ݱ�ͷ
eth_header* make_pheader_eth();
// ���� IP ���ݱ�ͷ
ip_header* make_pheader_ip(ip_address local_ip_add);
// ���� UDP ���ݱ�ͷ
udp_header* make_pheader_udp();
// ���� TCP ���ݱ�ͷ
tcp_header* make_pheader_tcp();
// ���� ICMP ���ݱ�ͷ
icmp_header* make_pheader_icmp();
// ���� ARP ���ݱ�ͷ
arp_header* make_pheader_arp();
// ��ȡ���ݱ�����������
u_char* get_packet_content();
// �������ݰ�
void send_packet(alldevCho oper, char errbuf[], u_char packet[]);

// UDP �ص��������������ݰ�
void packet_handler_udp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// TCP �ص��������������ݰ�
void packet_handler_tcp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// ICMP �ص��������������ݰ�
void packet_handler_icmp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// ARP �ص��������������ݰ�
void packet_handler_arp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// ץ�������Ϣ���--ͨ�ò��֣�ֻ��� ip �źͶ˿ں�
void show_catch_infos(const struct pcap_pkthdr* header, eth_header* eth, ip_header* ih, bool port, u_short sport, u_short dport);


int GetAdapterMacAddr(char* lpszAdapterName, unsigned char ucMacAddr[]) {//��ȡmac��ַ�ĺ���
    LPADAPTER lpAdapter = PacketOpenAdapter(lpszAdapterName);
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        return -1;
    }
    PPACKET_OID_DATA oidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (NULL == oidData) {
        PacketCloseAdapter(lpAdapter);
        return -1;
    }
    oidData->Oid = OID_802_3_CURRENT_ADDRESS;
    oidData->Length = 6;
    memset(oidData->Data, 0, 6);
    BOOLEAN  bStatus = PacketRequest(lpAdapter, FALSE, oidData);
    if (bStatus) {
        for (int i = 0; i < 6; ++i)
            ucMacAddr[i] = (oidData->Data)[i];
    }
    else {
        return -1;
        free(oidData);
    }
    free(oidData);
    PacketCloseAdapter(lpAdapter);
    return 0;
}


int main()
{
    int inum;                           // �û�ѡ��Ҫ�������豸�����
    int mode_type;                      // ����ģʽ��1.ץ������� 2.����������
    int protocol_type;                  // Э�����ͣ�1.UDPЭ�� 2.TCPЭ�� 3.ICMPЭ�� 4.ARPЭ��
    char errbuf[PCAP_ERRBUF_SIZE];      // ������Ϣ
    u_int netmask;                      // ����
    char *packet_filter;                // ����ģʽ
    struct bpf_program fcode;

    choose_work_mode(mode_type);        // ѡ����ģʽ

    if (mode_type == 1)                 // ����ģʽΪץ�������
    {
        packet_filter = choose_protocol_type(protocol_type);    // ѡ����Э��
        alldevCho oper = find_and_choose_dev(errbuf);           // ���Ҳ�ѡ���豸
        pcap_t* adhandle = open_device(oper, errbuf, netmask, packet_filter);      // ���豸
        start_catch(adhandle, protocol_type);                   // ����ץ��
    }
    else {                              // ����ģʽΪ����������
        alldevCho oper = find_and_choose_dev(errbuf);           // ���Ҳ�ѡ���豸
        u_char* packet = make_packet(oper);                     // �������ݰ�
        send_packet(oper, errbuf, packet);                      // �������ݰ�
    }

    return 0;
}

// ѡ����ģʽ
void choose_work_mode(int& mode_type)
{
    cout << "���������ѡ����ģʽ:     1.ץ�������    2.����������\n����ѡ����: ";
	while (1)
	{
        // TODO: ������bug������Ƿ��ַ����һֱѭ����ͣ
		cin >> mode_type;
		if (mode_type != 1 && mode_type != 2)
			cout << "�������ѡ��Ƿ�������������: " << endl;
		else
			break;
	}
}

// ѡ��Э������
char* choose_protocol_type(int& protocol_type)
{
    cout << "���������ѡ��Ҫ�������ݰ���Э��: \n  1.UDPЭ��  2.TCPЭ��  3.ICMPЭ��  4.ARPЭ��\n����ѡ����: ";
    while (1)
    {
        // TODO: ������bug������Ƿ��ַ����һֱѭ����ͣ
        cin >> protocol_type;
        if (protocol_type < 1 || protocol_type > 4)
            cout << "�������ѡ��Ƿ�������������: ";
        else
            break;
    }
    // ���ù���ģʽ
    char* packet_filter;
    switch (protocol_type)
    {
    case 1:
        packet_filter = "ip and udp";
        break;
    case 2:
        packet_filter = "ip and tcp";
        break;
    case 3:
        packet_filter = "ip and icmp";
        break;
    case 4:
        packet_filter = "ip and arp";
        break;
    default:
        packet_filter = "ip and udp";
        break;
    }
    return packet_filter;
}

// ѡ��ʹ���豸
void choose_use_device(int i, int& inum)
{
    cout << "����Ҫ�����Ľӿڱ�� (1-" << i << "), ��������0�˳�: ";
    while (1)
    {
        // TODO: ������bug������Ƿ��ַ����һֱѭ����ͣ
        cin >> inum;
        if (inum == 0)
            exit(1);
        else if (inum < 1 || inum > i)
            cout << "\n������ı�Ų��淶������������: ";
        else
            break;
    }
}

// �����豸��ѡ���豸
alldevCho find_and_choose_dev(char* errbuf)
{
    alldevCho operators;    // ����Ԫ
    int inum;               // �û�ѡ��Ҫ�������豸�����
    int i = 0;                  // �豸��ţ�����豸�б���

    // �����豸�б�
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &operators.alldevs, errbuf) == -1)
    {
        fprintf(stderr, "���������豸ʧ��: %s\n", errbuf);
        exit(1);
    }

    // ��ӡ�豸�б�
    for (operators.choosed = operators.alldevs; operators.choosed; operators.choosed = operators.choosed->next)
    {
        cout << ++i << "." << operators.choosed->name;
        if (operators.choosed->description)
            cout << "(" << operators.choosed->description << ")" << endl;
        else
            cout << "(�޿�������)" << endl;
    }

    // �����ʱ i Ϊ 0 ��˵���豸�б�Ϊ�գ�Ҳ����û�в��ҵ��豸
    if (i == 0)
    {
        cout << "\nû�з��ֽӿڣ���ȷ���Ƿ�װ�� WinPcap.\n";
        exit(1);
    }

    // ѡ��Ҫʹ�õ��豸
    choose_use_device(i, inum);

    // ��ת��ѡ�е��豸
    for (operators.choosed = operators.alldevs, i = 0; i < inum - 1; operators.choosed = operators.choosed->next, i++);
    return operators;
}

// ���豸
pcap_t* open_device(alldevCho oper, char* errbuf, u_int& netmask, const char *packet_filter)
{
    pcap_t* adhandle;
    struct bpf_program fcode;
    // �򿪸��豸
    if ((adhandle = pcap_open(oper.choosed->name,   // �豸����
        65536,                                      // Ҫ����İ��Ĳ���
                                                    // 65536����������mac�ϲ����������ݰ�
        PCAP_OPENFLAG_PROMISCUOUS,                  // ����ģʽ
        1000,                                       // ��ʱʱ��
        NULL,                                       // Զ���豸�����֤��Ϣ
        errbuf                                      // ������Ϣ����
    )) == NULL)
    {
        fprintf(stderr, "\n�޷�����������WinPcap��֧�ִ��豸\n");
        pcap_freealldevs(oper.alldevs);
        exit(1);
    }

    // �����·�㡣Ϊ�˼������ֻ֧����̫��
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\n�˳������������̫��\n");
        pcap_freealldevs(oper.alldevs);
        exit(1);
    }

    if (oper.choosed->addresses != NULL)
        // �����ӿڵĵ�һ����ַ������
        netmask = ((struct sockaddr_in*)(oper.choosed->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        // ����ӿ�û�е�ַ��������Ϊ����һ��C��������
        netmask = 0xffffff;

    // ���������
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\n�޷������������������﷨\n");
        pcap_freealldevs(oper.alldevs);
        exit(1);
    }

    // ���ù�����
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\n���ð�������ʧ��\n");
        pcap_freealldevs(oper.alldevs);
        exit(1);
    }

    cout << "\n���ڼ����豸" << oper.choosed->description << "..." << endl;
    // ��ʱ�Ѿ�����Ҫ�����豸�ˣ�ֱ���ͷż���
    pcap_freealldevs(oper.alldevs);
    return adhandle;
}

// ��������
void start_catch(pcap_t* adhandle, int protocol_type)
{
    switch (protocol_type)
    {
    case 1:
        pcap_loop(adhandle, 0, packet_handler_udp, NULL);
        break;
    case 2:
        pcap_loop(adhandle, 0, packet_handler_tcp, NULL);
        break;
    case 3:
        pcap_loop(adhandle, 0, packet_handler_icmp, NULL);
        break;
    case 4:
        pcap_loop(adhandle, 0, packet_handler_arp, NULL);
        break;
    default:
        pcap_loop(adhandle, 0, packet_handler_udp, NULL);
        break;
    }
}

// �������ݰ�
u_char* make_packet(alldevCho oper)
{
    u_char packet[512];
    int protocol_choose; // �û�ѡ�񷢰�Э��
    cout << "���������ѡ�񷢰���Э�� (1.UDP  2.TCP  3.ICMP  4.ARP) : ";
    while (1)
    {
        // TODO: ������bug������Ƿ��ַ����һֱѭ����ͣ
        cin >> protocol_choose;
        if (protocol_choose < 1 || protocol_choose > 4)
            cout << "�������ѡ��Ƿ�������������: ";
        else
            break;
    }
    u_char Mac[6];
    ip_address local_ip_add = *get_local_ip(oper.choosed);      // ��ȡ�����豸�� IP ��ַ
    //mac_address local_mac_add = *get_local_mac(oper.choosed, Mac);    // ��ȡ�����豸�� MAC ��ַ
    eth_header eth_header = *make_pheader_eth();                // ������̫�����ݱ�ͷ
    ip_header ip_header = *make_pheader_ip(local_ip_add);       // ���� IP ���ݱ�ͷ

    int length_eth = sizeof(struct eth_header);
    int length_ip = sizeof(struct ip_header);
    // �ϰ�
    for (int i = 0; i < length_eth; i++)
        // TODO: �����и����⣬short �ȳ��ֽ�����ת char ʱ��ӵ�λ��ʼȡ����ô�ڻ�ԭ��ʱ��᲻�����˳�����
        packet[i] = ((u_char*)&eth_header)[i];
    for (int i = 0; i < length_ip; i++)
        // TODO: ���������ͬ��
        packet[length_eth + i] = ((u_char*)&ip_header)[i];
    // ���ݷ�����Э���趨�����������
    switch (protocol_choose)
	{
	case 1:     // UDP��
	{
		udp_header udp_header = *make_pheader_udp();
		int length_udp = sizeof(struct udp_header);
        for (int i = 0; i < length_udp; i++)
            // TODO: ���������ͬ��
            packet[length_eth + length_ip + i] = ((u_char*)&udp_header)[i];
        u_char* content = get_packet_content();
        for (int i = 0; i < 300; i++)
            packet[length_eth + length_ip + length_udp + i] = content[i];
		break;
	}
    case 2:     // TCP ��
    {
        tcp_header tcp_header = *make_pheader_tcp();
        int length_tcp = sizeof(struct tcp_header);
        for (int i = 0; i < length_tcp; i++)
            // TODO: ���������ͬ��
            packet[length_eth + length_ip + i] = ((u_char*)&tcp_header)[i];
        u_char* content = get_packet_content();
        for (int i = 0; i < 300; i++)
            packet[length_eth + length_ip + length_tcp + i] = content[i];
        break;
    }
    case 3:     // ICMP ��
    {
        icmp_header icmp_header = *make_pheader_icmp();
        int length_icmp = sizeof(struct icmp_header);
        for (int i = 0; i < length_icmp; i++)
            // TODO: ���������ͬ��
            packet[length_eth + length_ip + i] = ((u_char*)&icmp_header)[i];
        u_char* content = get_packet_content();
        for (int i = 0; i < 300; i++)
            packet[length_eth + length_ip + length_icmp + i] = content[i];
        break;
    }
    case 4:     // ARP ��
    {
        arp_header arp_header = *make_pheader_arp();
        int length_arp = sizeof(struct arp_header);
        arp_header.dest_mac = eth_header.dest_mac;
        arp_header.source_mac = eth_header.sour_mac;
        arp_header.dest_addr = eth_header.dest_mac;
        arp_header.dest_ip = ip_header.daddr;
        arp_header.sour_addr = eth_header.sour_mac;
        arp_header.sour_ip = ip_header.saddr;
        for (int i = 0; i < length_arp; i++)
            // ���������ͬ��
            packet[length_eth + length_ip + i] = ((u_char*)&arp_header)[i];
        u_char* content = get_packet_content();
        for (int i = 0; i < 300; i++)
            packet[length_eth + length_ip + length_arp + i] = content[i];
        break;
    }
	default:
		break;
	}  

    return packet;
}

// ��ȡѡ���豸�� IP ��ַ
ip_address* get_local_ip(pcap_if_t* dev)
{
    ip_address local_ip_add;
    u_int ip_add = 0;
    // ��ȡ IP ��ַ
    for (pcap_addr* pa = dev->addresses; pa; pa = pa->next)
    {
        if (pa->addr->sa_family == AF_INET)
            if (pa->addr)
            {
                ip_add = (((struct sockaddr_in*)pa->addr)->sin_addr.s_addr);
            }
    }
    if (ip_add == 0)        // ��ȡ���� ip ֵΪ0��˵��û�� ip
    {
        cout << "���豸û�� IPv4 ��ַ���볢�������豸��" << endl;
        exit(1);
    }
    // ���õ���10���� IP ת����2����
    local_ip_add.byte1 = ip_add & 255;
    local_ip_add.byte2 = (ip_add & (255 << 8)) >> 8;
    local_ip_add.byte3 = (ip_add & (255 << 16)) >> 16;
    local_ip_add.byte4 = (ip_add & (255 << 24)) >> 24;
    // ��ӡ����ip
    cout << "���豸�� IP ��ַΪ: ";
    cout << (int)local_ip_add.byte1 << "."
        << (int)local_ip_add.byte2 << "."
        << (int)local_ip_add.byte3 << "."
        << (int)local_ip_add.byte4 << endl;
    return &local_ip_add;
}

// ��ȡѡ���豸�� MAC ��ַ
mac_address* get_local_mac(pcap_if_t* dev, u_char ucMacAddr[])
{
    // TODO: ������Ҫ�޸ģ������޷�ʵ��
    mac_address local_mac_add;

    char *rename = new char[strlen(dev->name)-20];
    char realname[] = "//./Packet_";
    strncpy(rename, dev->name + 16, strlen(dev->name)-16);
    cout << "��Ƭ��: " << rename << endl;
    strcat(realname, rename);
    cout << "�ϲ���: " << realname << endl;

    LPADAPTER lpAdapter = PacketOpenAdapter(realname);
    cout << lpAdapter << endl;
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        cout << "�޷���ȡ���豸�� MAC ��ַ��ԭ��1��������ѡ�������豸" << endl;
    }
    PPACKET_OID_DATA oidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (NULL == oidData) {
        PacketCloseAdapter(lpAdapter);
        cout << "�޷���ȡ���豸�� MAC ��ַ��ԭ��2��������ѡ�������豸" << endl;
    }
    oidData->Oid = OID_802_3_CURRENT_ADDRESS;
    oidData->Length = 6;
    memset(oidData->Data, 0, 6);
    BOOLEAN  bStatus = PacketRequest(lpAdapter, FALSE, oidData);
    if (bStatus) {
        for (int i = 0; i < 6; ++i)
            ucMacAddr[i] = (oidData->Data)[i];
    }
    else {
        cout << "�޷���ȡ���豸�� MAC ��ַ��ԭ��3��������ѡ�������豸" << endl;
        free(oidData);
    }
    free(oidData);
    PacketCloseAdapter(lpAdapter);
    return 0;

    ////��ȡ������MAC��ַ����ӡ
    //PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PPACKET_OID_DATA));
    //OidData->Oid = OID_802_3_PERMANENT_ADDRESS;
    //OidData->Length = 6;
    //ZeroMemory(OidData->Data, 6);
    //BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData);
    //printf("The MAC address of the adapter is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
    //    (unsigned char)(OidData->Data)[0],
    //    (unsigned char)(OidData->Data)[1],
    //    (unsigned char)(OidData->Data)[2],
    //    (unsigned char)(OidData->Data)[3],
    //    (unsigned char)(OidData->Data)[4],
    //    (unsigned char)(OidData->Data)[5]);
    //PacketCloseAdapter(lpAdapter);//�ر��豸
}

// ������̫�����ݱ�ͷ
eth_header* make_pheader_eth()
{
    eth_header eth_header;
    // �û�����Ŀ���豸�� MAC ��ַ
    cout << "������Ŀ������ MAC ��ַ����д��ĸ+���֣��Կո�ָ�: ";
    u_short mac_addr_hex[6];
    for (int i = 0; i < 6; i++)
        cin >> hex >> mac_addr_hex[i];
    eth_header.dest_mac.byte1 = (u_char)mac_addr_hex[0];
    eth_header.dest_mac.byte2 = (u_char)mac_addr_hex[1];
    eth_header.dest_mac.byte3 = (u_char)mac_addr_hex[2];
    eth_header.dest_mac.byte4 = (u_char)mac_addr_hex[3];
    eth_header.dest_mac.byte5 = (u_char)mac_addr_hex[4];
    eth_header.dest_mac.byte6 = (u_char)mac_addr_hex[5];
    cout << dec << "Ŀ������ MAC ��ַΪ: "
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte1 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte2 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte3 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte4 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte5 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte6 << endl;

    cout << "������Դ������ MAC ��ַ����д��ĸ+���֣��Կո�ָ�: ";
    for (int i = 0; i < 6; i++)         // TODO:����ı��� MAC ��ʱ���������������Ҳ��Ϊ�� IP һ���Զ���ȡ
        cin >> hex >> mac_addr_hex[i];
    eth_header.sour_mac.byte1 = (char)mac_addr_hex[0];
    eth_header.sour_mac.byte2 = (char)mac_addr_hex[1];
    eth_header.sour_mac.byte3 = (char)mac_addr_hex[2];
    eth_header.sour_mac.byte4 = (char)mac_addr_hex[3];
    eth_header.sour_mac.byte5 = (char)mac_addr_hex[4];
    eth_header.sour_mac.byte6 = (char)mac_addr_hex[5];
    cout << dec << "Դ������ MAC ��ַΪ:  "
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte1 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte2 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte3 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte4 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte5 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte6 << endl;

    eth_header.eh_type = 2048;
    return &eth_header;
}

// ���� IP ���ݱ�ͷ
ip_header* make_pheader_ip(ip_address local_ip_add)
{
    ip_header ip_header;

    cout << dec << "������Ŀ�������� IP ��ַ���Կո�ָ�: ";
    u_short ip_addr[4];
    for (int i = 0; i < 4; i++)
        cin >> dec >> ip_addr[i];
    ip_header.daddr.byte1 = (char)ip_addr[0];
    ip_header.daddr.byte2 = (char)ip_addr[1];
    ip_header.daddr.byte3 = (char)ip_addr[2];
    ip_header.daddr.byte4 = (char)ip_addr[3];
    cout << dec << "Ŀ������ IP ��ַΪ: "
        << (int)ip_header.daddr.byte1 << "."
        << (int)ip_header.daddr.byte2 << "."
        << (int)ip_header.daddr.byte3 << "."
        << (int)ip_header.daddr.byte4 << endl;

    ip_header.saddr = local_ip_add;     // ����ı��� IP ���Զ���ȡ��
    cout << dec << "Դ������ IP ��ַΪ: "
        << (int)local_ip_add.byte1 << "."
        << (int)local_ip_add.byte2 << "."
        << (int)local_ip_add.byte3 << "."
        << (int)local_ip_add.byte4 << endl;

    // TODO: �û��趨 ip ���ݱ�ͷ


    return &ip_header;
}

// ���� UDP ���ݱ�ͷ
udp_header* make_pheader_udp()
{
    udp_header udp_header;
    cout << "\n������ UDP �ײ���Ϣ -> Ŀ�Ķ˿�: ";
    cin >> dec >> udp_header.dport;
    cout << "\n������ UDP �ײ���Ϣ -> Դ�˿�: " << endl;
    cin >> dec >> udp_header.sport;
    return &udp_header;
}

// ���� TCP ���ݱ�ͷ
tcp_header* make_pheader_tcp()
{
    tcp_header tcp_header;
    cout << "\n������ TCP �ײ���Ϣ -> Ŀ�Ķ˿�: ";
    cin >> dec >> tcp_header.dport;
    cout << "\n������ TCP �ײ���Ϣ -> Դ�˿�: ";
    cin >> dec >> tcp_header.sport;
    cout << "\n������ TCP �ײ���Ϣ -> ���: ";
    cin >> dec >> tcp_header.seril_num;
    cout << "\n������ TCP �ײ���Ϣ -> ȷ�Ϻ�: ";
    cin >> dec >> tcp_header.acknow_num;
    cout << "\n������ TCP �ײ���Ϣ -> ��־λ: (�ֱ�Ϊ URG ACK PSH RST SYN FIN)";
    cout << "\n��8λ0/1�����ʾ��־λ��Ϣ(����λ��0)��Ȼ��תΪ 16 ����������: ";
    u_short temp;
    cin >> hex >> temp;
    tcp_header.flags = (u_char)temp;
    return &tcp_header;
}

// ���� ICMP ���ݱ�ͷ
icmp_header* make_pheader_icmp()
{
    icmp_header icmp_header;
    cout << "\n������ ICMP �ײ���Ϣ -> ����(ת����10����): ";
    cin >> dec >> icmp_header.type;
    cout << "\n������ ICMP �ײ���Ϣ -> ����(ת����10����): ";
    cin >> dec >> icmp_header.code;
    return &icmp_header;
}

// ���� ARP ���ݱ�ͷ
arp_header* make_pheader_arp()
{
    arp_header arp_header;
    cout << "������ ARP ������ (1.�����  2.Ӧ���): ";
    cin >> arp_header.op;
    return &arp_header;
}

// ��ȡ���ݱ�����������
u_char* get_packet_content()
{
    cout << "������ 300 �ַ����ڵ�Ҫ���͵��������ݣ����� # ����\n ";
    u_char content[300];
    int i = 0;
    u_char x;
    cin >> x;
    while (x != '#')
    {
        content[i] = x;
        i++;
        cin >> x;
    }
    return content;
}

// �������ݰ�
void send_packet(alldevCho oper, char errbuf[], u_char packet[])
{
    pcap_t* choosed;
    if ((choosed = pcap_open(oper.choosed->name, 65536,
        PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        fprintf(stderr, "\n�޷����豸�����豸��֧�� Winpcap��\n");
        return;
    }
    if (pcap_sendpacket(choosed, packet, sizeof(packet)) != 0)
    {
        fprintf(stderr, "\n�������ݰ�ʧ��: %s\n", pcap_geterr(choosed));
        return;
    }
    // ��ʱ�Ѿ�����Ҫ�����豸�ˣ�ֱ���ͷż���
    pcap_freealldevs(oper.alldevs);
    cout << "�������ݰ��ɹ�!" << endl;
    return;
}

// UDP �ص��������������ݰ�
void packet_handler_udp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    eth_header* eth;
    ip_header* ih;
    udp_header* udph;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    // �ָ���̫��ͷ��λ��
    eth = (eth_header*)pkt_data;
    // �ָ� ip ͷ��λ��
    ih = (ip_header*)(pkt_data + 14);   // ��̫����ͷ����
    // �ָ� udp ͷ��λ��
    ip_len = (ih->ver_ihl & 0xf) * 4;   // ���˳� ip �ײ����ȣ����Ե�λ4���ֽڣ������ײ�ʵ�ʳ���
    udph = (udp_header*)((u_char*)ih + ip_len);
    // �������ֽ�˳��ת��Ϊ�����ֽ�˳��
    sport = ntohs(udph->sport);
    dport = ntohs(udph->dport);
    // ��ӡ ip ��˿���Ϣ
    show_catch_infos(header, eth, ih, true, sport, dport);
    // ��ӡ�ײ��ֶ�
    cout << "                     <- UDP �ײ��ֶ���Ϣ�� ->" << endl;
    cout << "................................................................." << endl;
    cout << "* \t16λԴ�˿ں�: " << sport;
    cout << "\t\t16λĿ�Ķ˿ں�: " << dport << "\t*" << endl;
    cout << "* \t16λ UDP ����: " << udph->len;
    cout << "\t\t16λУ���: " << udph->crc << "\t*" << endl;
    cout << "................................................................." << endl;
    // ��ӡ���ݲ���
    cout << "�ð�����������Ϊ:" << endl;
    for (int i = 1; i < header->caplen; i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }

    cout << endl;
}

// TCP �ص��������������ݰ�
void packet_handler_tcp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    eth_header* eth;
    ip_header* ih;
    tcp_header* tcph;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    // �ָ���̫��ͷ��λ��
    eth = (eth_header*)pkt_data;
    // �ָ� ip ͷ��λ��
    ih = (ip_header*)(pkt_data + 14); // ��̫����ͷ����
    // �ָ� tcp ͷ��λ��
    ip_len = (ih->ver_ihl & 0xf) * 4;  // ���˳� ip �ײ����ȣ����Ե�λ4���ֽڣ������ײ�ʵ�ʳ���
    tcph = (tcp_header*)((u_char*)ih + ip_len);
    // �������ֽ�˳��ת��Ϊ�����ֽ�˳��
    sport = ntohs(tcph->sport);
    dport = ntohs(tcph->dport);
    // ��ӡ ip ��ַ�� udp �˿�
    show_catch_infos(header, eth, ih, true, sport, dport);
    // ��ӡ�ײ��ֶ�
    cout << "                     <- TCP �ײ��ֶ���Ϣ�� ->" << endl;
    cout << "................................................................." << endl;
    cout << "* \t16λԴ�˿ں�: " << sport;
    cout << "\t\t16λĿ�Ķ˿ں�: " << dport << "\t*" << endl;
    cout << "* \t\t\t32λ���: " << tcph->seril_num << "\t\t\t*" << endl;
    cout << "* \t\t\t32λȷ�����:  " << tcph->acknow_num << "\t\t*" << endl;
    cout << "* 8λ�ײ�����+����" <<(int)tcph->offset_retain << "\t8λ��־" << (int)tcph->flags;
    cout << "*\t16λ���ڴ�С: " << tcph->window << "\t*" << endl;
    cout << "* \t16λУ���: " << tcph->crc;
    cout << "\t\t16λ����ָ��: " << tcph->urgency_pt << "\t\t*" << endl;
    cout << "*\t\t\t32λ��ѡ�ֶ�"<< tcph->op_pad << "\t\t\t*" << endl;
    cout << "................................................................." << endl;
    // ��ӡ���ݲ���
    cout << "�ð�����������Ϊ:" << endl;
    for (int i = 0; i < sizeof(pkt_data); i++)
        cout << pkt_data[14 + ip_len + 24 + i];
    // ��ӡ���ݲ���
    cout << "�ð�����������Ϊ:" << endl;
    for (int i = 1; i < header->caplen; i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }

    cout << endl;
    
}

// ICMP �ص��������������ݰ�
void packet_handler_icmp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    eth_header* eth;
    ip_header* ih;
    icmp_header* icmph;
    u_int ip_len;
    time_t local_tv_sec;

    // �ָ���̫��ͷ��λ��
    eth = (eth_header*)pkt_data;
    // �ָ� ip ͷ��λ��
    ih = (ip_header*)(pkt_data + 14); // ��̫����ͷ����
    // �ָ� tcp ͷ��λ��
    ip_len = (ih->ver_ihl & 0xf) * 4;  // ���˳� ip �ײ����ȣ����Ե�λ4���ֽڣ������ײ�ʵ�ʳ���
    icmph = (icmp_header*)((u_char*)ih + ip_len);
    // ��ӡ ip ��ַ�� udp �˿�
    show_catch_infos(header, eth, ih, false, 0, 0);
    // ��ӡ�ײ��ֶ�
    cout << "                     <- ICMP �ײ��ֶ���Ϣ�� ->" << endl;
    cout << "................................................................." << endl;
    cout << "*    8λ����: " << (int)icmph->type;
    cout << "    8λ����: " << (int)icmph->code;
    cout << "\t\t16λУ���: " << icmph->crc << "\t*" << endl;
    cout << "* \t16λ��ʶ��: " << icmph->flags;
    cout << "\t\t\t16λ���: " << icmph->seril_num << "\t\t*" << endl;
    cout << "*\t\t    32λѡ�� :  " << icmph->op << " \t\t\t*" << endl;
    cout << "................................................................." << endl;
    // ��ӡ���ݲ���
    cout << "�ð�����������Ϊ:" << endl;
    for (int i = 1; i < header->caplen; i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }
    cout << endl;
}

// ARP �ص��������������ݰ�
void packet_handler_arp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    eth_header* eth;
    ip_header* ih;
    arp_header* arph;
    u_int ip_len;
    time_t local_tv_sec;
    // �ָ���̫��ͷ��λ��
    eth = (eth_header*)pkt_data;
    // �ָ� ip ͷ��λ��
    ih = (ip_header*)(pkt_data + 14); // ��̫����ͷ����
    // �ָ� tcp ͷ��λ��
    ip_len = (ih->ver_ihl & 0xf) * 4;  // ���˳� ip �ײ����ȣ����Ե�λ4���ֽڣ������ײ�ʵ�ʳ���
    arph = (arp_header*)((u_char*)ih + ip_len);
    // ��ӡ ip ��ַ�� udp �˿�
    show_catch_infos(header, eth, ih, false, 0, 0);
    // ��ӡ�ײ��ֶ�
    cout << "                     <- ARP �ײ��ֶ���Ϣ�� ->" << endl;
    cout << "................................................................." << endl;
    cout << "*\t Ŀ������ MAC : "
        << arph->dest_mac.byte1 << ":" << arph->dest_mac.byte2 << ":"
        << arph->dest_mac.byte3 << ":" << arph->dest_mac.byte4 << ":"
        << arph->dest_mac.byte5 << ":" << arph->dest_mac.byte6 << "\t*" << endl;
    cout << "*\t Դ ���� MAC : "
        << arph->source_mac.byte1 << ":" << arph->source_mac.byte2 << ":"
        << arph->source_mac.byte3 << ":" << arph->source_mac.byte4 << ":"
        << arph->source_mac.byte5 << ":" << arph->source_mac.byte6 << "\t*" << endl;
    cout << "* \t16λ����: " << arph->et_type;
    cout << "\t16λӲ������: " << arph->hardware_type;
    cout << "\t16λЭ������: " << arph->protocol_type << "\t*" << endl;
    cout << "*8λӲ����ַ����: " << (int)arph->add_len;
    cout << "8λЭ���ַ����: " << (int)arph->pro_len;
    cout << "\t\t16λ����: " << arph->op << "\t*" << endl;
    cout << dec << "*\t Դ ���� MAC : " << hex
        << setw(2) << setfill('0') << (int)arph->sour_addr.byte1 << ":"
        << arph->sour_addr.byte2 << ":"
        << arph->sour_addr.byte3 << ":" 
        << arph->sour_addr.byte4 << ":"
        << arph->sour_addr.byte5 << ":" 
        << arph->sour_addr.byte6;
    cout << "\tԴ IP : "
        << arph->sour_ip.byte1 << ":" << arph->sour_ip.byte2 << ":"
        << arph->sour_ip.byte3 << ":" << arph->sour_ip.byte4 << "\t*" << endl;
    cout << "*\t Ŀ������ MAC : "
        << arph->dest_addr.byte1 << ":" << arph->dest_addr.byte2 << ":"
        << arph->dest_addr.byte3 << ":" << arph->dest_addr.byte4 << ":"
        << arph->dest_addr.byte5 << ":" << arph->dest_addr.byte6;
    cout << "\tĿ�� IP : "
        << arph->dest_ip.byte1 << ":" << arph->dest_ip.byte2 << ":"
        << arph->dest_ip.byte3 << ":" << arph->dest_ip.byte4 << "\t*" << endl;
    cout << "................................................................." << endl;
    // ��ӡ���ݲ���
    cout << "�ð�����������Ϊ:" << endl;
    for (int i = 1; i < header->caplen; i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }
    cout << endl;
}

// ץ�������Ϣ���--ͨ�ò��֣�ֻ��� ip �źͶ˿ں�
void show_catch_infos(const struct pcap_pkthdr* header, eth_header* eth, ip_header* ih, bool port, u_short sport, u_short dport)
{
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    // ��ʱ���ת��Ϊ�ɶ���ʽ
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
    // ��ӡʱ����ͳ���
    cout << "\n=================================================================" << endl;
    printf("%s.%.6d len:%d || ", timestr, header->ts.tv_usec, header->len);

    // ��ӡ ip ��ַ�� udp �˿�
    cout << (int)ih->saddr.byte1 << "."
        << (int)ih->saddr.byte2 << "."
        << (int)ih->saddr.byte3 << "."
        << (int)ih->saddr.byte4;
    if (port)
        cout << ":" << sport;
    cout << " -> ";
    cout << (int)ih->daddr.byte1 << "."
        << (int)ih->daddr.byte2 << "."
        << (int)ih->daddr.byte3 << "."
        << (int)ih->daddr.byte4;
    if(port)
        cout << ":" << dport;
    cout << endl;
    // ��̫����ͷ
    cout << "\n                       <- ��̫����ͷ ->" << endl;
    cout << "................................................................." << endl;
    cout << dec << "\tĿ�� MAC : " << hex
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte1 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte2 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte3 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte4 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte5 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte6;
    cout << dec << "\tԴ MAC : " << hex
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte1 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte2 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte3 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte4 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte5 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte6 << endl;
    cout << "\t\t\t    ����: " << dec << eth->eh_type << endl;
    cout << "................................................................." << endl;
    // ip ��ͷ
    cout << "                       <- ip  ��ͷ ->" << endl;
    cout << "................................................................." << endl;
    cout << "\t\t�汾: " << (((int)ih->ver_ihl) >> 4);
    cout << "    �ײ�����: " << (((int)ih->ver_ihl) & 0xf);
    cout << "\t��������: " << (int)ih->tos << endl;
    cout << "\t\t�ܳ���: " << ih->tlen << "\t\t��ʶ: " << ih->identification << endl;
    cout << "\t��־λ: "
        << ((ih->flags_fo) >> 15) << " "
        << (((ih->flags_fo) >> 14) & 0x1) << " "
        << (((ih->flags_fo) >> 13) & 0x1)
        << "\t��ƫ����: " << ((ih->flags_fo) & 0x1fff);
    cout << "\t���ʱ��: " << (int)ih->ttl << "  Э��:" << (int)ih->proto << endl;
    cout << "\t\t\t�ײ�У���: " << ih->crc << endl;
    cout << "\tԴ��ַ: "
        << (int)ih->saddr.byte1 << "."
        << (int)ih->saddr.byte2 << "."
        << (int)ih->saddr.byte3 << "."
        << (int)ih->saddr.byte4;
    cout << "\t\tĿ�ĵ�ַ: "
        << (int)ih->daddr.byte1 << "."
        << (int)ih->daddr.byte2 << "."
        << (int)ih->daddr.byte3 << "."
        << (int)ih->daddr.byte4 << endl;
    cout << "\t\t  ��ѡ�ֶ�+���: " << ih->op_pad << endl;
    cout << "................................................................." << endl;
}

#endif