#if 1
#define WIN32  
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
//#pragma pack(1)       // 按一字节对齐
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

// 选择工作模式
void choose_work_mode(int &mode_type);
// 选择协议类型
char* choose_protocol_type(int& protocol_type);
// 选择使用设备
void choose_use_device(int i, int& num);
// 查找设备与选择设备
alldevCho find_and_choose_dev(char *errbuf);
// 打开设备
pcap_t* open_device(alldevCho oper, char* errbuf, u_int &netmask, const char* packet_filter);
// 启动捕获
void start_catch(pcap_t* adhandle, int protocol_type);

// 制作数据包
u_char* make_packet(alldevCho oper);
// 获取主机设备 IP 地址
ip_address* get_local_ip(pcap_if_t* dev);
// 获取主机设备 MAC 地址
mac_address* get_local_mac(pcap_if_t* dev, u_char ucMacAddr[]);
int GetGateWayMac();
// 制作以太网数据报头
eth_header* make_pheader_eth();
// 制作 IP 数据报头
ip_header* make_pheader_ip(ip_address local_ip_add);
// 制作 UDP 数据报头
udp_header* make_pheader_udp();
// 制作 TCP 数据报头
tcp_header* make_pheader_tcp();
// 制作 ICMP 数据报头
icmp_header* make_pheader_icmp();
// 制作 ARP 数据报头
arp_header* make_pheader_arp();
// 获取数据报的数据内容
u_char* get_packet_content();
// 发送数据包
void send_packet(alldevCho oper, char errbuf[], u_char packet[]);

// UDP 回调函数，解析数据包
void packet_handler_udp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// TCP 回调函数，解析数据包
void packet_handler_tcp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// ICMP 回调函数，解析数据包
void packet_handler_icmp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// ARP 回调函数，解析数据包
void packet_handler_arp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// 抓包解包信息输出--通用部分，只输出 ip 号和端口号
void show_catch_infos(const struct pcap_pkthdr* header, eth_header* eth, ip_header* ih, bool port, u_short sport, u_short dport);


int GetAdapterMacAddr(char* lpszAdapterName, unsigned char ucMacAddr[]) {//获取mac地址的函数
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
    int inum;                           // 用户选择要操作的设备的序号
    int mode_type;                      // 工作模式，1.抓包、解包 2.做包、发包
    int protocol_type;                  // 协议类型，1.UDP协议 2.TCP协议 3.ICMP协议 4.ARP协议
    char errbuf[PCAP_ERRBUF_SIZE];      // 错误信息
    u_int netmask;                      // 掩码
    char *packet_filter;                // 过滤模式
    struct bpf_program fcode;

    choose_work_mode(mode_type);        // 选择工作模式

    if (mode_type == 1)                 // 工作模式为抓包、解包
    {
        packet_filter = choose_protocol_type(protocol_type);    // 选择解包协议
        alldevCho oper = find_and_choose_dev(errbuf);           // 查找并选择设备
        pcap_t* adhandle = open_device(oper, errbuf, netmask, packet_filter);      // 打开设备
        start_catch(adhandle, protocol_type);                   // 启动抓包
    }
    else {                              // 工作模式为做包、发包
        alldevCho oper = find_and_choose_dev(errbuf);           // 查找并选择设备
        u_char* packet = make_packet(oper);                     // 制作数据包
        send_packet(oper, errbuf, packet);                      // 发送数据包
    }

    return 0;
}

// 选择工作模式
void choose_work_mode(int& mode_type)
{
    cout << "请输入序号选择工作模式:     1.抓包、解包    2.做包、发包\n您的选择是: ";
	while (1)
	{
        // TODO: 这里有bug，输入非法字符后会一直循环不停
		cin >> mode_type;
		if (mode_type != 1 && mode_type != 2)
			cout << "您输入的选项非法，请重新输入: " << endl;
		else
			break;
	}
}

// 选择协议类型
char* choose_protocol_type(int& protocol_type)
{
    cout << "请输入序号选择要解析数据包的协议: \n  1.UDP协议  2.TCP协议  3.ICMP协议  4.ARP协议\n您的选择是: ";
    while (1)
    {
        // TODO: 这里有bug，输入非法字符后会一直循环不停
        cin >> protocol_type;
        if (protocol_type < 1 || protocol_type > 4)
            cout << "您输入的选项非法，请重新输入: ";
        else
            break;
    }
    // 设置过滤模式
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

// 选择使用设备
void choose_use_device(int i, int& inum)
{
    cout << "输入要操作的接口编号 (1-" << i << "), 输入数字0退出: ";
    while (1)
    {
        // TODO: 这里有bug，输入非法字符后会一直循环不停
        cin >> inum;
        if (inum == 0)
            exit(1);
        else if (inum < 1 || inum > i)
            cout << "\n您输入的编号不规范，请重新输入: ";
        else
            break;
    }
}

// 查找设备与选择设备
alldevCho find_and_choose_dev(char* errbuf)
{
    alldevCho operators;    // 操作元
    int inum;               // 用户选择要操作的设备的序号
    int i = 0;                  // 设备序号，输出设备列表用

    // 查找设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &operators.alldevs, errbuf) == -1)
    {
        fprintf(stderr, "查找主机设备失败: %s\n", errbuf);
        exit(1);
    }

    // 打印设备列表
    for (operators.choosed = operators.alldevs; operators.choosed; operators.choosed = operators.choosed->next)
    {
        cout << ++i << "." << operators.choosed->name;
        if (operators.choosed->description)
            cout << "(" << operators.choosed->description << ")" << endl;
        else
            cout << "(无可用描述)" << endl;
    }

    // 如果此时 i 为 0 ，说明设备列表为空，也就是没有查找到设备
    if (i == 0)
    {
        cout << "\n没有发现接口！请确认是否安装了 WinPcap.\n";
        exit(1);
    }

    // 选择要使用的设备
    choose_use_device(i, inum);

    // 跳转到选中的设备
    for (operators.choosed = operators.alldevs, i = 0; i < inum - 1; operators.choosed = operators.choosed->next, i++);
    return operators;
}

// 打开设备
pcap_t* open_device(alldevCho oper, char* errbuf, u_int& netmask, const char *packet_filter)
{
    pcap_t* adhandle;
    struct bpf_program fcode;
    // 打开该设备
    if ((adhandle = pcap_open(oper.choosed->name,   // 设备名称
        65536,                                      // 要捕获的包的部分
                                                    // 65536允许在所有mac上捕获整个数据包
        PCAP_OPENFLAG_PROMISCUOUS,                  // 混杂模式
        1000,                                       // 超时时间
        NULL,                                       // 远程设备身份验证信息
        errbuf                                      // 错误信息保存
    )) == NULL)
    {
        fprintf(stderr, "\n无法打开适配器，WinPcap不支持此设备\n");
        pcap_freealldevs(oper.alldevs);
        exit(1);
    }

    // 检查链路层。为了简单起见，只支持以太网
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\n此程序仅工作于以太网\n");
        pcap_freealldevs(oper.alldevs);
        exit(1);
    }

    if (oper.choosed->addresses != NULL)
        // 检索接口的第一个地址的掩码
        netmask = ((struct sockaddr_in*)(oper.choosed->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        // 如果接口没有地址，我们认为是在一个C类网络中
        netmask = 0xffffff;

    // 编译过滤器
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\n无法编译包过滤器，检查语法\n");
        pcap_freealldevs(oper.alldevs);
        exit(1);
    }

    // 设置过滤器
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\n设置包过滤器失败\n");
        pcap_freealldevs(oper.alldevs);
        exit(1);
    }

    cout << "\n正在监听设备" << oper.choosed->description << "..." << endl;
    // 此时已经不需要其他设备了，直接释放即可
    pcap_freealldevs(oper.alldevs);
    return adhandle;
}

// 启动捕获
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

// 制作数据包
u_char* make_packet(alldevCho oper)
{
    u_char packet[512];
    int protocol_choose; // 用户选择发包协议
    cout << "请输入序号选择发包的协议 (1.UDP  2.TCP  3.ICMP  4.ARP) : ";
    while (1)
    {
        // TODO: 这里有bug，输入非法字符后会一直循环不停
        cin >> protocol_choose;
        if (protocol_choose < 1 || protocol_choose > 4)
            cout << "您输入的选项非法！请重新输入: ";
        else
            break;
    }
    u_char Mac[6];
    ip_address local_ip_add = *get_local_ip(oper.choosed);      // 获取本机设备的 IP 地址
    //mac_address local_mac_add = *get_local_mac(oper.choosed, Mac);    // 获取本机设备的 MAC 地址
    eth_header eth_header = *make_pheader_eth();                // 制作以太网数据报头
    ip_header ip_header = *make_pheader_ip(local_ip_add);       // 制作 IP 数据报头

    int length_eth = sizeof(struct eth_header);
    int length_ip = sizeof(struct ip_header);
    // 合包
    for (int i = 0; i < length_eth; i++)
        // TODO: 这里有个问题，short 等长字节类型转 char 时会从低位开始取，那么在还原的时候会不会出现顺序错误
        packet[i] = ((u_char*)&eth_header)[i];
    for (int i = 0; i < length_ip; i++)
        // TODO: 这里的问题同上
        packet[length_eth + i] = ((u_char*)&ip_header)[i];
    // 根据发包的协议设定具体包的内容
    switch (protocol_choose)
	{
	case 1:     // UDP包
	{
		udp_header udp_header = *make_pheader_udp();
		int length_udp = sizeof(struct udp_header);
        for (int i = 0; i < length_udp; i++)
            // TODO: 这里的问题同上
            packet[length_eth + length_ip + i] = ((u_char*)&udp_header)[i];
        u_char* content = get_packet_content();
        for (int i = 0; i < 300; i++)
            packet[length_eth + length_ip + length_udp + i] = content[i];
		break;
	}
    case 2:     // TCP 包
    {
        tcp_header tcp_header = *make_pheader_tcp();
        int length_tcp = sizeof(struct tcp_header);
        for (int i = 0; i < length_tcp; i++)
            // TODO: 这里的问题同上
            packet[length_eth + length_ip + i] = ((u_char*)&tcp_header)[i];
        u_char* content = get_packet_content();
        for (int i = 0; i < 300; i++)
            packet[length_eth + length_ip + length_tcp + i] = content[i];
        break;
    }
    case 3:     // ICMP 包
    {
        icmp_header icmp_header = *make_pheader_icmp();
        int length_icmp = sizeof(struct icmp_header);
        for (int i = 0; i < length_icmp; i++)
            // TODO: 这里的问题同上
            packet[length_eth + length_ip + i] = ((u_char*)&icmp_header)[i];
        u_char* content = get_packet_content();
        for (int i = 0; i < 300; i++)
            packet[length_eth + length_ip + length_icmp + i] = content[i];
        break;
    }
    case 4:     // ARP 包
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
            // 这里的问题同上
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

// 获取选中设备的 IP 地址
ip_address* get_local_ip(pcap_if_t* dev)
{
    ip_address local_ip_add;
    u_int ip_add = 0;
    // 获取 IP 地址
    for (pcap_addr* pa = dev->addresses; pa; pa = pa->next)
    {
        if (pa->addr->sa_family == AF_INET)
            if (pa->addr)
            {
                ip_add = (((struct sockaddr_in*)pa->addr)->sin_addr.s_addr);
            }
    }
    if (ip_add == 0)        // 获取到的 ip 值为0，说明没有 ip
    {
        cout << "此设备没有 IPv4 地址，请尝试其他设备！" << endl;
        exit(1);
    }
    // 将得到的10进制 IP 转换成2进制
    local_ip_add.byte1 = ip_add & 255;
    local_ip_add.byte2 = (ip_add & (255 << 8)) >> 8;
    local_ip_add.byte3 = (ip_add & (255 << 16)) >> 16;
    local_ip_add.byte4 = (ip_add & (255 << 24)) >> 24;
    // 打印本机ip
    cout << "此设备的 IP 地址为: ";
    cout << (int)local_ip_add.byte1 << "."
        << (int)local_ip_add.byte2 << "."
        << (int)local_ip_add.byte3 << "."
        << (int)local_ip_add.byte4 << endl;
    return &local_ip_add;
}

// 获取选中设备的 MAC 地址
mac_address* get_local_mac(pcap_if_t* dev, u_char ucMacAddr[])
{
    // TODO: 这里需要修改，功能无法实现
    mac_address local_mac_add;

    char *rename = new char[strlen(dev->name)-20];
    char realname[] = "//./Packet_";
    strncpy(rename, dev->name + 16, strlen(dev->name)-16);
    cout << "切片后: " << rename << endl;
    strcat(realname, rename);
    cout << "合并后: " << realname << endl;

    LPADAPTER lpAdapter = PacketOpenAdapter(realname);
    cout << lpAdapter << endl;
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        cout << "无法获取此设备的 MAC 地址，原因1，请重新选择其他设备" << endl;
    }
    PPACKET_OID_DATA oidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (NULL == oidData) {
        PacketCloseAdapter(lpAdapter);
        cout << "无法获取此设备的 MAC 地址，原因2，请重新选择其他设备" << endl;
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
        cout << "无法获取此设备的 MAC 地址，原因3，请重新选择其他设备" << endl;
        free(oidData);
    }
    free(oidData);
    PacketCloseAdapter(lpAdapter);
    return 0;

    ////获取网卡的MAC地址并打印
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
    //PacketCloseAdapter(lpAdapter);//关闭设备
}

// 制作以太网数据报头
eth_header* make_pheader_eth()
{
    eth_header eth_header;
    // 用户输入目的设备的 MAC 地址
    cout << "请输入目的主机 MAC 地址，大写字母+数字，以空格分隔: ";
    u_short mac_addr_hex[6];
    for (int i = 0; i < 6; i++)
        cin >> hex >> mac_addr_hex[i];
    eth_header.dest_mac.byte1 = (u_char)mac_addr_hex[0];
    eth_header.dest_mac.byte2 = (u_char)mac_addr_hex[1];
    eth_header.dest_mac.byte3 = (u_char)mac_addr_hex[2];
    eth_header.dest_mac.byte4 = (u_char)mac_addr_hex[3];
    eth_header.dest_mac.byte5 = (u_char)mac_addr_hex[4];
    eth_header.dest_mac.byte6 = (u_char)mac_addr_hex[5];
    cout << dec << "目的主机 MAC 地址为: "
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte1 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte2 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte3 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte4 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte5 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.dest_mac.byte6 << endl;

    cout << "请输入源主机的 MAC 地址，大写字母+数字，以空格分隔: ";
    for (int i = 0; i < 6; i++)         // TODO:这里的本机 MAC 暂时由输入决定，后期也改为和 IP 一样自动获取
        cin >> hex >> mac_addr_hex[i];
    eth_header.sour_mac.byte1 = (char)mac_addr_hex[0];
    eth_header.sour_mac.byte2 = (char)mac_addr_hex[1];
    eth_header.sour_mac.byte3 = (char)mac_addr_hex[2];
    eth_header.sour_mac.byte4 = (char)mac_addr_hex[3];
    eth_header.sour_mac.byte5 = (char)mac_addr_hex[4];
    eth_header.sour_mac.byte6 = (char)mac_addr_hex[5];
    cout << dec << "源主机的 MAC 地址为:  "
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte1 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte2 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte3 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte4 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte5 << "-"
        << hex << setw(2) << setfill('0') << (int)eth_header.sour_mac.byte6 << endl;

    eth_header.eh_type = 2048;
    return &eth_header;
}

// 制作 IP 数据报头
ip_header* make_pheader_ip(ip_address local_ip_add)
{
    ip_header ip_header;

    cout << dec << "请输入目的主机的 IP 地址，以空格分隔: ";
    u_short ip_addr[4];
    for (int i = 0; i < 4; i++)
        cin >> dec >> ip_addr[i];
    ip_header.daddr.byte1 = (char)ip_addr[0];
    ip_header.daddr.byte2 = (char)ip_addr[1];
    ip_header.daddr.byte3 = (char)ip_addr[2];
    ip_header.daddr.byte4 = (char)ip_addr[3];
    cout << dec << "目的主机 IP 地址为: "
        << (int)ip_header.daddr.byte1 << "."
        << (int)ip_header.daddr.byte2 << "."
        << (int)ip_header.daddr.byte3 << "."
        << (int)ip_header.daddr.byte4 << endl;

    ip_header.saddr = local_ip_add;     // 这里的本机 IP 是自动获取的
    cout << dec << "源主机的 IP 地址为: "
        << (int)local_ip_add.byte1 << "."
        << (int)local_ip_add.byte2 << "."
        << (int)local_ip_add.byte3 << "."
        << (int)local_ip_add.byte4 << endl;

    // TODO: 用户设定 ip 数据报头


    return &ip_header;
}

// 制作 UDP 数据报头
udp_header* make_pheader_udp()
{
    udp_header udp_header;
    cout << "\n请输入 UDP 首部信息 -> 目的端口: ";
    cin >> dec >> udp_header.dport;
    cout << "\n请输入 UDP 首部信息 -> 源端口: " << endl;
    cin >> dec >> udp_header.sport;
    return &udp_header;
}

// 制作 TCP 数据报头
tcp_header* make_pheader_tcp()
{
    tcp_header tcp_header;
    cout << "\n请输入 TCP 首部信息 -> 目的端口: ";
    cin >> dec >> tcp_header.dport;
    cout << "\n请输入 TCP 首部信息 -> 源端口: ";
    cin >> dec >> tcp_header.sport;
    cout << "\n请输入 TCP 首部信息 -> 序号: ";
    cin >> dec >> tcp_header.seril_num;
    cout << "\n请输入 TCP 首部信息 -> 确认号: ";
    cin >> dec >> tcp_header.acknow_num;
    cout << "\n请输入 TCP 首部信息 -> 标志位: (分别为 URG ACK PSH RST SYN FIN)";
    cout << "\n用8位0/1代码表示标志位信息(高两位置0)，然后转为 16 进制数输入: ";
    u_short temp;
    cin >> hex >> temp;
    tcp_header.flags = (u_char)temp;
    return &tcp_header;
}

// 制作 ICMP 数据报头
icmp_header* make_pheader_icmp()
{
    icmp_header icmp_header;
    cout << "\n请输入 ICMP 首部信息 -> 类型(转化成10进制): ";
    cin >> dec >> icmp_header.type;
    cout << "\n请输入 ICMP 首部信息 -> 代码(转化成10进制): ";
    cin >> dec >> icmp_header.code;
    return &icmp_header;
}

// 制作 ARP 数据报头
arp_header* make_pheader_arp()
{
    arp_header arp_header;
    cout << "请输入 ARP 包类型 (1.请求包  2.应答包): ";
    cin >> arp_header.op;
    return &arp_header;
}

// 获取数据报的数据内容
u_char* get_packet_content()
{
    cout << "请输入 300 字符以内的要发送的数据内容，输入 # 结束\n ";
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

// 发送数据包
void send_packet(alldevCho oper, char errbuf[], u_char packet[])
{
    pcap_t* choosed;
    if ((choosed = pcap_open(oper.choosed->name, 65536,
        PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        fprintf(stderr, "\n无法打开设备，该设备不支持 Winpcap！\n");
        return;
    }
    if (pcap_sendpacket(choosed, packet, sizeof(packet)) != 0)
    {
        fprintf(stderr, "\n发送数据包失败: %s\n", pcap_geterr(choosed));
        return;
    }
    // 此时已经不需要其他设备了，直接释放即可
    pcap_freealldevs(oper.alldevs);
    cout << "发送数据包成功!" << endl;
    return;
}

// UDP 回调函数，解析数据包
void packet_handler_udp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    eth_header* eth;
    ip_header* ih;
    udp_header* udph;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    // 恢复以太网头的位置
    eth = (eth_header*)pkt_data;
    // 恢复 ip 头的位置
    ih = (ip_header*)(pkt_data + 14);   // 以太网报头长度
    // 恢复 udp 头的位置
    ip_len = (ih->ver_ihl & 0xf) * 4;   // 过滤出 ip 首部长度，乘以单位4个字节，就是首部实际长度
    udph = (udp_header*)((u_char*)ih + ip_len);
    // 将网络字节顺序转换为主机字节顺序
    sport = ntohs(udph->sport);
    dport = ntohs(udph->dport);
    // 打印 ip 与端口信息
    show_catch_infos(header, eth, ih, true, sport, dport);
    // 打印首部字段
    cout << "                     <- UDP 首部字段信息表 ->" << endl;
    cout << "................................................................." << endl;
    cout << "* \t16位源端口号: " << sport;
    cout << "\t\t16位目的端口号: " << dport << "\t*" << endl;
    cout << "* \t16位 UDP 长度: " << udph->len;
    cout << "\t\t16位校验和: " << udph->crc << "\t*" << endl;
    cout << "................................................................." << endl;
    // 打印数据部分
    cout << "该包的数据内容为:" << endl;
    for (int i = 1; i < header->caplen; i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }

    cout << endl;
}

// TCP 回调函数，解析数据包
void packet_handler_tcp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    eth_header* eth;
    ip_header* ih;
    tcp_header* tcph;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    // 恢复以太网头的位置
    eth = (eth_header*)pkt_data;
    // 恢复 ip 头的位置
    ih = (ip_header*)(pkt_data + 14); // 以太网报头长度
    // 恢复 tcp 头的位置
    ip_len = (ih->ver_ihl & 0xf) * 4;  // 过滤出 ip 首部长度，乘以单位4个字节，就是首部实际长度
    tcph = (tcp_header*)((u_char*)ih + ip_len);
    // 将网络字节顺序转换为主机字节顺序
    sport = ntohs(tcph->sport);
    dport = ntohs(tcph->dport);
    // 打印 ip 地址和 udp 端口
    show_catch_infos(header, eth, ih, true, sport, dport);
    // 打印首部字段
    cout << "                     <- TCP 首部字段信息表 ->" << endl;
    cout << "................................................................." << endl;
    cout << "* \t16位源端口号: " << sport;
    cout << "\t\t16位目的端口号: " << dport << "\t*" << endl;
    cout << "* \t\t\t32位序号: " << tcph->seril_num << "\t\t\t*" << endl;
    cout << "* \t\t\t32位确认序号:  " << tcph->acknow_num << "\t\t*" << endl;
    cout << "* 8位首部长度+保留" <<(int)tcph->offset_retain << "\t8位标志" << (int)tcph->flags;
    cout << "*\t16位窗口大小: " << tcph->window << "\t*" << endl;
    cout << "* \t16位校验和: " << tcph->crc;
    cout << "\t\t16位紧急指针: " << tcph->urgency_pt << "\t\t*" << endl;
    cout << "*\t\t\t32位可选字段"<< tcph->op_pad << "\t\t\t*" << endl;
    cout << "................................................................." << endl;
    // 打印数据部分
    cout << "该包的数据内容为:" << endl;
    for (int i = 0; i < sizeof(pkt_data); i++)
        cout << pkt_data[14 + ip_len + 24 + i];
    // 打印数据部分
    cout << "该包的数据内容为:" << endl;
    for (int i = 1; i < header->caplen; i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }

    cout << endl;
    
}

// ICMP 回调函数，解析数据包
void packet_handler_icmp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    eth_header* eth;
    ip_header* ih;
    icmp_header* icmph;
    u_int ip_len;
    time_t local_tv_sec;

    // 恢复以太网头的位置
    eth = (eth_header*)pkt_data;
    // 恢复 ip 头的位置
    ih = (ip_header*)(pkt_data + 14); // 以太网报头长度
    // 恢复 tcp 头的位置
    ip_len = (ih->ver_ihl & 0xf) * 4;  // 过滤出 ip 首部长度，乘以单位4个字节，就是首部实际长度
    icmph = (icmp_header*)((u_char*)ih + ip_len);
    // 打印 ip 地址和 udp 端口
    show_catch_infos(header, eth, ih, false, 0, 0);
    // 打印首部字段
    cout << "                     <- ICMP 首部字段信息表 ->" << endl;
    cout << "................................................................." << endl;
    cout << "*    8位类型: " << (int)icmph->type;
    cout << "    8位代码: " << (int)icmph->code;
    cout << "\t\t16位校验和: " << icmph->crc << "\t*" << endl;
    cout << "* \t16位标识符: " << icmph->flags;
    cout << "\t\t\t16位序号: " << icmph->seril_num << "\t\t*" << endl;
    cout << "*\t\t    32位选项 :  " << icmph->op << " \t\t\t*" << endl;
    cout << "................................................................." << endl;
    // 打印数据部分
    cout << "该包的数据内容为:" << endl;
    for (int i = 1; i < header->caplen; i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }
    cout << endl;
}

// ARP 回调函数，解析数据包
void packet_handler_arp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    eth_header* eth;
    ip_header* ih;
    arp_header* arph;
    u_int ip_len;
    time_t local_tv_sec;
    // 恢复以太网头的位置
    eth = (eth_header*)pkt_data;
    // 恢复 ip 头的位置
    ih = (ip_header*)(pkt_data + 14); // 以太网报头长度
    // 恢复 tcp 头的位置
    ip_len = (ih->ver_ihl & 0xf) * 4;  // 过滤出 ip 首部长度，乘以单位4个字节，就是首部实际长度
    arph = (arp_header*)((u_char*)ih + ip_len);
    // 打印 ip 地址和 udp 端口
    show_catch_infos(header, eth, ih, false, 0, 0);
    // 打印首部字段
    cout << "                     <- ARP 首部字段信息表 ->" << endl;
    cout << "................................................................." << endl;
    cout << "*\t 目的主机 MAC : "
        << arph->dest_mac.byte1 << ":" << arph->dest_mac.byte2 << ":"
        << arph->dest_mac.byte3 << ":" << arph->dest_mac.byte4 << ":"
        << arph->dest_mac.byte5 << ":" << arph->dest_mac.byte6 << "\t*" << endl;
    cout << "*\t 源 主机 MAC : "
        << arph->source_mac.byte1 << ":" << arph->source_mac.byte2 << ":"
        << arph->source_mac.byte3 << ":" << arph->source_mac.byte4 << ":"
        << arph->source_mac.byte5 << ":" << arph->source_mac.byte6 << "\t*" << endl;
    cout << "* \t16位类型: " << arph->et_type;
    cout << "\t16位硬件类型: " << arph->hardware_type;
    cout << "\t16位协议类型: " << arph->protocol_type << "\t*" << endl;
    cout << "*8位硬件地址长度: " << (int)arph->add_len;
    cout << "8位协议地址长度: " << (int)arph->pro_len;
    cout << "\t\t16位操作: " << arph->op << "\t*" << endl;
    cout << dec << "*\t 源 主机 MAC : " << hex
        << setw(2) << setfill('0') << (int)arph->sour_addr.byte1 << ":"
        << arph->sour_addr.byte2 << ":"
        << arph->sour_addr.byte3 << ":" 
        << arph->sour_addr.byte4 << ":"
        << arph->sour_addr.byte5 << ":" 
        << arph->sour_addr.byte6;
    cout << "\t源 IP : "
        << arph->sour_ip.byte1 << ":" << arph->sour_ip.byte2 << ":"
        << arph->sour_ip.byte3 << ":" << arph->sour_ip.byte4 << "\t*" << endl;
    cout << "*\t 目的主机 MAC : "
        << arph->dest_addr.byte1 << ":" << arph->dest_addr.byte2 << ":"
        << arph->dest_addr.byte3 << ":" << arph->dest_addr.byte4 << ":"
        << arph->dest_addr.byte5 << ":" << arph->dest_addr.byte6;
    cout << "\t目的 IP : "
        << arph->dest_ip.byte1 << ":" << arph->dest_ip.byte2 << ":"
        << arph->dest_ip.byte3 << ":" << arph->dest_ip.byte4 << "\t*" << endl;
    cout << "................................................................." << endl;
    // 打印数据部分
    cout << "该包的数据内容为:" << endl;
    for (int i = 1; i < header->caplen; i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }
    cout << endl;
}

// 抓包解包信息输出--通用部分，只输出 ip 号和端口号
void show_catch_infos(const struct pcap_pkthdr* header, eth_header* eth, ip_header* ih, bool port, u_short sport, u_short dport)
{
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    // 将时间戳转换为可读格式
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
    // 打印时间戳和长度
    cout << "\n=================================================================" << endl;
    printf("%s.%.6d len:%d || ", timestr, header->ts.tv_usec, header->len);

    // 打印 ip 地址和 udp 端口
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
    // 以太网报头
    cout << "\n                       <- 以太网报头 ->" << endl;
    cout << "................................................................." << endl;
    cout << dec << "\t目的 MAC : " << hex
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte1 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte2 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte3 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte4 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte5 << "-"
        << setw(2) << setfill('0') << (int)eth->dest_mac.byte6;
    cout << dec << "\t源 MAC : " << hex
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte1 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte2 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte3 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte4 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte5 << "-"
        << setw(2) << setfill('0') << (int)eth->sour_mac.byte6 << endl;
    cout << "\t\t\t    类型: " << dec << eth->eh_type << endl;
    cout << "................................................................." << endl;
    // ip 报头
    cout << "                       <- ip  报头 ->" << endl;
    cout << "................................................................." << endl;
    cout << "\t\t版本: " << (((int)ih->ver_ihl) >> 4);
    cout << "    首部长度: " << (((int)ih->ver_ihl) & 0xf);
    cout << "\t服务类型: " << (int)ih->tos << endl;
    cout << "\t\t总长度: " << ih->tlen << "\t\t标识: " << ih->identification << endl;
    cout << "\t标志位: "
        << ((ih->flags_fo) >> 15) << " "
        << (((ih->flags_fo) >> 14) & 0x1) << " "
        << (((ih->flags_fo) >> 13) & 0x1)
        << "\t段偏移量: " << ((ih->flags_fo) & 0x1fff);
    cout << "\t存活时间: " << (int)ih->ttl << "  协议:" << (int)ih->proto << endl;
    cout << "\t\t\t首部校验和: " << ih->crc << endl;
    cout << "\t源地址: "
        << (int)ih->saddr.byte1 << "."
        << (int)ih->saddr.byte2 << "."
        << (int)ih->saddr.byte3 << "."
        << (int)ih->saddr.byte4;
    cout << "\t\t目的地址: "
        << (int)ih->daddr.byte1 << "."
        << (int)ih->daddr.byte2 << "."
        << (int)ih->daddr.byte3 << "."
        << (int)ih->daddr.byte4 << endl;
    cout << "\t\t  可选字段+填充: " << ih->op_pad << endl;
    cout << "................................................................." << endl;
}

#endif