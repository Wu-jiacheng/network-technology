#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning( disable : 4996 )
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;
#pragma pack(1)  
//帧的首部
struct e_head 
{
	uint8_t ether_dst[6];  
	uint8_t ether_src[6];  
	uint16_t ether_type;      
};
//IP的首部
struct ip_head 
{
	uint8_t ip_header_length : 4,ip_version : 4;
	uint8_t tos;         
	uint16_t total_length;  
	uint16_t ip_id;         
	uint16_t ip_offset;       
	uint8_t ttl;            
	uint8_t ip_protocol;     
	uint16_t ip_checksum;  
	uint16_t cal_checksum();
	struct in_addr  ip_source_address;
	struct in_addr ip_destination_address; 
};

uint16_t ip_head::cal_checksum()
{
	uint32_t cal_checksum = 0;
	uint16_t var1 = (((this->ip_version << 4) + this->ip_header_length) << 8) + this->tos;
	uint16_t var2 = (this->ttl << 8) + this->ip_protocol;
	uint16_t var3 = ntohl(this->ip_source_address.S_un.S_addr) >> 16;
	uint16_t var4 = ntohl(this->ip_source_address.S_un.S_addr);
	uint16_t var5 = ntohl(this->ip_destination_address.S_un.S_addr) >> 16;
	uint16_t var6 = ntohl(this->ip_destination_address.S_un.S_addr);
	cal_checksum = cal_checksum + var1 + ntohs(this->total_length) + ntohs(this->ip_id) + ntohs(this->ip_offset) + var2 + var3 + var4 + var5 + var6;
	cal_checksum = (cal_checksum >> 16) + (cal_checksum & 0xffff);
	cal_checksum += (cal_checksum >> 16);
	return (uint16_t)(~cal_checksum);
}
//分析IP数据包
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	ip_head* ip_protocol; 
	uint32_t  head_length; 
	uint16_t  offset;         
	uint8_t  tos;            
	uint16_t checksum;       
	ip_protocol = (struct ip_head*)(packet_content + 14); 
	checksum = ntohs(ip_protocol->ip_checksum);      
	head_length = ip_protocol->ip_header_length * 4; 
	tos = ip_protocol->tos;    
	offset = ntohs(ip_protocol->ip_offset);   
	cout << "-----------解析IP层数据包----------- " << endl;
	printf("IP版本:IPv%d\n", ip_protocol->ip_version);
	cout << "IP协议首部长度:" << head_length << endl;
	printf("服务类型:%d\n", tos);
	cout << "数据包总长度:" << ntohs(ip_protocol->total_length) << endl;
	cout << "标识:" << ntohs(ip_protocol->ip_id) << endl;
	cout << "片偏移:" << (offset & 0x1fff) * 8 << endl;
	cout << "生存时间:" << int(ip_protocol->ttl) << endl;
	cout << "首部检验和:" << htons(checksum) << endl;
	cout << "(计算所得)首部检验和:" << htons(ip_protocol->cal_checksum()) << endl;
	char src[17];
	::inet_ntop(AF_INET, (const void*)&ip_protocol->ip_source_address, src, 17);
	cout << "源IP地址:" << src << endl;
	char dst[17];
	::inet_ntop(AF_INET, (const void*)&ip_protocol->ip_destination_address, dst, 17);
	cout << "目的IP:" << dst << endl;
	printf("协议号:%d\n", ip_protocol->ip_protocol);
	cout << "传输层协议是:";
	switch (ip_protocol->ip_protocol)
	{
	case 1:
		cout << "ICMP" << endl;
		break;
	case 2:
		cout << "IGMP" << endl;
		break;
	case 3:
		cout << "GGP" << endl;
		break;
	case 6:
		cout << "TCP" << endl;
		break;
	case 8:
		cout << "EGP" << endl;
		break;
	case 17:
		cout << "UDP" << endl;
		break;
	case 89:
		cout << "OSPF" << endl;
		break;
	default:break;
	}
}
//解析数据链路层，获取MAC地址
void epp_callback(u_char* argument, const pcap_pkthdr* packet_header, const u_char* packet_content)
{
	uint16_t e_type; 
	e_head* e_protocol = (e_head*)packet_content;  
	uint8_t* mac_src;
	uint8_t* mac_dst;
	static int packet_number = 1;
	e_type = ntohs(e_protocol->ether_type); 
	e_protocol = (e_head*)packet_content;  
	mac_src = e_protocol->ether_src;
	mac_dst = e_protocol->ether_dst;
	cout << endl;
	printf("第[ %d ]个IP数据包被捕获\n", packet_number);
	cout << "----------链路层协议---------" << endl;;
	printf("以太网的类型为 :%04x\n", e_type);
	switch (e_type)
	{
	case 0x0800:
		cout << "网络层使用的是IPv4协议" << endl;
		break;
	case 0x0806:
		cout << "网络层使用的是ARP协议" << endl;
		break;
	case 0x8035:
		cout << "网络层使用的是RARP协议" << endl;
		break;
	default: break;
	}
	printf("Mac源地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_src, *(mac_src + 1), *(mac_src + 2), *(mac_src + 3), *(mac_src + 4), *(mac_src + 5));//X 表示以十六进制形式输出 02 表示不足两位，前面补0输出
	printf("Mac目的地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_dst, *(mac_dst + 1), *(mac_dst + 2), *(mac_dst + 3), *(mac_dst + 4), *(mac_dst + 5));
	switch (e_type)
	{
	case 0x0800:
		ip_protocol_packet_callback(argument, packet_header, packet_content);
		break;
	default:
		cout << "不是IP数据包，不进行解析" << endl;
		break;
	}
	packet_number++;
}
void Catch()
{
	pcap_if_t* allAdapters;    
	pcap_if_t* ptr;           
	pcap_t* pcap_handle;   
	int index = 0;
	int num = 0; 
	int i = 0; 
	char errbuf[PCAP_ERRBUF_SIZE];
	int flag = 0;
	char packet_filter[40] = ""; 
	struct bpf_program fcode;
	u_int netmask;
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
		{
			++index;
			if (ptr->description)
				printf("ID %d  Name: %s \n", index, ptr->description);
		}
	}
	if (index == 0)
	{
		cout << "没有找到接口，请确认是否安装了Npcap或WinPcap" << endl;
	}
	cout << "请输入要获取数据包的ID" << endl;
	cin >> num;
	if (num < 1 || num > index)
	{
		cout << "ID不在上述列表中" << endl;
		pcap_freealldevs(allAdapters);
	}
	for (ptr = allAdapters, i = 0; i < num - 1; ptr = ptr->next, i++);
	if ((pcap_handle = pcap_open_live(ptr->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,errbuf)) == NULL)
	{
		cout << "无法打开适配器,Npcap不支持" << endl;
		pcap_freealldevs(allAdapters);
		exit(0);
	}
	cout << "正在监听" << ptr->description << endl;
	pcap_freealldevs(allAdapters);
	int cnt = -1;
	cout << "请输入想要捕获的数据包个数:" << endl;
	cin >> cnt;
	pcap_loop(pcap_handle, cnt, epp_callback, NULL);
	cout << "解析ip数据包结束" << endl;
}
int main()
{
	Catch();
	return 0;
} 