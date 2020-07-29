#pragma once

#pragma warning(disable:4244)
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WINPCAP_H_INCLUDED
#define _CRT_SECURE_NO_WARNINGS

#include <iostream> 
#include <string>
#include <vector>
#include <fstream>
#include <bitset>
#include <time.h>
#include <Windows.h>
#include "packet-segmentation-enums.h"
//#include <pcap/pcap.h>

class Packet {
public:
	Packet();
	~Packet();

	unsigned int BinaryToInteger_256bits(const unsigned int _initBit, const unsigned int _endBit, std::vector<unsigned char>& _packetArrayBits) const;
	unsigned char ByteToChar(const unsigned int byte_position, std::vector<unsigned char>& _packetArrayBytes) const;

	void Ethernet(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits);
	void IPv4(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits);
	void ICMPv4(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits);
	void ARP_RARP(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits);
	void IPv6(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits);
	void ICMPv6(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits);
	void TCP(const unsigned int start_bit, const unsigned int& next_protocol, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits);
	void UDP(const unsigned int start_bit, const unsigned int& next_protocol, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits);
	void DNS(const unsigned int start_bit);

	//void PCAP_Listener();

	bool TPC_UDP_PortCategoryEvaluation(const unsigned int& port) const;
	void DNS_Question_Fields_Evalaution(const unsigned int start_bit);
	void DNS_Answer_Fields_Evalaution(const unsigned int start_bit);
};
