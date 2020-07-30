#pragma once

#include <pcap.h>
#include "packet.h"
#include "network_adapter.h"

class AdapterPacket : private Packet {
private:
	unsigned int selectedAdapter;
	std::vector<unsigned char> packetArrayBytes;
	std::vector<unsigned char> packetArrayBits;
	std::vector<NetworkAdapter> networkAdapters;
	std::string status;
	void PacketDataInitialization();
	void PacketShowData();
public:
	AdapterPacket();
	AdapterPacket(std::vector<NetworkAdapter>& _networkAdapters);
	~AdapterPacket();
	void ShowAdapters();
	const std::string TaskStatus();
	void SelectorEvent(int _selectorValue);
};
