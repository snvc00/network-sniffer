#pragma once
#include <pcap.h>

class NetworkAdapter {
public:
	pcap_if_t* adapter;
	char* adapterName;
	char* adapterDescription;
	NetworkAdapter();
	NetworkAdapter(pcap_if_t* _adapter, char* _adapterName, char* _adapterDescription);
};