#include "network_adapter.h"

NetworkAdapter::NetworkAdapter()
{}

NetworkAdapter::NetworkAdapter(pcap_if_t* _adapter, char* _adapterName, char* _adapterDescription)
	:adapter(_adapter), adapterName(_adapterName), adapterDescription(_adapterDescription)
{}
