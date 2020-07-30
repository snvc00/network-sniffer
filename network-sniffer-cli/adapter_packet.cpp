#include "adapter_packet.h"

void AdapterPacket::PacketDataInitialization()
{
	char errorBuffer[PCAP_ERRBUF_SIZE];
	pcap_t* session = pcap_open_live(networkAdapters[selectedAdapter].adapterName, BUFSIZ, 1, 0, errorBuffer);
	
	if (session == NULL) {
		SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FORERED);
		std::cout << "\n Error: " << errorBuffer << "\n";
		std::cin.get();
		SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);
		return;
	}

	const u_char* buffer;
	struct pcap_pkthdr header;
	std::string temporalBits;

	buffer = pcap_next(session, &header);

	if (packetArrayBytes.size())
		packetArrayBytes.clear();
	if (packetArrayBits.size())
		packetArrayBits.clear();

	for (bpf_u_int32 i(0); i < header.len; ++i)
		packetArrayBytes.emplace_back(buffer[i]);

	for (unsigned int i = 14; i < packetArrayBytes.size(); ++i) {
		temporalBits = std::bitset<8>(packetArrayBytes[i]).to_string();

		for (int j = 0; j < 8; ++j)
			packetArrayBits.push_back(temporalBits[j]);
	}

	system("cls");

	status = "Packet readed";

	std::cout << "\n Adapter: ";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREPURPLE);
	std::cout << networkAdapters[selectedAdapter].adapterDescription;
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);
	std::cout << "\n Adapter device: " << networkAdapters[selectedAdapter].adapterName;
	std::cout << "\n Status: ";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FORELIME);
	std::cout << status << "\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);
	std::cout << " Packet size: " << header.len << " bytes\n";
	std::cout << " Time stamp: " << header.ts.tv_sec << " seconds\n\n";

	PacketShowData();
	status = "Finished";
}

void AdapterPacket::PacketShowData()
{
	Ethernet(packetArrayBytes, packetArrayBits);
}

AdapterPacket::AdapterPacket()
	: selectedAdapter(0U), packetArrayBytes{}, packetArrayBits{}, networkAdapters{}, status("Initializating")
{}

AdapterPacket::AdapterPacket(std::vector<NetworkAdapter>& _networkAdapters)
	: selectedAdapter(0U), packetArrayBytes{}, packetArrayBits{}, networkAdapters(_networkAdapters), status("Initializating")
{}

AdapterPacket::~AdapterPacket() {}

void AdapterPacket::ShowAdapters()
{
	for (unsigned int adapterIndex = 0; adapterIndex < networkAdapters.size(); ++adapterIndex) {
		if (adapterIndex == selectedAdapter) {
			SetConsoleTextAttribute(STDOUT_HANDLE, BACKWHITE_FOREBLACK);
			std::cout << "> " << networkAdapters[adapterIndex].adapterDescription << ", " << networkAdapters[adapterIndex].adapterName << " <\n";
			SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);
		}
		else {
			std::cout << "  " << networkAdapters[adapterIndex].adapterDescription << ", " << networkAdapters[adapterIndex].adapterName << "\n";
		}
	}
}

const std::string AdapterPacket::TaskStatus()
{
	return this->status;
}

void AdapterPacket::SelectorEvent(int _selectorValue)
{
	const unsigned int FIRST_ADAPTER_INDEX = 0U, LAST_ADAPTER_INDEX = unsigned int(networkAdapters.size() - 1);

	if (_selectorValue == ARROW_DOWN) {
		if (selectedAdapter == LAST_ADAPTER_INDEX)
			selectedAdapter = FIRST_ADAPTER_INDEX;
		else
			++selectedAdapter;
	}
	else if (_selectorValue == ARROW_UP) {
		if (selectedAdapter == FIRST_ADAPTER_INDEX)
			selectedAdapter = LAST_ADAPTER_INDEX;
		else
			--selectedAdapter;
	}
	else if (_selectorValue == ENTER) {
		PacketDataInitialization();
	}
}