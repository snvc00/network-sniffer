#pragma once
#include <filesystem>
#include "packet.h"

class LocalPacket : private Packet  {
private:
	unsigned int selectedFile;
	std::vector<unsigned char> packetArrayBytes;
	std::vector<unsigned char> packetArrayBits;
	std::vector<std::filesystem::directory_entry> files;
	std::string status;
	void PacketDataInitialization();
	void PacketShowData();
public:
	LocalPacket();
	LocalPacket(const std::vector<std::filesystem::directory_entry>& _files);
	~LocalPacket();
	void ShowFiles();
	const std::string TaskStatus();
	void SelectorEvent(int _selectorValue);
};