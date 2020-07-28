#pragma once
#include <vector>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <bitset>
#include "hmi.h"

class LocalPacket {
private:
	unsigned int selectedFile;
	std::vector<unsigned char> packetArrayBytes;
	std::vector<unsigned char> packetArrayBits;
	std::vector<std::filesystem::directory_entry> files;
	std::string status;
	void ShowPacketData();
public:
	LocalPacket();
	LocalPacket(const std::vector<std::filesystem::directory_entry>& _files);
	void ShowFiles();
	const std::string TaskStatus();
	void SelectorEvent(int _selectorValue);
};