#pragma once
#include <string>
#include <array>
#include <iostream>
#include <filesystem>
#include <vector>
#include <conio.h>
#include "local-packet.h"

const int OPTIONS_SIZE = 4;

class HMI {
private:
	bool onExecution;
	int selectedOption;
	std::array<std::string, OPTIONS_SIZE> options;
	void ExecuteSelectedOption();
	void OpenLocal();
	void OpenAdapter();
public:
	HMI();
	~HMI();
	void ShowOptions();
	void SelectorEvent(int _selectorValue);
	bool IsOnExecution();
};


