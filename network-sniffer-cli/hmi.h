#pragma once
#include <string>
#include <array>
#include <iostream>
#include <filesystem>
#include <vector>
#include <Windows.h>
#include <conio.h>
#include "local-packet.h"

const int OPTIONS_SIZE = 4;
const HANDLE STDOUT_HANDLE = GetStdHandle(STD_OUTPUT_HANDLE);

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
	void ShowOptions();
	void SelectorEvent(int _selectorValue);
	bool IsOnExecution();
};

const enum HMI_OPTIONS {
	OPEN_LOCAL   = 0,
	OPEN_ADAPTER = 1,
	ABOUT_APP    = 2,
	CLOSE_APP    = 3
};

const enum EVENT_KEYS {
	ENTER      = 13,
	ARROW_UP   = 72,
	ARROW_DOWN = 80
};


