#include "hmi.h"

void HMI::ExecuteSelectedOption()
{
	switch (selectedOption)
	{
	case OPEN_LOCAL:
		OpenLocal();
		break;
	case OPEN_ADAPTER:
		OpenAdapter();
		break;
	case ABOUT_APP:
		system("start https://github.com/snvc00/network-sniffer-cli");
		break;
	case CLOSE_APP:
		onExecution = false;
		break;
	default:
		std::cout << "\n WARNING: Invalid option\n";
		break;
	}
}

HMI::HMI() 
    : onExecution(true), selectedOption(0),
	  options 
	  { 
		"Open from local file",
		"Open from network adapter",
		"About this application", 
		"Close network sniffer" 
	  }
{}

void HMI::ShowOptions()
{
	for (int optionIndex = 0; optionIndex < OPTIONS_SIZE; ++optionIndex) {
		if (optionIndex == selectedOption) {
			SetConsoleTextAttribute(STDOUT_HANDLE, 240);
			std::cout << "> " + options[optionIndex] + " <\n";
			SetConsoleTextAttribute(STDOUT_HANDLE, 7);
		}
		else {
			std::cout << "  " + options[optionIndex] + "\n";
		}
	}
}

void HMI::SelectorEvent(int _selectorValue)
{
	if (_selectorValue == ARROW_DOWN) {
		if (selectedOption == CLOSE_APP)
			selectedOption = OPEN_LOCAL;
		else
			++selectedOption;
	}
	else if (_selectorValue == ARROW_UP) {
		if (selectedOption == OPEN_LOCAL)
			selectedOption = CLOSE_APP;
		else
			--selectedOption;
	}
	else if (_selectorValue == ENTER) {
		ExecuteSelectedOption();
	}
}

bool HMI::IsOnExecution()
{
	return this->onExecution;
}

void HMI::OpenLocal()
{
	system("cls");
	std::cout << "\n OPEN FROM LOCAL FILE\n\n";

	std::vector<std::filesystem::directory_entry> files;

	std::string localPacketsPath = std::filesystem::current_path().concat("\\..\\local-packets").string();

	for (const std::filesystem::directory_entry& dirEntry : std::filesystem::directory_iterator(localPacketsPath))
		files.emplace_back(dirEntry);

	if (files.size() > 0) {
		LocalPacket localPacket(files);
		int selector(0);
		
		do {
			system("cls");

			std::cout << "\n OPEN FROM LOCAL FILE\n\n";
			std::cout << " Select a file:\n\n";

			localPacket.ShowFiles();

			selector = _getch();

			if (selector != ENTER) {
				fflush(stdin);
				selector = _getch();
			}

			localPacket.SelectorEvent(selector);

		} while (localPacket.TaskStatus() != "Finished");
	}
	else {
		SetConsoleTextAttribute(STDOUT_HANDLE, 6);
		std::cout << "\n WARNING: Local packets directory is empty\n";
		std::cin.get();
		SetConsoleTextAttribute(STDOUT_HANDLE, 7);
	}
}

void HMI::OpenAdapter()
{
	system("cls");
	std::cout << "\n OPEN FROM NETWORK ADAPTER\n\n";

	system("pause");
}