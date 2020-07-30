#include <iostream>
#include <conio.h>
#include "hmi.h"

int main()
{
	int selector(0);
	HMI interfaceController;

	do {
		system("cls");

		SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FORECYAN);
		std::cout << "\n\t\tNetwork Sniffer CLI\n\n";
		SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);
		std::cout << " Select an option:\n\n";

		interfaceController.ShowOptions();

		selector = _getch();

		if (selector != ENTER) {
			fflush(stdin);
			selector = _getch();
		}

		interfaceController.SelectorEvent(selector);

	} while (interfaceController.IsOnExecution());
}