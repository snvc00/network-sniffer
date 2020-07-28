#include <iostream>
#include <conio.h>
#include "hmi.h"

int main()
{
	int selector(0);
	HMI interfaceController;

	do {
		system("cls");

		std::cout << "\n\t\tNetwork Sniffer CLI\n\n";
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