#include <iostream>
#include <thread>
#include "Memory.h"
#include "Offsets.h"

Memory Interface;
uint64_t ProcessBase;

int main()
{
	if (Interface.IsRunning())
		cout << "[Kernel driver loaded]\n";
	else
		cout << "[Kernel driver not loaded]\n";

	cout << "Press [F10] when game loaded into menu...\n";

	while (true)
	{
		if (GetAsyncKeyState(VK_F10))
			break;

		this_thread::sleep_for(20ms);
	}

	Interface.AttachProcess("RainbowSix.exe");

	ProcessBase = Interface.GetProcessBase();

	system("cls");

	cout << "Running!\n";

	// Patch terminateprocess

	uint64_t terminateProcess = (uint64_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "TerminateProcess");

	uint8_t patch[] = { 0xC3 };

	Interface.WriteProtectedMemory(terminateProcess, patch, sizeof(patch));

	// Patch unlockall

	const uint8_t patch1[] = { 0x19 };
	const uint8_t patch2[] = { 0x0 };

	Interface.WriteProtectedMemory(ProcessBase + ADDRESS_UNLOCKALL + OFFSET_UNLOCKALL_JNE, const_cast<uint8_t*>(patch1), sizeof(patch1));
	Interface.WriteProtectedMemory(ProcessBase + ADDRESS_UNLOCKALL + OFFSET_UNLOCKALL_ENABLE, const_cast<uint8_t*>(patch2), sizeof(patch2));
	
	// ESP

	const uint8_t spotted = 1;

	while (true)
	{
		uint64_t roundManager = Interface.ReadMemory<uint64_t>(ProcessBase + ADDRESS_ROUNDMANAGER);

		int state = Interface.ReadMemory<int>(roundManager + OFFSET_ROUNDMANAGER_STATE);

		if (state == 2 || state == 3) {
			uint64_t gameManager = Interface.ReadMemory<uint64_t>(ProcessBase + ADDRESS_GAMEMANAGER);

			uint64_t entityList = Interface.ReadMemory<uint64_t>(ProcessBase + OFFSET_GAMEMANAGER_ENTITYLIST);

			for (size_t i = 0; i < 16; i++)
			{
				uint64_t entity = Interface.ReadMemory<uint64_t>(entityList + (0x8 * i));

				if (entity == 0)
					continue;

				uint64_t entityInfo = Interface.ReadMemory<uint64_t>(entity + OFFSET_ENTITY_ENTITYINFO);
				uint64_t mainComponent = Interface.ReadMemory<uint64_t>(entityInfo + OFFSET_ENTITYINFO_MAINCOMPONENT);

				for (size_t ii = 0; ii < 30; ii++)
				{
					uint64_t espBase = Interface.ReadMemory<uint64_t>(mainComponent + OFFSET_MAINCOMPONENT_ESPCHAIN + (ii * 0x8));

					uint64_t check = Interface.ReadMemory<uint64_t>(espBase + 0x0) - ProcessBase;

					if (check != ADDRESS_VTABLE)
						continue;

					Interface.WriteMemory(espBase + OFFSET_ESPCHAIN_SPOTTED, spotted);

					break;
				}
			}
		}
	}
}