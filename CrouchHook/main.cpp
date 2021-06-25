#include <Windows.h>
#include "MinHook.h"

typedef int(__fastcall* CrouchFunction)(int* param_1, void* EDX, int param_1_00);

CrouchFunction CrouchTrampoline;

int __fastcall CrouchHookedd(int* param_1, void* EDX, int param_1_00)
{
	if (*reinterpret_cast<DWORD*>(0xB6F5F0) == param_1_00) 
		return 1;
	else
		return CrouchTrampoline(param_1, EDX, param_1_00);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	DisableThreadLibraryCalls(hinstDLL);
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (MH_Initialize() == MH_OK)
		{
			MH_CreateHook(reinterpret_cast<CrouchFunction>(0x694390), &CrouchHookedd, reinterpret_cast<LPVOID*>(&CrouchTrampoline));
			MH_EnableHook(MH_ALL_HOOKS);
		}
	}
	else
	{
		MH_Uninitialize();
	}
	return TRUE;
}