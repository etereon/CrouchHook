#include <Windows.h>
#include "MinHook.h"

typedef bool(__thiscall* CrouchFunction)(void*, void*);

WNDPROC WndProcTrampoline;
CrouchFunction CrouchTrampoline;

bool state = false;

LRESULT CALLBACK WndProcHooked(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_KEYUP) {
		if (wParam == VK_F11) {
			state = !state;
		}
	}
	return WndProcTrampoline(hWnd, uMsg, wParam, lParam);
}

bool __fastcall CrouchHooked(void* ecx, void* edx, byte* ped) {
	if (state && *reinterpret_cast<byte**>(0xB6F5F0) == ped && ped[0x46F] == 128) return 1;
	return CrouchTrampoline(ecx, ped);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		if (MH_Initialize() == MH_OK) {
			MH_CreateHook(reinterpret_cast<WNDPROC>(0x747EB0), &WndProcHooked, reinterpret_cast<LPVOID*>(&WndProcTrampoline));
			MH_CreateHook(reinterpret_cast<CrouchFunction>(0x694390), &CrouchHooked, reinterpret_cast<LPVOID*>(&CrouchTrampoline));
			MH_EnableHook(MH_ALL_HOOKS);
		}
	}
	else MH_Uninitialize();
	return TRUE;
}
