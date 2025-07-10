// patternScanner.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <iomanip>
#include <cstdint>
#include "reconutil.h"

#ifdef DEBUG
#define LOG(msg);
#else
#define LOG(msg) std::cout << msg << std::endl;
#endif

void disable(HMODULE instance, FILE* f) {
    LOG("Stopping.");
    Sleep(3000);

    std::cout << "End." << std::endl;

    FreeConsole();
    fclose(f);

    Sleep(2000);
    FreeLibraryAndExitThread(instance, 0);
}

void onEnable(HMODULE instance) {
    DisableThreadLibraryCalls(instance);

    AllocConsole(); // Allocate a new console for this process
    //AttachConsole(GetCurrentProcessId()); // Attach the new console to this process

    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    Sleep(2000);

    std::vector<std::int16_t> pattern = { 0x48, 0x83, 0xEC, 0x58, 0x48, 0x89, 0x54, 0x24, 0x20, 0x48, 0x89, 0xCF, 0x48, 0x8B, 0x05, 0x71, 0xEF, 0x2F, 0x0D, 0x48, 0x31, 0xE0, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8D, 0x59, 0x78, 0x4C, 0x8B, 0x71, 0x78, 0x4D, 0x85, 0xF6 };
    
    LOG("Scanning...")
    LPVOID address = getAddressByPattern(pattern);
    LOG("Address: " << address)

    LOG("Done scanning.")

   
    LOG("Success");
    while (!GetAsyncKeyState(VK_UP)) {
        Sleep(200);
    }

    LOG("Uninjecting");

    disable(instance, f);

}

int __stdcall DllMain(
    const HMODULE instance,
    const std::uintptr_t reason,
    const void* reserved
)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        const auto thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(onEnable), instance, 0, nullptr);

        if (thread) {
            CloseHandle(thread);
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        //onDisable(instance);

    }
    return 1;
}