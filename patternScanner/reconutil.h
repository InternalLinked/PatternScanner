#pragma once
#include <iostream>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <emmintrin.h>

typedef struct {
    LPVOID         baseAddress;
    size_t  moduleSize;
}preciseModuleInfo;

bool getMemoryRegionByAddr(std::vector<preciseModuleInfo> modules, preciseModuleInfo* module_info_result, void* address);

bool getAllModules(std::vector<preciseModuleInfo>* modules);

std::vector<preciseModuleInfo> filterForAccessableModules(std::vector<preciseModuleInfo> modules);

LPVOID getAddressByPattern(const std::vector<std::int16_t> pattern);


class SIMDScanner {

    std::vector<std::int16_t> original_pattern;
    std::uint8_t* pattern = nullptr;
    std::uint8_t* wildcards = nullptr;
    size_t pattern_size;
    size_t pad;

    bool match(std::uint8_t* one, std::uint8_t* two, std::uint8_t* wildcards);

public:
    SIMDScanner(std::vector<std::int16_t> pattern, size_t pad);

    bool scanForPattern(std::uint8_t* dst);

    size_t parsePattern(std::vector<std::int16_t> vec_pattern, std::uint8_t*& pattern, std::uint8_t*& wildcard, int pad);

    ~SIMDScanner();

};