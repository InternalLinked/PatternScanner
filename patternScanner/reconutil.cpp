#include "reconutil.h"


bool getMemoryRegionByAddr(std::vector<preciseModuleInfo> modules, preciseModuleInfo* module_info_result, void* address) {


    size_t addr = (size_t)address;

    for (preciseModuleInfo mod : modules) {

        size_t from = (size_t)mod.baseAddress;
        size_t to = size_t(mod.baseAddress) + mod.moduleSize;

        //std::cout << (LPVOID)from << " -> " << (LPVOID)to << std::endl;

        if (addr > from && addr < to) {
            module_info_result->baseAddress = mod.baseAddress;
            module_info_result->moduleSize = mod.moduleSize;

            return true;
        }

    }

    return false;

}

bool getAllModules(std::vector<preciseModuleInfo>* modules) {
    /*
    Getting all modules and storing the baseAddresses and the baseSizes into an std::vector<preciseModuleInfo>*
    */
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32 snap_module;
    snap_module.dwSize = sizeof(MODULEENTRY32);

    Module32First(snapshot, &snap_module);
    preciseModuleInfo moduleInfo;
    moduleInfo.baseAddress = snap_module.modBaseAddr;
    moduleInfo.moduleSize = snap_module.modBaseSize;
    modules->push_back(moduleInfo);

    while (Module32Next(snapshot, &snap_module)) {

        preciseModuleInfo moduleInfo;
        moduleInfo.baseAddress = snap_module.modBaseAddr;
        moduleInfo.moduleSize = snap_module.modBaseSize;
        modules->push_back(moduleInfo);

    }

    return true;
}

bool SIMDScanner::match(std::uint8_t* one, std::uint8_t* two, std::uint8_t* wildcards) {
    /*Acutal SIMD comparing implementation. Currently it is only able to compare 16 bytes relative from the start of the pointer
    at the time (SSE)
    
    TODO: Adding AVX mode so that 32 bytes can be compared at the same time.
    */

    __m128i vc = _mm_loadu_si128(reinterpret_cast<const __m128i*>(wildcards));


    __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(one));
    __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(two));

    //comparing both byte arrays
    __m128i cmp = _mm_cmpeq_epi8(va, vb);

    //masking the result for the wildcards
    __m128i masked_cmp = _mm_or_si128(cmp, vc);

    int mask = _mm_movemask_epi8(masked_cmp);

    return (mask == 0xFFFF);
}

SIMDScanner::SIMDScanner(std::vector<std::int16_t> pattern, size_t pad) {
    this->pad = pad;
    this->original_pattern = pattern;
    this->pattern_size = parsePattern(this->original_pattern, this->pattern, this->wildcards, pad);
}

bool SIMDScanner::scanForPattern(std::uint8_t* dst) {
    /*Scans at *dst for the pattern that was given to the construtor earlier*/

    int chunks = (this->original_pattern.size() / this->pad);
    int padding = original_pattern.size() - chunks * this->pad;

    if (padding != 0) {
        chunks += 1;
    }

    for (int i = 0; i < chunks; i++) {
        int offset = this->pad * i;
        bool result = match(this->pattern + offset, dst + offset, this->wildcards + offset);
        if (!result) {
            return false;
        }
        if (i == chunks - 1) {
            return true;
        }

    }

}

size_t SIMDScanner::parsePattern(std::vector<std::int16_t> vec_pattern, std::uint8_t*& pattern, std::uint8_t*& wildcard, int pad) {
    /*Parses the int16_t vector into two seperate byte arrays. It creates an normal pattern byte array and an wildcard array that is
    lateron used to ignore certain bytes if wanted. 
    
    Also this implementation makes it possible to only pass one int16 vector instead of two different uint8 vectors that seperated in the acutal
    pattern and wildcard vectors.

    If the given values in vec_pattern are n < 0 then the value gets interpreted as a wildcard
    */

    int padding = vec_pattern.size() - (vec_pattern.size() / pad) * pad;
    if (padding != 0) {
        padding = pad - padding;
    }
    const size_t size = vec_pattern.size() + padding;

    //creating buffers
    pattern = new std::uint8_t[size];
    wildcard = new std::uint8_t[size];

    //add padding for alignment
    memset(pattern + vec_pattern.size(), 0x0, padding);
    memset(wildcard + vec_pattern.size(), 0xFF, padding);

    //parsing pattern into pattern* and wildcard*
    for (int i = 0; i < vec_pattern.size(); i++) {

        int card = vec_pattern[i];

        if (card >= 0 && card <= 0xFF) {
        pattern[i] = static_cast<uint8_t>(card);
        wildcard[i] = 0x0;

        }
        else {
            pattern[i] = 0x0;
            wildcard[i] = 0xFF;
        }

    }

    return size;

}

SIMDScanner::~SIMDScanner() {
    delete[] this->pattern;
    delete[] this->wildcards;
    this->pattern = nullptr;
    this->wildcards = nullptr;

}

std::vector<preciseModuleInfo> filterForAccessableModules(std::vector<preciseModuleInfo> modules) {
    /*
    Filtering all segments for accessible memory regions and returns a filtered vector.
    */
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<preciseModuleInfo> filtered;

    for (preciseModuleInfo mod : modules) {

        void* address = mod.baseAddress;

        while (VirtualQuery(address, &mbi, sizeof(mbi))) {

            if ((std::uint64_t)address + mod.moduleSize < (std::uint64_t)address + mbi.RegionSize) {
                break;
            }

            if (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE) {

                preciseModuleInfo modInfo;
                modInfo.baseAddress = mbi.BaseAddress;
                modInfo.moduleSize = mbi.RegionSize;

                filtered.push_back(modInfo);

            }
            address = (void*)((std::uint64_t)mbi.BaseAddress + mbi.RegionSize);

        }

    }

    return filtered;
}

LPVOID getAddressByPattern(const std::vector<std::int16_t> pattern) {

    /*
    Scans all memory segments that arr accessible for a pattern and returns the first result found. The wildcards need to be the same
    size of the pattern and can be used to ignore bytes. Bytes that should be ignored needs to be set to n < 0 in the wildcards vector.
    */

    std::vector<preciseModuleInfo> modules;
    if (!getAllModules(&modules)) {
        return nullptr;
    }

    modules = filterForAccessableModules(modules);
    SIMDScanner scanner(pattern, 16);

    for (preciseModuleInfo mod : modules) {

        std::uint8_t* base = static_cast<std::uint8_t*>(mod.baseAddress);

        //using size_t here for x32 compatibility
        for (std::size_t offset = 0; offset < mod.moduleSize - pattern.size(); offset++) {
            std::uint8_t* current = base + offset;

            if (scanner.scanForPattern(current)) {
                return current;
            }

        }

    }

    return 0;
}