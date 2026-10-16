#include "include/Memory.h"

#include "include/Log.h"

#include <windows.h>
#include <psapi.h>

namespace OSTPlatform::Memory {

std::optional<ModuleImage> GetModuleImage(DynamicLibrary::ModuleHandle module) {
    MODULEINFO info{};
    if (!module || !GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(module), &info, sizeof(info))) {
        OSTP_LOG_DEBUG("GetModuleImage(module={}) failed (error={})", module, GetLastError());
        return std::nullopt;
    }

    return ModuleImage{
        static_cast<uint8_t*>(info.lpBaseOfDll),
        static_cast<size_t>(info.SizeOfImage),
    };
}

bool WriteExecutableByte(void* target, uint8_t value) {
    if (!target) {
        OSTP_LOG_WARN("WriteExecutableByte: target is null");
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        OSTP_LOG_WARN("WriteExecutableByte(target={}) VirtualProtect(RWX) failed (error={})",
                      target, GetLastError());
        return false;
    }
    *static_cast<uint8_t*>(target) = value;

    DWORD ignored = 0;
    if (!VirtualProtect(target, 1, oldProtect, &ignored)) {
        OSTP_LOG_WARN("WriteExecutableByte(target={}) VirtualProtect(restore=0x{:X}) failed (error={})",
                      target, oldProtect, GetLastError());
        return false;
    }
    if (!FlushInstructionCache(GetCurrentProcess(), target, 1)) {
        OSTP_LOG_WARN("WriteExecutableByte(target={}) FlushInstructionCache failed (error={})",
                      target, GetLastError());
        return false;
    }
    return true;
}

bool IsReadable(const void* address, size_t bytes) {
    if (!address || bytes == 0) return false;

    auto cursor = reinterpret_cast<uintptr_t>(address);
    if (cursor + bytes < cursor) return false;   // wraps the address space
    const uintptr_t end = cursor + bytes;

    constexpr DWORD kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_EXECUTE_WRITECOPY;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT) return false;
        if ((mbi.Protect & kReadable) == 0) return false;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;

        const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (regionEnd <= cursor) return false;
        cursor = regionEnd;
    }
    return true;
}

} // namespace OSTPlatform::Memory
