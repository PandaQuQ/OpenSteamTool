#pragma once

#include "include/DynamicLibrary.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace OSTPlatform::Memory {

    struct ModuleImage {
        uint8_t* base = nullptr;
        size_t size = 0;
    };

    std::optional<ModuleImage> GetModuleImage(DynamicLibrary::ModuleHandle module);
    bool WriteExecutableByte(void* target, uint8_t value);

    // True when every byte of [address, address + bytes) lies in committed,
    // readable memory of the current process. Cheap enough for a one-off probe;
    // not meant for per-call use on hot paths.
    bool IsReadable(const void* address, size_t bytes);

} // namespace OSTPlatform::Memory
