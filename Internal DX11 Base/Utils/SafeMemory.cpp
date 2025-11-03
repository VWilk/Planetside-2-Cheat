#include "../pch.h"  
#include "SafeMemory.h"
#include "Logger.h"
#include "../Game/Offsets.h"
#include <TlHelp32.h>
#include <iostream>
#include <algorithm>
#include <Psapi.h>
#include <vector>
#include <immintrin.h>  // For _mm_crc32_u64 and _mm_crc32_u8
#include <sstream>
#include <thread>
#include <chrono>

namespace Utils
{
    SafeMemory::SafeMemory() : m_processHandle(nullptr), m_baseAddress(0), m_processId(0), m_isAttached(false)
    {
    }
    
    SafeMemory::~SafeMemory()
    {
        DetachFromProcess();
    }
    
    bool SafeMemory::AttachToProcess(const std::string& processName)
    {
        DetachFromProcess();
        
        // processName parameter is ignored - we use GetCurrentProcess() since we're injected
        Logger::Log("DLL is already injected into the process, using current process handle");
        
        try {
            // Since we're injected into the process, we can use the current process
            m_processHandle = GetCurrentProcess();
            m_processId = GetCurrentProcessId();
            
            // Method 1: Try fast method first - GetModuleHandle(nullptr) gets main module base
            // This is much faster than EnumProcessModules and works on all Windows versions
            HMODULE hMainModule = GetModuleHandleA(nullptr);
            if (hMainModule) {
                m_baseAddress = (uintptr_t)hMainModule;
                m_isAttached = true;
                Logger::Log("Successfully initialized memory access (fast method)");
                char buffer[256];
                snprintf(buffer, sizeof(buffer), "Base address: 0x%llX", (unsigned long long)m_baseAddress);
                Logger::Log(buffer);
                return true;
            }
            
            // Method 2: Fallback to EnumProcessModules if GetModuleHandle fails
            // Add a small delay for slower systems
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
            HMODULE hMods[1024];
            DWORD cbNeeded;
            
            // Try with timeout - for very slow systems, this might take a while
            auto startTime = std::chrono::steady_clock::now();
            const auto timeout = std::chrono::seconds(5); // 5 second timeout
            
            bool enumSuccess = false;
            while (std::chrono::steady_clock::now() - startTime < timeout) {
                enumSuccess = EnumProcessModules(m_processHandle, hMods, sizeof(hMods), &cbNeeded) != 0;
                if (enumSuccess) break;
                
                // If failed, wait a bit and retry (might be system load issue)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            
            if (enumSuccess && cbNeeded > 0) {
                MODULEINFO mi;
                if (GetModuleInformation(m_processHandle, hMods[0], &mi, sizeof(mi)))
                {
                    m_baseAddress = (uintptr_t)mi.lpBaseOfDll;
                    m_isAttached = true;
                    Logger::Log("Successfully initialized memory access (EnumProcessModules method)");
                    char buffer[256];
                    snprintf(buffer, sizeof(buffer), "Base address: 0x%llX", (unsigned long long)m_baseAddress);
                    Logger::Log(buffer);
                    return true;
                }
                else
                {
                    DWORD error = GetLastError();
                    Logger::Warning("GetModuleInformation failed. Error: %d, trying alternative...", error);
                }
            }
            else
            {
                DWORD error = GetLastError();
                Logger::Warning("EnumProcessModules failed or timed out. Error: %d, trying alternative...", error);
            }
            
            // Method 3: Last resort - try GetModuleHandle with executable name
            // Sometimes this works when other methods fail
            char exePath[MAX_PATH] = {0};
            if (GetModuleFileNameA(nullptr, exePath, MAX_PATH)) {
                char* exeName = strrchr(exePath, '\\');
                if (exeName) exeName++; else exeName = exePath;
                
                HMODULE hExeModule = GetModuleHandleA(exeName);
                if (hExeModule) {
                    m_baseAddress = (uintptr_t)hExeModule;
                    m_isAttached = true;
                    Logger::Log("Successfully initialized memory access (executable name method)");
                    char buffer[256];
                    snprintf(buffer, sizeof(buffer), "Base address: 0x%llX", (unsigned long long)m_baseAddress);
                    Logger::Log(buffer);
                    return true;
                }
            }
            
            // All methods failed
            Logger::Error("All methods to get base address failed. Memory access may not work correctly.");
            // Still mark as attached with base address 0 - might work for some operations
            m_isAttached = true;
            m_baseAddress = 0;
            return false;
        }
        catch (const std::exception& e) {
            Logger::Error("Exception in AttachToProcess: %s", e.what());
            m_isAttached = false;
            return false;
        }
        catch (...) {
            Logger::Error("Unknown exception in AttachToProcess");
            m_isAttached = false;
            return false;
        }
    }
    
    void SafeMemory::DetachFromProcess()
    {
        if (m_processHandle)
        {
            CloseHandle(m_processHandle);
            m_processHandle = nullptr;
        }
        m_baseAddress = 0;
        m_isAttached = false;
    }
    
    bool SafeMemory::ReadBytes(uintptr_t address, void* buffer, size_t size)
    {
        if (!m_isAttached || !buffer || size == 0)
            return false;
            
        if (!ValidateAddress(address))
            return false;
            
        SIZE_T bytesRead;
        return ReadProcessMemory(m_processHandle, (LPCVOID)address, buffer, size, &bytesRead) && 
               bytesRead == size;
    }
    
    std::string SafeMemory::ReadString(uintptr_t address, size_t maxLength)
    {
        if (!m_isAttached || maxLength == 0)
            return "";

        // This structure represents the std::string in memory
        struct StringLayout {
            union {
                char inlineBuffer[16]; // For short strings (SSO)
                char* pString;         // For long strings
            } data;
            size_t length;
            size_t capacity;
        };

        StringLayout stringStruct;
        if (!Read(address, stringStruct))
        {
            return "";
        }

        // Determine if it is a short or long string
        if (stringStruct.capacity >= 16)
        {
            // Long string: The pointer points to the data
            if (!IsValidPointer(reinterpret_cast<uintptr_t>(stringStruct.data.pString)))
            {
                return "";
            }

            size_t readLength = (stringStruct.length < maxLength) ? stringStruct.length : maxLength;
            if (readLength == 0)
            {
                return "";
            }

            std::vector<char> buffer(readLength);
            if (ReadBytes(reinterpret_cast<uintptr_t>(stringStruct.data.pString), buffer.data(), readLength))
            {
                return std::string(buffer.data(), readLength);
            }
        }
        else
        {
            // Short string: Data is directly in buffer
            size_t readLength = (stringStruct.length < 15) ? stringStruct.length : 15; // Max 15 chars + null terminator
            if (readLength == 0)
            {
                return "";
            }
            return std::string(stringStruct.data.inlineBuffer, readLength);
        }

        return "";
    }
    
    Utils::Vector3 SafeMemory::ReadVector3(uintptr_t address)
    {
        if (!m_isAttached)
            return Utils::Vector3();
            
        Utils::Vector3 vector;
        if (Read(address, vector))
            return vector;
        return Utils::Vector3();
    }
    
    bool SafeMemory::WriteBytes(uintptr_t address, const void* buffer, size_t size)
    {
        if (!m_isAttached || !buffer || size == 0)
            return false;
            
        if (!ValidateAddress(address))
            return false;
            
        SIZE_T bytesWritten;
        return WriteProcessMemory(m_processHandle, (LPVOID)address, buffer, size, &bytesWritten) && 
               bytesWritten == size;
    }
    
    void SafeMemory::WriteVector3(uintptr_t address, const Utils::Vector3& vector)
    {
        if (!m_isAttached)
            return;
            
        Write(address, vector);
    }
    
    uintptr_t SafeMemory::ResolvePointerChain(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets)
    {
        if (!m_isAttached || offsets.empty())
            return 0;
            
        uintptr_t currentAddress = baseAddress;
        
        // Read initial pointer
        if (!Read(currentAddress, currentAddress) || currentAddress == 0)
            return 0;
            
        // Follow pointer chain (all but last offset)
        for (size_t i = 0; i < offsets.size() - 1; ++i)
        {
            currentAddress += offsets[i];
            if (!Read(currentAddress, currentAddress) || currentAddress == 0)
                return 0;
        }
        
        // Add final offset
        currentAddress += offsets.back();
        return currentAddress;
    }
    
    bool SafeMemory::IsValidAddress(uintptr_t address)
    {
        if (!m_isAttached || address == 0)
            return false;
            
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(m_processHandle, (LPCVOID)address, &mbi, sizeof(mbi)) == 0)
            return false;
            
        return (mbi.State == MEM_COMMIT) && 
               (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
    }
    
    bool SafeMemory::IsValidPointer(uintptr_t address)
    {
        return IsValidAddress(address);
    }
    
    bool SafeMemory::ValidateAddress(uintptr_t address)
    {
        return IsValidAddress(address);
    }
    
    bool SafeMemory::PatchMemory(uintptr_t address, const std::vector<uint8_t>& newBytes)
    {
        if (!m_isAttached || newBytes.empty())
            return false;

        // Change memory protection to PAGE_EXECUTE_READWRITE
        DWORD oldProtect;
        if (!VirtualProtectEx(m_processHandle, (LPVOID)address, newBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        // Write new bytes
        SIZE_T bytesWritten;
        bool result = WriteProcessMemory(m_processHandle, (LPVOID)address, newBytes.data(), newBytes.size(), &bytesWritten);

        // Restore original protection
        VirtualProtectEx(m_processHandle, (LPVOID)address, newBytes.size(), oldProtect, &oldProtect);

        return result && bytesWritten == newBytes.size();
    }
    
    uintptr_t SafeMemory::PatternScan(const std::string& pattern, const std::string& mask)
    {
        return PatternScan(m_baseAddress, Offsets::GameConstants::PATTERN_SCAN_SIZE, pattern, mask); // Scan first 256MB
    }
    
    uintptr_t SafeMemory::PatternScan(uintptr_t startAddress, size_t size, const std::string& pattern, const std::string& mask)
    {
        if (!m_isAttached || pattern.empty() || mask.empty() || pattern.length() != mask.length())
            return 0;

        std::vector<uint8_t> buffer(size);
        if (!ReadBytes(startAddress, buffer.data(), size))
            return 0;

        for (size_t i = 0; i <= size - pattern.length(); ++i)
        {
            bool found = true;
            for (size_t j = 0; j < pattern.length(); ++j)
            {
                if (mask[j] == 'x' && buffer[i + j] != static_cast<uint8_t>(pattern[j]))
                {
                    found = false;
                    break;
                }
            }
            if (found)
                return startAddress + i;
        }

        return 0;
    }
    
    uintptr_t SafeMemory::GetModuleBase(const std::string& moduleName)
    {
        if (!m_isAttached)
            return 0;

        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(m_processHandle, hMods, sizeof(hMods), &cbNeeded))
        {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i)
            {
                char moduleNameBuffer[MAX_PATH];
                if (GetModuleBaseNameA(m_processHandle, hMods[i], moduleNameBuffer, sizeof(moduleNameBuffer)))
                {
                    if (moduleName == moduleNameBuffer)
                    {
                        return (uintptr_t)hMods[i];
                    }
                }
            }
        }
        return 0;
    }
    
    std::vector<uintptr_t> SafeMemory::GetModuleBases()
    {
        std::vector<uintptr_t> modules;
        if (!m_isAttached)
            return modules;

        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(m_processHandle, hMods, sizeof(hMods), &cbNeeded))
        {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i)
            {
                modules.push_back((uintptr_t)hMods[i]);
            }
        }
        return modules;
    }
    
    std::string SafeMemory::PatternToBytes(const std::string& pattern)
    {
        std::string bytes;
        std::stringstream ss(pattern);
        std::string byte;
        
        while (ss >> byte)
        {
            if (byte == "?" || byte == "??")
            {
                bytes += '\x00'; // Placeholder for wildcard
            }
            else
            {
                bytes += static_cast<char>(std::stoi(byte, nullptr, 16));
            }
        }
        
        return bytes;
    }
    
    uint32_t SafeMemory::CalculateBulletHash(const Utils::Vector3& position, const Utils::Vector3& direction)
    {
        // Combine position and direction for hash calculation
        struct BulletData {
            Utils::Vector3 pos;
            Utils::Vector3 dir;
        } data = { position, direction };
        
        return CalculateBulletHashInternal(&data, sizeof(data));
    }
    
    uint32_t SafeMemory::CalculateBulletHashForPosition(const Utils::Vector3& position)
    {
        // Position is stored as __m128: x, y, z, w (4 floats = 16 bytes)
        float positionData[4] = { 
            position.x, 
            position.y, 
            position.z, 
            1.0f  // W=1.0f IMPORTANT for hash validation!
        };
        
        return CalculateBulletHashInternal(positionData, 16);
    }
    
    uint32_t SafeMemory::CalculateBulletHashInternal(const void* data, size_t size)
    {
        // HARDWARE CRC32 - exactly like the game (sub_1408CD350)
        constexpr uint32_t CRC32_SEED = Offsets::GameConstants::CRC32_SEED;
        
        // Start with inverted seed
        uint64_t crc = ~static_cast<uint64_t>(CRC32_SEED);
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        
        // Process 8-byte chunks with hardware CRC32
        size_t numQwords = size / 8;
        const uint64_t* qwords = reinterpret_cast<const uint64_t*>(bytes);
        
        for (size_t i = 0; i < numQwords; i++)
        {
            crc = _mm_crc32_u64(crc, qwords[i]);
        }
        
        // Process remaining bytes
        bytes += numQwords * 8;
        size_t remaining = size % 8;
        
        for (size_t i = 0; i < remaining; i++)
        {
            crc = _mm_crc32_u8(static_cast<uint32_t>(crc), bytes[i]);
        }
        
        // Return inverted result
        return ~static_cast<uint32_t>(crc);
    }
    
    Utils::Vector3 SafeMemory::ReadSimpleBoneData(uintptr_t boneAddress)
    {
        if (!m_isAttached)
            return Utils::Vector3();
            
        Utils::Vector3 bonePos;
        if (Read(boneAddress, bonePos))
            return bonePos;
        return Utils::Vector3();
    }
    
    // Global hash calculation functions
    uint32_t CalculatePositionHash(const Utils::Vector3& position)
    {
        SafeMemory temp;
        return temp.CalculateBulletHashForPosition(position);
    }
    
    uint32_t CalculateEntityHash(uintptr_t entityAddress, const Utils::Vector3& position)
    {
        SafeMemory temp;
        return temp.CalculateBulletHashForPosition(position) ^ static_cast<uint32_t>(entityAddress);
    }
} // End of namespace Utils
