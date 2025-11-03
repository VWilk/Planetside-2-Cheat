#pragma once
#include <Windows.h>
#include <cstdio>

class Logger {
public:
    static void Init();      // AllocConsole, redirect stdout (with fallback to file logging)
    static void Shutdown();  // FreeConsole
    static void Log(const char* format, ...);   // printf-style, thread-safe with critical section
    static void Error(const char* format, ...);
    static void Warning(const char* format, ...);
    
private:
    static CRITICAL_SECTION m_cs;  // Win32 Critical Section (more reliable than std::mutex for early DLL init)
    static FILE* m_console;
    static FILE* m_logFile;      // Fallback file logging
    static bool m_initialized;
    static bool m_useFileLogging; // True if console failed, use file instead
    static bool m_csInitialized;  // Track if critical section is initialized
    
    // NEW: Separate into locked and unlocked function
    static void PrintWithPrefix(const char* prefix, const char* format, va_list args); // This will now contain the lock
    static void PrintUnsafe(const char* prefix, const char* format, va_list args);    // This only does the printf
    
    // Fallback file logging functions
    static bool InitFileLogging();  // Initialize file logging as fallback
    static void WriteToFile(const char* prefix, const char* format, va_list args);  // Write to file
};
