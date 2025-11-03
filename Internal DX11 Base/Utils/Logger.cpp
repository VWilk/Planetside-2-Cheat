#include "pch.h"
#include "Logger.h"
#include <iostream>
#include <cstdarg>

CRITICAL_SECTION Logger::m_cs;
FILE* Logger::m_console = nullptr;
FILE* Logger::m_logFile = nullptr;
bool Logger::m_initialized = false;
bool Logger::m_useFileLogging = false;
bool Logger::m_csInitialized = false;

// RAII helper for critical section (ensures unlock even on exception)
class CSLock {
    CRITICAL_SECTION* m_cs;
public:
    CSLock(CRITICAL_SECTION* cs) : m_cs(cs) {
        if (m_cs) EnterCriticalSection(m_cs);
    }
    ~CSLock() {
        if (m_cs) LeaveCriticalSection(m_cs);
    }
    // Non-copyable
    CSLock(const CSLock&) = delete;
    CSLock& operator=(const CSLock&) = delete;
};

void Logger::Init() {
    // Initialize critical section on first call (thread-safe via double-checked locking)
    if (!m_csInitialized) {
        static volatile long initLock = 0;
        while (InterlockedCompareExchange(&initLock, 1, 0) != 0) {
            Sleep(1); // Wait for other thread to finish initialization
        }
        if (!m_csInitialized) {
            InitializeCriticalSection(&m_cs);
            m_csInitialized = true;
        }
        InterlockedExchange(&initLock, 0);
    }
    
    // Use RAII to ensure critical section is always released
    CSLock lock(&m_cs);
    
    // Early return if already initialized
    if (m_initialized) {
        return;
    }
    
    // Try to initialize console logging first
    bool consoleSuccess = false;
    bool consoleWasExisting = false;
    
    try {
        // Check if console already exists
        HWND existingConsole = GetConsoleWindow();
        consoleWasExisting = (existingConsole != nullptr);
        
        if (!existingConsole) {
            // Only allocate if it doesn't exist
            if (AllocConsole()) {
                SetConsoleTitleA("PS2 Cheat - Debug Console");
                consoleSuccess = true;
            }
            else {
                // AllocConsole failed - will use file logging
                DWORD error = GetLastError();
                // ERROR_ACCESS_DENIED means console already exists in another process
                if (error != ERROR_ACCESS_DENIED) {
                    // Some other error - try file logging fallback
                }
            }
        }
        else {
            // Console already exists, try to use it
            consoleSuccess = true;
        }
        
        if (consoleSuccess) {
            // Redirect stdout
            errno_t err = freopen_s(&m_console, "CONOUT$", "w", stdout);
            if (err == 0 && m_console) {
                // Successfully redirected
                // Make console window a bit larger (only if we created it)
                if (!consoleWasExisting) {
                    HWND consoleWindow = GetConsoleWindow();
                    if (consoleWindow) {
                        RECT rect;
                        if (GetWindowRect(consoleWindow, &rect)) {
                            SetWindowPos(consoleWindow, HWND_TOP, rect.left, rect.top, 800, 600, SWP_NOZORDER);
                        }
                    }
                }
                
                m_useFileLogging = false;
                m_initialized = true;
                
                // Direct, simpler call without vaPrintf detour (avoids deadlock!)
                SYSTEMTIME st;
                GetLocalTime(&st);
                printf("[%02d:%02d:%02d.%03d] [INFO] Logger initialized successfully (Console)!\n", 
                       st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                fflush(stdout);
                
                return; // Success (lock released by RAII)
            }
            else {
                // freopen_s failed - close console and use file logging
                FreeConsole();
                consoleSuccess = false;
            }
        }
    }
    catch (...) {
        // Any exception - fall back to file logging
        consoleSuccess = false;
    }
    
    // If console logging failed, try file logging as fallback
    if (!consoleSuccess) {
        if (InitFileLogging()) {
            m_useFileLogging = true;
            m_initialized = true;
            
            // Log initialization message to file
            SYSTEMTIME st;
            GetLocalTime(&st);
            fprintf(m_logFile, "[%02d:%02d:%02d.%03d] [INFO] Logger initialized successfully (File Logging - Console failed)!\n", 
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            fflush(m_logFile);
            
            // Also show a MessageBox as emergency feedback
            MessageBoxA(nullptr, 
                       "Logger: Console initialization failed! Using file logging instead.\nCheck 'PS2Cheat_Log.txt' for logs.",
                       "PS2 Cheat - Logger Warning", 
                       MB_OK | MB_ICONWARNING);
        }
        else {
            // Even file logging failed - this is critical
            // At least try to show a MessageBox
            MessageBoxA(nullptr, 
                       "CRITICAL: Logger initialization completely failed!\nThe cheat may not work correctly.",
                       "PS2 Cheat - Critical Error", 
                       MB_OK | MB_ICONERROR);
            
            // Mark as initialized anyway to prevent infinite loops
            m_initialized = true;
            m_useFileLogging = false;
        }
    }
    // lock released automatically by RAII
}

void Logger::Shutdown() {
    if (!m_csInitialized) return; // Never initialized, nothing to shut down
    
    CSLock lock(&m_cs);
    
    if (!m_initialized) {
        return;
    }
    
    // Log shutdown message before file is closed
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    if (m_useFileLogging && m_logFile) {
        fprintf(m_logFile, "[%02d:%02d:%02d.%03d] [INFO] Logger shutting down.\n", 
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        fflush(m_logFile);
    }
    else if (m_console) {
        printf("[%02d:%02d:%02d.%03d] [INFO] Logger shutting down.\n", 
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        fflush(stdout);
    }
    
    if (m_console) {
        fclose(m_console);
        m_console = nullptr;
    }
    
    if (m_logFile) {
        fclose(m_logFile);
        m_logFile = nullptr;
    }
    
    // Only free console if we allocated it
    if (!m_useFileLogging) {
        FreeConsole();
    }
    
    m_initialized = false;
    m_useFileLogging = false;
    
    // lock released automatically by RAII
    
    // Delete critical section on shutdown (after releasing lock)
    // Note: We need to delete it outside the lock, but we've already left the section
    // Actually, we should delete it at the very end, but we need to be careful
    // For now, just mark it as not initialized - deletion will happen on process exit anyway
}

void Logger::Log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    PrintWithPrefix("[INFO] ", format, args);
    va_end(args);
}

void Logger::Error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    PrintWithPrefix("[ERROR] ", format, args);
    va_end(args);
}

void Logger::Warning(const char* format, ...) {
    va_list args;
    va_start(args, format);
    PrintWithPrefix("[WARNING] ", format, args);
    va_end(args);
}

// NEW UNSAFE FUNCTION (without mutex!)
void Logger::PrintUnsafe(const char* prefix, const char* format, va_list args) {
    if (!m_initialized) return;
    
    // Timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    if (m_useFileLogging && m_logFile) {
        WriteToFile(prefix, format, args);
    }
    else if (m_console) {
        printf("[%02d:%02d:%02d.%03d] %s", 
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, prefix);
        
        vprintf(format, args);
        printf("\n");
        fflush(stdout);
    }
    // If neither console nor file is available, silently fail (better than crash)
}

bool Logger::InitFileLogging() {
    try {
        errno_t err = fopen_s(&m_logFile, "PS2Cheat_Log.txt", "a"); // Append mode
        if (err == 0 && m_logFile) {
            // Write a header
            SYSTEMTIME st;
            GetLocalTime(&st);
            fprintf(m_logFile, "\n=== PS2 Cheat Log Started [%04d-%02d-%02d %02d:%02d:%02d] ===\n",
                   st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            fflush(m_logFile);
            return true;
        }
    }
    catch (...) {
        // File logging failed
        m_logFile = nullptr;
    }
    return false;
}

void Logger::WriteToFile(const char* prefix, const char* format, va_list args) {
    if (!m_logFile) return;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    fprintf(m_logFile, "[%02d:%02d:%02d.%03d] %s", 
           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, prefix);
    
    vfprintf(m_logFile, format, args);
    fprintf(m_logFile, "\n");
    fflush(m_logFile);
}

// ADAPTED PrintWithPrefix (now just a wrapper with critical section)
void Logger::PrintWithPrefix(const char* prefix, const char* format, va_list args) {
    if (!m_csInitialized) return; // Logger not initialized yet
    
    CSLock lock(&m_cs);
    PrintUnsafe(prefix, format, args);
    // lock released automatically by RAII
}
