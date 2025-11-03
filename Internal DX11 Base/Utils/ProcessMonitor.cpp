#include "pch.h"
#include "ProcessMonitor.h"
#include "CrashDump.h"
#include "Logger.h"
#include <tlhelp32.h>

namespace DX11Base
{
    ProcessMonitor::ProcessMonitor()
        : m_processId(0)
        , m_processHandle(nullptr)
        , m_monitoring(false)
        , m_shouldStop(false)
    {
    }

    ProcessMonitor::~ProcessMonitor()
    {
        StopMonitoring();
    }

    void ProcessMonitor::StartMonitoring()
    {
        if (m_monitoring.load())
        {
            Logger::Warning("Process monitoring is already active!");
            return;
        }
        
        m_shouldStop = false;
        
        if (InitializeProcessHandle())
        {
            m_monitoring = true;
            m_monitorThread = std::thread(&ProcessMonitor::MonitorThread, this);
            Logger::Log("Started monitoring current process (PID: %d)", m_processId);
        }
        else
        {
            Logger::Error("Failed to initialize process handle for monitoring");
        }
    }

    void ProcessMonitor::StopMonitoring()
    {
        if (!m_monitoring.load())
            return;
        
        m_shouldStop = true;
        
        if (m_monitorThread.joinable())
        {
            m_monitorThread.join();
        }
        
        // Note: Don't close GetCurrentProcess() handle - it's a pseudo-handle
        // Just reset our reference
        m_processHandle = nullptr;
        
        m_monitoring = false;
        Logger::Log("Stopped monitoring process (PID: %d)", m_processId);
    }

    bool ProcessMonitor::IsProcessRunning()
    {
        if (!m_processHandle)
            return false;
        
        DWORD exitCode;
        if (GetExitCodeProcess(m_processHandle, &exitCode))
        {
            return exitCode == STILL_ACTIVE;
        }
        
        return false;
    }

    void ProcessMonitor::SetCrashCallback(std::function<void()> callback)
    {
        m_crashCallback = callback;
    }

    void ProcessMonitor::MonitorThread()
    {
        Logger::Log("Process monitor thread started for current process (PID: %d)", m_processId);
        
        while (!m_shouldStop.load())
        {
            try
            {
                CheckProcessStatus();
                std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Check every second
            }
            catch (const std::exception& e)
            {
                Logger::Error("Exception in monitor thread: %s", e.what());
            }
            catch (...)
            {
                Logger::Error("Unknown exception in monitor thread");
            }
        }
        
        Logger::Log("Process monitor thread stopped");
    }

    bool ProcessMonitor::InitializeProcessHandle()
    {
        // Use GetCurrentProcess() since we're injected into the target process
        m_processId = GetCurrentProcessId();
        m_processHandle = GetCurrentProcess();
        
        if (m_processHandle != nullptr)
        {
            Logger::Log("Initialized process handle for current process (PID: %d)", m_processId);
            return true;
        }
        else
        {
            Logger::Error("Failed to get current process handle. Error: %d", GetLastError());
            return false;
        }
    }

    void ProcessMonitor::CheckProcessStatus()
    {
        // If we still have no handle, reinitialize it
        if (!m_processHandle)
        {
            if (InitializeProcessHandle())
            {
                Logger::Log("Process handle reinitialized (PID: %d)", m_processId);
            }
            return;
        }
        
        // Check if process is still running
        if (!IsProcessRunning())
        {
            Logger::Error("Target process has crashed or terminated (PID: %d)", m_processId);
            
            // Create crash dump
            char processName[MAX_PATH] = {0};
            if (GetModuleFileNameA(nullptr, processName, MAX_PATH))
            {
                // Extract just the filename
                char* fileName = strrchr(processName, '\\');
                if (fileName)
                    fileName++;
                else
                    fileName = processName;
                
                std::string dumpPath = "CrashDumps\\" + std::string(fileName) + "_" + 
                                      CrashDump::GetCurrentDateTimeStringPublic() + "_ProcessTerminated.dmp";
                
                // Try to create a dump of the terminated process
                // (only works if process is still in memory)
                if (CrashDump::CreateProcessDump(m_processId, dumpPath))
                {
                    Logger::Log("Process dump created: %s", dumpPath.c_str());
                }
                else
                {
                    Logger::Warning("Could not create process dump - process may have already been cleaned up");
                }
            }
            
            // Call callback
            if (m_crashCallback)
            {
                try
                {
                    m_crashCallback();
                }
                catch (...)
                {
                    Logger::Error("Exception in crash callback");
                }
            }
            
            // Reset handle (but don't close GetCurrentProcess() handle)
            m_processHandle = nullptr;
            m_processId = 0;
        }
    }
}
