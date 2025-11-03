#include "pch.h"
#include "Engine.h"
#include "Menu.h"
#include "Utils/Logger.h"
#include "Utils/CrashDump.h"
#include "Utils/ProcessMonitor.h"
#include "Game/Game.h"
#include "Game/BulletHarvester.h"
#include "Renderer/Renderer.h"
#include "Features/ESP.h"
#include "Features/MagicBullet.h"
#include "Features/TargetManager.h"
#include "Features/Misc.h"
#include "Features/Noclip.h"
#include "Features/NoRecoil.h"
#include "Features/Aimbot.h"
#include "Hooking/hookmain.h"
#include "Hooking/MinHook.h"
#include "Utils/SettingsManager.h"

using namespace DX11Base;

std::thread dataThread;
std::unique_ptr<ProcessMonitor> g_ProcessMonitor;
PVOID g_pVehHandler = nullptr;

void GameDataThread()
{
    Logger::Log("---> GameDataThread has entered its loop.");

    int startup_tries = 0;
    while (!g_Running) {
        if (++startup_tries > 100) { // Timeout after approximately 1 second
            Logger::Error("GameDataThread timed out waiting for g_Running.");
            return;
        }
        std::this_thread::yield();
    }
    Logger::Log("GameDataThread: g_Running confirmed, starting main loop.");

    while (g_Running)
    {
        if (g_Game && g_MagicBullet && g_Misc && g_Noclip && g_NoRecoil && g_Aimbot) {
            g_Game->Update();
            g_Misc->Update();
            g_Noclip->Update();
            g_NoRecoil->Update();
            g_Aimbot->Update();
        }
        else {
            Logger::Log("GameDataThread: One or more objects destroyed, exiting...");
            break;
        }

        std::this_thread::yield();
    }
    Logger::Log("---> GameDataThread has exited its loop.");
}

void Shutdown()
{
    Logger::Log("====== SHUTDOWN SEQUENCE INITIATED ======");

    g_Running = false;
    Logger::Log("--> g_Running set to false, signaling all threads to stop");

    if (dataThread.joinable()) {
        Logger::Log("--> Waiting for GameDataThread to join...");
        dataThread.join();
        Logger::Log("... GameDataThread joined successfully.");
    }

    Logger::Log("--> Waiting for feature threads to stop...");
    
    if (g_Aimbot) {
        Logger::Log("--> Stopping Aimbot threads...");
        g_Aimbot.reset();
        Logger::Log("... Aimbot threads stopped.");
    }
    
    if (g_NoRecoil) {
        Logger::Log("--> Stopping NoRecoil threads...");
        g_NoRecoil.reset();
        Logger::Log("... NoRecoil threads stopped.");
    }
    
    std::this_thread::sleep_for(500ms);
    
    if (g_MagicBullet) {
        Logger::Log("--> Stopping MagicBullet threads...");
        g_MagicBullet.reset();
        Logger::Log("... MagicBullet threads stopped.");
    }
    
    if (g_TargetManager) {
        Logger::Log("--> Stopping TargetManager threads...");
        g_TargetManager.reset();
        Logger::Log("... TargetManager threads stopped.");
    }
    
    std::this_thread::sleep_for(500ms);
    
    Logger::Log("--> Final thread cleanup check...");
    std::this_thread::sleep_for(100ms);

    // Restore original Window Procedure
    if (g_D3D11Window && g_D3D11Window->m_OldWndProc)
    {
        Logger::Log("--> Restoring original WndProc...");
        SetWindowLongPtr(g_Engine->pGameWindow, GWLP_WNDPROC, (LONG_PTR)g_D3D11Window->m_OldWndProc);
        g_D3D11Window->m_OldWndProc = nullptr;
        Logger::Log("... Original WndProc restored.");
    }

    if (g_D3D11Window)
    {
        Logger::Log("--> Unhooking D3D...");
        g_D3D11Window->UnhookD3D();
        Logger::Log("... D3D unhooked.");
    }

    if (g_D3D11Window && g_D3D11Window->bInitImGui)
    {
        Logger::Log("--> Shutting down ImGui...");
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        Logger::Log("... ImGui context destroyed.");
    }

    if (g_pVehHandler)
    {
        Logger::Log("--> Removing Vectored Exception Handler...");
        if (RemoveVectoredExceptionHandler(g_pVehHandler))
        {
            Logger::Log("... Vectored Exception Handler removed successfully.");
        }
        else
        {
            Logger::Error("... FAILED to remove Vectored Exception Handler!");
        }
        g_pVehHandler = nullptr;
    }

    if (g_ProcessMonitor) {
        Logger::Log("--> Stopping process monitor...");
        g_ProcessMonitor->StopMonitoring();
        g_ProcessMonitor.reset();
        Logger::Log("... Process monitor stopped.");
    }
    
    if (g_BulletHarvester) {
        Logger::Log("--> Stopping BulletHarvester threads...");
        g_BulletHarvester.reset();
        Logger::Log("... BulletHarvester threads stopped.");
    }

    Logger::Log("--> Destroying remaining feature classes...");
    
    
    delete g_Noclip;
    g_Noclip = nullptr;
    Logger::Log("Noclip destroyed.");
    
    g_Misc.reset();
    Logger::Log("Misc destroyed.");
    
    g_ESP.reset();
    Logger::Log("ESP destroyed.");
    
    
    g_Renderer.reset();
    g_Game.reset();
    g_Engine.reset();
    Logger::Log("... All classes destroyed.");

    Logger::Log("Waiting for threads to finish...");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    Logger::Log("--> Uninitializing MinHook...");
    MH_Uninitialize();
    
    Logger::Log("--> Performing final cleanup...");
    
    g_Running = false;
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    Logger::Log("====== SHUTDOWN SEQUENCE COMPLETED ======");

    Logger::Log("--> Finalizing shutdown. Shutting down logger.");
    Logger::Shutdown();

    FreeLibraryAndExitThread(g_hModule, 0);
}


DWORD WINAPI MainThread_Initialize(LPVOID dwModule) {
    DX11Base::g_hModule = static_cast<HMODULE>(dwModule);

    // Critical: Logger must be initialized first, but wrap it in try-catch
    try {
        Logger::Init();
        Logger::Log("-> MainThread_Initialize started.");
    }
    catch (...) {
        // Logger failed - show MessageBox as last resort
        MessageBoxA(nullptr, 
                   "CRITICAL: Logger initialization failed!\nThe cheat cannot continue.",
                   "PS2 Cheat - Fatal Error", 
                   MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }
    
    // Check for Visual C++ Runtime (MSVCP140.dll)
    HMODULE hVCRuntime = GetModuleHandleA("MSVCP140.dll");
    if (!hVCRuntime) {
        // Try to load it explicitly
        hVCRuntime = LoadLibraryA("MSVCP140.dll");
        if (!hVCRuntime) {
            Logger::Error("MSVCP140.dll not found! Visual C++ Runtime may be missing.");
            MessageBoxA(nullptr,
                "CRITICAL: Visual C++ Runtime (MSVCP140.dll) not found!\n\n"
                "Please install:\n"
                "Microsoft Visual C++ Redistributable 2015-2022 (x64)\n\n"
                "Download from:\n"
                "https://aka.ms/vs/17/release/vc_redist.x64.exe\n\n"
                "Without this, the cheat will crash immediately.",
                "PS2 Cheat - Missing Runtime",
                MB_OK | MB_ICONERROR);
            return EXIT_FAILURE;
        }
        FreeLibrary(hVCRuntime); // Don't keep it loaded, just check if it exists
    }
    else {
        Logger::Log("Visual C++ Runtime (MSVCP140.dll) detected");
    }
    
    // Check for BattlEye Service (BEService.exe) and Driver (BEDaisy.sys)
    // Only check if they are actually RUNNING, not just if they exist
    bool beserviceDetected = false;
    bool bedaisyDetected = false;
    std::string detectedComponents = "";
    
    // Check for BEService.exe as a Windows Service (only if RUNNING)
    SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCManager) {
        SC_HANDLE hService = OpenServiceA(hSCManager, "BEService", SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS_PROCESS serviceStatus = {0};
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, 
                                    sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
                if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                    beserviceDetected = true;
                    detectedComponents = "BEService.exe";
                    Logger::Warning("BEService.exe detected as running Windows Service!");
                }
            }
            CloseServiceHandle(hService);
        }
        
        // Check for BEDaisy.sys as a Kernel Driver Service (only if RUNNING)
        SC_HANDLE hBEDaisyService = OpenServiceA(hSCManager, "BEDaisy", SERVICE_QUERY_STATUS);
        if (hBEDaisyService) {
            SERVICE_STATUS_PROCESS serviceStatus = {0};
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(hBEDaisyService, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, 
                                    sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
                // For kernel drivers, check if state is SERVICE_RUNNING
                // Note: Kernel drivers might show different states, but RUNNING means loaded
                if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                    bedaisyDetected = true;
                    if (!detectedComponents.empty()) {
                        detectedComponents += " or ";
                    }
                    detectedComponents += "BEDaisy.sys";
                    Logger::Warning("BEDaisy.sys detected as running Kernel Driver!");
                }
            }
            CloseServiceHandle(hBEDaisyService);
        }
        
        CloseServiceHandle(hSCManager);
    }
    
    // Also check if BEService.exe exists as a process (fallback check)
    if (!beserviceDetected) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    // Convert WCHAR to char for comparison
                    char processName[260];
                    WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, processName, sizeof(processName), NULL, NULL);
                    if (_stricmp(processName, "BEService.exe") == 0) {
                        beserviceDetected = true;
                        detectedComponents = "BEService.exe";
                        Logger::Warning("BEService.exe detected as running process!");
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    // If either is detected, show error and unload
    if (beserviceDetected || bedaisyDetected) {
        std::string errorMessage = "BattlEye is running!\n\n";
        if (beserviceDetected && bedaisyDetected) {
            errorMessage += "BEService.exe and BEDaisy.sys are both running.\n\n";
        }
        else {
            errorMessage += detectedComponents + " is running.\n\n";
        }
        errorMessage += "This cheat will not work with BattlEye running.\n\n";
        errorMessage += "Please stop the service/driver using System Informer or restart your PC before injecting again.";
        
        Logger::Error("BattlEye detected: %s - Unloading cheat DLL", detectedComponents.c_str());
        MessageBoxA(nullptr,
            errorMessage.c_str(),
            "PS2 Cheat - BattlEye Detected",
            MB_OK | MB_ICONERROR);
        
        g_Running = false;
        Sleep(100);
        Logger::Shutdown();
        FreeLibraryAndExitThread(DX11Base::g_hModule, 0);
        return EXIT_FAILURE;
    }
    else {
        Logger::Log("BEService.exe and BEDaisy.sys not running - BattlEye is not active");
    }
    
    // Check for BattlEye Anticheat DLL
    HMODULE hBEClient = GetModuleHandleA("BEClient_x64.dll");
    if (hBEClient) {
        Logger::Warning("BEClient_x64.dll detected! BattlEye Anticheat is running.");
        
        int result = MessageBoxA(nullptr,
            "Warning: \"BEClient_x64.dll\" BattlEye Anticheat is running!\n\n"
            "Make sure to unload the BEClient dll first, before you inject the Cheat, "
            "otherwise you will be kicked out of the game after a few minutes.\n\n"
            "We can unload the dll for you if you want, but this only works if you are "
            "within the Character Selection screen. If you are already ingame, unloading "
            "the BE Dll will kick you out of the game too.\n\n"
            "Do you want me to unload the dll for you?",
            "PS2 Cheat - BattlEye Warning",
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
        
        if (result == IDYES) {
            Logger::Log("User chose to unload BEClient_x64.dll");
            
            // Try to unload the DLL
            // Note: This may not work if the DLL is actively being used by the game
            BOOL unloadResult = FreeLibrary(hBEClient);
            
            if (unloadResult) {
                Logger::Log("Successfully unloaded BEClient_x64.dll");
                MessageBoxA(nullptr,
                    "BE Client DLL has been successfully unloaded.\n\n"
                    "You can go ingame now.",
                    "PS2 Cheat - DLL Unloaded",
                    MB_OK | MB_ICONINFORMATION);
            }
            else {
                DWORD error = GetLastError();
                Logger::Error("Failed to unload BEClient_x64.dll. Error: %d", error);
                
                MessageBoxA(nullptr,
                    "Unloading BE DLL failed!\n\n"
                    "You need to restart the game now and make sure to bypass the anticheat first!",
                    "PS2 Cheat - Unload Failed",
                    MB_OK | MB_ICONERROR);
            }
        }
        else {
            Logger::Log("User chose NOT to unload BEClient_x64.dll - continuing anyway");
        }
    }
    else {
        Logger::Log("BEClient_x64.dll not detected - BattlEye is not running");
    }
    
    // Settings loading - non-critical, continue if it fails
    try {
        SettingsManager::LoadSettings();
        Logger::Log("Settings loaded from config file.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to load settings: %s (using defaults)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to load settings (unknown error), using defaults");
    }
    
    // MinHook initialization - critical
    try {
        if (MH_Initialize() != MH_OK) {
            Logger::Error("!!! CRITICAL: Failed to initialize MinHook! !!!");
            MessageBoxA(nullptr, 
                       "CRITICAL: MinHook initialization failed!\nThe cheat will not work.",
                       "PS2 Cheat - Critical Error", 
                       MB_OK | MB_ICONERROR);
            return EXIT_FAILURE;
        }
        Logger::Log("0. MinHook initialized successfully.");
    }
    catch (...) {
        Logger::Error("Exception during MinHook initialization");
        MessageBoxA(nullptr, 
                   "CRITICAL: Exception during MinHook initialization!",
                   "PS2 Cheat - Critical Error", 
                   MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    // CrashDump initialization - try to continue even if it fails
    try {
        g_pVehHandler = CrashDump::Initialize();
        Logger::Log("1. CrashDump system initialized.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to initialize CrashDump: %s (continuing anyway)", e.what());
        g_pVehHandler = nullptr;
    }
    catch (...) {
        Logger::Error("Unknown exception in CrashDump::Initialize (continuing anyway)");
        g_pVehHandler = nullptr;
    }

    // Engine creation - critical
    try {
        g_Engine = std::make_unique<Engine>();
        Logger::Log("2. g_Engine created.");
    }
    catch (const std::exception& e) {
        Logger::Error("CRITICAL: Failed to create Engine! Error: %s", e.what());
        MessageBoxA(nullptr, 
                   "CRITICAL: Failed to create Engine!\nThe cheat will not work.",
                   "PS2 Cheat - Critical Error", 
                   MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }
    catch (...) {
        Logger::Error("CRITICAL: Unknown exception while creating Engine!");
        MessageBoxA(nullptr, 
                   "CRITICAL: Unknown exception while creating Engine!",
                   "PS2 Cheat - Critical Error", 
                   MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    // Game initialization - critical, but SafeMemory might fail on slow PCs
    try {
        g_Game = std::make_unique<Game>();
        Logger::Log("3. g_Game created.");
    }
    catch (const std::exception& e) {
        Logger::Error("CRITICAL: Failed to create Game! Error: %s", e.what());
        MessageBoxA(nullptr, 
                   "CRITICAL: Failed to create Game!\nCheck if PlanetSide 2 is running correctly.",
                   "PS2 Cheat - Critical Error", 
                   MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }
    catch (...) {
        Logger::Error("CRITICAL: Unknown exception while creating Game!");
        MessageBoxA(nullptr, 
                   "CRITICAL: Unknown exception while creating Game!\nPossible memory access issue.",
                   "PS2 Cheat - Critical Error", 
                   MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    // BulletHarvester - non-critical
    try {
        g_BulletHarvester = std::make_unique<BulletHarvester>();
        Logger::Log("3a. g_BulletHarvester created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create BulletHarvester: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to create BulletHarvester (continuing)");
    }

    // Renderer - critical for ESP
    try {
        g_Renderer = std::make_unique<Renderer>();
        Logger::Log("4. g_Renderer created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create Renderer: %s (ESP may not work)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to create Renderer (ESP may not work)");
    }

    // ESP - non-critical
    try {
        g_ESP = std::make_unique<ESP>();
        Logger::Log("5. g_ESP created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create ESP: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to create ESP (continuing)");
    }

    g_Running = true;
    Logger::Log("5a. g_Running set to true.");

    // MagicBullet - non-critical
    try {
        g_MagicBullet = std::make_unique<MagicBullet>();
        Logger::Log("6. g_MagicBullet created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create MagicBullet: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to create MagicBullet (continuing)");
    }

    // TargetManager - non-critical
    try {
        g_TargetManager = std::make_unique<TargetManager>();
        Logger::Log("6a. g_TargetManager created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create TargetManager: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to create TargetManager (continuing)");
    }

    // Small delay for slower systems
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Misc - non-critical
    try {
        g_Misc = std::make_unique<Misc>();
        Logger::Log("7. g_Misc created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create Misc: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to create Misc (continuing)");
    }
    
    // Noclip - non-critical
    try {
        g_Noclip = new Noclip();
        Logger::Log("7a. g_Noclip created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create Noclip: %s (continuing)", e.what());
        g_Noclip = nullptr;
    }
    catch (...) {
        Logger::Warning("Failed to create Noclip (continuing)");
        g_Noclip = nullptr;
    }
    
    // NoRecoil - non-critical
    try {
        g_NoRecoil = std::make_unique<NoRecoil>();
        Logger::Log("7b. g_NoRecoil created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create NoRecoil: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to create NoRecoil (continuing)");
    }

    // Aimbot - non-critical
    try {
        g_Aimbot = std::make_unique<Aimbot>();
        Logger::Log("7c. g_Aimbot created.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to create Aimbot: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to create Aimbot (continuing)");
    }

    // ProcessMonitor - non-critical
    try {
        g_ProcessMonitor = std::make_unique<ProcessMonitor>();
        g_ProcessMonitor->SetCrashCallback([]() {
            try {
                Logger::Error("PlanetSide 2 process crash detected! Creating emergency dump...");
                CrashDump::CreateCrashDump("Process Crash Detected");
            }
            catch (...) {
                // Even crash callback can fail, just ignore
            }
        });
        g_ProcessMonitor->StartMonitoring();
        Logger::Log("8. Process monitor started for current process");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to start ProcessMonitor: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to start ProcessMonitor (continuing)");
    }

    // D3D Hooking - critical for menu
    try {
        if (g_D3D11Window) {
            g_D3D11Window->HookD3D();
            Logger::Log("9. D3D Hooks created.");
        }
        else {
            Logger::Error("g_D3D11Window is NULL! D3D hooks not created.");
        }
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to hook D3D: %s (menu may not work)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to hook D3D (menu may not work)");
    }

    // Game hooks - critical
    try {
        if (g_Hooking) {
            g_Hooking->Initialize();
            Logger::Log("10. All hooks enabled.");
        }
        else {
            Logger::Error("g_Hooking is NULL! Game hooks not enabled.");
        }
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to initialize game hooks: %s", e.what());
    }
    catch (...) {
        Logger::Error("Unknown exception while initializing game hooks");
    }

    // GameDataThread - non-critical
    try {
        dataThread = std::thread(GameDataThread);
        Logger::Log("11. GameDataThread started.");
    }
    catch (const std::exception& e) {
        Logger::Error("Failed to start GameDataThread: %s (continuing)", e.what());
    }
    catch (...) {
        Logger::Warning("Failed to start GameDataThread (continuing)");
    }

    Logger::Log("-> PS2 Cheat started successfully!");

    while (g_Running)
    {
        if (GetAsyncKeyState(VK_INSERT) & 1)
        {
            g_Engine->bShowMenu = !g_Engine->bShowMenu;
        }
        if (GetAsyncKeyState(VK_END) & 1)
        {
            break;
        }
        std::this_thread::yield();
    }

    SettingsManager::SaveSettings();
    Logger::Log("Settings saved to config file.");

    Shutdown();

    return EXIT_SUCCESS;
}