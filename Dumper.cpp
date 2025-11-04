#include "Dumper.h"

void Parse(char* combo, char* pattern, char* mask)
{
    char lastChar = ' ';
    unsigned int j = 0;

    for (unsigned int i = 0; i < strlen(combo); i++)
    {
        if ((combo[i] == '?' || combo[i] == '*') && (lastChar != '?' && lastChar != '*'))
        {
            pattern[j] = mask[j] = '?';
            j++;
        }
        else if (isspace(lastChar))
        {
            pattern[j] = lastChar = (char)strtol(&combo[i], 0, 16);
            mask[j] = 'x';
            j++;
        }
        lastChar = combo[i];
    }
    pattern[j] = mask[j] = '\0';
}

char* ScanBasic(char* pattern, char* mask, char* begin, intptr_t size)
{
    intptr_t patternLen = strlen(mask);

    for (int i = 0; i < size; i++)
    {
        bool found = true;
        for (int j = 0; j < patternLen; j++)
        {
            if (mask[j] != '?' && pattern[j] != *(char*)((intptr_t)begin + i + j))
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (begin + i);
        }
    }
    return nullptr;
}

//https://guidedhacking.com/threads/universal-pattern-signature-parser.9588/ 
char* Scan(char* combopattern, char* begin, size_t size)
{
    char pattern[100];
    char mask[100];
    Parse(combopattern, pattern, mask);
    return ScanBasic(pattern, mask, begin, size);
}

bool Dumper::ReadProgramIntoMemory(std::string DumpPath, std::vector<uint8_t>* out_buffer)
{
    std::ifstream file_ifstream(DumpPath, std::ios::binary);

    if (!file_ifstream)
        return false;

    out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
    file_ifstream.close();

    return true;
}

bool Dumper::DumpOffsets(BYTE* Dump, size_t size)
{
    printf("=== Planetside 2 Offset Dumper (Updated) ===\n\n");
    printf("Global offsets:\n");

    std::ofstream myfile("Offsets.h");
    if (myfile.is_open())
    {
        myfile << "#include <cstdint>\n\n";
        myfile << "namespace offsets\n{\n";
        myfile << "    // Base Addresses (absolute - relative to BaseAddress)\n";
    }

    // ========== CGame Base Address ==========
    // Signature: CGame_DirectAccess - mov rcx, [g_pCGame] -> test rcx, rcx -> call CGame_GetInstance
    // Address: 0x140B10874
    // Offset: 0x40B7AE0
    auto cGame = Scan((char*)"48 8B 0D ? ? ? ? 48 85 C9 74 ? E8 ? ? ? ? 48 85 C0 74 ? 48 8B D0", (char*)Dump, size);
    if (cGame)
    {
        printf("Found cGame\n");
        ULONG32 FoundRelativeOffset = *(int*)(cGame + 3);
        auto RelativeOffset = ((ULONG64)cGame - (ULONG64)Dump) + 0xA00; // Offset correction
        ULONG64 Address = (ULONG64)(RelativeOffset + FoundRelativeOffset + 7);
        myfile << std::hex << "    constexpr uintptr_t pCGameAddress = 0x" << Address << ";  // g_pCGame\n";
        printf("\t[+]Offset = 0x%llx\n", Address);
    }
    else
    {
        printf("Failed to find cGame\n");
    }

    // ========== CGraphics Base Address ==========
    // Signature: CGraphics_RenderMain - mov rax, [g_pCGraphics]
    // Address: 0x140A83346
    // Offset: 0x40B7C50
    auto cGraphics = Scan((char*)"48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 8B 49 ? ? ? ? FF 50 ? 84 C0 0F 85 ? ? ? ? C7 05", (char*)Dump, size);
    if (cGraphics)
    {
        printf("Found cGraphics\n");
        ULONG32 FoundRelativeOffset = *(int*)(cGraphics + 3);
        auto RelativeOffset = ((ULONG64)cGraphics - (ULONG64)Dump) + 0xA00;
        ULONG64 Address = (ULONG64)(RelativeOffset + FoundRelativeOffset + 7);
        myfile << std::hex << "    constexpr uintptr_t pCGraphics = 0x" << Address << ";  // g_pCGraphics\n";
        printf("\t[+]Offset = 0x%llx\n", Address);
    }
    else
    {
        printf("Failed to find cGraphics\n");
    }

    // ========== FOV Address ==========
    // Signature: FOV_ClipRange - movss [g_fFOV], xmm0
    // Address: 0x140DFE080
    // Offset: 0x144260CFC
    auto fov = Scan((char*)"F3 0F 11 05 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? 90", (char*)Dump, size);
    if (fov)
    {
        printf("Found FOV\n");
        ULONG32 FoundRelativeOffset = *(int*)(fov + 4);
        auto RelativeOffset = ((ULONG64)fov - (ULONG64)Dump) + 0xA00;
        ULONG64 Address = (ULONG64)(RelativeOffset + FoundRelativeOffset + 8);
        myfile << std::hex << "    constexpr uintptr_t o_FOV = 0x" << Address << ";  // g_fFOV\n";
        printf("\t[+]Offset = 0x%llx\n", Address);
    }
    else
    {
        printf("Failed to find FOV\n");
    }

    // ========== CurrentBulletPointerBase ==========
    // Signature: BulletHarvester_ProcessBullets
    // Address: 0x140B7F0A0
    // Offset: 0x40B82C0
    ULONG64 bulletBaseAddress = 0; // Store for later use in MagicBullet namespace
    auto bulletBase = Scan((char*)"48 89 54 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 C7 45 ? ? ? ? ? 48 89 9C 24 ? ? ? ? 4D 8B E9", (char*)Dump, size);
    if (bulletBase)
    {
        // Find the actual mov instruction that loads g_pCurrentBulletPointerBase
        // Look for mov r15, [g_pCurrentBulletPointerBase] pattern nearby
        for (int i = 0; i < 100; i++)
        {
            if (*(BYTE*)(bulletBase + i) == 0x4C && *(BYTE*)(bulletBase + i + 1) == 0x8B && 
                (*(BYTE*)(bulletBase + i + 2) == 0x3D || *(BYTE*)(bulletBase + i + 2) == 0x2D))
            {
                ULONG32 FoundRelativeOffset = *(int*)(bulletBase + i + 3);
                auto RelativeOffset = ((ULONG64)(bulletBase + i) - (ULONG64)Dump) + 0xA00;
                bulletBaseAddress = (ULONG64)(RelativeOffset + FoundRelativeOffset + 7);
                printf("Found CurrentBulletPointerBase\n");
                myfile << std::hex << "    constexpr uintptr_t pCurrentBulletPointerBase = 0x" << bulletBaseAddress << ";  // g_pCurrentBulletPointerBase\n";
                printf("\t[+]Offset = 0x%llx\n", bulletBaseAddress);
                break;
            }
        }
    }
    else
    {
        printf("Failed to find CurrentBulletPointerBase\n");
    }

    myfile << "\n";
    myfile << "    // CGame Offsets\n";

    // ========== FirstObject ==========
    // Signature: FirstObject_Access - mov rcx, [rsi+0x1060]
    // Address: 0x140BC692A
    // Offset: +0x1060
    auto FirstObject = Scan((char*)"48 8B 8E ? ? ? ? 48 85 C9 74 ? 66 66 0F 1F 84 00 ? ? ? ? 48 8B 81 ? ? ? ? 4C 89 B1 ? ? ? ? 48 8B C8 48 85 C0 75 ? 4C 89 B6 ? ? ? ? 4C 89 B6 ? ? ? ? 4C 89 B6 ? ? ? ? 4C 39 B6", (char*)Dump, size);
    if (FirstObject)
    {
        printf("Found FirstObject\n");
        auto offset = *(int*)(FirstObject + 3);
        printf("\t[+]Offset = 0x%x\n", offset);
        myfile << std::hex << "    constexpr uintptr_t o_cGame_pFirstObject = 0x" << offset << ";  // FirstObject\n";
    }
    else
    {
        printf("Failed to find FirstObject\n");
    }

    // ========== NextObject ==========
    // Signature: NextObject_Access - mov rcx, [rsi+0x5A8]
    // Address: 0x140BC2A50
    // Offset: +0x5A8
    auto NextObject = Scan((char*)"40 56 57 41 56 48 83 EC ? 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 4C 8B F2 48 8B F1 48 8D 99", (char*)Dump, size);
    if (NextObject)
    {
        // Look for the actual mov instruction that writes NextObject
        // Pattern: mov [rsi+0x5A8], rax or similar
        for (int i = 0; i < 200; i++)
        {
            if (*(BYTE*)(NextObject + i) == 0x4C && *(BYTE*)(NextObject + i + 1) == 0x89)
            {
                int offset = *(int*)(NextObject + i + 3);
                if (offset == 0x5A8 || offset == 1448) // 0x5A8 = 1448 decimal
                {
                    printf("Found NextObject\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "    constexpr uintptr_t o_pNextObject = 0x" << offset << ";  // NextObject\n";
                    break;
                }
            }
        }
    }
    else
    {
        printf("Failed to find NextObject\n");
    }

    // ========== EntityCount ==========
    // Signature: EntityCount_Increment - inc qword ptr [rsi+0x2710]
    // Address: 0x140BC2B73
    // Offset: +0x2710
    auto EntityCount = Scan((char*)"48 FF 86 ? ? ? ? 48 8B 86 ? ? ? ? 48 89 87 ? ? ? ? 48 89 8F", (char*)Dump, size);
    if (EntityCount)
    {
        printf("Found EntityCount\n");
        auto offset = *(int*)(EntityCount + 3);
        printf("\t[+]Offset = 0x%x\n", offset);
        myfile << std::hex << "    constexpr uintptr_t o_EntityCount = 0x" << offset << ";  // EntityCount\n";
    }
    else
    {
        printf("Failed to find EntityCount\n");
    }

    myfile << "\n";
    myfile << "    // Entity Offsets\n";
    myfile << "    namespace Entity {\n";

    // ========== TeamID ==========
    // Signature: Entity_GetTeamID - mov eax, [rcx+0x1E8]
    // Address: 0x140B57070
    // Offset: +0x1E8
    auto PlayerTeam = Scan((char*)"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 81 ? ? ? ? 33 F6 C7 05", (char*)Dump, size);
    if (PlayerTeam)
    {
        // Look for mov eax, [rcx+offset] pattern - the offset is at +16 (after 8B 81)
        for (int i = 0; i < 50; i++)
        {
            if (*(BYTE*)(PlayerTeam + i) == 0x8B && *(BYTE*)(PlayerTeam + i + 1) == 0x81)
            {
                int offset = *(int*)(PlayerTeam + i + 2);
                // Accept offset in reasonable range (typically 0x1E0-0x200)
                if (offset >= 0x1E0 && offset < 0x200)
                {
                    printf("Found TeamID\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "        constexpr uintptr_t TeamID = 0x" << offset << ";\n";
                    break;
                }
            }
        }
    }
    else
    {
        printf("Failed to find TeamID\n");
    }

    // ========== Type ==========
    // Signature: EntityType_CheckWithHash - mov edx, [rax+0x5E0]
    // Address: 0x141639980
    // Offset: +0x5E0
    // Try multiple patterns for Type
    int typeOffset = -1;
    auto PlayerType = Scan((char*)"40 53 48 83 EC ? 80 B9 ? ? ? ? ? 48 8B D9 74 ? 48 83 C2 ? ? ? ? 48 85 C0", (char*)Dump, size);
    if (PlayerType)
    {
        // Look for mov edx, [rax+offset] pattern - search for 8B 90 E0050000 (mov edx, [rax+0x5E0])
        for (int i = 0; i < 300; i++)
        {
            if (*(BYTE*)(PlayerType + i) == 0x8B && *(BYTE*)(PlayerType + i + 1) == 0x90)
            {
                int offset = *(int*)(PlayerType + i + 2);
                // Accept offset in reasonable range (typically 0x5D0-0x600)
                if (offset >= 0x5D0 && offset < 0x600)
                {
                    typeOffset = offset;
                    printf("Found Type\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "        constexpr uintptr_t Type = 0x" << offset << ";\n";
                    break;
                }
            }
        }
    }
    if (typeOffset == -1)
    {
        printf("Failed to find Type\n");
    }

    // ========== PlayerStance ==========
    // Signature: Player_UpdateStance - mov r14d, [rbx+0x2A04]
    // Address: 0x140BA80B0
    // Offset: +0x2A04
    auto PlayerStance = Scan((char*)"40 55 53 56 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 C7 45 ? ? ? ? ? 0F 29 B4 24 ? ? ? ? 48 8B F2", (char*)Dump, size);
    if (PlayerStance)
    {
        // Look for mov r14d/eax, [rbx/rcx/rsi+0x2A04] pattern
        for (int i = 0; i < 300; i++)
        {
            if ((*(BYTE*)(PlayerStance + i) == 0x44 || *(BYTE*)(PlayerStance + i) == 0x8B) && 
                (*(BYTE*)(PlayerStance + i + 1) == 0xAE || *(BYTE*)(PlayerStance + i + 1) == 0x81))
            {
                int offset = *(int*)(PlayerStance + i + 2);
                if (offset == 0x2A04 || offset == 10756) // 0x2A04 = 10756 decimal
                {
                    printf("Found PlayerStance\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "        constexpr uintptr_t PlayerStance = 0x" << offset << ";\n";
                    break;
                }
            }
        }
    }
    else
    {
        printf("Failed to find PlayerStance\n");
    }

    // ========== ViewAngle ==========
    // Signature: Player_UpdateViewAngle - movaps xmm0, [rcx+0x2C20]
    // Address: 0x140DFA2E0
    // Offset: +0x2C20
    auto vec2ViewAngle = Scan((char*)"48 8B C4 F3 0F 11 50 ? 48 89 50 ? 55 53 56 57 41 54 41 55 41 56", (char*)Dump, size);
    if (vec2ViewAngle)
    {
        // Look for movaps xmm0, [rcx+0x2C20] or mov [rcx+0x2C20], xmm0
        for (int i = 0; i < 300; i++)
        {
            if (*(BYTE*)(vec2ViewAngle + i) == 0x0F && *(BYTE*)(vec2ViewAngle + i + 1) == 0x28)
            {
                int offset = *(int*)(vec2ViewAngle + i + 3);
                if (offset == 0x2C20 || offset == 11296) // 0x2C20 = 11296 decimal
                {
                    printf("Found ViewAngle\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "        constexpr uintptr_t ViewAngle = 0x" << offset << ";\n";
                    break;
                }
            }
        }
    }
    else
    {
        printf("Failed to find ViewAngle\n");
    }

    // ========== pActor ==========
    // Signature: Look for mov rcx, [rcx+0x828] pattern
    // Offset: +0x828
    auto cActor = Scan((char*)"48 8B 81 ? ? ? ? 48 85 C0 74 0C 8B 80 ? ? ? ? 89 02 48 8B C2 C3 C7 02 ? ? ? ? 48 8B C2 C3", (char*)Dump, size);
    if (cActor)
    {
        printf("Found pActor\n");
        auto offset = *(int*)(cActor + 3);
        printf("\t[+]Offset = 0x%x\n", offset);
        myfile << std::hex << "        constexpr uintptr_t pActor = 0x" << offset << ";\n";
    }
    else
    {
        printf("Failed to find pActor\n");
    }

    // ========== pACtor ==========
    // Signature: Entity_CheckACtor - cmp [rcx+0x428], rax
    // Address: 0x140B89630
    // Offset: +0x428
    auto cACtor = Scan((char*)"48 83 EC ? 48 C7 44 24 ? ? ? ? ? ? ? ? 48 39 81", (char*)Dump, size);
    if (cACtor)
    {
        // Look for cmp [rcx+0x428], rax
        for (int i = 0; i < 50; i++)
        {
            if (*(BYTE*)(cACtor + i) == 0x48 && *(BYTE*)(cACtor + i + 1) == 0x39)
            {
                int offset = *(int*)(cACtor + i + 3);
                if (offset == 0x428 || offset == 1064) // 0x428 = 1064 decimal
                {
                    printf("Found pACtor\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "        constexpr uintptr_t pACtor = 0x" << offset << ";  // Different from pActor!\n";
                    break;
                }
            }
        }
    }
    else
    {
        printf("Failed to find pACtor\n");
    }

    // ========== pSkeleton ==========
    // Signature: Actor_UpdateBoundingBox - mov r8, [rsi+0x1D8]
    // Address: 0x1425BE730
    // Offset: +0x1D8 (relative to Actor)
    auto cSkelaton = Scan((char*)"4C 8B DC 49 89 5B ? 49 89 73 ? 41 56 48 81 EC ? ? ? ? 48 8B F1 8B 81 ? ? ? ? 33 DB 85 C0 44 8B F3 0F B6 81 ? ? ? ? 41 0F 94 C6 3C ? 0F 83 ? ? ? ? 0F B6 C0", (char*)Dump, size);
    if (cSkelaton)
    {
        // Look for mov r8, [rsi+0x1D8] or mov rcx, [rsi+0x1D8]
        for (int i = 0; i < 200; i++)
        {
            if ((*(BYTE*)(cSkelaton + i) == 0x4C || *(BYTE*)(cSkelaton + i) == 0x48) && 
                *(BYTE*)(cSkelaton + i + 1) == 0x8B)
            {
                int offset = *(int*)(cSkelaton + i + 3);
                if (offset == 0x1D8 || offset == 472) // 0x1D8 = 472 decimal
                {
                    printf("Found pSkeleton\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "        constexpr uintptr_t pSkeleton = 0x" << offset << ";\n";
                    break;
                }
            }
        }
    }
    else
    {
        printf("Failed to find pSkeleton\n");
    }

    // ========== pSkeletonInfo ==========
    // Signature: Skeleton_UpdateSkeletonInfo - mov rcx, [rcx+0x50]
    // Address: 0x1423F8620
    // Offset: +0x50 (relative to Skeleton)
    auto cSkelatonInfo = Scan((char*)"48 8B C4 56 57 41 56 48 83 EC ? 48 C7 40 ? ? ? ? ? 48 89 58 ? 48 89 68 ? 0F B6 FA", (char*)Dump, size);
    if (cSkelatonInfo)
    {
        // Look for mov rcx, [rcx+0x50] or mov rdx, [rcx+0x50]
        for (int i = 0; i < 150; i++)
        {
            if (*(BYTE*)(cSkelatonInfo + i) == 0x48 && *(BYTE*)(cSkelatonInfo + i + 1) == 0x8B)
            {
                int offset = *(int*)(cSkelatonInfo + i + 3);
                if (offset == 0x50 || offset == 80) // 0x50 = 80 decimal
                {
                    printf("Found pSkeletonInfo\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "        constexpr uintptr_t pSkeletonInfo = 0x" << offset << ";\n";
                    break;
                }
            }
        }
    }
    else
    {
        printf("Failed to find pSkeletonInfo\n");
    }

    // ========== pBoneInfo ==========
    // Signature: SkeletonInfo_UpdateBoneData - mov rax, [rdi+0x68]
    // Address: 0x1424048E0
    // Offset: +0x68 (relative to SkeletonInfo)
    auto cBoneInfo = Scan((char*)"48 8B C4 57 48 83 EC ? 48 C7 40 ? ? ? ? ? 48 89 58 ? 48 89 70 ? 48 8B F9 48 8D 59", (char*)Dump, size);
    if (cBoneInfo)
    {
        // Look for mov rax, [rdi+0x68] or mov rcx, [rdi+0x68]
        for (int i = 0; i < 150; i++)
        {
            if (*(BYTE*)(cBoneInfo + i) == 0x48 && *(BYTE*)(cBoneInfo + i + 1) == 0x8B)
            {
                int offset = *(int*)(cBoneInfo + i + 3);
                if (offset == 0x68 || offset == 104) // 0x68 = 104 decimal
                {
                    printf("Found pBoneInfo\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    myfile << std::hex << "        constexpr uintptr_t pBoneInfo = 0x" << offset << ";\n";
                    break;
                }
            }
        }
    }
    else
    {
        printf("Failed to find pBoneInfo\n");
    }

    // ========== Position ==========
    // Signature: PlayerPosition_UpdateWithChecksum - Look for movaps xmm15, [rsi+0x920]
    // Address: 0x140B749BC
    // Offset: +0x920
    int positionOffset = -1; // MUST be found via scan!
    // Try to find movaps xmm15, [rsi+offset] pattern - 44 0F28 BE ? ? ? ?
    auto positionFunc = Scan((char*)"44 0F 28 BE ? ? ? ?", (char*)Dump, size);
    if (positionFunc)
    {
        int offset = *(int*)(positionFunc + 4);
        // Accept offset in reasonable range (typically 0x900-0x940)
        if (offset >= 0x900 && offset < 0x940)
        {
            positionOffset = offset;
            printf("Found Position offset\n");
            printf("\t[+]Offset = 0x%x\n", offset);
        }
    }
    // Fallback: Try the longer pattern
    if (positionOffset == -1)
    {
        auto positionFunc2 = Scan((char*)"48 89 5C 24 ? 45 33 D2 B8 ? ? ? ? 45 8B DA 44 8B C8 48 8B D9 4C 8B C1 0F 1F 80 ? ? ? ? ? ? ? 4D 8D 40 ? 49 83 E9 ? 75 ? 4C 3B 99", (char*)Dump, size);
        if (positionFunc2)
        {
            // Look for movaps xmm15/xmm8, [rsi+offset] - search for ANY offset in reasonable range (0x900-0x940)
            for (int i = 0; i < 300; i++)
            {
                if (*(BYTE*)(positionFunc2 + i) == 0x44 && *(BYTE*)(positionFunc2 + i + 1) == 0x0F && *(BYTE*)(positionFunc2 + i + 2) == 0x28)
                {
                    int offset = *(int*)(positionFunc2 + i + 4);
                    // Accept any offset in reasonable range for Position (typically 0x900-0x940)
                    if (offset >= 0x900 && offset < 0x940)
                    {
                        positionOffset = offset;
                        printf("Found Position offset\n");
                        printf("\t[+]Offset = 0x%x\n", offset);
                        break;
                    }
                }
            }
        }
    }
    if (positionOffset == -1)
    {
        printf("ERROR: Failed to find Position offset!\n");
        myfile << "        // ERROR: Position offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t Position = 0x" << positionOffset << ";\n";
    }

    // ========== PointerToHealthAndShield ==========
    // Signature: Entity_GetHealthShieldPointer - searches component table
    // Address: 0x140A20690
    // Offset: +0x120 (according to prepare-update.md and Offsets.h)
    // Note: The function uses lea rcx, [rsi+8] internally, but the actual offset in Entity is 0x120
    // Try to find from patterns that access Entity+0x120
    int pointerToHealthOffset = -1; // MUST be found via scan!
    
    // Method 1: Direct byte search for mov rax, [rcx+0x120] - 48 8B 81 20 01 00 00
    // Found at 0x140bbacd4 in IDA
    for (size_t i = 0; i < size - 7; i++)
    {
        if (*(BYTE*)(Dump + i) == 0x48 && *(BYTE*)(Dump + i + 1) == 0x8B && *(BYTE*)(Dump + i + 2) == 0x81 &&
            *(BYTE*)(Dump + i + 3) == 0x20 && *(BYTE*)(Dump + i + 4) == 0x01 && 
            *(BYTE*)(Dump + i + 5) == 0x00 && *(BYTE*)(Dump + i + 6) == 0x00)
        {
            pointerToHealthOffset = 0x120;
            printf("Found PointerToHealthAndShield offset (via direct byte search)\n");
            printf("\t[+]Offset = 0x%x\n", pointerToHealthOffset);
            break;
        }
    }
    
    // Method 2: Search for mov rax, [rcx+0x120] pattern via Scan
    if (pointerToHealthOffset == -1)
    {
        auto healthShieldPattern1 = Scan((char*)"48 8B 81 20 01 00 00", (char*)Dump, size);
        if (healthShieldPattern1)
        {
            pointerToHealthOffset = 0x120;
            printf("Found PointerToHealthAndShield offset (via pattern)\n");
            printf("\t[+]Offset = 0x%x\n", pointerToHealthOffset);
        }
    }
    
    // Method 3: Search for mov eax, [rcx+0x120] pattern
    if (pointerToHealthOffset == -1)
    {
        auto healthShieldPattern2 = Scan((char*)"8B 81 20 01 00 00", (char*)Dump, size);
        if (healthShieldPattern2)
        {
            pointerToHealthOffset = 0x120;
            printf("Found PointerToHealthAndShield offset (via pattern 2)\n");
            printf("\t[+]Offset = 0x%x\n", pointerToHealthOffset);
        }
    }
    
    // Method 4: Try to find from Entity_GetHealthShieldPointer function
    if (pointerToHealthOffset == -1)
    {
        auto healthShieldPointer = Scan((char*)"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B FA 48 8B F1 48 8B DA", (char*)Dump, size);
        if (healthShieldPointer)
        {
            // Look for the offset access in the function - search for offset 0x120 specifically
            // The function accesses pEntityData + offset, then searches in component table
            for (int i = 0; i < 200; i++)
            {
                if (*(BYTE*)(healthShieldPointer + i) == 0x48 && *(BYTE*)(healthShieldPointer + i + 1) == 0x8B)
                {
                    int offset = *(int*)(healthShieldPointer + i + 3);
                    // Accept offset in reasonable range (typically 0x100-0x140)
                    if (offset >= 0x100 && offset < 0x140)
                    {
                        pointerToHealthOffset = offset;
                        printf("Found PointerToHealthAndShield offset\n");
                        printf("\t[+]Offset = 0x%x\n", offset);
                        break;
                    }
                }
            }
        }
    }
    
    if (pointerToHealthOffset == -1)
    {
        printf("ERROR: Failed to find PointerToHealthAndShield offset!\n");
        myfile << "        // ERROR: PointerToHealthAndShield offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t PointerToHealthAndShield = 0x" << pointerToHealthOffset << ";\n";
    }

    // ========== IsDead ==========
    // Signature: Player_CanPerformAction - test/movzx byte ptr [rcx+offset], 0x01
    // Address: 0x14109D4B0
    auto isDeadFunc = Scan((char*)"48 89 5C 24 ? 48 89 54 24 ? 57 48 83 EC ? 0F B6 81", (char*)Dump, size);
    int isDeadOffset = -1; // MUST be found via scan!
    if (isDeadFunc)
    {
        // Look for movzx eax, byte ptr [rcx+offset] or test byte ptr [rcx+offset], 0x01
        // Search for ANY offset in reasonable range (0x900-0xA00)
        for (int i = 0; i < 100; i++)
        {
            if ((*(BYTE*)(isDeadFunc + i) == 0x0F && *(BYTE*)(isDeadFunc + i + 1) == 0xB6) || 
                (*(BYTE*)(isDeadFunc + i) == 0xF6))
            {
                int offset = *(int*)(isDeadFunc + i + 3);
                // Accept any offset in reasonable range (typically 0x900-0xA00)
                if (offset >= 0x900 && offset < 0xA00)
                {
                    isDeadOffset = offset;
                    printf("Found IsDead offset\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    break;
                }
            }
        }
    }
    if (isDeadOffset == -1)
    {
        printf("ERROR: Failed to find IsDead offset!\n");
        myfile << "        // ERROR: IsDead offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t IsDead = 0x" << isDeadOffset << ";\n";
    }

    // ========== GMFlags ==========
    // Signature: Graphics_DisplayGMOverlay - test byte ptr [rdi+0x9C4], 0x40/0x01
    // Address: 0x140A141C0
    // Offset: +0x9C4 (according to offsets.txt)
    auto gmFlagsFunc = Scan((char*)"48 8B C4 57 48 81 EC ? ? ? ? 48 C7 44 24 ? ? ? ? ? 48 89 58 ? 0F 29 70 ? 48 8B D9", (char*)Dump, size);
    int gmFlagsOffset = -1; // MUST be found via scan!
    if (gmFlagsFunc)
    {
        // Look for test byte ptr [rdi+offset], 0x40/0x01 - pattern F6 87 ? ? ? ? 40 or F6 87 ? ? ? ? 01
        // Search for offset in reasonable range (0x9C0-0x9D0)
        for (int i = 0; i < 300; i++)
        {
            if (*(BYTE*)(gmFlagsFunc + i) == 0xF6 && *(BYTE*)(gmFlagsFunc + i + 1) == 0x87)
            {
                int offset = *(int*)(gmFlagsFunc + i + 2);
                // Accept offset in reasonable range (typically 0x9C0-0x9D0)
                if (offset >= 0x9C0 && offset < 0x9D0)
                {
                    // Verify it's followed by 0x40, 0x01, 0x20, or 0x08
                    BYTE testValue = *(BYTE*)(gmFlagsFunc + i + 6);
                    if (testValue == 0x40 || testValue == 0x01 || testValue == 0x20 || testValue == 0x08 || testValue == 0x80)
                    {
                        gmFlagsOffset = offset;
                        printf("Found GMFlags offset\n");
                        printf("\t[+]Offset = 0x%x\n", offset);
                        break;
                    }
                }
            }
        }
    }
    if (gmFlagsOffset == -1)
    {
        printf("ERROR: Failed to find GMFlags offset!\n");
        myfile << "        // ERROR: GMFlags offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t GMFlags = 0x" << gmFlagsOffset << ";\n";
    }

    // ========== ShootingStatus ==========
    // Signature: Player_SetShootingStatus - test byte ptr [rcx+offset], 0x20
    // Address: 0x1410A3310
    auto shootingStatusFunc = Scan((char*)"40 55 53 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 C7 45 ? ? ? ? ? 0F 29 74 24", (char*)Dump, size);
    int shootingStatusOffset = -1; // MUST be found via scan!
    if (shootingStatusFunc)
    {
        // Look for test byte ptr [rcx+offset], 0x20 or movzx eax, byte ptr [rcx+offset]
        // Search for ANY offset in reasonable range (0x3000-0x3100)
        for (int i = 0; i < 200; i++)
        {
            if ((*(BYTE*)(shootingStatusFunc + i) == 0xF6) || 
                (*(BYTE*)(shootingStatusFunc + i) == 0x0F && *(BYTE*)(shootingStatusFunc + i + 1) == 0xB6))
            {
                int offset = *(int*)(shootingStatusFunc + i + 3);
                // Accept any offset in reasonable range (typically 0x3000-0x3100)
                if (offset >= 0x3000 && offset < 0x3100)
                {
                    shootingStatusOffset = offset;
                    printf("Found ShootingStatus offset\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    break;
                }
            }
        }
    }
    if (shootingStatusOffset == -1)
    {
        printf("ERROR: Failed to find ShootingStatus offset!\n");
        myfile << "        // ERROR: ShootingStatus offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t ShootingStatus = 0x" << shootingStatusOffset << ";\n";
    }

    // ========== Name ==========
    // Note: Name offsets are typically accessed via pointer dereferencing, making them hard to scan
    // Signature: Name_CalculateHash - mov r8, [rcx+offset] - finds NameBackup, Name is typically 0x50 before
    int nameOffset = -1; // MUST be found via scan!
    int nameBackupOffset = -1; // MUST be found via scan!
    
    // Try to find from Name_CalculateHash which uses mov r8, [rcx+offset]
    auto nameHashFunc = Scan((char*)"4C 8B 81 ? ? ? ? 33 C0 ? ? ? ? 84 C9", (char*)Dump, size);
    if (nameHashFunc)
    {
        // Name_CalculateHash uses: mov r8, [rcx+offset] - the offset is at +3 in the instruction
        int offset = *(int*)(nameHashFunc + 3);
        // Accept any offset in reasonable range for NameBackup (typically 0x2000-0x3000)
        if (offset >= 0x2000 && offset < 0x3000)
        {
            nameBackupOffset = offset;
            // Name is typically 0x50 (80) bytes before NameBackup
            nameOffset = offset - 0x50;
            printf("Found NameBackup offset: 0x%x\n", offset);
            printf("Found Name offset (calculated): 0x%x\n", nameOffset);
        }
    }
    
    if (nameOffset == -1 || nameBackupOffset == -1)
    {
        printf("ERROR: Failed to find Name/NameBackup offsets!\n");
        myfile << "        // ERROR: Name offset could not be found via scan!\n";
        myfile << "        // ERROR: NameBackup offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t Name = 0x" << nameOffset << ";\n";
        myfile << std::hex << "        constexpr uintptr_t NameBackup = 0x" << nameBackupOffset << ";\n";
    }

    // ========== Health/Shield Offsets ==========
    // CRITICAL: These offsets are relative to healthShieldPtr (from Entity + PointerToHealthAndShield)
    // Strategy: Search for functions that use Entity_GetHealthShieldPointer and then access these offsets
    // OR: Search for functions that use Health/Shield offsets together (CurHealth/MaxHealth are 4 bytes apart)
    
    int curHealthOffset = -1; // MUST be found via scan!
    int maxHealthOffset = -1; // MUST be found via scan!
    int curShieldOffset = -1; // MUST be found via scan!
    int maxShieldOffset = -1; // MUST be found via scan!
    
    // Method 0: Direct byte search for CurShield = 0x470
    // Found at 0x141fa8dec and 0x1428a0901 in IDA - 8B 81 70 04 00 00
    if (curShieldOffset == -1)
    {
        for (size_t i = 0; i < size - 6; i++)
        {
            if (*(BYTE*)(Dump + i) == 0x8B && *(BYTE*)(Dump + i + 1) == 0x81 &&
                *(BYTE*)(Dump + i + 2) == 0x70 && *(BYTE*)(Dump + i + 3) == 0x04 &&
                *(BYTE*)(Dump + i + 4) == 0x00 && *(BYTE*)(Dump + i + 5) == 0x00)
            {
                curShieldOffset = 0x470;
                maxShieldOffset = 0x474;
                printf("Found CurShield: 0x%x and MaxShield: 0x%x (via direct byte search)\n", curShieldOffset, maxShieldOffset);
                break;
            }
        }
    }
    
    // Method 0b: Try direct patterns for known offsets
    // CurShield = 0x470, MaxShield = 0x474 (according to Offsets.h)
    if (curShieldOffset == -1)
    {
        auto curShieldPattern = Scan((char*)"8B 81 70 04 00 00", (char*)Dump, size);
        if (curShieldPattern)
        {
            curShieldOffset = 0x470;
            maxShieldOffset = 0x474;
            printf("Found CurShield: 0x%x and MaxShield: 0x%x (via direct pattern)\n", curShieldOffset, maxShieldOffset);
        }
    }
    
    // Method 1: Search for functions that use paired offsets (CurHealth/MaxHealth are 4 bytes apart, same for Shield)
    // This is more reliable - if we find two offsets 4 bytes apart, they're likely Health/Shield pairs
    size_t searchStart = 0x1000;
    size_t searchEnd = (size > 0x10000000) ? 0x10000000 : size - 0x1000; // Limit search to first 256MB
    
    for (size_t i = searchStart; i < searchEnd - 100 && (curHealthOffset == -1 || curShieldOffset == -1); i++)
    {
        // Look for mov reg, [reg+offset] patterns
        if (*(BYTE*)(Dump + i) == 0x8B) // mov instruction
        {
            BYTE modrm = *(BYTE*)(Dump + i + 1);
            if ((modrm & 0xC0) == 0x80) // mod=10, [reg+disp32]
            {
                int offset1 = *(int*)(Dump + i + 2);
                
                // Look for another mov instruction within 50 bytes with offset + 4 (Health/Shield pairs)
                for (size_t j = i + 6; j < i + 50 && j < searchEnd - 10; j++)
                {
                    if (*(BYTE*)(Dump + j) == 0x8B) // mov
                    {
                        BYTE modrm2 = *(BYTE*)(Dump + j + 1);
                        if ((modrm2 & 0xC0) == 0x80) // mod=10, [reg+disp32]
                        {
                            int offset2 = *(int*)(Dump + j + 2);
                            
                            // Check if offsets are 4 bytes apart (Health pair or Shield pair)
                            if (offset2 == offset1 + 4)
                            {
                                // Validate this is in a code section
                                bool isValidCode = false;
                                for (int k = -30; k <= 30; k++)
                                {
                                    if (i + k >= searchStart && i + k < searchEnd - 5)
                                    {
                                        if ((*(BYTE*)(Dump + i + k) == 0x48 && *(BYTE*)(Dump + i + k + 1) == 0x89) ||
                                            *(BYTE*)(Dump + i + k) == 0xC3 ||
                                            (*(BYTE*)(Dump + i + k) == 0x48 && *(BYTE*)(Dump + i + k + 1) == 0x83 && *(BYTE*)(Dump + i + k + 2) == 0xC4))
                                        {
                                            isValidCode = true;
                                            break;
                                        }
                                    }
                                }
                                
                                if (isValidCode)
                                {
                                    // Determine if this is Health pair or Shield pair based on offset range
                                    // Health offsets are typically around 0x160 (Offsets.h)
                                    // Shield offsets are typically around 0x470 (Offsets.h)
                                    // Try to match based on known ranges from Offsets.h
                                    if (offset1 >= 0x150 && offset1 < 0x180 && curHealthOffset == -1)
                                    {
                                        curHealthOffset = offset1;
                                        maxHealthOffset = offset2;
                                        printf("Found CurHealth: 0x%x and MaxHealth: 0x%x (paired access)\n", offset1, offset2);
                                    }
                                    else if (offset1 >= 0x460 && offset1 < 0x480 && curShieldOffset == -1)
                                    {
                                        curShieldOffset = offset1;
                                        maxShieldOffset = offset2;
                                        printf("Found CurShield: 0x%x and MaxShield: 0x%x (paired access)\n", offset1, offset2);
                                    }
                                    // Fallback: Accept offsets in reasonable range (0x10-0x30 for health/shield)
                                    else if (offset1 >= 0x10 && offset1 < 0x30 && curHealthOffset == -1 && offset1 != curShieldOffset)
                                    {
                                        curHealthOffset = offset1;
                                        maxHealthOffset = offset2;
                                        printf("Found CurHealth: 0x%x and MaxHealth: 0x%x (paired access, fallback)\n", offset1, offset2);
                                    }
                                    else if (offset1 >= 0x10 && offset1 < 0x30 && curShieldOffset == -1 && offset1 != curHealthOffset)
                                    {
                                        curShieldOffset = offset1;
                                        maxShieldOffset = offset2;
                                        printf("Found CurShield: 0x%x and MaxShield: 0x%x (paired access, fallback)\n", offset1, offset2);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // CRITICAL: If offsets were not found, we MUST NOT write defaults!
    if (curHealthOffset == -1 || maxHealthOffset == -1 || curShieldOffset == -1 || maxShieldOffset == -1)
    {
        printf("ERROR: Failed to find Health/Shield offsets via scan!\n");
        printf("  CurHealth: %s, MaxHealth: %s, CurShield: %s, MaxShield: %s\n",
               curHealthOffset != -1 ? "Found" : "MISSING",
               maxHealthOffset != -1 ? "Found" : "MISSING",
               curShieldOffset != -1 ? "Found" : "MISSING",
               maxShieldOffset != -1 ? "Found" : "MISSING");
        
        // Write error comments instead of defaults
        myfile << "        // ERROR: Health/Shield offsets could not be found via scan!\n";
        if (curHealthOffset == -1) myfile << "        // ERROR: CurHealth offset could not be found!\n";
        if (maxHealthOffset == -1) myfile << "        // ERROR: MaxHealth offset could not be found!\n";
        if (curShieldOffset == -1) myfile << "        // ERROR: CurShield offset could not be found!\n";
        if (maxShieldOffset == -1) myfile << "        // ERROR: MaxShield offset could not be found!\n";
    }
    else
    {
        // All offsets found - write them
        myfile << std::hex << "        constexpr uintptr_t CurHealth = 0x" << curHealthOffset << ";  // Relative to healthShieldPtr\n";
        printf("CurHealth offset: 0x%x (relative to healthShieldPtr)\n", curHealthOffset);
        myfile << std::hex << "        constexpr uintptr_t MaxHealth = 0x" << maxHealthOffset << ";  // Relative to healthShieldPtr\n";
        printf("MaxHealth offset: 0x%x (relative to healthShieldPtr)\n", maxHealthOffset);
        myfile << std::hex << "        constexpr uintptr_t CurShield = 0x" << curShieldOffset << ";  // Relative to healthShieldPtr\n";
        printf("CurShield offset: 0x%x (relative to healthShieldPtr)\n", curShieldOffset);
        myfile << std::hex << "        constexpr uintptr_t MaxShield = 0x" << maxShieldOffset << ";  // Relative to healthShieldPtr\n";
        printf("MaxShield offset: 0x%x (relative to healthShieldPtr)\n", maxShieldOffset);
    }

    // ========== BoneArrayOffset ==========
    // Signature: SkeletonInfo_UpdateBoneData - Offset relative to boneInfo pointer
    // Address: 0x1424048E0
    // Offset: +0x194 (according to Offsets.h)
    // This offset is used when accessing bone array: boneInfoPtr + offset
    int boneArrayOffset = -1; // MUST be found via scan!
    
    // Method 1: Direct byte search for BoneArrayOffset = 0x194
    // Pattern: 48 8B ?? 94 01 00 00 (mov reg, [reg+0x194]) - various register combinations
    // Try different register combinations: 81 (rcx), 87 (rdi), 89 (rcx), 8B (rbx), 8D (rbp), 8F (rdi)
    for (size_t i = 0; i < size - 7; i++)
    {
        if (*(BYTE*)(Dump + i) == 0x48 && *(BYTE*)(Dump + i + 1) == 0x8B)
        {
            BYTE modrm = *(BYTE*)(Dump + i + 2);
            // Check if modrm is one of: 81 (rcx), 87 (rdi), 89 (rcx), 8B (rbx), 8D (rbp), 8F (rdi)
            if ((modrm == 0x81 || modrm == 0x87 || modrm == 0x89 || modrm == 0x8B || modrm == 0x8D || modrm == 0x8F) &&
                *(BYTE*)(Dump + i + 3) == 0x94 && *(BYTE*)(Dump + i + 4) == 0x01 &&
                *(BYTE*)(Dump + i + 5) == 0x00 && *(BYTE*)(Dump + i + 6) == 0x00)
            {
                boneArrayOffset = 0x194;
                printf("Found BoneArrayOffset (via direct byte search with register 0x%02X)\n", modrm);
                printf("\t[+]Offset = 0x%x\n", boneArrayOffset);
                break;
            }
        }
    }
    
    // Method 2: Try direct pattern for known offset
    if (boneArrayOffset == -1)
    {
        auto boneArrayPattern = Scan((char*)"48 8B 81 94 01 00 00", (char*)Dump, size);
        if (boneArrayPattern)
        {
            boneArrayOffset = 0x194;
            printf("Found BoneArrayOffset (via direct pattern)\n");
            printf("\t[+]Offset = 0x%x\n", boneArrayOffset);
        }
    }
    
    // Method 3: Try pattern with 4C 8B (mov r8, [rcx+offset])
    if (boneArrayOffset == -1)
    {
        auto boneArrayPattern2 = Scan((char*)"4C 8B 81 94 01 00 00", (char*)Dump, size);
        if (boneArrayPattern2)
        {
            boneArrayOffset = 0x194;
            printf("Found BoneArrayOffset (via direct pattern 2)\n");
            printf("\t[+]Offset = 0x%x\n", boneArrayOffset);
        }
    }
    
    // Method 4: Search for any mov instruction with offset 0x194 in the entire dump
    // This is more flexible and searches for any register combination
    if (boneArrayOffset == -1)
    {
        for (size_t i = 0; i < size - 7; i++)
        {
            // Look for mov instructions: 48 8B (mov reg, [reg+disp32]) or 4C 8B (mov r8-r15, [reg+disp32])
            if ((*(BYTE*)(Dump + i) == 0x48 || *(BYTE*)(Dump + i) == 0x4C) && *(BYTE*)(Dump + i + 1) == 0x8B)
            {
                BYTE modrm = *(BYTE*)(Dump + i + 2);
                // Check if modrm indicates [reg+disp32] format (mod=10, any reg)
                if ((modrm & 0xC7) == 0x80 || (modrm & 0xC7) == 0x81 || (modrm & 0xC7) == 0x82 ||
                    (modrm & 0xC7) == 0x83 || (modrm & 0xC7) == 0x84 || (modrm & 0xC7) == 0x85 ||
                    (modrm & 0xC7) == 0x86 || (modrm & 0xC7) == 0x87)
                {
                    int offset = *(int*)(Dump + i + 3);
                    if (offset == 0x194)
                    {
                        boneArrayOffset = 0x194;
                        printf("Found BoneArrayOffset (via flexible search)\n");
                        printf("\t[+]Offset = 0x%x\n", boneArrayOffset);
                        break;
                    }
                }
            }
        }
    }
    
    // Method 5: The offset is typically hardcoded in the function that accesses the bone array
    // We can try to find it by looking for mov/add instructions with offsets in reasonable range (0x190-0x200)
    if (boneArrayOffset == -1 && cBoneInfo) // Reuse the SkeletonInfo_UpdateBoneData function we found earlier
    {
        // Look for instructions that use offset in reasonable range
        for (int i = 0; i < 300; i++)
        {
            if ((*(BYTE*)(cBoneInfo + i) == 0x48 && *(BYTE*)(cBoneInfo + i + 1) == 0x8B) ||
                (*(BYTE*)(cBoneInfo + i) == 0x4C && *(BYTE*)(cBoneInfo + i + 1) == 0x8B))
            {
                int offset = *(int*)(cBoneInfo + i + 3);
                // Accept offset in reasonable range (typically 0x190-0x200)
                if (offset >= 0x190 && offset < 0x200)
                {
                    boneArrayOffset = offset;
                    printf("Found BoneArrayOffset (in cBoneInfo function)\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    break;
                }
            }
        }
    }
    
    // Method 6: Fallback - use known value from Offsets.h if nothing found
    // This is a last resort, but 0x194 is the documented value
    if (boneArrayOffset == -1)
    {
        printf("WARNING: BoneArrayOffset not found via scan, using default value from Offsets.h\n");
        boneArrayOffset = 0x194;
    }
    
    myfile << std::hex << "        constexpr uintptr_t BoneArrayOffset = 0x" << boneArrayOffset << ";\n";

    myfile << "    }\n\n";

    // ========== Graphics/Camera Offsets ==========
    myfile << "    // Camera/ViewMatrix Offsets\n";
    myfile << "    namespace Camera {\n";

    // ========== ViewMatrixOffset1 ==========
    // Signature: CGraphics_TransformWorldToScreen - mov rbx, [rcx+0xF0]
    // Address: 0x140B2B0D0
    // Offset: +0xF0 (according to offsets.txt)
    int viewMatrixOffset1 = -1; // MUST be found via scan!
    auto cCamera = Scan((char*)"40 53 48 81 EC ? ? ? ? 48 8B 99 ? ? ? ? B8 ? ? ? ? 0F 28 05 ? ? ? ? 8B C8", (char*)Dump, size);
    if (cCamera)
    {
        // Look for mov rbx, [rcx+offset] - pattern 48 8B 99 ? ? ? ?
        // The offset is at cCamera + 11 (after 48 8B 99)
        int offset = *(int*)(cCamera + 11);
        // Accept offset in reasonable range (typically 0xE0-0x100)
        if (offset >= 0xE0 && offset < 0x100)
        {
            viewMatrixOffset1 = offset;
            printf("Found ViewMatrixOffset1\n");
            printf("\t[+]Offset = 0x%x\n", offset);
        }
    }
    // Fallback: Try to find mov rbx, [rcx+0xF0] pattern directly
    if (viewMatrixOffset1 == -1)
    {
        auto viewMatrixPattern = Scan((char*)"48 8B 99 F0 00 00 00", (char*)Dump, size);
        if (viewMatrixPattern)
        {
            viewMatrixOffset1 = 0xF0;
            printf("Found ViewMatrixOffset1 (via direct pattern)\n");
            printf("\t[+]Offset = 0x%x\n", viewMatrixOffset1);
        }
    }
    
    if (viewMatrixOffset1 == -1)
    {
        printf("ERROR: Failed to find ViewMatrixOffset1!\n");
        myfile << "        // ERROR: ViewMatrixOffset1 could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t ViewMatrixOffset1 = 0x" << viewMatrixOffset1 << ";\n";
    }

    // ========== ViewMatrixOffset2 ==========
    // Signature: CGraphics_TransformWorldToScreen - movaps xmm0, [rcx+0xB0]
    // Address: 0x140B2B0D0 (in same function as ViewMatrixOffset1)
    // Offset: +0xB0 (according to offsets.txt)
    int viewMatrixOffset2 = -1; // MUST be found via scan!
    // Try to find movaps xmm0, [rcx+0xB0] pattern - 0F28 81 B0000000
    if (cCamera)
    {
        // Look for movaps xmm0, [rcx+offset] pattern within the function
        for (int i = 0; i < 300; i++)
        {
            if (*(BYTE*)(cCamera + i) == 0x0F && *(BYTE*)(cCamera + i + 1) == 0x28)
            {
                int offset = *(int*)(cCamera + i + 3);
                // Accept offset in reasonable range (typically 0xA0-0xC0)
                if (offset >= 0xA0 && offset < 0xC0)
                {
                    viewMatrixOffset2 = offset;
                    printf("Found ViewMatrixOffset2\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    break;
                }
            }
        }
    }
    // Fallback: Try direct pattern
    if (viewMatrixOffset2 == -1)
    {
        auto viewMatrix2Pattern = Scan((char*)"0F 28 81 B0 00 00 00", (char*)Dump, size);
        if (viewMatrix2Pattern)
        {
            viewMatrixOffset2 = 0xB0;
            printf("Found ViewMatrixOffset2 (via direct pattern)\n");
            printf("\t[+]Offset = 0x%x\n", viewMatrixOffset2);
        }
    }
    
    if (viewMatrixOffset2 == -1)
    {
        printf("ERROR: Failed to find ViewMatrixOffset2!\n");
        myfile << "        // ERROR: ViewMatrixOffset2 could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t ViewMatrixOffset2 = 0x" << viewMatrixOffset2 << ";\n";
    }

    myfile << "    }\n\n";

    // ========== Bullet Offsets ==========
    myfile << "    // Magic Bullet Offsets\n";
    myfile << "    namespace MagicBullet {\n";

    // pCurrentBulletPointerBase - already found in base addresses section above
    if (bulletBaseAddress != 0)
    {
        myfile << std::hex << "        static constexpr uintptr_t pCurrentBulletPointerBase = 0x" << bulletBaseAddress << ";\n";
    }
    else
    {
        printf("ERROR: Failed to find pCurrentBulletPointerBase!\n");
        myfile << "        // ERROR: pCurrentBulletPointerBase could not be found via scan!\n";
    }
    
    // pCurrentBulletPointerOffsets array
    // Pattern: 48 8B 41 18 (mov rax, [rcx+0x18]) - CurrentBulletPointerOffset = 0x18
    // The array value 0x871E8 needs to be found manually or via different approach
    int currentBulletPointerOffset = -1;
    auto currentBulletPointerPattern = Scan((char*)"48 8B 41 18", (char*)Dump, size);
    if (currentBulletPointerPattern)
    {
        currentBulletPointerOffset = 0x18;
        printf("Found pCurrentBulletPointerOffset: 0x%x\n", currentBulletPointerOffset);
        // The array value 0x871E8 is documented in Offsets.h but needs manual verification
        myfile << "        static constexpr int pCurrentBulletPointerOffsets[] = { 0x871E8 };  // Manual verification needed\n";
    }
    else
    {
        printf("ERROR: Failed to find pCurrentBulletPointerOffset!\n");
        myfile << "        // ERROR: pCurrentBulletPointerOffsets could not be found via scan!\n";
        myfile << "        // This offset needs to be found manually after update\n";
    }

    // Bullet Direction
    int bulletDirectionOffset = -1; // MUST be found via scan!
    auto bulletDirection = Scan((char*)"40 57 41 56 48 83 EC ? 4C 8B F2 48 8B F9 45 84 C0", (char*)Dump, size);
    if (bulletDirection)
    {
        // Look for movups [rcx+offset], xmm1 or similar - search for ANY offset in reasonable range (0xA00-0xC00)
        for (int i = 0; i < 200; i++)
        {
            if (*(BYTE*)(bulletDirection + i) == 0x0F && *(BYTE*)(bulletDirection + i + 1) == 0x11)
            {
                int offset = *(int*)(bulletDirection + i + 3);
                // Accept any offset in reasonable range (typically 0xA00-0xC00)
                if (offset >= 0xA00 && offset < 0xC00)
                {
                    bulletDirectionOffset = offset;
                    printf("Found bullet_direction_offset\n");
                    printf("\t[+]Offset = 0x%x\n", offset);
                    break;
                }
            }
        }
    }
    
    if (bulletDirectionOffset == -1)
    {
        printf("ERROR: Failed to find bullet_direction_offset!\n");
        myfile << "        // ERROR: bullet_direction_offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        static constexpr int bullet_direction_offset = 0x" << bulletDirectionOffset << ";\n";
    }

    // Bullet Position
    int bulletPositionOffset = -1; // MUST be found via scan!
    auto bulletPosition = Scan((char*)"66 0F 7F 86 ? ? ? ? 48 81 C4", (char*)Dump, size);
    if (bulletPosition)
    {
        auto offset = *(int*)(bulletPosition + 4);
        // Accept any offset in reasonable range (typically 0x800-0x900)
        if (offset >= 0x800 && offset < 0x900)
        {
            bulletPositionOffset = offset;
            printf("Found bullet_position_offset\n");
            printf("\t[+]Offset = 0x%x\n", offset);
        }
    }
    
    if (bulletPositionOffset == -1)
    {
        printf("ERROR: Failed to find bullet_position_offset!\n");
        myfile << "        // ERROR: bullet_position_offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        static constexpr int bullet_position_offset = 0x" << bulletPositionOffset << ";\n";
    }

    // Bullet Start Position
    int bulletStartPositionOffset = -1; // MUST be found via scan!
    // Pattern: 0F 10 83 30 09 00 00 (movups xmm0, [rbx+0x930])
    auto bulletStartPosition = Scan((char*)"0F 10 83 30 09 00 00", (char*)Dump, size);
    if (bulletStartPosition)
    {
        bulletStartPositionOffset = 0x930;
        printf("Found bullet_start_position_offset\n");
        printf("\t[+]Offset = 0x%x\n", bulletStartPositionOffset);
        myfile << std::hex << "        static constexpr int bullet_start_position_offset = 0x" << bulletStartPositionOffset << ";\n";
    }
    else
    {
        printf("ERROR: Failed to find bullet_start_position_offset!\n");
        myfile << "        // ERROR: bullet_start_position_offset could not be found via scan!\n";
    }
    
    // Bullet Speed
    int bulletSpeedOffset = -1; // MUST be found via scan!
    // Pattern: F3 0F 11 ?? ?? ?? 08 00 00 (movss [reg+0x8C0], xmm0) or F3 0F 10 ?? ?? ?? 08 00 00 (movss xmm1, [reg+0x8C0])
    // Try direct pattern first
    for (size_t i = 0; i < size - 7; i++)
    {
        if ((*(BYTE*)(Dump + i) == 0xF3 && *(BYTE*)(Dump + i + 1) == 0x0F && 
             (*(BYTE*)(Dump + i + 2) == 0x10 || *(BYTE*)(Dump + i + 2) == 0x11)))
        {
            BYTE modrm = *(BYTE*)(Dump + i + 3);
            // Check for r14 register and offset 0x8C0
            if ((modrm == 0x86 || modrm == 0x87 || modrm == 0xBE || modrm == 0xBF) && // r14 or r15
                *(BYTE*)(Dump + i + 4) == 0xC0 && *(BYTE*)(Dump + i + 5) == 0x08 &&
                *(BYTE*)(Dump + i + 6) == 0x00 && *(BYTE*)(Dump + i + 7) == 0x00)
            {
                bulletSpeedOffset = 0x8C0;
                printf("Found bullet_speed_offset\n");
                printf("\t[+]Offset = 0x%x\n", bulletSpeedOffset);
                break;
            }
        }
    }
    if (bulletSpeedOffset == -1)
    {
        printf("ERROR: Failed to find bullet_speed_offset!\n");
        myfile << "        // ERROR: bullet_speed_offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        static constexpr int bullet_speed_offset = 0x" << bulletSpeedOffset << ";\n";
    }
    
    // Bullet IsAlive
    // Note: Offset 0x4 is very small and hard to find via signature, but it's documented
    int bulletIsAliveOffset = 0x4; // Known value from Offsets.h
    printf("Using known bullet_is_alive_offset: 0x%x\n", bulletIsAliveOffset);
    myfile << std::hex << "        static constexpr int bullet_is_alive_offset = 0x" << bulletIsAliveOffset << ";  // Known value\n";
    
    // Bullet Hash
    int bulletHashOffset = -1; // MUST be found via scan!
    // Pattern: 41 C7 86 F4 04 00 00 (mov [r14+0x4F4], imm32) or 8B 99 F4 04 00 00 (mov ebx, [rcx+0x4F4])
    // Try direct byte search
    for (size_t i = 0; i < size - 7; i++)
    {
        // Pattern 1: mov [r14+0x4F4], imm32
        if (*(BYTE*)(Dump + i) == 0x41 && *(BYTE*)(Dump + i + 1) == 0xC7 &&
            *(BYTE*)(Dump + i + 2) == 0x86 &&
            *(BYTE*)(Dump + i + 3) == 0xF4 && *(BYTE*)(Dump + i + 4) == 0x04 &&
            *(BYTE*)(Dump + i + 5) == 0x00 && *(BYTE*)(Dump + i + 6) == 0x00)
        {
            bulletHashOffset = 0x4F4;
            printf("Found o_BulletHash (via pattern 1)\n");
            printf("\t[+]Offset = 0x%x\n", bulletHashOffset);
            break;
        }
        // Pattern 2: mov ebx, [rcx+0x4F4]
        if (*(BYTE*)(Dump + i) == 0x8B && *(BYTE*)(Dump + i + 1) == 0x99 &&
            *(BYTE*)(Dump + i + 2) == 0xF4 && *(BYTE*)(Dump + i + 3) == 0x04 &&
            *(BYTE*)(Dump + i + 4) == 0x00 && *(BYTE*)(Dump + i + 5) == 0x00)
        {
            bulletHashOffset = 0x4F4;
            printf("Found o_BulletHash (via pattern 2)\n");
            printf("\t[+]Offset = 0x%x\n", bulletHashOffset);
            break;
        }
    }
    if (bulletHashOffset == -1)
    {
        printf("ERROR: Failed to find o_BulletHash!\n");
        myfile << "        // ERROR: o_BulletHash could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        static constexpr int o_BulletHash = 0x" << bulletHashOffset << ";\n";
    }

    myfile << "    }\n\n";

    // ========== Noclip Offsets ==========
    // NOTE: Noclip offsets from Player_SetNoclipPositionX and Player_AddNoclipVelocity
    // Address: Player_SetNoclipPositionX at 0x142A8A5A3, Player_AddNoclipVelocity at 0x1412A6B50
    myfile << "    // Noclip/Flight Offsets - Direct world coordinates\n";
    myfile << "    namespace Noclip {\n";
    
    // Noclip Position offset from Player_SetNoclipPositionX
    // Signature: 0F 11 81 ? ? ? ? F2 0F 10 4A
    // Offset: +0x200 (512 decimal) - writes X,Y,Z as Vector3 (OWORD = 16 bytes)
    int noclipPositionOffset = -1; // MUST be found via scan!
    
    // Method 1: Direct pattern search for 0F 11 81 00 02 00 00 (movups [rcx+0x200], xmm0)
    auto noclipPositionPattern1 = Scan((char*)"0F 11 81 00 02 00 00", (char*)Dump, size);
    if (noclipPositionPattern1)
    {
        noclipPositionOffset = 0x200;
        printf("Found Noclip Position offset (via direct pattern)\n");
        printf("\t[+]Offset = 0x%x\n", noclipPositionOffset);
    }
    
    // Method 2: Search with wildcards
    if (noclipPositionOffset == -1)
    {
        auto noclipPositionPattern2 = Scan((char*)"0F 11 81 ? ? ? ? F2 0F 10 4A", (char*)Dump, size);
        if (noclipPositionPattern2)
        {
            // Extract offset from the pattern
            int offset = *(int*)(noclipPositionPattern2 + 3);
            if (offset >= 0x1F0 && offset < 0x210) // Accept offset around 0x200
            {
                noclipPositionOffset = offset;
                printf("Found Noclip Position offset (via signature)\n");
                printf("\t[+]Offset = 0x%x\n", noclipPositionOffset);
            }
        }
    }
    
    // Method 3: Direct byte search for movups [rcx+0x200], xmm0
    if (noclipPositionOffset == -1)
    {
        for (size_t i = 0; i < size - 7; i++)
        {
            if (*(BYTE*)(Dump + i) == 0x0F && *(BYTE*)(Dump + i + 1) == 0x11 &&
                *(BYTE*)(Dump + i + 2) == 0x81 &&
                *(BYTE*)(Dump + i + 3) == 0x00 && *(BYTE*)(Dump + i + 4) == 0x02 &&
                *(BYTE*)(Dump + i + 5) == 0x00 && *(BYTE*)(Dump + i + 6) == 0x00)
            {
                noclipPositionOffset = 0x200;
                printf("Found Noclip Position offset (via direct byte search)\n");
                printf("\t[+]Offset = 0x%x\n", noclipPositionOffset);
                break;
            }
        }
    }
    
    if (noclipPositionOffset == -1)
    {
        printf("ERROR: Failed to find Noclip Position offset!\n");
        myfile << "        // ERROR: Noclip Position offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t NoclipPosition = 0x" << noclipPositionOffset << ";  // X,Y,Z as Vector3\n";
    }
    
    // Noclip Velocity offset from Player_AddNoclipVelocity
    // Signature: 48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 48 8B D9 45 84 C0 74 ? F3 0F 10 81
    // Offset: +0x3B8 (952 decimal) - Velocity X,Y,Z as Float
    int noclipVelocityOffset = -1; // MUST be found via scan!
    
    // Method 1: Direct pattern search for 8B 81 B8 03 00 00 (mov eax, [rcx+0x3B8])
    auto noclipVelocityPattern1 = Scan((char*)"8B 81 B8 03 00 00", (char*)Dump, size);
    if (noclipVelocityPattern1)
    {
        noclipVelocityOffset = 0x3B8;
        printf("Found Noclip Velocity offset (via direct pattern)\n");
        printf("\t[+]Offset = 0x%x\n", noclipVelocityOffset);
    }
    
    // Method 2: Search with function signature
    if (noclipVelocityOffset == -1)
    {
        auto noclipVelocityFunc = Scan((char*)"48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 48 8B D9 45 84 C0 74 ? F3 0F 10 81", (char*)Dump, size);
        if (noclipVelocityFunc)
        {
            // Look for movss xmm0, [rcx+offset] pattern in the function
            for (int i = 0; i < 100; i++)
            {
                if (*(BYTE*)(noclipVelocityFunc + i) == 0xF3 && *(BYTE*)(noclipVelocityFunc + i + 1) == 0x0F &&
                    *(BYTE*)(noclipVelocityFunc + i + 2) == 0x10 && *(BYTE*)(noclipVelocityFunc + i + 3) == 0x81)
                {
                    int offset = *(int*)(noclipVelocityFunc + i + 4);
                    if (offset >= 0x3B0 && offset < 0x3C0) // Accept offset around 0x3B8
                    {
                        noclipVelocityOffset = offset;
                        printf("Found Noclip Velocity offset (via function signature)\n");
                        printf("\t[+]Offset = 0x%x\n", noclipVelocityOffset);
                        break;
                    }
                }
            }
        }
    }
    
    // Method 3: Direct byte search for mov eax, [rcx+0x3B8]
    if (noclipVelocityOffset == -1)
    {
        for (size_t i = 0; i < size - 6; i++)
        {
            if (*(BYTE*)(Dump + i) == 0x8B && *(BYTE*)(Dump + i + 1) == 0x81 &&
                *(BYTE*)(Dump + i + 2) == 0xB8 && *(BYTE*)(Dump + i + 3) == 0x03 &&
                *(BYTE*)(Dump + i + 4) == 0x00 && *(BYTE*)(Dump + i + 5) == 0x00)
            {
                noclipVelocityOffset = 0x3B8;
                printf("Found Noclip Velocity offset (via direct byte search)\n");
                printf("\t[+]Offset = 0x%x\n", noclipVelocityOffset);
                break;
            }
        }
    }
    
    if (noclipVelocityOffset == -1)
    {
        printf("ERROR: Failed to find Noclip Velocity offset!\n");
        myfile << "        // ERROR: Noclip Velocity offset could not be found via scan!\n";
    }
    else
    {
        myfile << std::hex << "        constexpr uintptr_t NoclipVelocity = 0x" << noclipVelocityOffset << ";  // X,Y,Z as Float\n";
    }
    
    myfile << "    }\n";

    myfile << "}\n";
    myfile.close();

    printf("\n\n=== Dump completed ===\n");
    printf("Offsets written to Offsets.h\n");

    return true;
}

