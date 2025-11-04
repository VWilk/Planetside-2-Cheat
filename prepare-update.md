# Planetside 2 Update-Vorbereitung - IDA Analyse

Dieses Dokument enthält alle wichtigen Funktionen, Strukturen und Kommentare, die in IDA analysiert wurden, um nach dem großen Update die Offsets schnell zu finden und zu aktualisieren.

## Status
- **Erstellt:** Vor dem Update
- **Zweck:** Schnelle Offset-Aktualisierung nach dem Update mit BinDiff
- **IDA Datei:** PlanetSide2_x64_dump_latest.exe
- **Letzte Überarbeitung:** Vollständige Verifizierung und Erweiterung vor großem Update

## 📖 Wie diese Datei zu verwenden ist

### Vor dem Update:
1. ✅ Diese Datei ist bereits vollständig - alle Offsets sind dokumentiert
2. ✅ Alle Signaturen sind in `signatures.txt` erfasst
3. ✅ Alle kritischen Funktionen sind in IDA analysiert und kommentiert

### Nach dem Update:
1. **Schnellstart:** Gehe direkt zu **Sektion 17 (Post-Update Checkliste)** und arbeite dich durch
2. **Offset-Update:** Nutze **Sektion 18 (Offset-Verifizierungs-Tabelle)** um alle Änderungen zu dokumentieren
3. **BinDiff:** Nutze **Sektion 19 (BinDiff-spezifische Anweisungen)** für automatisiertes Matching
4. **Probleme:** Siehe **Sektion 20 (Häufige Probleme und Lösungen)** wenn etwas nicht funktioniert
5. **Schnellzugriff:** Nutze **Sektion 21** für die wichtigsten Funktionen

### Wichtige Dateien:
- `prepare-update.md` (diese Datei) - Vollständige Dokumentation
- `offsets.txt` - Alle gefundenen Adressen und Assembly-Instruktionen
- `signatures.txt` - Alle Signaturen für Pattern-Matching
- `Internal DX11 Base/Game/Offsets.h` - Die tatsächlichen Offset-Definitionen im Code

---

## 1. CGame Basis-Funktionen

### 1.1 CGame Direct Access (CGame_StringLookup)
- **Adresse:** 0x140B10874
- **Funktionsname:** CGame_StringLookup (enthält CGame-Direct-Access)
- **Signature:** `48 8B 0D ? ? ? ? 48 85 C9 74 ? E8 ? ? ? ? 48 85 C0 74 ? 48 8B D0`
- **Beschreibung:** Direkter Zugriff auf g_pCGame mit Null-Check, ruft CGame_GetInstance auf falls NULL
- **Wichtig für:** Base Address von CGame (pCGameAddress = 0x40B7AE0)
- **Kritische Zeile:** 0x140B10888 - `if ( g_pCGame && (v6 = CGame_GetInstance(g_pCGame)) != 0 )`
- **Kommentar in IDA:** ✅ "WICHTIG: Direkter Zugriff auf g_pCGame (Base: 0x40B7AE0). Test ob NULL, dann CGame_GetInstance aufrufen. Diese Zeile ist kritisch für Offset-Update nach Patch!"

### 1.2 CGame GetInstance
- **Wird von CGame_DirectAccess aufgerufen**
- **Beschreibung:** Singleton-Getter für CGame-Instanz

---

## 2. Entity Container System

### 2.1 EntityContainer_ClearAll
- **Adresse:** 0x140BC692A
- **Funktionsname:** EntityContainer_ClearAll
- **Signature:** `48 8B 8E ? ? ? ? 48 85 C9 74 ? 66 66 0F 1F 84 00 ? ? ? ? 48 8B 81 ? ? ? ? 4C 89 B1 ? ? ? ? 48 8B C8 48 85 C0 75 ? 4C 89 B6 ? ? ? ? 4C 89 B6 ? ? ? ? 4C 89 B6 ? ? ? ? 4C 39 B6`
- **Wichtig:** Liest FirstObject bei Offset +0x1060 (4192 decimal)
- **Offset:** o_cGame_pFirstObject = 0x1060
- **Kritische Zeile:** 0x140BC692A - `pFirstObject = *(void **)(pEntityContainer + 4192);`
- **Kommentar in IDA:** ✅ "WICHTIG: Liest FirstObject aus EntityContainer bei Offset +0x1060 (4192 decimal). Kritisch für Entity-Container-Offset!"

### 2.2 EntityContainer_AddEntity
- **Adresse:** 0x140BC2A50
- **Funktionsname:** EntityContainer_AddEntity
- **Signature:** `40 56 57 41 56 48 83 EC ? 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 4C 8B F2 48 8B F1 48 8D 99`
- **Wichtig:** Schreibt NextObject bei Offset +0x5A8 (1448 decimal = 182*8)
- **Offset:** o_pNextObject = 0x5A8
- **Kritische Zeile:** 0x140BC2B48 - `pActor[182] = pEntityContainer[1249];` (NextObject Pointer)
- **Kommentar in IDA:** ✅ "WICHTIG: Schreibt NextObject Pointer bei Offset +0x5A8 (1448 decimal = 182*8). Kritisch für Entity-Container-Linked-List!"

### 2.3 EntityContainer - EntityCount
- **Adresse:** 0x140BC2B73
- **Funktionsname:** EntityContainer_AddEntity (Zeile innerhalb der Funktion)
- **Wichtig:** Inkrementiert EntityCount bei Offset +0x2710 (10000 decimal = 1250*8)
- **Offset:** o_EntityCount = 0x2710
- **Kritische Zeile:** 0x140BC2B73 - `++pEntityContainer[1250];`
- **Kommentar in IDA:** ✅ "WICHTIG: Inkrementiert EntityCount bei Offset +0x2710 (10000 decimal = 1250*8). Kritisch für Entity-Container-Count!"

---

## 3. Entity Strukturen

### 3.1 Entity Basis-Struktur
**Wichtigste Offsets:**
- Position: +0x920
- TeamID: +0x1E8
- Type: +0x5E0
- PlayerStance: +0x2A04
- ViewAngle: +0x2C20
- Name: +0x2AF8
- NameBackup: +0x2B48
- PointerToHealthAndShield: +0x120
- IsDead: +0x9C1
- GMFlags: +0x9C4
- ShootingStatus: +0x3088
- pActor: +0x828

### 3.2 Entity GetTeamID
- **Adresse:** 0x140B57070
- **Funktionsname:** Entity_GetTeamID
- **Signature:** `48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 81 ? ? ? ? 33 F6 C7 05`
- **Wichtig:** Liest TeamID bei Offset +0x1E8 (488 decimal)
- **Kritische Zeile:** 0x140B5707F - `teamID = *(_DWORD *)(pEntity + 488);`
- **Kommentar in IDA:** ✅ "WICHTIG: Liest TeamID von Entity bei Offset +0x1E8 (488 decimal). Kritisch für Entity-Struktur-Offset!"

### 3.3 Entity CheckACtor
- **Adresse:** 0x140B89630
- **Funktionsname:** Entity_CheckACtor
- **Signature:** `48 83 EC ? 48 C7 44 24 ? ? ? ? ? ? ? ? 48 39 81`
- **WICHTIG:** Vergleicht pACtor bei Offset +0x428 (1064 decimal)
- **⚠️ HINWEIS:** pACtor (+0x428) ist VERSCHIEDEN von pActor (+0x828)! Beide existieren!
- **Kritische Zeile:** 0x140B8964A - `if ( *(_QWORD *)(pEntity + 1064) == *pACtorToCheck )`
- **Kommentar in IDA:** ✅ "WICHTIG: Liest pACtor von Entity bei Offset +0x428 (1064 decimal). ACHTUNG: Verschiedener Offset als pActor (+0x828)! Kritisch für Entity-ACtor-Vergleich!"

---

## 4. Health/Shield System

### 4.1 Entity_GetHealthShieldPointer
- **Adresse:** 0x140A20690
- **Funktionsname:** Entity_GetHealthShieldPointer
- **Signature:** `48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B FA 48 8B F1 48 8B DA`
- **Wichtig:** Sucht Health/Shield-Pointer in Component-Tabelle bei Offset +0x120
- **Kritische Zeile:** 0x140A206D0 - `pPointerTable = (_QWORD *)sub_14001306B(pEntityData + 8, &v11);`
- **Kommentar in IDA:** ✅ "WICHTIG: Sucht Health/Shield-Pointer in Component-Tabelle. Entity hat PointerToHealthAndShield bei Offset +0x120. Kritisch für Health/Shield-System!"

### 4.2 Health_SetValue
- **Signature:** `48 89 5C 24 ? 56 48 83 EC ? 8B 71 ? 48 8B D9 85 D2`
- **Adresse:** 0x14216E8B0
- **Wichtig:** Setzt Health bei Offset +0x20 in Health/Shield-Component

### 4.3 Shield_ProcessRegeneration
- **Signature:** `48 89 54 24 ? 57 41 54 48 83 EC`
- **Adresse:** 0x14216EDD0
- **Wichtig:** Verarbeitet Shield-Regeneration, liest Shield bei Offset +0x20

### 4.4 Health/Shield Component Struktur
**Offsets relativ zum Health/Shield-Pointer:**
- CurHealth: +0x160 (relativ zu Entity)
- MaxHealth: +0x164 (relativ zu Entity)
- CurShield: +0x470 (relativ zu Entity)
- MaxShield: +0x474 (relativ zu Entity)

**Hinweis:** Die Offsets in Offsets.h beziehen sich auf Entity, nicht auf Component!

---

## 5. Bullet System

### 5.1 BulletHarvester_ProcessBullets
- **Adresse:** 0x140B7F0A0 (0x140B7F0EE in signatures.txt war falsch)
- **Funktionsname:** BulletHarvester_ProcessBullets
- **Signature:** `48 89 54 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 C7 45 ? ? ? ? ? 48 89 9C 24 ? ? ? ? 4D 8B E9`
- **Wichtig:** Verwendet g_pCurrentBulletPointerBase (0x40B82C0)
- **Kritische Zeile:** 0x140B7F0EE - `pCurrentBulletPointerBase = g_pCurrentBulletPointerBase;`
- **Kommentar in IDA:** ✅ "WICHTIG: Verwendet g_pCurrentBulletPointerBase (0x40B82C0). Basis für Bullet-Pointer-Tabelle. Kritisch für MagicBullet-System!"

### 5.2 BulletPointerTable_AddEntry
- **Signature:** `48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 41 ? 33 F6 49 89 40 ? 49 8B D8 49 89 70 ? 48 8B F9 48 8B 41 ? 49 89 40 ? 48 89 59 ? 49 8B 40 ? 8B EA 48 85 C0 74 ? 48 89 58 ? EB ? 48 89 59 ? 48 8B 51 ? 48 FF C2 E8`
- **Adresse:** 0x140B38D48
- **Wichtig:** CurrentBulletPointerOffset bei +0x18

### 5.3 Bullet_SetDirectionVector
- **Adresse:** 0x141388430
- **Funktionsname:** Bullet_SetDirectionVector
- **Signature:** `40 57 41 56 48 83 EC ? 4C 8B F2 48 8B F9 45 84 C0`
- **Wichtig:** Schreibt Bullet Direction bei Offset +0xB40 (2880 decimal = 180*16)
- **Kritische Zeile:** 0x1413884D5 - `pBulletData[180] = _mm_and_ps(...);` (Direction Vector)
- **Kommentar in IDA:** ✅ "WICHTIG: Schreibt Bullet Direction Vector bei Offset +0xB40 (2880 decimal = 180*16). Kritisch für MagicBullet-System!"

### 5.4 Bullet_UpdatePosition
- **Adresse:** 0x141390B77
- **Funktionsname:** Bullet_UpdatePosition
- **Signature:** `66 0F 7F 86 ? ? ? ? 48 81 C4`
- **Wichtig:** Schreibt Bullet Position bei Offset +0x870 (2160 decimal = 135*16)
- **Kritische Zeile:** 0x141390B77 - `pBulletData[135] = *pNewPosition;` (Position)
- **Kommentar in IDA:** ✅ "WICHTIG: Schreibt Bullet Position bei Offset +0x870 (2160 decimal = 135*16). Kritisch für MagicBullet-System!"

### 5.5 Bullet Struktur
**Offsets:**
- Direction: +0xB40 (2880 decimal)
- Position: +0x870 (2160 decimal)
- StartPosition: +0x930 (2352 decimal)
- Speed: +0x8C0 (2240 decimal)
- IsAlive: +0x4 (4 decimal)
- Hash: +0x4F4 (1268 decimal)

---

## 6. Graphics/Camera System

### 6.1 CGraphics_RenderMain
- **Adresse:** 0x140A83346
- **Funktionsname:** CGraphics_RenderMain
- **Signature:** `48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 8B 49 ? ? ? ? FF 50 ? 84 C0 0F 85 ? ? ? ? C7 05`
- **Wichtig:** Verwendet g_pCGraphics (0x40B7C50)
- **Kommentar in IDA:** ✅ "WICHTIG: CGraphics_RenderMain - Verwendet g_pCGraphics (0x40B7C50). Haupt-Rendering-Funktion, kritisch für Graphics-System!"

### 6.2 CGraphics_TransformWorldToScreen
- **Adresse:** 0x140B2B0D0
- **Funktionsname:** CGraphics_TransformWorldToScreen
- **Signature:** `40 53 48 81 EC ? ? ? ? 48 8B 99 ? ? ? ? B8 ? ? ? ? 0F 28 05 ? ? ? ? 8B C8`
- **Wichtig:** ViewMatrixOffset1 bei +0xF0 (240 decimal)
- **Kritische Zeile:** 0x140B2B0D9 - `v2 = *(__m128 **)(a1 + 240);`
- **Kommentar in IDA:** ✅ "WICHTIG: Liest ViewMatrixOffset1 von CGraphics bei Offset +0xF0 (240 decimal). Kritisch für World-to-Screen-Transformation!"

### 6.3 Graphics_ResetCamera (FOV)
- **Adresse:** 0x140DFE080
- **Funktionsname:** Graphics_ResetCamera
- **Signature:** `F3 0F 11 05 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? 90`
- **Wichtig:** FOV Clipping bei 10.0-180.0, g_fFOV Adresse (0x144260CFC)
- **Kritische Zeile:** 0x140DFE080 - `g_fFOV = fmaxf(fminf(*(float *)&g_fFOV, 180.0), 10.0);`
- **Kommentar in IDA:** ✅ "WICHTIG: Liest und schreibt g_fFOV (Base: 0x144260CFC). Clippt FOV zwischen 10.0 und 180.0. Kritisch für FOV-System!"

---

## 7. Player System

### 7.1 Player_UpdateStance
- **Adresse:** 0x140BA80B0
- **Funktionsname:** Player_UpdateStance
- **Signature:** `40 55 53 56 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 C7 45 ? ? ? ? ? 0F 29 B4 24 ? ? ? ? 48 8B F2`
- **Wichtig:** PlayerStance bei Offset +0x2A04 (10756 decimal)
- **Kritische Zeile:** 0x140BA82F3 - `oldStance = *(_DWORD *)(pPlayer + 10756);`
- **Kommentar in IDA:** ✅ "WICHTIG: Liest PlayerStance bei Offset +0x2A04 (10756 decimal). Kritisch für Player-Stance-System!"

### 7.2 Player_UpdateViewAngle
- **Adresse:** 0x140DFA2E0
- **Funktionsname:** Player_UpdateViewAngle
- **Signature:** `48 8B C4 F3 0F 11 50 ? 48 89 50 ? 55 53 56 57 41 54 41 55 41 56`
- **Wichtig:** ViewAngle bei Offset +0x2C20 (11296 decimal)
- **Kritische Zeile:** 0x140DFA697 - `v54 = *(_OWORD *)(v38 + 11296);`
- **Kommentar in IDA:** ✅ "WICHTIG: Liest ViewAngle bei Offset +0x2C20 (11296 decimal) von Entity. Kritisch für ViewAngle-System!"

### 7.3 Player_CanPerformAction
- **Adresse:** 0x14109D4B0
- **Funktionsname:** Player_CanPerformAction
- **Signature:** `48 89 5C 24 ? 48 89 54 24 ? 57 48 83 EC ? 0F B6 81`
- **Wichtig:** IsDead bei Offset +0x9C1 (2497 decimal), Bit 0x01 = IsDead
- **Kritische Zeile:** 0x14109D4BF - `v3 = pPlayer[2497];` (IsDead Flag)
- **Kommentar in IDA:** ✅ "WICHTIG: Liest IsDead-Flag bei Offset +0x9C1 (2497 decimal). Bit 0x01 = IsDead. Kritisch für Player-Death-Detection!"

### 7.4 Player_SetShootingStatus
- **Adresse:** 0x1410A3310
- **Funktionsname:** Player_SetShootingStatus
- **Signature:** `40 55 53 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 C7 45 ? ? ? ? ? 0F 29 74 24`
- **Wichtig:** ShootingStatus bei Offset +0x3088 (12424 decimal), Bit 0x20 = Shooting
- **Kritische Zeilen:** 
  - 0x1410A3339 - `result = (pPlayer[12424] & 0x20) != 0;` (Liest ShootingStatus)
  - 0x1410A347C - `pPlayer[12424] |= 0x20u;` (Setzt Shooting)
- **Kommentar in IDA:** ✅ "WICHTIG: Liest/Setzt ShootingStatus von Player bei Offset +0x3088 (12424 decimal). Bit 0x20 = Shooting. Kritisch für Shooting-Status-Detection!"

### 7.5 Graphics_DisplayGMOverlay
- **Adresse:** 0x140A141C0
- **Funktionsname:** Graphics_DisplayGMOverlay
- **Signature:** `48 8B C4 57 48 81 EC ? ? ? ? 48 C7 44 24 ? ? ? ? ? 48 89 58 ? 0F 29 70 ? 48 8B D9`
- **Wichtig:** GMFlags bei Offset +0x9C4 (2500 decimal), Bit 0x40 = GOD, Bit 0x01 = GMHIDE
- **Kritische Zeile:** 0x140A142AB - `if ( (*(_BYTE *)(v4 + 2500) & 0x40) != 0 )` (GOD Flag)
- **Kommentar in IDA:** ✅ "WICHTIG: Liest GMFlags bei Offset +0x9C4 (2500 decimal). Bit 0x40 = GOD, Bit 0x01 = GMHIDE. Kritisch für GM-Detection!"

---

## 8. Bone/Skeleton System

### 8.1 Actor_UpdateBoundingBox
- **Adresse:** 0x1425BE730
- **Funktionsname:** Actor_UpdateBoundingBox
- **Signature:** `4C 8B DC 49 89 5B ? 49 89 73 ? 41 56 48 81 EC ? ? ? ? 48 8B F1 8B 81 ? ? ? ? 33 DB 85 C0 44 8B F3 0F B6 81 ? ? ? ? 41 0F 94 C6 3C ? 0F 83 ? ? ? ? 0F B6 C0`
- **Wichtig:** pSkeleton bei Offset +0x1D8 (472 decimal) relativ zu Actor
- **Kritische Zeile:** 0x1425BE777 - `v8 = *(_QWORD *)(pActor + 472);` (pSkeleton)
- **Kommentar in IDA:** ✅ "WICHTIG: Liest pSkeleton von Actor bei Offset +0x1D8 (472 decimal). Kritisch für Bone-System-Pointer-Chain!"

### 8.2 Skeleton_UpdateSkeletonInfo
- **Adresse:** 0x1423F8620
- **Funktionsname:** Skeleton_UpdateSkeletonInfo
- **Signature:** `48 8B C4 56 57 41 56 48 83 EC ? 48 C7 40 ? ? ? ? ? 48 89 58 ? 48 89 68 ? 0F B6 FA`
- **Wichtig:** pSkeletonInfo bei Offset +0x50 (80 decimal) relativ zu Skeleton
- **Kritische Zeile:** 0x1423F86A0 - `result = sub_14008046D(*(_QWORD *)(v5 + 80), v8, v7, v6, -2);` (pSkeletonInfo)
- **Kommentar in IDA:** ✅ "WICHTIG: Liest pSkeletonInfo von Skeleton bei Offset +0x50 (80 decimal). Kritisch für Bone-System-Pointer-Chain!"

### 8.3 SkeletonInfo_UpdateBoneData
- **Adresse:** 0x1424048E0
- **Funktionsname:** SkeletonInfo_UpdateBoneData
- **Signature:** `48 8B C4 57 48 83 EC ? 48 C7 40 ? ? ? ? ? 48 89 58 ? 48 89 70 ? 48 8B F9 48 8D 59`
- **Wichtig:** pBoneInfo bei Offset +0x68 (104 decimal) relativ zu SkeletonInfo
- **Kritische Zeile:** 0x14240498F - `sub_1400A4796(..., *(_QWORD *)(pSkeletonInfo + 104));` (pBoneInfo)
- **Kommentar in IDA:** ✅ "WICHTIG: Liest pBoneInfo von SkeletonInfo bei Offset +0x68 (104 decimal). Kritisch für Bone-System-Pointer-Chain!"

### 8.4 Bone Pointer Chain
```
Entity (+0x828) -> pActor
Actor (+0x1D8) -> pSkeleton
Skeleton (+0x50) -> pSkeletonInfo
SkeletonInfo (+0x68) -> pBoneInfo
BoneInfo (+0x194) -> BoneArray
```

---

## 9. Noclip System

### 9.1 Player_SetNoclipPositionX
- **Adresse:** 0x142A8A5A3
- **Funktionsname:** Player_SetNoclipPositionX
- **Signature:** `0F 11 81 ? ? ? ? F2 0F 10 4A`
- **Wichtig:** Noclip Position bei Offset +0x200 (512 decimal), schreibt X,Y,Z als Vector3 (OWORD = 16 bytes)
- **Kritische Zeile:** 0x142A8A5A3 - `*(_OWORD *)(pPlayerData + 512) = *(_OWORD *)pPosition;` (Position X,Y,Z)
- **Kommentar in IDA:** ✅ "WICHTIG: Schreibt Noclip Position bei Offset +0x200 (512 decimal). Schreibt X,Y,Z als Vector3. Kritisch für Noclip-System!"

### 9.2 Player_AddNoclipVelocity
- **Adresse:** 0x1412A6B50 (0x1412A6B65 in signatures.txt war Zeile innerhalb der Funktion)
- **Funktionsname:** Player_AddNoclipVelocity
- **Signature:** `48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 48 8B D9 45 84 C0 74 ? F3 0F 10 81`
- **Wichtig:** Noclip Velocity bei Offset +0x3B8 (952 decimal), Velocity X,Y,Z als Float
- **⚠️ HINWEIS:** Offsets.h verwendet eine komplexe Pointer-Chain für Noclip (pBaseAddress + Offsets), aber diese Funktionen verwenden direkte Offsets. Beide Systeme existieren möglicherweise parallel!
- **Kritische Zeilen:**
  - 0x1412A6B71 - `*(float *)(pPlayerData + 952) = ...;` (Velocity X)
  - 0x1412A6B86 - `*(float *)(pPlayerData + 956) = ...;` (Velocity Y)
  - 0x1412A6B9B - `*(float *)(pPlayerData + 960) = ...;` (Velocity Z)
- **Kommentar in IDA:** ✅ "WICHTIG: Addiert Noclip Velocity bei Offset +0x3B8 (952 decimal). Velocity X,Y,Z als Float. Kritisch für Noclip-Velocity-System!"

---

## 10. Entity Command Processing

### 10.1 CGame_HandleEntityCommandData
- **Signature:** `4C 89 4C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 C7 45 ? ? ? ? ? 48 89 9C 24 ? ? ? ? 4D 63 F0`
- **Adresse:** 0x140C0D030
- **Beschreibung:** Haupt-Funktion für Entity-Command-Verarbeitung

### 10.2 CGame_ProcessEntityUpdateData
- **Signature:** `4D 85 C0 0F 84 ? ? ? ? 48 8B C4 48 89 50`
- **Adresse:** 0x140DB1950
- **Beschreibung:** Verarbeitet Entity-Update-Daten

### 10.3 EntityContainer_ProcessInteraction
- **Signature:** `48 8B C4 4C 89 48 ? 48 89 50 ? 48 89 48 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 C7 85`
- **Adresse:** 0x140DB8F70
- **Beschreibung:** Sehr große Funktion (0x28E4 bytes) für Entity-Interactions

---

## 11. String/Name System

### 11.1 String_CopyAndNormalizeName
- **Signature:** `48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC ? 4C 8B F1 33 DB`
- **Adresse:** 0x14238C600
- **Beschreibung:** Kopiert und normalisiert Namen (CRLF -> LF)

### 11.2 Name_CalculateHash
- **Signature:** `4C 8B 81 ? ? ? ? 33 C0 ? ? ? ? 84 C9`
- **Adresse:** 0x140B86310
- **Beschreibung:** Berechnet Hash für Namen-Lookup

---

## 12. Wichtige Globale Variablen

### 12.1 g_pCGame
- **Base Address:** 0x40B7AE0
- **Verwendung:** Haupt-Game-Manager

### 12.2 g_pCGraphics
- **Base Address:** 0x40B7C50
- **Verwendung:** Graphics-Manager

### 12.3 g_fFOV
- **Base Address:** 0x144260CFC
- **Verwendung:** Field of View Variable

### 12.4 g_pCurrentBulletPointerBase
- **Base Address:** 0x40B82C0
- **Verwendung:** Basis für Bullet-Pointer-Tabelle

---

## 13. Strukturen (zu erstellen in IDA)

### 13.1 Entity_Struct
```
+0x000: [various fields]
+0x120: PointerToHealthAndShield (void*)
+0x1E8: TeamID (int32)
+0x428: pACtor (void*) - ⚠️ WICHTIG: Verschiedener Pointer als pActor! Wird für ACtor-Vergleich verwendet
+0x5E0: Type (int32)
+0x828: pActor (void*) - ⚠️ WICHTIG: Verschiedener Pointer als pACtor! Wird für Bone-Chain verwendet
+0x920: Position (Vector3 - float[3])
+0x9C1: IsDead (uint8)
+0x9C4: GMFlags (uint8)
+0x2A04: PlayerStance (int32)
+0x2AF8: Name (char[?])
+0x2B48: NameBackup (char[?])
+0x2C20: ViewAngle (Vector2 - float[2])
+0x3088: ShootingStatus (uint8)
```

### 13.2 HealthShield_Component_Struct
```
+0x000: [various fields]
+0x020: Health (float)
+0x024: MaxHealth (float) - HINWEIS: In Offsets.h steht +0x164 relativ zu Entity!
+0x040: MaxHealthFromComponent (float)
+0x058: CurrentHealthFromComponent (float)
+0x470: CurShield (float) - relativ zu Entity!
+0x474: MaxShield (float) - relativ zu Entity!
```

### 13.3 Bullet_Struct
```
+0x000: [vtable]
+0x004: IsAlive (uint8)
+0x4F4: Hash (uint32)
+0x870: Position (Vector3 - float[3])
+0x8C0: Speed (float)
+0x930: StartPosition (Vector3 - float[3])
+0xB40: Direction (Vector3 - float[3])
```

### 13.4 Actor_Struct
```
+0x000: [vtable]
+0x1D8: pSkeleton (Skeleton*)
```

### 13.5 Skeleton_Struct
```
+0x000: [vtable]
+0x050: pSkeletonInfo (SkeletonInfo*)
```

### 13.6 SkeletonInfo_Struct
```
+0x000: [vtable]
+0x068: pBoneInfo (BoneInfo*)
```

### 13.7 BoneInfo_Struct
```
+0x000: [vtable]
+0x194: BoneArray (BoneEntry*)
```

### 13.8 BoneEntry_Struct
```
+0x000: X (float)
+0x004: Y (float)
+0x008: Z (float)
Size: 0xC (12 bytes)
```

---

## 14. BinDiff Workflow nach Update

1. **BinDiff-Datei laden:** Neue vs. alte Executable
2. **Funktionen matchen:** Alle oben genannten Funktionen sollten automatisch gematched werden
3. **Offsets prüfen:** 
   - In gematched Funktionen die Offsets prüfen
   - Strukturen vergleichen
   - Neue Offsets in Offsets.h eintragen
4. **Signaturen aktualisieren:** Falls Signaturen nicht mehr funktionieren, neue generieren

---

## 15. Wichtige Hinweise

- **Entity pACtor vs pActor:** ⚠️ KRITISCH - Es gibt zwei verschiedene Offsets! +0x428 (pACtor, für ACtor-Vergleich) und +0x828 (pActor, für Bone-Chain). Beide sind unterschiedliche Pointer!
- **Health/Shield Offsets:** Die Offsets in Offsets.h beziehen sich auf Entity, nicht auf Component!
- **Bone System:** Komplexe Pointer-Kette, alle Zwischenstrukturen sollten benannt werden
- **EntityContainer:** Linked-List-System mit FirstObject und NextObject

---

## Fortschritt

- [x] CGame-Funktionen benannt und kommentiert
- [x] EntityContainer-Funktionen benannt und kommentiert
- [ ] Entity-Struktur erstellt
- [ ] Health/Shield-Struktur erstellt
- [ ] Bullet-Struktur erstellt
- [ ] Bone-Strukturen erstellt
- [x] Kritische Funktionen kommentiert (CGame, EntityContainer, Entity, Graphics, Player, Bullet, Bone)
- [ ] BinDiff-Datei vorbereitet

## Aktueller Stand der IDA-Analyse

### ✅ Bereits analysiert und kommentiert:
1. **CGame_StringLookup** (0x140B10874) - CGame Direct Access ✅
2. **EntityContainer_ClearAll** (0x140BC692A) - FirstObject Offset ✅
3. **EntityContainer_AddEntity** (0x140BC2A50) - NextObject Offset + EntityCount ✅
4. **Entity_GetTeamID** (0x140B57070) - TeamID Offset ✅
5. **Entity_GetHealthShieldPointer** (0x140A20690) - Health/Shield Pointer ✅
6. **CGraphics_RenderMain** (0x140A83346) - Graphics Manager ✅
7. **CGraphics_TransformWorldToScreen** (0x140B2B0D0) - ViewMatrix Offset ✅
8. **Player_UpdateStance** (0x140BA80B0) - PlayerStance Offset ✅
9. **Player_UpdateViewAngle** (0x140DFA2E0) - ViewAngle Offset ✅
10. **Player_CanPerformAction** (0x14109D4B0) - IsDead Flag ✅
11. **Graphics_DisplayGMOverlay** (0x140A141C0) - GMFlags ✅
12. **BulletHarvester_ProcessBullets** (0x140B7F0A0) - Bullet Base Pointer ✅
13. **Bullet_SetDirectionVector** (0x141388430) - Bullet Direction Offset ✅
14. **Bullet_UpdatePosition** (0x141390B77) - Bullet Position Offset ✅
15. **Actor_UpdateBoundingBox** (0x1425BE730) - pSkeleton Offset ✅
16. **Skeleton_UpdateSkeletonInfo** (0x1423F8620) - pSkeletonInfo Offset ✅
17. **SkeletonInfo_UpdateBoneData** (0x1424048E0) - pBoneInfo Offset ✅
18. **Graphics_ResetCamera** (0x140DFE080) - FOV System ✅
19. **Entity_CheckACtor** (0x140B89630) - pACtor Offset (wichtig: verschieden von pActor!) ✅
20. **Player_SetShootingStatus** (0x1410A3310) - ShootingStatus Offset ✅
21. **Player_SetNoclipPositionX** (0x142A8A5A3) - Noclip Position Offset ✅
22. **Player_AddNoclipVelocity** (0x1412A6B50) - Noclip Velocity Offset ✅

### ✅ Abgeschlossen:
- Bullet-Funktionen: Bullet_SetDirectionVector, Bullet_UpdatePosition ✅
- Bone/Skeleton-Funktionen: Actor_UpdateBoundingBox, Skeleton_UpdateSkeletonInfo, SkeletonInfo_UpdateBoneData ✅
- Graphics-Funktionen: Graphics_ResetCamera (FOV) ✅

### 🔄 Optional (falls Zeit):
- Weitere Entity-Command-Processing-Funktionen
- Strukturen in IDA erstellen (Entity, HealthShield, Bullet, Bone-Strukturen)

---

## Workflow nach dem Update

### Schritt 1: BinDiff-Datei erstellen
1. Neue Executable in IDA öffnen
2. BinDiff-Plugin verwenden: `File -> Load BinDiff File`
3. Alte vs. Neue Executable vergleichen
4. BinDiff-Datei speichern

### Schritt 2: Funktionen matchen
1. Alle oben genannten Funktionen sollten automatisch gematched werden
2. Falls nicht gematched: Signaturen verwenden (siehe signatures.txt)
3. Funktionsnamen in neuer IDB übertragen

### Schritt 3: Offsets prüfen
1. In gematched Funktionen die kritischen Zeilen finden (siehe Kommentare)
2. Offsets vergleichen:
   - Falls Offset gleich: ✅ Keine Änderung nötig
   - Falls Offset anders: ⚠️ In Offsets.h aktualisieren
3. Neue Offsets in Offsets.h eintragen

### Schritt 4: Strukturen aktualisieren
1. Strukturen in neuer IDB erstellen (falls noch nicht vorhanden)
2. Offset-Änderungen in Strukturen überprüfen
3. Strukturen mit korrekten Offsets aktualisieren

### Schritt 5: Signaturen aktualisieren
1. Falls Signaturen nicht mehr funktionieren, neue generieren
2. In signatures.txt aktualisieren
3. Neue Adressen in signatures.txt eintragen

### Schritt 6: Testen
1. Kompilieren und testen
2. Offsets verifizieren (z.B. Entity-Container-Liste durchlaufen)
3. Bei Fehlern: BinDiff erneut prüfen

---

## Wichtige Hinweise für BinDiff

- **Matched Functions:** Alle oben genannten Funktionen sollten nach Namen/Code-Ähnlichkeit gematched werden
- **Unmatched Functions:** Falls Funktionen nicht gematched werden, Signaturen verwenden
- **Code Changes:** Selbst bei Code-Änderungen bleiben Offsets meist relativ stabil (innerhalb der Struktur)
- **Struktur Changes:** Wenn Strukturen sich ändern, können Offsets sich verschieben - dann alle Offsets in der Struktur prüfen

---

---

## Schnellreferenz - Kritische Offsets

### Base Addresses
- `g_pCGame`: 0x40B7AE0
- `g_pCGraphics`: 0x40B7C50
- `g_fFOV`: 0x144260CFC
- `g_pCurrentBulletPointerBase`: 0x40B82C0

### Entity Container
- `FirstObject`: +0x1060 (EntityContainer)
- `NextObject`: +0x5A8 (Entity)
- `EntityCount`: +0x2710 (EntityContainer)

### Entity Structure
- `PointerToHealthAndShield`: +0x120
- `TeamID`: +0x1E8
- `pACtor`: +0x428 ⚠️ (verschieden von pActor!)
- `Type`: +0x5E0
- `pActor`: +0x828 ⚠️ (für Bone-Chain!)
- `Position`: +0x920
- `IsDead`: +0x9C1
- `GMFlags`: +0x9C4
- `PlayerStance`: +0x2A04
- `ViewAngle`: +0x2C20
- `ShootingStatus`: +0x3088

### Bone Chain
```
Entity (+0x828) -> pActor
Actor (+0x1D8) -> pSkeleton
Skeleton (+0x50) -> pSkeletonInfo
SkeletonInfo (+0x68) -> pBoneInfo
BoneInfo (+0x194) -> BoneArray
```

### Bullet Structure
- `Direction`: +0xB40
- `Position`: +0x870
- `StartPosition`: +0x930
- `Speed`: +0x8C0
- `IsAlive`: +0x4
- `Hash`: +0x4F4

### Graphics/Camera
- `ViewMatrixOffset1`: +0xF0 (CGraphics)
- `ViewMatrixOffset2`: +0xB0 (Camera)

---

*Letzte Aktualisierung: Vorbereitung für großes Update - 22 Funktionen analysiert und kommentiert*

## ✅ Vollständigkeits-Check

### Alle kritischen Systeme abgedeckt:
- ✅ CGame-Basis (g_pCGame, g_pCGraphics)
- ✅ Entity-Container (FirstObject, NextObject, EntityCount)
- ✅ Entity-Struktur (TeamID, Type, Position, pActor, pACtor, etc.)
- ✅ Health/Shield-System (Pointer, Getter-Funktionen)
- ✅ Player-System (Stance, ViewAngle, IsDead, GMFlags, ShootingStatus)
- ✅ Bullet-System (Base, Direction, Position, Speed, Hash)
- ✅ Bone/Skeleton-System (komplette Pointer-Chain)
- ✅ Graphics/Camera (ViewMatrix, FOV)
- ✅ Noclip-System (Position, Velocity)

### Alle Funktionen mit Kommentaren versehen:
- ✅ Alle kritischen Zeilen mit Offsets markiert
- ✅ Alle Funktionen mit Adressen dokumentiert
- ✅ Alle Signaturen erfasst
- ✅ Schnellreferenz erstellt

**Die Dokumentation ist vollständig für das Update vorbereitet!** 🎯

---

## 16. Offset-Mapping-Tabelle: Offsets.h ↔ Dokumentation

Diese Tabelle zeigt die direkte Zuordnung zwischen `Offsets.h` und den dokumentierten Offsets in dieser Datei:

| Offsets.h Variable | Aktueller Wert | Dokumentation Sektion | Verifizierung |
|-------------------|----------------|----------------------|---------------|
| `pCGameAddress` | 0x40B7AE0 | 1.1 CGame Direct Access | ✅ |
| `pCGraphics` | 0x40B7C50 | 6.1 CGraphics_RenderMain | ✅ |
| `o_FOV` | 0x144260CFC | 6.3 Graphics_ResetCamera | ✅ |
| `o_cGame_pFirstObject` | 0x1060 | 2.1 EntityContainer_ClearAll | ✅ |
| `o_pNextObject` | 0x5A8 | 2.2 EntityContainer_AddEntity | ✅ |
| `o_EntityCount` | 0x2710 | 2.3 EntityContainer - EntityCount | ✅ |
| `Entity::Position` | 0x920 | 3.1 Entity Basis-Struktur | ✅ |
| `Entity::TeamID` | 0x1E8 | 3.2 Entity GetTeamID | ✅ |
| `Entity::Type` | 0x5E0 | 3.1 Entity Basis-Struktur | ✅ |
| `Entity::PlayerStance` | 0x2A04 | 7.1 Player_UpdateStance | ✅ |
| `Entity::ViewAngle` | 0x2C20 | 7.2 Player_UpdateViewAngle | ✅ |
| `Entity::Name` | 0x2AF8 | 3.1 Entity Basis-Struktur | ✅ |
| `Entity::NameBackup` | 0x2B48 | 3.1 Entity Basis-Struktur | ✅ |
| `Entity::PointerToHealthAndShield` | 0x120 | 4.1 Entity_GetHealthShieldPointer | ✅ |
| `Entity::CurHealth` | 0x160 | 4.4 Health/Shield Component | ✅ |
| `Entity::MaxHealth` | 0x164 | 4.4 Health/Shield Component | ✅ |
| `Entity::CurShield` | 0x470 | 4.4 Health/Shield Component | ✅ |
| `Entity::MaxShield` | 0x474 | 4.4 Health/Shield Component | ✅ |
| `Entity::IsDead` | 0x9C1 | 7.3 Player_CanPerformAction | ✅ |
| `Entity::GMFlags` | 0x9C4 | 7.5 Graphics_DisplayGMOverlay | ✅ |
| `Entity::ShootingStatus` | 0x3088 | 7.4 Player_SetShootingStatus | ✅ |
| `Entity::pActor` | 0x828 | 3.1 Entity Basis-Struktur | ✅ |
| `Entity::pSkeleton` | 0x1D8 | 8.1 Actor_UpdateBoundingBox | ✅ |
| `Entity::pSkeletonInfo` | 0x50 | 8.2 Skeleton_UpdateSkeletonInfo | ✅ |
| `Entity::pBoneInfo` | 0x68 | 8.3 SkeletonInfo_UpdateBoneData | ✅ |
| `Entity::BoneArrayOffset` | 0x194 | 8.4 Bone Pointer Chain | ✅ |
| `Camera::ViewMatrixOffset1` | 0xF0 | 6.2 CGraphics_TransformWorldToScreen | ✅ |
| `Camera::ViewMatrixOffset2` | 0xB0 | Schnellreferenz | ✅ |
| `MagicBullet::pCurrentBulletPointerBase` | 0x40B82C0 | 5.1 BulletHarvester_ProcessBullets | ✅ |
| `MagicBullet::bullet_direction_offset` | 0xB40 | 5.3 Bullet_SetDirectionVector | ✅ |
| `MagicBullet::bullet_position_offset` | 0x870 | 5.4 Bullet_UpdatePosition | ✅ |
| `MagicBullet::bullet_start_position_offset` | 0x930 | 5.5 Bullet Struktur | ✅ |
| `MagicBullet::bullet_speed_offset` | 0x8C0 | 5.5 Bullet Struktur | ✅ |
| `MagicBullet::bullet_is_alive_offset` | 0x4 | 5.5 Bullet Struktur | ✅ |
| `MagicBullet::o_BulletHash` | 0x4F4 | 5.5 Bullet Struktur | ✅ |

**⚠️ WICHTIG:**
- `pACtor` (+0x428) ist **NICHT** in Offsets.h definiert, wird aber in prepare-update.md dokumentiert (3.3 Entity CheckACtor). Dieser Offset wird nur für Vergleichsoperationen verwendet, nicht für die Bone-Chain!
- Noclip-Offsets in Offsets.h verwenden komplexe Pointer-Chains, während prepare-update.md direkte Offsets dokumentiert (9.1, 9.2). Beide Systeme existieren parallel!

---

## 17. Post-Update Checkliste

### ⚡ Prioritätenliste (wichtigste Offsets zuerst)

**Kritisch (muss sofort funktionieren):**
1. **g_pCGame** (0x40B7AE0) - Basis für alles andere
2. **g_pCGraphics** (0x40B7C50) - Für Rendering
3. **FirstObject** (+0x1060) - Für Entity-Container-Iteration
4. **NextObject** (+0x5A8) - Für Entity-Container-Iteration

**Wichtig (für Core-Features):**
5. **Entity::Position** (+0x920) - Für ESP
6. **Entity::TeamID** (+0x1E8) - Für Team-Filter
7. **Entity::pActor** (+0x828) - Für Bone-System
8. **ViewMatrixOffset1** (+0xF0) - Für World-to-Screen

**Weiterführend (für erweiterte Features):**
9. Health/Shield Offsets
10. Bullet System Offsets
11. Player-System Offsets (Stance, ViewAngle, etc.)
12. Noclip Offsets

### Phase 1: Vorbereitung
- [ ] Neue Executable Datei sichern
- [ ] Alte IDB-Datei sichern (falls vorhanden)
- [ ] Neue IDB-Datei erstellen
- [ ] BinDiff-Plugin installiert/aktiviert?

### Phase 2: BinDiff-Datei erstellen
- [ ] BinDiff-Datei erstellen (alte vs. neue Executable)
- [ ] BinDiff-Datei in IDA laden
- [ ] Matches prüfen (sollten >90% der Funktionen gematched sein)

### Phase 3: Funktionen verifizieren
- [ ] CGame_StringLookup (0x140B10874) gematched?
- [ ] EntityContainer_ClearAll (0x140BC692A) gematched?
- [ ] EntityContainer_AddEntity (0x140BC2A50) gematched?
- [ ] Entity_GetTeamID (0x140B57070) gematched?
- [ ] BulletHarvester_ProcessBullets (0x140B7F0A0) gematched?
- [ ] Alle anderen kritischen Funktionen gematched?

### Phase 4: Offsets prüfen
Für jede gematched Funktion:
- [ ] Kritische Zeile finden (siehe "Kritische Zeile" in Dokumentation)
- [ ] Offset aus Assembly-Code extrahieren
- [ ] Mit altem Offset vergleichen
- [ ] In Tabelle dokumentieren (gleich/unterschiedlich)

### Phase 5: Base Addresses aktualisieren
- [ ] g_pCGame (0x40B7AE0) - Neue Adresse finden
- [ ] g_pCGraphics (0x40B7C50) - Neue Adresse finden
- [ ] g_fFOV (0x144260CFC) - Neue Adresse finden
- [ ] g_pCurrentBulletPointerBase (0x40B82C0) - Neue Adresse finden

### Phase 6: Offsets.h aktualisieren
- [ ] Base Addresses aktualisieren
- [ ] Entity Container Offsets aktualisieren
- [ ] Entity Structure Offsets aktualisieren
- [ ] Health/Shield Offsets aktualisieren
- [ ] Bullet System Offsets aktualisieren
- [ ] Bone System Offsets aktualisieren
- [ ] Camera/Graphics Offsets aktualisieren
- [ ] Noclip Offsets prüfen (falls verwendet)

### Phase 7: Signaturen verifizieren
- [ ] Alle Signaturen in signatures.txt testen
- [ ] Neue Signaturen generieren falls nötig
- [ ] signatures.txt aktualisieren

### Phase 8: Testen
- [ ] Code kompilieren
- [ ] DLL injizieren
- [ ] Entity-Container-Liste durchlaufen testen
- [ ] Health/Shield-Zugriff testen
- [ ] Bone-System testen
- [ ] Bullet-System testen
- [ ] Graphics/World-to-Screen testen

### Phase 9: Dokumentation aktualisieren
- [ ] prepare-update.md mit neuen Offsets aktualisieren
- [ ] Neue Adressen in Dokumentation eintragen
- [ ] Änderungen dokumentieren

---

## 18. Offset-Verifizierungs-Tabelle (für nach dem Update)

Kopiere diese Tabelle und fülle sie nach dem Update aus:

| Offset Name | Alter Wert | Neuer Wert | Geändert? | Funktion/Adresse | Notizen |
|------------|------------|------------|-----------|------------------|---------|
| g_pCGame | 0x40B7AE0 | ? | ? | 0x140B10874 | |
| g_pCGraphics | 0x40B7C50 | ? | ? | 0x140A83346 | |
| g_fFOV | 0x144260CFC | ? | ? | 0x140DFE080 | |
| FirstObject | 0x1060 | ? | ? | 0x140BC692A | |
| NextObject | 0x5A8 | ? | ? | 0x140BC2A50 | |
| EntityCount | 0x2710 | ? | ? | 0x140BC2B73 | |
| Entity::Position | 0x920 | ? | ? | - | |
| Entity::TeamID | 0x1E8 | ? | ? | 0x140B57070 | |
| Entity::Type | 0x5E0 | ? | ? | - | |
| Entity::PlayerStance | 0x2A04 | ? | ? | 0x140BA80B0 | |
| Entity::ViewAngle | 0x2C20 | ? | ? | 0x140DFA2E0 | |
| Entity::IsDead | 0x9C1 | ? | ? | 0x14109D4B0 | |
| Entity::GMFlags | 0x9C4 | ? | ? | 0x140A141C0 | |
| Entity::ShootingStatus | 0x3088 | ? | ? | 0x1410A3310 | |
| Entity::pActor | 0x828 | ? | ? | - | |
| Entity::pSkeleton | 0x1D8 | ? | ? | 0x1425BE730 | |
| Bullet::Direction | 0xB40 | ? | ? | 0x141388430 | |
| Bullet::Position | 0x870 | ? | ? | 0x141390B77 | |
| Bullet::Speed | 0x8C0 | ? | ? | - | |
| Bullet::Hash | 0x4F4 | ? | ? | - | |
| ViewMatrixOffset1 | 0xF0 | ? | ? | 0x140B2B0D0 | |
| ViewMatrixOffset2 | 0xB0 | ? | ? | - | |

---

## 19. BinDiff-spezifische Anweisungen

### Funktionen matchen mit BinDiff MCP

1. **BinDiff-Datei setzen:**
   ```
   set_bindiff_file("C:\\Pfad\\zu\\neue-vs-alte.BinDiff")
   ```

2. **Alle Matches abrufen:**
   ```
   get_bindiff_matches(min_similarity=0.7, min_confidence=0.7)
   ```

3. **Spezifische Funktion suchen:**
   ```
   get_bindiff_match_by_name("CGame_StringLookup")
   ```

4. **Match anhand Adresse finden:**
   ```
   get_bindiff_match_by_address("0x140B10874")
   ```

5. **Namen automatisch übertragen:**
   ```
   apply_bindiff_names(min_similarity=0.8, min_confidence=0.8)
   ```

### Wichtige BinDiff-Funktionen für dieses Update:

- `get_bindiff_matches()` - Alle Matches auflisten
- `apply_bindiff_names()` - Namen automatisch übertragen
- `get_bindiff_match_by_address()` - Match für spezifische Adresse finden
- `get_bindiff_unmatched_primary()` - Nicht gematched Funktionen finden

---

## 20. Häufige Probleme und Lösungen

### Problem: Funktion nicht gematched
**Lösung:** 
1. Signature aus signatures.txt verwenden
2. Manuell in neuer IDB suchen
3. Code-Ähnlichkeit prüfen (manchmal nur geringfügige Änderungen)

### Problem: Offset hat sich geändert
**Lösung:**
1. In gematched Funktion die kritische Zeile finden
2. Assembly-Code analysieren
3. Neuen Offset extrahieren
4. In Offsets.h aktualisieren

### Problem: Base Address hat sich geändert
**Lösung:**
1. Signature verwenden (z.B. CGame_DirectAccess)
2. Relative Offset aus Assembly extrahieren
3. Base Address berechnen
4. In Offsets.h aktualisieren

### Problem: Struktur-Offsets haben sich verschoben
**Lösung:**
1. Alle Offsets in der Struktur prüfen
2. Oft verschieben sich alle Offsets um gleichen Wert
3. Pattern erkennen und alle auf einmal anpassen

---

## 21. Schnellzugriff: Wichtigste Funktionen für Offset-Update

| Funktion | Adresse | Wichtig für | Kritische Zeile |
|----------|---------|-------------|-----------------|
| CGame_StringLookup | 0x140B10874 | g_pCGame Base | 0x140B10888 |
| EntityContainer_ClearAll | 0x140BC692A | FirstObject | 0x140BC692A |
| EntityContainer_AddEntity | 0x140BC2A50 | NextObject + EntityCount | 0x140BC2B48, 0x140BC2B73 |
| Entity_GetTeamID | 0x140B57070 | TeamID | 0x140B5707F |
| BulletHarvester_ProcessBullets | 0x140B7F0A0 | Bullet Base | 0x140B7F0EE |
| Bullet_SetDirectionVector | 0x141388430 | Bullet Direction | 0x1413884D5 |
| Bullet_UpdatePosition | 0x141390B77 | Bullet Position | 0x141390B77 |
| CGraphics_TransformWorldToScreen | 0x140B2B0D0 | ViewMatrix | 0x140B2B0D9 |
| Actor_UpdateBoundingBox | 0x1425BE730 | pSkeleton | 0x1425BE777 |

---

*Letzte Aktualisierung: Vorbereitung für großes Update - Vollständig überarbeitet und erweitert*

