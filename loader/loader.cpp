/*
 * loader/loader.cpp
 *
 * User-mode controller for the HWIDSpoofer kernel driver.
 *
 * Two modes:
 *   1. Interactive menu (no args)  — arrow-key/number-key console UI
 *   2. CLI mode (with args)        — backward-compatible argument dispatch
 *
 * Build (MSVC):
 *   cl /std:c++17 /W4 /EHsc /nologo loader.cpp /link advapi32.lib iphlpapi.lib /out:loader.exe
 *
 * Requirements:
 *   Administrator privileges (needed to create/start a kernel driver service).
 *   Test-signing must be enabled on the target machine:
 *     bcdedit /set testsigning on   (reboot)
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ntddstor.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <string_view>
#include <format>
#include <vector>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include "../shared/protocol.h"

/* ─── Constants ──────────────────────────────────────────────────────── */
static constexpr std::wstring_view kDriverName    = L"volflt";
static constexpr std::wstring_view kDriverDisplay = L"Volume Filter Driver";

/* ─── Console helpers ────────────────────────────────────────────────── */
static HANDLE g_hStdout = INVALID_HANDLE_VALUE;
static HANDLE g_hStdin  = INVALID_HANDLE_VALUE;

static void InitConsole()
{
    g_hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hStdin  = GetStdHandle(STD_INPUT_HANDLE);
    SetConsoleMode(g_hStdin, ENABLE_PROCESSED_INPUT);
}

static void SetColor(WORD attr)
{
    SetConsoleTextAttribute(g_hStdout, attr);
}

static void PrintColour(int colour, std::string_view msg)
{
    SetColor(static_cast<WORD>(colour));
    std::cout << msg;
    SetColor(7);
}

#define LOG_OK(m)   PrintColour(10, std::string("[+] ") + (m) + "\n")
#define LOG_ERR(m)  PrintColour(12, std::string("[-] ") + (m) + "\n")
#define LOG_INFO(m) PrintColour(11, std::string("[*] ") + (m) + "\n")

static void ClearScreen()
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(g_hStdout, &csbi);
    DWORD cells = csbi.dwSize.X * csbi.dwSize.Y;
    DWORD written;
    COORD origin = {0, 0};
    FillConsoleOutputCharacterW(g_hStdout, L' ', cells, origin, &written);
    FillConsoleOutputAttribute(g_hStdout, csbi.wAttributes, cells, origin, &written);
    SetConsoleCursorPosition(g_hStdout, origin);
}

static void WaitForKey()
{
    std::cout << "\n  Press any key to continue...";
    FlushConsoleInputBuffer(g_hStdin);
    INPUT_RECORD ir;
    DWORD read;
    while (true) {
        ReadConsoleInputW(g_hStdin, &ir, 1, &read);
        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
            break;
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 * Service management — install, start, stop, remove
 * ═══════════════════════════════════════════════════════════════════════ */

static SC_HANDLE OpenSCM()
{
    SC_HANDLE h = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!h) LOG_ERR("OpenSCManager failed: " + std::to_string(GetLastError()));
    return h;
}

static bool CopyDriverToSystemDir(const std::wstring& srcPath)
{
    wchar_t sysDir[MAX_PATH]{};
    GetWindowsDirectoryW(sysDir, MAX_PATH);
    std::wstring dest = std::wstring(sysDir) + L"\\System32\\drivers\\volflt.sys";
    if (!CopyFileW(srcPath.c_str(), dest.c_str(), FALSE)) {
        DWORD err = GetLastError();
        if (err != ERROR_SHARING_VIOLATION) {
            LOG_ERR("CopyFile to drivers dir failed: " + std::to_string(err));
            return false;
        }
    }
    return true;
}

static void PersistConfig(const SPOOFER_CONFIG& cfg)
{
    HKEY hKey = nullptr;
    LONG err = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\volflt\\Parameters",
        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
        nullptr, &hKey, nullptr);
    if (err != ERROR_SUCCESS) return;
    RegSetValueExW(hKey, L"SpoofConfig", 0, REG_BINARY,
        reinterpret_cast<const BYTE*>(&cfg), sizeof(cfg));
    RegCloseKey(hKey);
}

static bool InstallDriver(const std::wstring& driverPath)
{
    if (!CopyDriverToSystemDir(driverPath)) return false;

    SC_HANDLE scm = OpenSCM();
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, kDriverName.data(), DELETE);
    if (svc) {
        DeleteService(svc);
        CloseServiceHandle(svc);
    }

    svc = CreateServiceW(
        scm, kDriverName.data(), kDriverDisplay.data(),
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_BOOT_START, SERVICE_ERROR_IGNORE,
        L"system32\\DRIVERS\\volflt.sys",
        L"Filter",    /* LoadOrderGroup — loads after storage stack */
        nullptr, nullptr, nullptr, nullptr);

    bool ok = (svc != nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            LOG_INFO("Service already exists");
            ok = true;
        } else {
            LOG_ERR("CreateService failed: " + std::to_string(err));
        }
    } else {
        LOG_OK("Boot-start driver service created");
        CloseServiceHandle(svc);
    }

    CloseServiceHandle(scm);
    return ok;
}

static bool StartDriver()
{
    SC_HANDLE scm = OpenSCM();
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, kDriverName.data(),
                                 SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        LOG_ERR("OpenService failed: " + std::to_string(GetLastError()));
        CloseServiceHandle(scm);
        return false;
    }

    bool ok = StartServiceW(svc, 0, nullptr) != 0;
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_INFO("Driver already running");
            ok = true;
        } else {
            LOG_ERR("StartService failed: " + std::to_string(err));
        }
    } else {
        LOG_OK("Driver started");
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

static bool StopDriver()
{
    SC_HANDLE scm = OpenSCM();
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, kDriverName.data(),
                                 SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS ss{};
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    LOG_OK("Driver stopped and service removed");
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Device communication — CreateFile, DeviceIoControl
 * ═══════════════════════════════════════════════════════════════════════ */

static HANDLE OpenDevice()
{
    HANDLE h = CreateFileW(
        SPOOFER_USERMODE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        LOG_ERR("CreateFile failed (code " + std::to_string(GetLastError()) + ")");
    }
    return h;
}

static bool SendIoctl(HANDLE dev, DWORD code,
                      void* inBuf  = nullptr, DWORD inLen  = 0,
                      void* outBuf = nullptr, DWORD outLen = 0)
{
    DWORD returned = 0;
    BOOL  ok = DeviceIoControl(dev, code, inBuf, inLen,
                               outBuf, outLen, &returned, nullptr);
    if (!ok) {
        LOG_ERR("DeviceIoControl 0x" +
                std::format("{:08X}", code) +
                " failed: " + std::to_string(GetLastError()));
    }
    return ok != 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * High-level operations — enable, disable, status, regen
 * ═══════════════════════════════════════════════════════════════════════ */

static void PrintStatus(HANDLE dev)
{
    SPOOFER_STATUS st{};
    if (!SendIoctl(dev, IOCTL_SPOOFER_GET_STATUS, nullptr, 0, &st, sizeof(st)))
        return;

    LOG_INFO(std::string("=== HWID Spoofer Status ==="));
    std::cout << "  Active              : " << (st.IsActive ? "YES" : "NO")  << "\n"
              << "  Disk filters        : " << st.DiskFiltersAttached         << "\n"
              << "  Total intercepts    : " << st.TotalIntercepts              << "\n"
              << "  Disk serial         : " << st.ActiveDiskSerial             << "\n"
              << "  MAC address         : " << st.ActiveMacAddress             << "\n"
              << "  Volume serial       : " << std::format("{:08X}", st.ActiveVolumeSerial) << "\n"
              << "  Install date        : " << st.ActiveInstallDate            << "\n"
              << "  EDID serial         : " << std::format("{:08X}", st.ActiveEdidSerial)   << "\n";

    char guidNarrow[128]{};
    WideCharToMultiByte(CP_ACP, 0, st.ActiveMachineGuid, -1,
                        guidNarrow, sizeof(guidNarrow), nullptr, nullptr);
    char prodNarrow[128]{};
    WideCharToMultiByte(CP_ACP, 0, st.ActiveProductId, -1,
                        prodNarrow, sizeof(prodNarrow), nullptr, nullptr);
    std::cout << "  Machine GUID        : " << guidNarrow << "\n"
              << "  Product ID          : " << prodNarrow << "\n";
}

static bool ConfigureAndEnable(HANDLE dev, bool autoGen,
                               const char* diskSerial    = nullptr,
                               const char* macAddress    = nullptr,
                               const wchar_t* machineGuid = nullptr,
                               ULONG volumeSerial = 0)
{
    SPOOFER_CONFIG cfg{};
    cfg.SpoofDiskSerial   = TRUE;
    cfg.SpoofMacAddress   = TRUE;
    cfg.SpoofMachineGuid  = TRUE;
    cfg.SpoofVolumeSerial = TRUE;
    cfg.SpoofInstallIds   = TRUE;
    cfg.SpoofEdidSerial   = TRUE;
    cfg.SpoofSmbios       = TRUE;
    cfg.SpoofGpu          = TRUE;
    cfg.AutoGenerate      = autoGen ? TRUE : FALSE;

    if (!autoGen) {
        if (diskSerial)
            strncpy_s(cfg.FakeDiskSerial, diskSerial, SPOOFER_DISK_SERIAL_LEN - 1);
        if (macAddress)
            strncpy_s(cfg.FakeMacAddress, macAddress, SPOOFER_MAC_LEN - 1);
        if (machineGuid)
            wcsncpy_s(cfg.FakeMachineGuid, machineGuid, SPOOFER_GUID_LEN - 1);
        cfg.FakeVolumeSerial = volumeSerial;
    }

    if (!SendIoctl(dev, IOCTL_SPOOFER_SET_CONFIG, &cfg, sizeof(cfg)))
        return false;

    LOG_OK("Config sent to driver");

    if (!SendIoctl(dev, IOCTL_SPOOFER_ENABLE))
        return false;

    LOG_OK("Spoofing enabled");

    /* Persist config to registry so boot-start auto-enable works on reboot */
    SPOOFER_STATUS st{};
    if (SendIoctl(dev, IOCTL_SPOOFER_GET_STATUS, nullptr, 0, &st, sizeof(st))) {
        SPOOFER_CONFIG persist = cfg;
        RtlCopyMemory(persist.FakeDiskSerial, st.ActiveDiskSerial, SPOOFER_DISK_SERIAL_LEN);
        RtlCopyMemory(persist.FakeMacAddress, st.ActiveMacAddress, SPOOFER_MAC_LEN);
        RtlCopyMemory(persist.FakeMachineGuid, st.ActiveMachineGuid, SPOOFER_GUID_LEN * sizeof(WCHAR));
        persist.FakeVolumeSerial = st.ActiveVolumeSerial;
        RtlCopyMemory(persist.FakeProductId, st.ActiveProductId, SPOOFER_PRODUCT_ID_LEN * sizeof(WCHAR));
        persist.FakeInstallDate = st.ActiveInstallDate;
        persist.FakeEdidSerial  = st.ActiveEdidSerial;
        RtlCopyMemory(persist.FakeDigitalProductBytes, st.ActiveDigitalProductBytes, 16);
        RtlCopyMemory(persist.FakeBiosSerial,    st.ActiveBiosSerial,    64);
        RtlCopyMemory(persist.FakeBoardSerial,   st.ActiveBoardSerial,   64);
        RtlCopyMemory(persist.FakeSystemSerial,  st.ActiveSystemSerial,  64);
        RtlCopyMemory(persist.FakeSystemUuid,    st.ActiveSystemUuid,    37);
        RtlCopyMemory(persist.FakeChassisSerial, st.ActiveChassisSerial, 64);
        RtlCopyMemory(persist.FakeGpuSerial,     st.ActiveGpuSerial,     64);
        RtlCopyMemory(persist.FakeGpuDescription,st.ActiveGpuDescription,128 * sizeof(WCHAR));
        persist.AutoGenerate = FALSE;
        PersistConfig(persist);
        LOG_OK("Config persisted for boot-start auto-enable");
    }

    return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 * AC Test functions — query HWIDs via the same APIs anti-cheats use
 * ═══════════════════════════════════════════════════════════════════════ */

struct AcTestResult {
    std::string name;
    std::string api;
    std::string value;
    bool        pass;
};

static std::string QueryDiskSerial()
{
    HANDLE hDisk = CreateFileW(
        L"\\\\.\\PhysicalDrive0",
        0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDisk == INVALID_HANDLE_VALUE) return "(open failed)";

    BYTE buf[4096]{};
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType  = PropertyStandardQuery;

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                              &query, sizeof(query),
                              buf, sizeof(buf), &returned, nullptr);
    CloseHandle(hDisk);

    if (!ok || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        return "(query failed)";

    auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf);
    if (desc->SerialNumberOffset == 0 || desc->SerialNumberOffset >= returned)
        return "(no serial)";

    return std::string(reinterpret_cast<char*>(buf) + desc->SerialNumberOffset);
}

static std::string QueryMacAddress()
{
    ULONG bufLen = 0;
    GetAdaptersInfo(nullptr, &bufLen);
    if (bufLen == 0) return "(no adapters)";

    std::vector<BYTE> buffer(bufLen);
    auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
    if (GetAdaptersInfo(info, &bufLen) != ERROR_SUCCESS)
        return "(GetAdaptersInfo failed)";

    if (info->AddressLength < 6) return "(bad address)";

    char mac[13];
    snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
             info->Address[0], info->Address[1], info->Address[2],
             info->Address[3], info->Address[4], info->Address[5]);
    return std::string(mac);
}

static std::string QueryRegistryString(HKEY root, const wchar_t* subkey,
                                       const wchar_t* valueName)
{
    HKEY hKey;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return "(open failed)";

    WCHAR data[256]{};
    DWORD dataSize = sizeof(data);
    DWORD type = 0;
    LONG  rc = RegQueryValueExW(hKey, valueName, nullptr, &type,
                                reinterpret_cast<LPBYTE>(data), &dataSize);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) return "(read failed)";

    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        char narrow[256]{};
        WideCharToMultiByte(CP_ACP, 0, data, -1, narrow, sizeof(narrow),
                            nullptr, nullptr);
        return std::string(narrow);
    }
    return "(unexpected type)";
}

static ULONG QueryRegistryDword(HKEY root, const wchar_t* subkey,
                                const wchar_t* valueName)
{
    HKEY hKey;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;

    DWORD data = 0;
    DWORD dataSize = sizeof(data);
    DWORD type = 0;
    RegQueryValueExW(hKey, valueName, nullptr, &type,
                     reinterpret_cast<LPBYTE>(&data), &dataSize);
    RegCloseKey(hKey);
    return data;
}

static std::string QueryVolumeSerial()
{
    DWORD serial = 0;
    if (!GetVolumeInformationW(L"C:\\", nullptr, 0, &serial,
                               nullptr, nullptr, nullptr, 0))
        return "(failed)";
    return std::format("{:08X}", serial);
}

/* Query NetworkAddress directly from the NIC class registry key.
   This is the path our CmCallback intercepts — different from GetAdaptersInfo
   which reads the live adapter, not necessarily the registry override. */
static std::string QueryNetworkAddressRegistry()
{
    const wchar_t* classKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Class"
        L"\\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    HKEY hClass;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, classKey, 0, KEY_READ, &hClass)
            != ERROR_SUCCESS)
        return "(open failed)";

    /* Enumerate subkeys (0000, 0001, ...) looking for one with NetworkAddress */
    std::string result = "(not found)";
    for (DWORD idx = 0; idx < 64; idx++) {
        WCHAR subName[16]{};
        DWORD subLen = 16;
        if (RegEnumKeyExW(hClass, idx, subName, &subLen,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        HKEY hSub;
        if (RegOpenKeyExW(hClass, subName, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
            continue;

        WCHAR data[64]{};
        DWORD dataSize = sizeof(data);
        DWORD type = 0;
        LONG rc = RegQueryValueExW(hSub, L"NetworkAddress", nullptr, &type,
                                   reinterpret_cast<LPBYTE>(data), &dataSize);
        RegCloseKey(hSub);

        if (rc == ERROR_SUCCESS && (type == REG_SZ) && data[0] != L'\0') {
            char narrow[64]{};
            WideCharToMultiByte(CP_ACP, 0, data, -1, narrow, sizeof(narrow),
                                nullptr, nullptr);
            result = std::string(narrow);
            break;
        }
    }

    RegCloseKey(hClass);
    return result;
}

/* Query DigitalProductId binary blob — check if bytes 8-23 are non-stock */
static std::string QueryDigitalProductId()
{
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return "(open failed)";

    BYTE data[256]{};
    DWORD dataSize = sizeof(data);
    DWORD type = 0;
    LONG rc = RegQueryValueExW(hKey, L"DigitalProductId", nullptr, &type,
                               data, &dataSize);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_BINARY || dataSize < 24)
        return "(read failed)";

    /* Return hex of bytes 8-23 for comparison */
    std::string hex;
    hex.reserve(32);
    for (DWORD i = 8; i < 24 && i < dataSize; i++)
        hex += std::format("{:02X}", data[i]);
    return hex;
}

/* Query EDID serial from the first display device's registry key.
   EDID bytes 12-15 are the 4-byte serial number (little-endian DWORD). */
static std::string QueryEdidSerial()
{
    const wchar_t* displayKey =
        L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY";

    HKEY hDisplay;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, displayKey, 0, KEY_READ, &hDisplay)
            != ERROR_SUCCESS)
        return "(open failed)";

    std::string result = "(not found)";

    /* Walk DISPLAY\<monitor>\<instance>\Device Parameters\EDID */
    for (DWORD m = 0; m < 16; m++) {
        WCHAR monName[128]{};
        DWORD monLen = 128;
        if (RegEnumKeyExW(hDisplay, m, monName, &monLen,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        HKEY hMon;
        if (RegOpenKeyExW(hDisplay, monName, 0, KEY_READ, &hMon) != ERROR_SUCCESS)
            continue;

        for (DWORD inst = 0; inst < 16; inst++) {
            WCHAR instName[128]{};
            DWORD instLen = 128;
            if (RegEnumKeyExW(hMon, inst, instName, &instLen,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                break;

            std::wstring dpPath = std::wstring(instName) + L"\\Device Parameters";
            HKEY hDp;
            if (RegOpenKeyExW(hMon, dpPath.c_str(), 0, KEY_READ, &hDp) != ERROR_SUCCESS)
                continue;

            BYTE edid[256]{};
            DWORD edidSize = sizeof(edid);
            DWORD edidType = 0;
            LONG rc = RegQueryValueExW(hDp, L"EDID", nullptr, &edidType,
                                       edid, &edidSize);
            RegCloseKey(hDp);

            if (rc == ERROR_SUCCESS && edidType == REG_BINARY && edidSize >= 128) {
                ULONG serial = *reinterpret_cast<ULONG*>(edid + 12);
                result = std::format("{:08X}", serial);
                RegCloseKey(hMon);
                goto edid_done;
            }
        }
        RegCloseKey(hMon);
    }
edid_done:
    RegCloseKey(hDisplay);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════
 * AC Test runner — compare queried values against SPOOFER_STATUS
 * ═══════════════════════════════════════════════════════════════════════ */

static void RunAcTests(HANDLE dev)
{
    SPOOFER_STATUS st{};
    bool haveSt = SendIoctl(dev, IOCTL_SPOOFER_GET_STATUS,
                            nullptr, 0, &st, sizeof(st));

    std::cout << "\n";
    SetColor(14);
    std::cout << "  === AC Spoof Verification ===\n";
    SetColor(7);
    std::cout << "\n";

    if (!haveSt) {
        LOG_ERR("Could not read driver status. Is the driver running?");
        return;
    }

    std::vector<AcTestResult> results;

    /* Disk Serial */
    {
        std::string val = QueryDiskSerial();
        /* Trim whitespace from SCSI space-padded serials */
        while (!val.empty() && (val.back() == ' ' || val.back() == '\0'))
            val.pop_back();
        std::string expected(st.ActiveDiskSerial);
        while (!expected.empty() && (expected.back() == ' ' || expected.back() == '\0'))
            expected.pop_back();
        bool pass = !expected.empty() && val.find(expected) != std::string::npos;
        results.push_back({"Disk Serial", "IOCTL_STORAGE_QUERY_PROPERTY", val, pass});
    }

    /* MAC Address (live adapter — CmCallback spoofs registry only, NIC restart needed) */
    {
        std::string val      = QueryMacAddress();
        std::string expected = st.ActiveMacAddress;
        bool pass = !expected.empty() && (_stricmp(val.c_str(), expected.c_str()) == 0);
        results.push_back({"MAC (live)", "GetAdaptersInfo (needs NIC restart)", val, pass});
    }

    /* MachineGuid */
    {
        std::string val = QueryRegistryString(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography",
            L"MachineGuid");
        char expected[128]{};
        WideCharToMultiByte(CP_ACP, 0, st.ActiveMachineGuid, -1,
                            expected, sizeof(expected), nullptr, nullptr);
        bool pass = !expected[0] ? false :
                    (_stricmp(val.c_str(), expected) == 0);
        results.push_back({"MachineGuid", "RegQueryValueEx", val, pass});
    }

    /* ProductId */
    {
        std::string val = QueryRegistryString(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"ProductId");
        char expected[128]{};
        WideCharToMultiByte(CP_ACP, 0, st.ActiveProductId, -1,
                            expected, sizeof(expected), nullptr, nullptr);
        bool pass = !expected[0] ? false :
                    (_stricmp(val.c_str(), expected) == 0);
        results.push_back({"ProductId", "RegQueryValueEx", val, pass});
    }

    /* InstallDate */
    {
        ULONG val = QueryRegistryDword(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"InstallDate");
        std::string valStr = std::to_string(val);
        bool pass = (st.ActiveInstallDate != 0) && (val == st.ActiveInstallDate);
        results.push_back({"InstallDate", "RegQueryValueEx", valStr, pass});
    }

    /* Volume Serial — no kernel interception implemented for GetVolumeInformation */
    {
        std::string val = QueryVolumeSerial();
        std::string expected = std::format("{:08X}", st.ActiveVolumeSerial);
        bool pass = (st.ActiveVolumeSerial != 0) &&
                    (_stricmp(val.c_str(), expected.c_str()) == 0);
        results.push_back({"Volume Serial", "NtQueryVolumeInformationFile", val, pass});
    }

    /* NetworkAddress (registry path — separate from GetAdaptersInfo above) */
    {
        std::string val = QueryNetworkAddressRegistry();
        std::string expected = st.ActiveMacAddress;
        bool pass = !expected.empty() && (_stricmp(val.c_str(), expected.c_str()) == 0);
        results.push_back({"NetworkAddress", "RegQueryValueEx (NIC class)", val, pass});
    }

    /* DigitalProductId (binary blob, bytes 8-23) */
    {
        std::string val = QueryDigitalProductId();
        std::string expected;
        expected.reserve(32);
        for (int i = 0; i < 16; i++)
            expected += std::format("{:02X}", st.ActiveDigitalProductBytes[i]);
        bool pass = !expected.empty() && (val.length() == 32) &&
                    (_stricmp(val.c_str(), expected.c_str()) == 0);
        results.push_back({"DigitalProductId", "RegQueryValueEx (binary)", val, pass});
    }

    /* EDID Serial */
    {
        std::string val = QueryEdidSerial();
        std::string expected = std::format("{:08X}", st.ActiveEdidSerial);
        bool pass = (st.ActiveEdidSerial != 0) &&
                    (_stricmp(val.c_str(), expected.c_str()) == 0);
        results.push_back({"EDID Serial", "RegQueryValueEx (DISPLAY)", val, pass});
    }

    /* Print results */
    int passed = 0;
    for (auto& r : results) {
        if (r.pass) {
            SetColor(10);
            std::cout << "  [PASS] ";
        } else {
            SetColor(12);
            std::cout << "  [FAIL] ";
        }
        SetColor(15);
        std::cout << std::format("{:<16}", r.name);
        SetColor(8);
        std::cout << " : " << std::format("{:<30}", r.api) << " -> ";
        SetColor(r.pass ? 10 : 12);
        std::cout << "\"" << r.value << "\"";
        if (r.pass) {
            SetColor(8);
            std::cout << " (matches spoofed)";
        } else {
            SetColor(12);
            std::cout << " (REAL - not spoofed)";
        }
        std::cout << "\n";
        if (r.pass) passed++;
    }

    SetColor(7);
    std::cout << "\n  ";
    SetColor(passed == (int)results.size() ? 10 : 14);
    std::cout << passed << "/" << results.size() << " checks spoofed.";
    SetColor(7);
    std::cout << "\n";
}

/* ═══════════════════════════════════════════════════════════════════════
 * Interactive menu
 * ═══════════════════════════════════════════════════════════════════════ */

static bool IsDriverLoaded()
{
    HANDLE h = CreateFileW(SPOOFER_USERMODE_PATH, GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

struct MenuItem {
    int         key;       /* '0'-'9' */
    const char* label;
};

static const MenuItem kMenuItems[] = {
    {'1', "Install driver"},
    {'2', "Start driver"},
    {'3', "Enable spoofing (auto-generate)"},
    {'4', "Disable spoofing"},
    {'5', "Regenerate IDs"},
    {'6', "Show status"},
    {'7', "Run AC tests"},
    {'8', "Stop driver"},
    {'0', "Exit"},
};
static constexpr int kMenuCount = sizeof(kMenuItems) / sizeof(kMenuItems[0]);

static void DrawMenu(int selected)
{
    ClearScreen();

    SetColor(14);
    std::cout << R"(
  ██╗  ██╗██╗    ██╗██╗██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗
  ██║  ██║██║    ██║██║██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
  ███████║██║ █╗ ██║██║██║  ██║    ███████╗██████╔╝██║   ██║██║   ██║█████╗
  ██╔══██║██║███╗██║██║██║  ██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝
  ██║  ██║╚███╔███╔╝██║██████╔╝    ███████║██║     ╚██████╔╝╚██████╔╝██║
  ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═════╝     ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝
)" << "\n";
    SetColor(7);

    /* Status bar */
    bool loaded = IsDriverLoaded();
    std::cout << "  Driver: ";
    SetColor(loaded ? 10 : 12);
    std::cout << (loaded ? "LOADED" : "NOT LOADED");
    SetColor(7);

    if (loaded) {
        HANDLE dev = OpenDevice();
        if (dev != INVALID_HANDLE_VALUE) {
            SPOOFER_STATUS st{};
            if (SendIoctl(dev, IOCTL_SPOOFER_GET_STATUS, nullptr, 0,
                          &st, sizeof(st))) {
                std::cout << " | Spoofing: ";
                SetColor(st.IsActive ? 10 : 12);
                std::cout << (st.IsActive ? "ON" : "OFF");
                SetColor(7);
                std::cout << " | Intercepts: ";
                SetColor(11);
                std::cout << st.TotalIntercepts;
                SetColor(7);
            }
            CloseHandle(dev);
        }
    }
    std::cout << "\n\n";

    /* Menu items */
    for (int i = 0; i < kMenuCount; i++) {
        if (i == selected) {
            SetColor(0x70);  /* inverse: white bg, black fg */
            std::cout << "  > [" << (char)kMenuItems[i].key << "] "
                      << kMenuItems[i].label << "  \n";
            SetColor(7);
        } else {
            std::cout << "    [" << (char)kMenuItems[i].key << "] "
                      << kMenuItems[i].label << "\n";
        }
    }

    std::cout << "\n";
}

static std::wstring PromptDriverPath()
{
    std::cout << "  Enter path to .sys file: ";
    SetColor(15);
    std::wstring path;
    std::wcin >> path;
    SetColor(7);
    return path;
}

static void HandleMenuAction(int choice)
{
    switch (choice) {
    case '1': {
        std::wstring path = PromptDriverPath();
        InstallDriver(path);
        WaitForKey();
        break;
    }
    case '2':
        StartDriver();
        WaitForKey();
        break;
    case '3': {
        HANDLE dev = OpenDevice();
        if (dev != INVALID_HANDLE_VALUE) {
            ConfigureAndEnable(dev, true);
            PrintStatus(dev);
            CloseHandle(dev);
        }
        WaitForKey();
        break;
    }
    case '4': {
        HANDLE dev = OpenDevice();
        if (dev != INVALID_HANDLE_VALUE) {
            if (SendIoctl(dev, IOCTL_SPOOFER_DISABLE))
                LOG_OK("Spoofing disabled");
            CloseHandle(dev);
        }
        WaitForKey();
        break;
    }
    case '5': {
        HANDLE dev = OpenDevice();
        if (dev != INVALID_HANDLE_VALUE) {
            if (SendIoctl(dev, IOCTL_SPOOFER_REGENERATE)) {
                LOG_OK("IDs regenerated");
                PrintStatus(dev);
            }
            CloseHandle(dev);
        }
        WaitForKey();
        break;
    }
    case '6': {
        HANDLE dev = OpenDevice();
        if (dev != INVALID_HANDLE_VALUE) {
            PrintStatus(dev);
            CloseHandle(dev);
        }
        WaitForKey();
        break;
    }
    case '7': {
        HANDLE dev = OpenDevice();
        if (dev != INVALID_HANDLE_VALUE) {
            RunAcTests(dev);
            CloseHandle(dev);
        } else {
            LOG_ERR("Driver not loaded. Load it first to run AC tests.");
        }
        WaitForKey();
        break;
    }
    case '8':
        StopDriver();
        WaitForKey();
        break;
    default:
        break;
    }
}

static void InteractiveMenu()
{
    int selected = 0;
    bool running = true;

    while (running) {
        DrawMenu(selected);

        FlushConsoleInputBuffer(g_hStdin);
        INPUT_RECORD ir;
        DWORD read;

        while (true) {
            ReadConsoleInputW(g_hStdin, &ir, 1, &read);
            if (ir.EventType != KEY_EVENT || !ir.Event.KeyEvent.bKeyDown)
                continue;

            WORD  vk  = ir.Event.KeyEvent.wVirtualKeyCode;
            WCHAR ch  = ir.Event.KeyEvent.uChar.UnicodeChar;

            /* Arrow keys */
            if (vk == VK_UP) {
                selected = (selected - 1 + kMenuCount) % kMenuCount;
                break;
            }
            if (vk == VK_DOWN) {
                selected = (selected + 1) % kMenuCount;
                break;
            }

            /* Enter confirms highlighted item */
            if (vk == VK_RETURN) {
                int choice = kMenuItems[selected].key;
                if (choice == '0') { running = false; break; }
                HandleMenuAction(choice);
                break;
            }

            /* Direct number key */
            if (ch >= L'0' && ch <= L'9') {
                char pressed = static_cast<char>(ch);
                if (pressed == '0') { running = false; break; }
                for (int i = 0; i < kMenuCount; i++) {
                    if (kMenuItems[i].key == pressed) {
                        selected = i;
                        HandleMenuAction(pressed);
                        break;
                    }
                }
                break;
            }

            /* Escape = exit */
            if (vk == VK_ESCAPE) {
                running = false;
                break;
            }
        }
    }

    ClearScreen();
    SetColor(7);
    std::cout << "  Exited.\n";
}

/* ═══════════════════════════════════════════════════════════════════════
 * CLI argument dispatch (backward compatible)
 * ═══════════════════════════════════════════════════════════════════════ */

static void Usage(const wchar_t* exe)
{
    char exeNarrow[MAX_PATH]{};
    WideCharToMultiByte(CP_ACP, 0, exe, -1,
                        exeNarrow, sizeof(exeNarrow), nullptr, nullptr);
    std::cout <<
        "Usage: " << exeNarrow << " <command> [options]\n\n"
        "Commands:\n"
        "  install  <path-to-driver.sys>    Install driver service\n"
        "  start                            Start the driver\n"
        "  enable   [--manual ...]          Enable spoofing (auto-generate IDs by default)\n"
        "  disable                          Disable spoofing\n"
        "  status                           Print current spoofed IDs\n"
        "  regen                            Regenerate all IDs\n"
        "  stop                             Stop driver + remove service\n\n"
        "  --manual options (for 'enable'):\n"
        "    --disk  <32-char hex serial>\n"
        "    --mac   <12-char hex, e.g. 0A1B2C3D4E5F>\n"
        "    --guid  <{xxxxxxxx-...} wide GUID>\n"
        "    --vol   <hex DWORD, e.g. DEADBEEF>\n\n"
        "Run with no arguments for interactive menu.\n";
}

static int CliDispatch(int argc, wchar_t* argv[])
{
    SetConsoleTitleW(L"HWID Spoofer \u2013 Research Tool");

    PrintColour(14, R"(
  ██╗  ██╗██╗    ██╗██╗██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗
  ██║  ██║██║    ██║██║██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
  ███████║██║ █╗ ██║██║██║  ██║    ███████╗██████╔╝██║   ██║██║   ██║█████╗
  ██╔══██║██║███╗██║██║██║  ██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝
  ██║  ██║╚███╔███╔╝██║██████╔╝    ███████║██║     ╚██████╔╝╚██████╔╝██║
  ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═════╝     ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝
  [ Ring-0 HWID Spoofer — Anti-Cheat Research Tool ]
)");

    std::wstring cmd = argv[1];

    if (cmd == L"install") {
        if (argc < 3) { LOG_ERR("Provide path to .sys file"); return 1; }
        return InstallDriver(argv[2]) ? 0 : 1;
    }
    if (cmd == L"start")  return StartDriver() ? 0 : 1;
    if (cmd == L"stop")   return StopDriver()  ? 0 : 1;

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) {
        LOG_ERR("Could not open driver device. Is the driver running?");
        return 1;
    }

    int ret = 0;

    if (cmd == L"status") {
        PrintStatus(dev);
    } else if (cmd == L"regen") {
        if (SendIoctl(dev, IOCTL_SPOOFER_REGENERATE)) {
            LOG_OK("IDs regenerated");
            PrintStatus(dev);
        }
    } else if (cmd == L"disable") {
        if (SendIoctl(dev, IOCTL_SPOOFER_DISABLE))
            LOG_OK("Spoofing disabled");
    } else if (cmd == L"enable") {
        bool manual = false;
        char    diskSerial[SPOOFER_DISK_SERIAL_LEN] = {};
        char    macAddr   [SPOOFER_MAC_LEN]          = {};
        wchar_t machGuid  [SPOOFER_GUID_LEN]         = {};
        ULONG   volSerial = 0;

        for (int i = 2; i < argc; i++) {
            std::wstring opt = argv[i];
            if (opt == L"--manual") {
                manual = true;
            } else if (opt == L"--disk" && i + 1 < argc) {
                WideCharToMultiByte(CP_ACP, 0, argv[++i], -1,
                                    diskSerial, sizeof(diskSerial), nullptr, nullptr);
            } else if (opt == L"--mac" && i + 1 < argc) {
                WideCharToMultiByte(CP_ACP, 0, argv[++i], -1,
                                    macAddr, sizeof(macAddr), nullptr, nullptr);
            } else if (opt == L"--guid" && i + 1 < argc) {
                wcsncpy_s(machGuid, argv[++i], SPOOFER_GUID_LEN - 1);
            } else if (opt == L"--vol" && i + 1 < argc) {
                volSerial = wcstoul(argv[++i], nullptr, 16);
            }
        }

        bool ok = ConfigureAndEnable(
                      dev, !manual,
                      manual ? diskSerial  : nullptr,
                      manual ? macAddr     : nullptr,
                      manual ? machGuid    : nullptr,
                      manual ? volSerial   : 0);
        if (ok) PrintStatus(dev);
        else    ret = 1;
    } else {
        Usage(argv[0]);
        ret = 1;
    }

    CloseHandle(dev);
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Entry point
 * ═══════════════════════════════════════════════════════════════════════ */

static bool IsRunAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

int wmain(int argc, wchar_t* argv[])
{
    InitConsole();
    SetConsoleTitleW(L"HWID Spoofer \u2013 Research Tool");

    if (!IsRunAsAdmin()) {
        SetColor(12);
        std::cout << "  [!] Not running as Administrator. "
                     "Driver operations will fail.\n";
        SetColor(7);
        std::cout << "  Right-click the executable and select "
                     "\"Run as administrator\".\n\n";
    }

    if (argc >= 2) {
        return CliDispatch(argc, argv);
    }

    InteractiveMenu();
    return 0;
}
