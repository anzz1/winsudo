// winsudo.c

// Windows Vista / Server 2008 and up
#define WINVER 0x0600
#define _WIN32_WINNT 0x0600

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <conio.h>
#include <userenv.h>
#include <shellapi.h>
#include "version.h"

#pragma comment (lib, "userenv.lib")
#pragma comment (lib, "ntdll.lib")
#pragma intrinsic (strlen, wcslen, wcscpy, wcscat)

#ifndef VERSION_STR
#error VERSION_STR undefined
#endif

#define countof(x) (sizeof(x)/sizeof(x[0]))
#define VAR_SID(x) struct _sid_##x {BYTE Revision; BYTE SubAuthorityCount; SID_IDENTIFIER_AUTHORITY IdentifierAuthority; DWORD SubAuthority[x];}
#define VAR_TKP(x) struct _tkp_##x {DWORD PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[x];}

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PVOID           ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PROCESS_ACCESS_TOKEN
{
  HANDLE Token;
  HANDLE Thread;
} PROCESS_ACCESS_TOKEN, * PPROCESS_ACCESS_TOKEN;

extern __declspec(dllimport) long __stdcall NtSetInformationProcess(
  HANDLE               ProcessHandle,
  ULONG                ProcessInformationClass,
  PVOID                ProcessInformation,
  ULONG                ProcessInformationLength
);
extern __declspec(dllimport) long __stdcall RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
extern __declspec(dllimport) long __stdcall ZwCreateToken(
  PHANDLE              TokenHandle,
  ACCESS_MASK          DesiredAccess,
  POBJECT_ATTRIBUTES   ObjectAttributes,
  TOKEN_TYPE           TokenType,
  PLUID                AuthenticationId,
  PLARGE_INTEGER       ExpirationTime,
  PTOKEN_USER          TokenUser,
  PTOKEN_GROUPS        TokenGroups,
  PTOKEN_PRIVILEGES    TokenPrivileges,
  PTOKEN_OWNER         TokenOwner,
  PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
  PTOKEN_DEFAULT_DACL  TokenDefaultDacl,
  PTOKEN_SOURCE        TokenSource
);

static DWORD ppid = 0;
static DWORD cpid = 0;

static union {
  struct {
    BYTE nopriv:1;
    BYTE notoken:1;
    BYTE access:2;
    BYTE verbosity:2;
  } f;
  DWORD u;
} flags;

static const char* sysProcs[] = {
  "lsass.exe",
  "smss.exe",
  "csrss.exe",
  "lsm.exe",
  "wmiprvse.exe",
  "services.exe",
  "winlogon.exe",
  "wininit.exe",
  "trustedinstaller.exe",
  "logonui.exe"
};

VAR_SID(1)
  sid_system = {1, 1, {0, 0, 0, 0, 0, 5}, {18}},
  sid_everyone = {1, 1, {0, 0, 0, 0, 0, 1}, {0}},
  sid_local = {1, 1, {0, 0, 0, 0, 0, 2}, {0}},
  sid_console = {1, 1, {0, 0, 0, 0, 0, 2}, {1}},
  sid_interactive = {1, 1, {0, 0, 0, 0, 0, 5}, {4}},
  sid_service = {1, 1, {0, 0, 0, 0, 0, 5}, {6}},
  sid_authed = {1, 1, {0, 0, 0, 0, 0, 5}, {11}},
  sid_localorg = {1, 1, {0, 0, 0, 0, 0, 5}, {15}},
  sid_localacc = {1, 1, {0, 0, 0, 0, 0, 5}, {113}},
  sid_localadmin = {1, 1, {0, 0, 0, 0, 0, 5}, {114}};

VAR_SID(2)
  sid_admins = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 544}},
  sid_users = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 545}},
  sid_bakops = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 551}},
  sid_netconf = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 556}},
  sid_perflog = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 559}},
  sid_authg = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 560}},
  sid_dcom = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 562}},
  sid_crypt = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 569}},
  sid_evlog = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 573}},
  sid_hyperv = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 578}},
  sid_sysman = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 581}},
  sid_devown = {1, 2, {0, 0, 0, 0, 0, 5}, {32, 583}},
  sid_ntlm = {1, 2, {0, 0, 0, 0, 0, 5}, {64, 10}};

VAR_SID(6)
  sid_ti = {1, 6, {0, 0, 0, 0, 0, 5}, {80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464}};

VAR_TKP(2)
  tkp_impersonate = {2, {
    {{20, 0}, 2}, // SeDebugPrivilege
    {{29, 0}, 2}  // SeImpersonatePrivilege
  }};

VAR_TKP(1)
  tkp_assign = {1, {
    {{3, 0}, 2}   // SeAssignPrimaryTokenPrivilege
  }};

VAR_TKP(35)
  tkp_all = {35, {
    {{2, 0}, 2},  // SeCreateTokenPrivilege
    {{3, 0}, 2},  // SeAssignPrimaryTokenPrivilege
    {{4, 0}, 2},  // SeLockMemoryPrivilege
    {{5, 0}, 2},  // SeIncreaseQuotaPrivilege
    {{6, 0}, 2},  // SeMachineAccountPrivilege
    {{7, 0}, 2},  // SeTcbPrivilege
    {{8, 0}, 2},  // SeSecurityPrivilege
    {{9, 0}, 2},  // SeTakeOwnershipPrivilege
    {{10, 0}, 2}, // SeLoadDriverPrivilege
    {{11, 0}, 2}, // SeSystemProfilePrivilege
    {{12, 0}, 2}, // SeSystemtimePrivilege
    {{13, 0}, 2}, // SeProfileSingleProcessPrivilege
    {{14, 0}, 2}, // SeIncreaseBasePriorityPrivilege
    {{15, 0}, 2}, // SeCreatePagefilePrivilege
    {{16, 0}, 2}, // SeCreatePermanentPrivilege
    {{17, 0}, 2}, // SeBackupPrivilege
    {{18, 0}, 2}, // SeRestorePrivilege
    {{19, 0}, 2}, // SeShutdownPrivilege
    {{20, 0}, 2}, // SeDebugPrivilege
    {{21, 0}, 2}, // SeAuditPrivilege
    {{22, 0}, 2}, // SeSystemEnvironmentPrivilege
    {{23, 0}, 2}, // SeChangeNotifyPrivilege
    {{24, 0}, 2}, // SeRemoteShutdownPrivilege
    {{25, 0}, 2}, // SeUndockPrivilege
    {{26, 0}, 2}, // SeSyncAgentPrivilege
    {{27, 0}, 2}, // SeEnableDelegationPrivilege
    {{28, 0}, 2}, // SeManageVolumePrivilege
    {{29, 0}, 2}, // SeImpersonatePrivilege
    {{30, 0}, 2}, // SeCreateGlobalPrivilege
    {{31, 0}, 2}, // SeTrustedCredManAccessPrivilege
    {{32, 0}, 2}, // SeRelabelPrivilege
    {{33, 0}, 2}, // SeIncreaseWorkingSetPrivilege
    {{34, 0}, 2}, // SeTimeZonePrivilege
    {{35, 0}, 2}, // SeCreateSymbolicLinkPrivilege
    {{36, 0}, 2}  // SeDelegateSessionUserImpersonatePrivilege
  }};

struct _token_grp_good {
  DWORD GroupCount;
  SID_AND_ATTRIBUTES Groups[13];
} tkg_good = {13, {
  {&sid_everyone, 7},
  {&sid_local, 15},
  {&sid_console, 7},
  {&sid_interactive, 7},
  {&sid_service, 7},
  {&sid_authed, 7},
  {&sid_localorg, 7},
  {&sid_localacc, 7},
  {&sid_localadmin, 7},
  {&sid_admins, 15},
  {&sid_users, 15},
  {&sid_ntlm, 7},
  {&sid_ti, 14}
}};

struct _token_grp_extra {
  DWORD GroupCount;
  SID_AND_ATTRIBUTES Groups[10];
} tkg_xtra = {10, {
  {&sid_bakops, 15},
  {&sid_netconf, 15},
  {&sid_perflog, 15},
  {&sid_authg, 15},
  {&sid_dcom, 15},
  {&sid_crypt, 15},
  {&sid_evlog, 15},
  {&sid_hyperv, 15},
  {&sid_sysman, 15},
  {&sid_devown, 15}
}};

__forceinline static int __stricmp(const char* s1, const char* s2) {
  char c1, c2;
  do {
    if (*s1 == 0 && *s2 == 0) return 0;
    c1 = (*s1>64 && *s1<91) ? (*s1+32):*s1; // A-Z -> a-z
    c2 = (*s2>64 && *s2<91) ? (*s2+32):*s2; // A-Z -> a-z
    s1++; s2++;
  } while (c1 == c2);
  return (*s1 > *s2) ? 1 : -1;
}

__forceinline static char* __strrchr(const char* s, char c) {
  char *p = 0;
  while (*s != 0) {
    if (*s == c) p = (char*)s;
    s++;
  }
  return p;
}

__forceinline static unsigned long __wtoul(const wchar_t *string) {
  unsigned long u = 0;
  if (!string) return 0;
  while (*string >= 48 && *string <= 57) {
    u = u * 10 + *string - 48;
    string++;
  }
  return u;
}

__forceinline static wchar_t* __ultow(unsigned long value, wchar_t* string) {
  wchar_t buf[11];
  wchar_t* pos;
  if (!string) return 0;
  pos = buf + 10;
  *pos = 0;
  do {
    *--pos = 48 + (value % 10);
  } while (value /= 10);
  __movsb((unsigned char*)string, (unsigned const char*)pos, (buf - pos + 11) * sizeof(wchar_t));
  return string;
}

__forceinline static void _ioprint(HANDLE std_handle, const char* cbuf) {
  DWORD u = 0;
  WriteFile(std_handle, cbuf, (DWORD)strlen(cbuf), &u, 0);
}

__declspec(dllexport) void __stdcall _print(const char* cbuf) {
  _ioprint(GetStdHandle(STD_OUTPUT_HANDLE), cbuf);
}

__declspec(dllexport) void __stdcall _perr(const char* cbuf) {
  _ioprint(GetStdHandle(STD_ERROR_HANDLE), cbuf);
}

DWORD __stdcall PrintThread(void* param) {
  void* pfn = GetProcAddress(GetModuleHandleA(0), "_print");
  if (pfn) ((void (__stdcall *)(const char*)) (void*)(pfn))(param);
  return 0;
}

DWORD __stdcall ErrThread(void* param) {
  void* pfn = GetProcAddress(GetModuleHandleA(0), "_perr");
  if (pfn) ((void (__stdcall *)(const char*)) (void*)(pfn))(param);
  return 0;
}

static void ThreadPrint(const char* cbuf, BOOL err) {
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ppid);
  if (hProc) {
    SIZE_T clen = strlen(cbuf)+1;
    void* page = VirtualAllocEx(hProc, NULL, clen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (page) {
      if (WriteProcessMemory(hProc, page, cbuf, clen, NULL)) {
        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)(err ? ErrThread : PrintThread), page, 0, NULL);
        if (hThread) {
          WaitForSingleObject(hThread, INFINITE);
          CloseHandle(hThread);
        }
      }
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      page = NULL;
    }
    CloseHandle(hProc);
  }
}

__forceinline static void print(const char* cbuf) {
  if (ppid) ThreadPrint(cbuf, 0);
  else _print(cbuf);
}

__forceinline static void perr(const char* cbuf) {
  if (ppid) ThreadPrint(cbuf, 1);
  else _perr(cbuf);
}

__forceinline static void fmt_print(const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2) {
  char* fmt_str = 0;
  DWORD_PTR pArgs[] = { (DWORD_PTR)arg1, (DWORD_PTR)arg2 };
  if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, fmt, 0, 0, (LPSTR)&fmt_str, 0, (va_list*)pArgs)) {
    print(fmt_str);
    LocalFree(fmt_str);
  }
}

__forceinline static void fmt_error(const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2) {
  char* fmt_str = 0;
  DWORD_PTR pArgs[] = { (DWORD_PTR)arg1, (DWORD_PTR)arg2 };
  if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, fmt, 0, 0, (LPSTR)&fmt_str, 0, (va_list*)pArgs)) {
    perr(fmt_str);
    LocalFree(fmt_str);
  }
}

__forceinline static HLOCAL MemAlloc(UINT uFlags, SIZE_T uBytes) {
  HLOCAL mem = LocalAlloc(uFlags, uBytes);
  if (!mem) {
    _perr("out of memory\r\n");
    ExitProcess(-3);
  }
  return mem;
}

__forceinline static BOOL ReadEnvironmentVariable(const wchar_t* pszName, wchar_t* pszBuffer, DWORD cchBuffer) {
  DWORD cchCopied = GetEnvironmentVariableW(pszName, pszBuffer, cchBuffer);
  return(cchCopied && cchCopied < cchBuffer);
}

__forceinline static BOOL EnableImpersonatePriv(int verbosity) {
  HANDLE hToken;
  DWORD dwErr;

  if (!OpenProcessToken((HANDLE)-1, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
    if (verbosity > 0)  {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:OpenProcessToken() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    return FALSE;
  }

  AdjustTokenPrivileges(hToken, FALSE, (TOKEN_PRIVILEGES*)&tkp_impersonate, 0, NULL, NULL);
  dwErr = GetLastError();
  CloseHandle(hToken);

  if (dwErr != ERROR_SUCCESS) {
    if (verbosity > 0)
      fmt_error("[!] advapi32:AdjustTokenPrivileges() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    return FALSE;
  }

  return TRUE;
}

__forceinline static BOOL EnableAllPriv(HANDLE hToken, int verbosity) {
  DWORD dwErr;

  AdjustTokenPrivileges(hToken, FALSE, (TOKEN_PRIVILEGES*)&tkp_all, 0, NULL, NULL);
  dwErr = GetLastError();

  if (dwErr != ERROR_SUCCESS && dwErr != ERROR_NOT_ALL_ASSIGNED) {
    if (verbosity > 0) {
      fmt_error("[!] advapi32:AdjustTokenPrivileges() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    return FALSE;
  }

  return TRUE;
}

__forceinline static HANDLE GetAccessToken(DWORD pid, int verbosity) {
  HANDLE hProc = NULL;
  HANDLE hToken = NULL;
  DWORD dwErr;

  hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
  if (!hProc) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] kernel32:OpenProcess() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
  } else {
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken)) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] advapi32:OpenProcessToken() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      }
    }
    CloseHandle(hProc);
  }
  return hToken;
}

static BOOL IsSidToken(HANDLE hToken, PSID pSID, int verbosity) {
  BOOL bIsMember = FALSE;
  DWORD dwErr;

  if (!CheckTokenMembership(hToken, pSID, &bIsMember)) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:CheckTokenMembership() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    return FALSE;
  }
  return bIsMember;
}

__forceinline static BOOL IsAdminToken(HANDLE hToken, int verbosity) {
  return IsSidToken(hToken, &sid_admins, verbosity);
}

__forceinline static BOOL IsSystemToken(HANDLE hToken, int verbosity) {
  return IsSidToken(hToken, &sid_system, verbosity);
}

__forceinline static BOOL IsTIToken(HANDLE hToken, int verbosity) {
  return IsSidToken(hToken, &sid_ti, verbosity);
}

static DWORD GetPIDForProcess(const char* process) {
  PROCESSENTRY32 lppe;
  char* pname;
  HANDLE hSnapshot;
  DWORD pid = 0;
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot) {
    __stosb((PBYTE)&lppe, 0, sizeof(PROCESSENTRY32));
    lppe.dwSize = sizeof(lppe);
    if (Process32First(hSnapshot,&lppe)) {
      do {
        pname = __strrchr(lppe.szExeFile, '\\');
        if(!__stricmp(process, (pname ? pname+1 : lppe.szExeFile))) {
          pid = lppe.th32ProcessID;
          break;
        }
      } while (Process32Next(hSnapshot,&lppe));
    }
  CloseHandle(hSnapshot);
  }
  return pid;
}

__forceinline static BOOL GetWindowSize(int* w, int* h) {
  HWND hWnd;
  RECT rect = {0, 0, 0, 0};
  hWnd = GetConsoleWindow();
  if (hWnd && GetClientRect(hWnd, &rect)) {
    *w = rect.right-rect.left;
    *h = rect.bottom-rect.top;
    return TRUE;
  }
  return FALSE;
}

__forceinline static BOOL GetConsoleBufferSize(int* cols, int* rows) {
  HANDLE hConOut;
  CONSOLE_SCREEN_BUFFER_INFO bi;
  hConOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hConOut && hConOut != (HANDLE)-1) {
    if (GetConsoleScreenBufferInfo(hConOut, &bi)) {
      *cols = bi.dwSize.X;
      *rows = bi.dwSize.Y;
      return TRUE;
    }
  }
  return FALSE;
}

static BOOL GetDupToken(const char* pname, PHANDLE phToken, PHANDLE phNewToken, int verbosity) {
  DWORD pid;
  DWORD dwErr;

  pid = GetPIDForProcess(pname);
  if (!pid) {
    if (verbosity >= 2) fmt_error("[!] Could not acquire PID for %1!s!\r\n", (DWORD_PTR)pname, (DWORD_PTR)"");
    return FALSE;
  }
  if (verbosity == 2) fmt_error("[+] Found %1!s! (PID: %2!u!)\r\n", (DWORD_PTR)pname, (DWORD_PTR)pid);

  *phToken = GetAccessToken(pid, verbosity);
  if (!*phToken || *phToken == INVALID_HANDLE_VALUE) {
    if (verbosity > 0) perr("[!] Could not acquire access token\r\n");
    return FALSE;
  }
  if (verbosity == 2) perr("[+] Access token acquired\r\n");

  if(!DuplicateTokenEx(*phToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, phNewToken)) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:DuplicateTokenEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      perr("[!] Could not duplicate access token\r\n");
    }
    CloseHandle(*phNewToken);
    CloseHandle(*phToken);
    *phNewToken = NULL;
    *phToken = NULL;
    return FALSE;
  }
  return TRUE;
}

static BOOL IsGroupSid(PSID pSID, int verbosity) {
  DWORD cchName = 0xFFFF;
  DWORD cchRefName = 0xFFFF;
  SID_NAME_USE eUse = 0;
  DWORD dwErr;
  if (!LookupAccountSidA(NULL, pSID, NULL, &cchName, NULL, &cchRefName, &eUse)) {
    dwErr = GetLastError();
    if (verbosity > 0 && dwErr != ERROR_NONE_MAPPED)
      fmt_error("[!] advapi32:LookupAccountSidA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    return FALSE;
  }
  switch (eUse) {
    case SidTypeGroup:
    case SidTypeAlias:
    case SidTypeWellKnownGroup:
      return TRUE;
    default:
      return FALSE;
  }
}

static LPVOID GetInfoFromToken(HANDLE hToken, TOKEN_INFORMATION_CLASS type, int verbosity) {
  DWORD dwLength;
  DWORD dwErr;
  LPVOID lpData = NULL;
  if (!GetTokenInformation(hToken, type, NULL, 0, &dwLength)) {
    dwErr = GetLastError();
    if (dwErr != ERROR_INSUFFICIENT_BUFFER) {
      if (verbosity > 0) fmt_error("[!] advapi32:GetTokenInformation() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      return NULL;
    }
  }
  lpData = (LPVOID)MemAlloc(LPTR, dwLength);
  if (!GetTokenInformation(hToken, type, lpData, dwLength, &dwLength)) {
    dwErr = GetLastError();
    if (verbosity > 0) fmt_error("[!] advapi32:GetTokenInformation() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    LocalFree(lpData);
    lpData = NULL;
  }
  return lpData;
}

static HANDLE CreateUserToken(HANDLE base_token, int verbosity) {
  HANDLE user_token = NULL;
  LUID luid;
  LARGE_INTEGER li;
  TOKEN_USER user;
  TOKEN_OWNER owner;
  PTOKEN_STATISTICS stats;
  PTOKEN_GROUPS groups, groups2;
  PTOKEN_PRIMARY_GROUP primary_group;
  PTOKEN_DEFAULT_DACL default_dacl;
  SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityDelegation, SECURITY_STATIC_TRACKING, FALSE };
  OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, &sqos };
  TOKEN_SOURCE source = { {'C', 'r', 'e', 'd', 'P', 'r', 'o', 0}, {0, 0} };
  LUID authid = SYSTEM_LUID;
  DWORD i, x, y;
  long ntStatus = -1;

  user.User.Attributes = 0;
  user.User.Sid = &sid_system;
  owner.Owner = &sid_system;
  li.LowPart = 0xFFFFFFFF;
  li.HighPart = 0xFFFFFFFF;
  AllocateLocallyUniqueId(&luid);
  source.SourceIdentifier.LowPart = luid.LowPart;
  source.SourceIdentifier.HighPart = luid.HighPart;
  stats = (PTOKEN_STATISTICS)GetInfoFromToken(base_token, TokenStatistics, verbosity);
  if (stats) {
    groups = (PTOKEN_GROUPS)GetInfoFromToken(base_token, TokenGroups, verbosity);
    if (groups) {
      primary_group = (PTOKEN_PRIMARY_GROUP)GetInfoFromToken(base_token, TokenPrimaryGroup, verbosity);
      if(primary_group) {
        default_dacl = (PTOKEN_DEFAULT_DACL)GetInfoFromToken(base_token, TokenDefaultDacl, verbosity);
        if (default_dacl) {
          BYTE* grpCopy = MemAlloc(LPTR, groups->GroupCount);

          DWORD grpCount = tkg_good.GroupCount + tkg_xtra.GroupCount;
          for (i = 0, y = 0; i < tkg_xtra.GroupCount; i++) {
            if (IsGroupSid(tkg_xtra.Groups[i].Sid, verbosity)) y |= (1 << i);
            else grpCount--;
          }
          for (i = 0; i < groups->GroupCount; i++) {
            for (x = 0; x < tkg_good.GroupCount; x++) {
              if (EqualSid(groups->Groups[i].Sid, tkg_good.Groups[x].Sid)) break;
            }
            if (x == tkg_good.GroupCount) {
              for (x = 0; x < tkg_xtra.GroupCount; x++) {
                if (((y >> x) & 1) && EqualSid(groups->Groups[i].Sid, tkg_xtra.Groups[x].Sid)) break;
              }
              if (x == tkg_xtra.GroupCount) {
                grpCopy[i] = 1;
                grpCount++;
              }
            }
          }
          groups2 = (PTOKEN_GROUPS)MemAlloc(LPTR, 4 + sizeof(SID_AND_ATTRIBUTES) * grpCount);
          __movsb((unsigned char*)groups2, (unsigned const char*)&tkg_good, sizeof(tkg_good));
          groups2->GroupCount = grpCount;
          for (i = 0, x = tkg_good.GroupCount; i < tkg_xtra.GroupCount; i++) {
            if ((y >> i) & 1)
              __movsb((unsigned char*)&groups2->Groups[x++], (unsigned const char*)&tkg_xtra.Groups[i], sizeof(SID_AND_ATTRIBUTES));
          }
          for (i = 0; i < groups->GroupCount; i++) {
            if (grpCopy[i]) {
              PSID_AND_ATTRIBUTES grp = &groups2->Groups[--grpCount];
              grp->Sid = groups->Groups[i].Sid;
              grp->Attributes = groups->Groups[i].Attributes;
              grp->Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
              // if(IsGroupSid(grp->Sid))
              if (((PISID)(grp->Sid))->IdentifierAuthority.Value[5] <= 5) // SECURITY_NT_AUTHORITY
                grp->Attributes |= SE_GROUP_ENABLED;
            }
          }

          ntStatus = ZwCreateToken(&user_token, TOKEN_ALL_ACCESS, &oa, TokenImpersonation, &authid, &li, &user, groups2,
            (PTOKEN_PRIVILEGES)&tkp_all, &owner, primary_group, default_dacl, &source);

          LocalFree(groups2);
          LocalFree(grpCopy);
          LocalFree(default_dacl);
          if (ntStatus && verbosity > 0)
            fmt_error("[!] ntdll:ZwCreateToken() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)ntStatus, (DWORD_PTR)"");
        }
        LocalFree(primary_group);
      }
      LocalFree(groups);
    }
    LocalFree(stats);
  }
  return ((ntStatus == 0) ? user_token : NULL);
}

__forceinline static BOOL DoStartSvc(int verbosity) {
  SC_HANDLE schSCManager;
  SC_HANDLE schService;
  SERVICE_STATUS_PROCESS ssStatus;
  DWORD dwOldCheckPoint;
  DWORD dwStartTickCount;
  DWORD dwWaitTime;
  DWORD dwBytesNeeded;
  DWORD dwErr;

  if (verbosity == 2) perr("[+] Starting TrustedInstaller service...\r\n");

  schSCManager = OpenSCManagerA(NULL, NULL, GENERIC_EXECUTE);
  if (!schSCManager) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:OpenSCManagerA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    return FALSE;
  }

  schService = OpenServiceA(schSCManager, "TrustedInstaller", GENERIC_READ | GENERIC_EXECUTE);
  if (!schService) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:OpenServiceA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    CloseServiceHandle(schSCManager);
    return FALSE;
  }

  if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:QueryServiceStatusEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return FALSE;
  }

  if(ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING) {
    // Already running
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return TRUE;
  }

  dwStartTickCount = GetTickCount();
  dwOldCheckPoint = ssStatus.dwCheckPoint;

  while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING) {
    dwWaitTime = ssStatus.dwWaitHint / 10;
    if(dwWaitTime < 1000)
      dwWaitTime = 1000;
    else if (dwWaitTime > 10000)
      dwWaitTime = 10000;

    Sleep(dwWaitTime);

    if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] advapi32:QueryServiceStatusEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      }
      CloseServiceHandle(schService);
      CloseServiceHandle(schSCManager);
      return FALSE;
    }

    if (ssStatus.dwCheckPoint > dwOldCheckPoint) {
      dwStartTickCount = GetTickCount();
      dwOldCheckPoint = ssStatus.dwCheckPoint;
    } else if(GetTickCount()-dwStartTickCount > ssStatus.dwWaitHint) {
      if (verbosity > 0) {
        perr("[!] TrustedInstaller service timeout\r\n");
      }
      CloseServiceHandle(schService);
      CloseServiceHandle(schSCManager);
      return FALSE;
    }
  }

  if (!StartServiceA(schService, 0, NULL)) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:StartServiceA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return FALSE;
  }

  if (!QueryServiceStatusEx(schService,SC_STATUS_PROCESS_INFO,(LPBYTE) &ssStatus,sizeof(SERVICE_STATUS_PROCESS),&dwBytesNeeded)) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:QueryServiceStatusEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return FALSE;
  }

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);
  return (ssStatus.dwCurrentState == SERVICE_RUNNING || ssStatus.dwCurrentState == SERVICE_START_PENDING);
}

static DWORD RunAs(wchar_t* buf, DWORD pid, int verbosity) {
  SHELLEXECUTEINFOW ShExecInfo;
  DWORD dwErr;
  DWORD exit_code = 0;
  wchar_t abc[64];
  DWORD ppid;

  dwErr = GetModuleFileNameW(0, buf, 2048);
  if (!dwErr || dwErr == 2048) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] kernel32:GetModuleFileNameW() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      perr("[!] Could not create elevated process. Exiting...\r\n");
    }
    return -1;
  }

  ppid = GetCurrentProcessId();
  wchar_t* s = abc;
  *s++ = L'@';
  *s++ = L'!';
  *s++ = L'@';
  *s++ = L'|';
  __ultow(ppid, s);
  while (*s >= L'0' && *s <= L'9') s++;
  *s++ = L'|';
  __ultow(pid, s);
  while (*s >= L'0' && *s <= L'9') s++;
  *s++ = L'|';
  __ultow(flags.u, s);

  __stosb((PBYTE)&ShExecInfo, 0, sizeof(SHELLEXECUTEINFOW));
  ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
  ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_UNICODE | SEE_MASK_NO_CONSOLE | SEE_MASK_NOASYNC;
  ShExecInfo.hwnd = NULL;
  ShExecInfo.lpVerb = L"runas";
  ShExecInfo.lpFile = buf;
  ShExecInfo.lpParameters = abc;
  ShExecInfo.lpDirectory = NULL;
  ShExecInfo.nShow = SW_HIDE;
  ShExecInfo.hInstApp = NULL;
  if (!ShellExecuteExW(&ShExecInfo)) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] shell32:ShellExecuteExW() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      perr("[!] Could not create elevated process. Exiting...\r\n");
    }
    return -1;
  }
  WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
  GetExitCodeProcess(ShExecInfo.hProcess, &exit_code);
  CloseHandle(ShExecInfo.hProcess);
  return exit_code;
}

__forceinline static DWORD OSMajorVersion(void) {
  OSVERSIONINFOW info;
  __stosb((PBYTE)&info, 0, sizeof(OSVERSIONINFOW));
  info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
  RtlGetVersion(&info);
  return info.dwMajorVersion;
}

#ifndef _WIN64
__forceinline static BOOL Is64BitOS(void) {
  void* fnIsWow64Process;
  BOOL bIsWow64 = FALSE;
  HMODULE k32 = GetModuleHandleA("kernel32.dll");
  if (!k32) return FALSE;
  fnIsWow64Process = GetProcAddress(k32, "IsWow64Process");
  if (!fnIsWow64Process) return FALSE;
  if (!((BOOL (__stdcall *)(HANDLE,PBOOL)) (void*)(fnIsWow64Process))((HANDLE)-1, &bIsWow64)) return FALSE;
  return bIsWow64;
}
#endif // !_WIN64

int main(void) {
  HANDLE hToken = NULL;
  HANDLE hNewToken = NULL;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  PROCESS_ACCESS_TOKEN tokenInfo;
  DWORD dwErr;
  wchar_t *cmdline = NULL;
  wchar_t *s = NULL;
  DWORD exit_code = 0;
  int verbosity = -1;
  BOOL new = FALSE;
  BOOL do_test = FALSE;
  BOOL wait = FALSE;
  BOOL nochange = FALSE;
  BOOL hide = FALSE;
  DWORD dirlen = 0;
  int w = 0, h = 0, cols = 0, rows = 0;
  wchar_t buf[2048];
  DWORD dwFlags = CREATE_SUSPENDED;
  BOOL runas = FALSE;
  BOOL bSuccess = FALSE;
  DWORD i;

  __stosb((PBYTE)&si, 0, sizeof(STARTUPINFOW));
  __stosb((PBYTE)&pi, 0, sizeof(PROCESS_INFORMATION));
  si.cb = sizeof(STARTUPINFOW);
  tokenInfo.Token = 0;
  tokenInfo.Thread = 0;
  flags.f.access = 1;

#ifndef _WIN64
  if (Is64BitOS()) {
    perr("[!] Processor architecture mismatch; sudo=x86, OS=x64\r\n\r\n");
    perr("Please use the 64-bit build for 64-bit OS.\r\n");
    ExitProcess(-2);
  }
#endif // !_WIN64

  if (OSMajorVersion() < 10)
    tkp_all.PrivilegeCount = 34;

  dirlen = GetCurrentDirectoryW(0,0);
  if (!dirlen) {
    nochange = TRUE;
  }

  s = GetCommandLineW();
  if (s && *s) {
    if (*s == L'"') {
      ++s;
      while (*s)
        if (*s++ == L'"')
          break;
    } else {
      while (*s && *s != L' ' && *s != L'\t')
        ++s;
    }
    while (*s == L' ' || *s == L'\t')
      s++;

    if (*s == L'@' && *(s+1) == L'!' && *(s+2) == L'@' && *(s+3) == L'|') {
      s += 4;
      ppid = __wtoul(s);
      while (*s >= L'0' && *s <= L'9') s++;
      if (*s++ != L'|') ExitProcess(-1);
      cpid = __wtoul(s);
      while (*s >= L'0' && *s <= L'9') s++;
      if (*s++ != L'|') ExitProcess(-1);
      flags.u = __wtoul(s);
      verbosity = flags.f.verbosity;
    }

    while (*s == L'-' || *s == L'/') {
      wchar_t* s2 = s;
      s++;
      if (*s == L'-' || *s == L'/') {
        s++;
      }
      if (*s == 0) {
        break;
      } else if (*s == L' ') {
        while (*s == L' ' || *s == L'\t') s++;
        break;
      } else if ((*s == L'?') ||
        ((*s == L'h' || *s == L'H') && (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-' ||
        ((*(s+1) == L'E' || *(s+1) == L'e') && (*(s+2) == L'L' || *(s+2) == L'l') && (*(s+3) == L'P' || *(s+3) == L'p')))) ||
        ((*s == L'V' || *s == L'v') &&
        (*(s+1) == L'E' || *(s+1) == L'e') &&
        (*(s+2) == L'R' || *(s+2) == L'r') &&
        (*(s+3) == L'\0' || *(s+3) == L' ' || *(s+3) == L'\t' || *(s+3) == L'/' || *(s+3) == L'-') ||
        ((*(s+3) == L'S' || *(s+3) == L's') &&
        (*(s+4) == L'I' || *(s+4) == L'i') &&
        (*(s+5) == L'O' || *(s+5) == L'o') &&
        (*(s+6) == L'N' || *(s+6) == L'n')))) {
        print("winsudo " VERSION_STR "\r\n"
              "Usage: sudo [OPTION] [COMMAND]\r\n\r\n"
              "  -a, --admin               run as Administrator\r\n"
              "  -t, --trustedinstaller    run as TrustedInstaller\r\n"
              "  -n, --new                 run in a new window\r\n"
              "  -w, --wait                wait for process to exit\r\n"
              "  -z, --hide                hide process window\r\n"
              "  -d, --nocd                do not change directory\r\n"
              "  -k, --notoken             do not use all-access token\r\n"
              "  -p, --nopriv              do not enable all privileges\r\n"
              "  -s, --silent              silent output\r\n"
              "  -v, --verbose             verbose output\r\n"
              "      --test                test privileges\r\n\r\n"
              "By default, run as SYSTEM user\r\n");
        ExitProcess(0);
      } else if ((*s == L'T' || *s == L't') &&
        (*(s+1) == L'E' || *(s+1) == L'e') &&
        (*(s+2) == L'S' || *(s+2) == L's') &&
        (*(s+3) == L'T' || *(s+3) == L't') &&
        (*(s+4) == L'\0' || *(s+4) == L' ' || *(s+4) == L'\t' || *(s+4) == L'/' || *(s+4) == L'-')) {
        s += 4;
        do_test = TRUE;
      } else if ((*s == L'S' || *s == L's') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        verbosity = 0;
      } else if ((*s == L'S' || *s == L's') &&
        (*(s+1) == L'I' || *(s+1) == L'i') &&
        (*(s+2) == L'L' || *(s+2) == L'l') &&
        (*(s+3) == L'E' || *(s+3) == L'e') &&
        (*(s+4) == L'N' || *(s+4) == L'n') &&
        (*(s+5) == L'T' || *(s+5) == L't') &&
        (*(s+6) == L'\0' || *(s+6) == L' ' || *(s+6) == L'\t' || *(s+6) == L'/' || *(s+6) == L'-')) {
        s += 6;
        verbosity = 0;
      } else if ((*s == L'V' || *s == L'v') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        verbosity = 2;
      } else if ((*s == L'V' || *s == L'v') &&
        (*(s+1) == L'E' || *(s+1) == L'e') &&
        (*(s+2) == L'R' || *(s+2) == L'r') &&
        (*(s+3) == L'B' || *(s+3) == L'b') &&
        (*(s+4) == L'O' || *(s+4) == L'o') &&
        (*(s+5) == L'S' || *(s+5) == L's') &&
        (*(s+6) == L'E' || *(s+6) == L'e') &&
        (*(s+7) == L'\0' || *(s+7) == L' ' || *(s+7) == L'\t' || *(s+7) == L'/' || *(s+7) == L'-')) {
        s += 7;
        verbosity = 2;
      } else if ((*s == L'W' || *s == L'w') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        wait = TRUE;
      } else if ((*s == L'W' || *s == L'w') &&
        (*(s+1) == L'A' || *(s+1) == L'a') &&
        (*(s+2) == L'I' || *(s+2) == L'i') &&
        (*(s+3) == L'T' || *(s+3) == L't') &&
        (*(s+4) == L'\0' || *(s+4) == L' ' || *(s+4) == L'\t' || *(s+4) == L'/' || *(s+4) == L'-')) {
        s += 4;
        wait = TRUE;
      } else if ((*s == L'D' || *s == L'd') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        nochange = TRUE;
      } else if ((*s == L'N' || *s == L'n') &&
        (*(s+1) == L'O' || *(s+1) == L'o') &&
        (*(s+2) == L'C' || *(s+2) == L'c') &&
        (*(s+3) == L'D' || *(s+3) == L'd') &&
        (*(s+4) == L'\0' || *(s+4) == L' ' || *(s+4) == L'\t' || *(s+4) == L'/' || *(s+4) == L'-')) {
        s += 4;
        nochange = TRUE;
      } else if ((*s == L'Z' || *s == L'z') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        hide = TRUE;
      } else if ((*s == L'H' || *s == L'h') &&
        (*(s+1) == L'I' || *(s+1) == L'i') &&
        (*(s+2) == L'D' || *(s+2) == L'd') &&
        (*(s+3) == L'E' || *(s+3) == L'e') &&
        (*(s+4) == L'\0' || *(s+4) == L' ' || *(s+4) == L'\t' || *(s+4) == L'/' || *(s+4) == L'-')) {
        s += 4;
        hide = TRUE;
      } else if ((*s == L'N' || *s == L'n') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        new = TRUE;
      } else if ((*s == L'N' || *s == L'n') &&
        (*(s+1) == L'E' || *(s+1) == L'e') &&
        (*(s+2) == L'W' || *(s+2) == L'w') &&
        (*(s+3) == L'\0' || *(s+3) == L' ' || *(s+3) == L'\t' || *(s+3) == L'/' || *(s+3) == L'-')) {
        s += 3;
        new = TRUE;
      } else if ((*s == L'T' || *s == L't') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        flags.f.access = 2;
      } else if ((*s == L'T' || *s == L't') &&
        (*(s+1) == L'I' || *(s+1) == L'i') &&
        (*(s+2) == L'\0' || *(s+2) == L' ' || *(s+2) == L'\t' || *(s+2) == L'/' || *(s+2) == L'-')) {
        s += 2;
        flags.f.access = 2;
      } else if ((*s == L'T' || *s == L't') &&
        (*(s+1) == L'R' || *(s+1) == L'r') &&
        (*(s+2) == L'U' || *(s+2) == L'u') &&
        (*(s+3) == L'S' || *(s+3) == L's') &&
        (*(s+4) == L'T' || *(s+4) == L't') &&
        (*(s+5) == L'E' || *(s+5) == L'e') &&
        (*(s+6) == L'D' || *(s+6) == L'd') &&
        (*(s+7) == L'I' || *(s+7) == L'i') &&
        (*(s+8) == L'N' || *(s+8) == L'n') &&
        (*(s+9) == L'S' || *(s+9) == L's') &&
        (*(s+10) == L'T' || *(s+10) == L't') &&
        (*(s+11) == L'A' || *(s+11) == L'a') &&
        (*(s+12) == L'L' || *(s+12) == L'l') &&
        (*(s+13) == L'L' || *(s+13) == L'l') &&
        (*(s+14) == L'E' || *(s+14) == L'e') &&
        (*(s+15) == L'R' || *(s+15) == L'r') &&
        (*(s+16) == L'\0' || *(s+16) == L' ' || *(s+16) == L'\t' || *(s+16) == L'/' || *(s+16) == L'-')) {
        s += 16;
        flags.f.access = 2;
      } else if ((*s == L'P' || *s == L'p') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        flags.f.nopriv = TRUE;
      } else if ((*s == L'N' || *s == L'n') &&
        (*(s+1) == L'O' || *(s+1) == L'o') &&
        (*(s+2) == L'P' || *(s+2) == L'p') &&
        (*(s+3) == L'R' || *(s+3) == L'r') &&
        (*(s+4) == L'I' || *(s+4) == L'i') &&
        (*(s+5) == L'V' || *(s+5) == L'v') &&
        (*(s+6) == L'\0' || *(s+6) == L' ' || *(s+6) == L'\t' || *(s+6) == L'/' || *(s+6) == L'-')) {
        s += 6;
        flags.f.nopriv = TRUE;
      } else if ((*s == L'A' || *s == L'a') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        flags.f.access = 0;
      } else if ((*s == L'A' || *s == L'a') &&
        (*(s+1) == L'D' || *(s+1) == L'd') &&
        (*(s+2) == L'M' || *(s+2) == L'm') &&
        (*(s+3) == L'I' || *(s+3) == L'i') &&
        (*(s+4) == L'N' || *(s+4) == L'n') &&
        (*(s+5) == L'\0' || *(s+5) == L' ' || *(s+5) == L'\t' || *(s+5) == L'/' || *(s+5) == L'-')) {
        s += 5;
        flags.f.access = 0;
      } else if ((*s == L'A' || *s == L'a') &&
        (*(s+1) == L'D' || *(s+1) == L'd') &&
        (*(s+2) == L'M' || *(s+2) == L'm') &&
        (*(s+3) == L'I' || *(s+3) == L'i') &&
        (*(s+4) == L'N' || *(s+4) == L'n') &&
        (*(s+5) == L'I' || *(s+5) == L'i') &&
        (*(s+6) == L'S' || *(s+6) == L's') &&
        (*(s+7) == L'T' || *(s+7) == L't') &&
        (*(s+8) == L'R' || *(s+8) == L'r') &&
        (*(s+9) == L'A' || *(s+9) == L'a') &&
        (*(s+10) == L'T' || *(s+10) == L't') &&
        (*(s+11) == L'O' || *(s+11) == L'o') &&
        (*(s+12) == L'R' || *(s+12) == L'r') &&
        (*(s+13) == L'\0' || *(s+13) == L' ' || *(s+13) == L'\t' || *(s+13) == L'/' || *(s+13) == L'-')) {
        s += 13;
        flags.f.access = 0;
      } else if ((*s == L'K' || *s == L'k') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        flags.f.notoken = TRUE;
      } else if ((*s == L'N' || *s == L'n') &&
        (*(s+1) == L'O' || *(s+1) == L'o') &&
        (*(s+2) == L'T' || *(s+2) == L't') &&
        (*(s+3) == L'O' || *(s+3) == L'o') &&
        (*(s+4) == L'K' || *(s+4) == L'k') &&
        (*(s+5) == L'E' || *(s+5) == L'e') &&
        (*(s+6) == L'N' || *(s+6) == L'n') &&
        (*(s+7) == L'\0' || *(s+7) == L' ' || *(s+7) == L'\t' || *(s+7) == L'/' || *(s+7) == L'-')) {
        s += 7;
        flags.f.notoken = TRUE;
      } else if ((*s == L'S' || *s == L's') &&
        (*(s+1) == L'Y' || *(s+1) == L'y') &&
        (*(s+2) == L'S' || *(s+2) == L's') &&
        (*(s+3) == L'T' || *(s+3) == L't') &&
        (*(s+4) == L'E' || *(s+4) == L'e') &&
        (*(s+5) == L'M' || *(s+5) == L'm') &&
        (*(s+6) == L'\0' || *(s+6) == L' ' || *(s+5) == L'\t' || *(s+5) == L'/' || *(s+5) == L'-')) {
        s += 6;
        flags.f.access = 1;
      } else {
        while (*s && *s != L' ' && *s != L'\t') ++s;
        fmt_error("unknown command line option: '%1!.*ws!'\r\n", (DWORD_PTR)(s-s2), (DWORD_PTR)s2);
        ExitProcess(-2);
      }
      while (*s == L' ' || *s == L'\t')
        ++s;
    }

    if (do_test) {
      BOOL isSystem, isTI, isAdmin;
      if (verbosity == -1) verbosity = 1;
      isAdmin = IsAdminToken(0, verbosity);
      isSystem = IsSystemToken(0, verbosity);
      isTI = IsTIToken(0, verbosity);
      if (verbosity > 0) {
        print("Is Administrator    ? ");
        print(isAdmin ? "YES\r\n" : "NO\r\n");
        print("Is SYSTEM           ? ");
        print(isSystem ? "YES\r\n" : "NO\r\n");
        print("Is TrustedInstaller ? ");
        print(isTI ? "YES\r\n" : "NO\r\n");
      }
      ExitProcess(flags.f.access > 0 ? (flags.f.access == 1 ? !isSystem : !isTI) : !isAdmin);
    }
  }

  if (!ppid) {
    if (s && *s) {
      if (nochange) {
       cmdline = (wchar_t*)MemAlloc(LMEM_FIXED, (wcslen(s)+16)*sizeof(wchar_t));
       wcscpy(cmdline, L"/d/x/s/v:off/r ");
      } else {
        cmdline = (wchar_t*)MemAlloc(LMEM_FIXED, (wcslen(s)+dirlen+27)*sizeof(wchar_t));
        wcscpy(cmdline, L"/d/x/s/v:off/r pushd \"");
        GetCurrentDirectoryW(dirlen, cmdline+22);
        wcscat(cmdline, L"\" & ");
      }
      wcscat(cmdline, s);
      if (verbosity == -1) verbosity = 1;
      if (!new) {
        wait = TRUE;
        hide = FALSE;
      }
    } else {
      if (!nochange) {
        cmdline = (wchar_t*)MemAlloc(LMEM_FIXED, (wcslen(s)+dirlen+24)*sizeof(wchar_t));
        wcscpy(cmdline, L"/d/x/s/v:off/k pushd \"");
        GetCurrentDirectoryW(dirlen, cmdline+22);
        wcscat(cmdline, L"\"");
      }
      if (verbosity == -1) verbosity = 2;
      hide = FALSE;
      new = TRUE;
    }
    flags.f.verbosity = verbosity;
    if (verbosity == 2) {
      perr("[+] Run As: ");
      if (flags.f.access == 2) {
        perr("TrustedInstaller\r\n");
      } else if (flags.f.access == 1) {
        perr("SYSTEM\r\n");
      } else {
        perr("Administrator\r\n");
      }
    }
  }

  if (!IsSystemToken(0, verbosity) && !IsAdminToken(0, verbosity)) {
    if (!ppid) {
      runas = TRUE;
      if (verbosity == 2) perr("[+] Requesting administrator privileges...\r\n");
    } else {
      if (verbosity > 0) perr("[!] Could not acquire administrator privileges. Exiting...\r\n");
      ExitProcess(-1);
    }
  } else if (ppid && verbosity == 2) {
    perr("[+] Administrator privileges acquired\r\n");
  }

  if (!runas && (flags.f.access > 0 || ppid)) {
    if (!EnableImpersonatePriv(verbosity)) {
      if (verbosity > 0) perr("[!] Could not acquire impersonation privileges. Exiting...\r\n");
      if (cmdline) LocalFree(cmdline);
      ExitProcess(-1);
    }
    if (verbosity == 2) perr("[+] Impersonation privileges acquired\r\n");

    for (i = 0; i < countof(sysProcs); i++) {
      if (GetDupToken(sysProcs[i], &hToken, &hNewToken, verbosity)) {
        if (IsSystemToken(hNewToken, verbosity)) break;
        if (verbosity == 2) perr("[!] Not a SYSTEM token\r\n");
        CloseHandle(hNewToken); hNewToken = NULL;
        CloseHandle(hToken); hToken = NULL;
      }
    }

    if (i == countof(sysProcs)) {
      if (verbosity > 0) perr("[!] Failed to acquire SYSTEM token. Exiting...\r\n");
      if (cmdline) LocalFree(cmdline);
      ExitProcess(-1);
    }

    bSuccess = FALSE;
    if (!AdjustTokenPrivileges(hNewToken, FALSE, (TOKEN_PRIVILEGES*)&tkp_assign, 0, NULL, NULL)) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:AdjustTokenPrivileges() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      CloseHandle(hNewToken); hNewToken = NULL;
      CloseHandle(hToken); hToken = NULL;
    } else if (!ImpersonateLoggedOnUser(hNewToken)) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:ImpersonateLoggedOnUser() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      CloseHandle(hNewToken); hNewToken = NULL;
      CloseHandle(hToken); hToken = NULL;
    } else if (flags.f.access > 0) {
      if (flags.f.access != 2) bSuccess = TRUE;
      if (!flags.f.notoken) {
        HANDLE hUserToken = CreateUserToken(hNewToken, verbosity);
        if (hUserToken) {
          bSuccess = TRUE;
          if (verbosity == 2) perr("[+] All-access token created\r\n");
          CloseHandle(hToken);
          hToken = hUserToken;
        } else if (verbosity > 0) {
          perr("[!] Could not create all-access token\r\n");
          if (verbosity == 2) {
            perr("[+] Falling back to ");
            perr((flags.f.access == 2) ? "TrustedInstaller" : "SYSTEM");
            perr(" token...\r\n");
          }
        }
      }
      CloseHandle(hNewToken); hNewToken = NULL;
      if (!bSuccess && flags.f.access == 2) {
        CloseHandle(hToken); hToken = NULL;
        if (!GetPIDForProcess("trustedinstaller.exe")) {
          if (DoStartSvc(verbosity)) {
            for (i = 0; i < 500; i++) {
              if (GetPIDForProcess("trustedinstaller.exe")) break;
              Sleep(10);
            }
          }
        }
        if (GetDupToken("trustedinstaller.exe", &hToken, &hNewToken, (verbosity == 1 ? 3 : verbosity))) {
          bSuccess = IsTIToken(hNewToken, verbosity);
          if (!bSuccess && verbosity == 2) perr("[!] Not a TrustedInstaller token\r\n");
          CloseHandle(hNewToken); hNewToken = NULL;
        }
      }
    } else {
      CloseHandle(hNewToken); hNewToken = NULL;
      CloseHandle(hToken);
      bSuccess = OpenProcessToken((HANDLE)-1, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);
      if (verbosity > 0 && !bSuccess) {
        dwErr = GetLastError();
        fmt_error("[!] advapi32:OpenProcessToken() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      }
    }

    if (!bSuccess) {
      if (verbosity > 0) perr("[!] Failed to acquire elevation token. Exiting...\r\n");
      if (cmdline) LocalFree(cmdline);
      ExitProcess(-1);
    }

    if(!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] advapi32:DuplicateTokenEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        perr("[!] Failed to duplicate access token. Exiting...\r\n");
      }
      if (cmdline) LocalFree(cmdline);
      CloseHandle(hToken); hToken = NULL;
      ExitProcess(-1);
    }
    if (verbosity == 2) perr("[+] Access token duplicated\r\n");

    tokenInfo.Token = hNewToken;
  }

  if (!runas && !flags.f.nopriv) {
    if (flags.f.access == 0 && !ppid) {
      if (!OpenProcessToken((HANDLE)-1, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hNewToken)) {
        if (verbosity > 0)  {
          dwErr = GetLastError();
          fmt_error("[!] advapi32:OpenProcessToken() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        }
        hNewToken = NULL;
      }
    }
    if (!hNewToken || !EnableAllPriv(hNewToken, verbosity)) {
      if (verbosity > 0) perr("[!] Could not enable all privileges\r\n");
    } else if (verbosity == 2) {
      perr("[+] All privileges enabled\r\n");
    }
    if (flags.f.access == 0 && hNewToken && !ppid) {
      CloseHandle(hNewToken); hNewToken = NULL;
    }
  }

  if (!runas && verbosity == 2) perr("[+] Spawning ComSpec...\r\n");

  if (ppid) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, cpid);
    if (hProc) {
      dwErr = NtSetInformationProcess(hProc, 9, &tokenInfo, sizeof(PROCESS_ACCESS_TOKEN));
      CloseHandle(hProc);
      if (dwErr) {
        exit_code = -1;
        if (verbosity > 0) fmt_error("[!] ntdll:NtSetInformationProcess() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      }
    } else if (verbosity > 0)  {
      exit_code = -1;
      dwErr = GetLastError();
      fmt_error("[!] kernel32:OpenProcess() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
  } else {
    if (hide) {
      dwFlags |= CREATE_NO_WINDOW;
      si.dwFlags = STARTF_USESHOWWINDOW;
      si.wShowWindow = SW_HIDE;
    } else {
      if (new) dwFlags |= CREATE_NEW_CONSOLE;
      si.dwFlags = STARTF_USECOUNTCHARS;
      if (GetWindowSize(&w, &h) && GetConsoleBufferSize(&cols, &rows)) {
        si.dwFlags |= STARTF_USESIZE;
        si.dwXSize = w;
        si.dwYSize = h;
        si.dwXCountChars = cols;
        si.dwYCountChars = rows;
     } else {
        si.dwXCountChars = 80;
        si.dwYCountChars = 300;
      }
    }
    bSuccess = CreateProcessW((ReadEnvironmentVariable(L"ComSpec", buf, 2048) ? buf : L"cmd.exe"), cmdline ? cmdline : L"/d/x/v:off", NULL, NULL, TRUE, dwFlags, NULL, NULL, &si, &pi);
    if (!bSuccess) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] kernel32:CreateProcessW() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        perr("[!] Could not create elevated process. Exiting...\r\n");
      }
    } else {
      if (runas) {
        bSuccess = !RunAs(buf, pi.dwProcessId, verbosity);
      } else if (flags.f.access > 0) {
        dwErr = NtSetInformationProcess(pi.hProcess, 9, &tokenInfo, sizeof(PROCESS_ACCESS_TOKEN));
        if (dwErr && verbosity > 0) {
          fmt_error("[!] ntdll:NtSetInformationProcess() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
          perr("[!] Could not create elevated process. Exiting...\r\n");
        }
        bSuccess = !dwErr;
      }
      if (!bSuccess) {
        TerminateProcess(pi.hProcess, (DWORD)-1);
      } else {
        if (verbosity == 2) perr("[+] Success\r\n");
        ResumeThread(pi.hThread);
        if (wait) {
          WaitForSingleObject(pi.hProcess, INFINITE);
          GetExitCodeProcess(pi.hProcess, &exit_code);
        }
      }
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
    }
    if (!bSuccess) {
      exit_code = -1;
    }
    if (cmdline) LocalFree(cmdline);
  }
  if (!runas && (flags.f.access > 0 || ppid)) {
    CloseHandle(hToken);
    CloseHandle(hNewToken);
  }
  ExitProcess(exit_code);
}
