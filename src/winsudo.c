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
#pragma intrinsic (strlen, wcslen, wcscpy, wcscat)

#define countof(x) (sizeof(x)/sizeof(x[0]))

#ifndef VERSION_STR
#error VERSION_STR undefined
#endif

static HANDLE g_hStdOut = 0;
static HANDLE g_hStdErr = 0;

static const char* allPriv[] = {
  "SeAssignPrimaryTokenPrivilege",
  "SeAuditPrivilege",
  "SeBackupPrivilege",
  "SeChangeNotifyPrivilege",
  "SeCreateGlobalPrivilege",
  "SeCreatePagefilePrivilege",
  "SeCreatePermanentPrivilege",
  "SeCreateSymbolicLinkPrivilege",
  "SeCreateTokenPrivilege",
  "SeDebugPrivilege",
  "SeDelegateSessionUserImpersonatePrivilege",
  "SeEnableDelegationPrivilege",
  "SeImpersonatePrivilege",
  "SeIncreaseBasePriorityPrivilege",
  "SeIncreaseQuotaPrivilege",
  "SeIncreaseWorkingSetPrivilege",
  "SeLoadDriverPrivilege",
  "SeLockMemoryPrivilege",
  "SeMachineAccountPrivilege",
  "SeManageVolumePrivilege",
  "SeProfileSingleProcessPrivilege",
  "SeRelabelPrivilege",
  "SeRemoteShutdownPrivilege",
  "SeRestorePrivilege",
  "SeSecurityPrivilege",
  "SeShutdownPrivilege",
  "SeSyncAgentPrivilege",
  "SeSystemEnvironmentPrivilege",
  "SeSystemProfilePrivilege",
  "SeSystemtimePrivilege",
  "SeTakeOwnershipPrivilege",
  "SeTcbPrivilege",
  "SeTimeZonePrivilege",
  "SeTrustedCredManAccessPrivilege",
  "SeUndockPrivilege"
};

static const char* sysProcs[] = {
  "winlogon.exe",
  "lsass.exe",
  "lsm.exe",
  "wininit.exe",
  "smss.exe",
  "csrss.exe",
  "services.exe",
  "wmiprvse.exe",
  "trustedinstaller.exe",
  "logonui.exe"
};

static DWORD sid_admin[] = {2, 32, 544, 0, 0, 0, 0};
static DWORD sid_system[] = {1, 18, 0, 0, 0, 0, 0};
static DWORD sid_ti[] = {6, 80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464};

struct token_privileges {
  DWORD PrivilegeCount;
  LUID_AND_ATTRIBUTES Privileges[countof(allPriv)];
} tkp;

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

__forceinline static char* __ultoa(unsigned long value, char* string) {
  char buf[11];
  char* pos;
  if (!string) return 0;
  pos = buf + 10;
  *pos = 0;
  do {
    *--pos = 48 + (value % 10);
  } while (value /= 10);
  __movsb((unsigned char*)string, (unsigned const char*)pos, (buf - pos + 11) * sizeof(char));
  return string;
}

__forceinline static void _ioprint(HANDLE std_handle, const char* cbuf) {
  DWORD u = 0;
  WriteFile(std_handle, cbuf, (DWORD)strlen(cbuf), &u, 0);
}

__forceinline static void print(const char* cbuf) {
  _ioprint(g_hStdOut, cbuf);
}

__forceinline static void perr(const char* cbuf) {
  _ioprint(g_hStdErr, cbuf);
}

__forceinline static void _fmt_ioprint(HANDLE std_handle, const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2) {
  char* fmt_str = 0;
  DWORD_PTR pArgs[] = { (DWORD_PTR)arg1, (DWORD_PTR)arg2 };
  if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, fmt, 0, 0, (LPSTR)&fmt_str, 0, (va_list*)pArgs)) {
    _ioprint(std_handle, fmt_str);
    LocalFree(fmt_str);
  }
}

__forceinline static void fmt_print(const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2) {
  _fmt_ioprint(g_hStdOut, fmt, arg1, arg2);
}

__forceinline static void fmt_error(const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2) {
  _fmt_ioprint(g_hStdErr, fmt, arg1, arg2);
}

__forceinline static BOOL ReadEnvironmentVariable(const wchar_t* pszName, wchar_t* pszBuffer, DWORD cchBuffer) {
  DWORD cchCopied = GetEnvironmentVariableW(pszName, pszBuffer, cchBuffer);
  return(cchCopied && cchCopied < cchBuffer);
}

__forceinline static BOOL EnableImpersonatePriv(int verbosity) {
  HANDLE hToken;
  DWORD dwErr;

  __stosb((PBYTE)&tkp, 0, sizeof(struct token_privileges));
  tkp.PrivilegeCount = 2;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  tkp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

  if (!OpenProcessToken((HANDLE)-1, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
    if (verbosity > 0)  {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:OpenProcessToken() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    return FALSE;
  }

  if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tkp.Privileges[0].Luid) || !LookupPrivilegeValueA(NULL, "SeImpersonatePrivilege", &tkp.Privileges[1].Luid)) {
    if (verbosity > 0)  {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:LookupPrivilegeValueA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
    CloseHandle(hToken);
    return FALSE;
  }

  AdjustTokenPrivileges(hToken, FALSE, (TOKEN_PRIVILEGES*)&tkp, 0, NULL, NULL);
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
  unsigned int i;

  __stosb((PBYTE)&tkp, 0, sizeof(struct token_privileges));
  for (i = 0; i < countof(allPriv); i++) {
    tkp.Privileges[tkp.PrivilegeCount].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueA(NULL, allPriv[i], &tkp.Privileges[tkp.PrivilegeCount].Luid)) {
      dwErr = GetLastError();
      if (dwErr != ERROR_NO_SUCH_PRIVILEGE) {
        if (verbosity > 0)
          fmt_error("[!] advapi32:LookupPrivilegeValueA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        return FALSE;
      }
    } else {
      tkp.PrivilegeCount++;
    }
  }

  AdjustTokenPrivileges(hToken, FALSE, (TOKEN_PRIVILEGES*)&tkp, 0, NULL, NULL);
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

static BOOL IsSidToken(HANDLE hToken, DWORD* sid, int verbosity) {
  PSID pSID = NULL;
  BOOL bSuccess = FALSE;
  BOOL bIsMember = FALSE;
  DWORD dwErr;
  SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

  if (AllocateAndInitializeSid(&NtAuthority, (BYTE)sid[0], sid[1], sid[2], sid[3], sid[4], sid[5], sid[6], 0, 0, &pSID)) {
    if (CheckTokenMembership(hToken, pSID, &bIsMember)) {
      bSuccess = TRUE;
    } else if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] advapi32:CheckTokenMembership() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
    }
  } else if (verbosity > 0) {
    dwErr = GetLastError();
    fmt_error("[!] advapi32:AllocateAndInitializeSid() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
  }
  if (pSID) {
    FreeSid(pSID);
    pSID = NULL;
  }
  return (bSuccess && bIsMember);
}

__forceinline static BOOL IsAdminToken(HANDLE hToken, int verbosity) {
  return IsSidToken(hToken, sid_admin, verbosity);
}

__forceinline static BOOL IsSystemToken(HANDLE hToken, int verbosity) {
  return IsSidToken(hToken, sid_system, verbosity);
}

__forceinline static BOOL IsTIToken(HANDLE hToken, int verbosity) {
  return IsSidToken(hToken, sid_ti, verbosity);
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
  }
  CloseHandle(hSnapshot);
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
  TOKEN_TYPE tokenImpersonation = TokenImpersonation;
  SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
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

  if(!DuplicateTokenEx(*phToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenImpersonation, phNewToken)) {
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

static void MarioLoop(char* buf, HANDLE hProc, HANDLE r_out, HANDLE r_err, HANDLE r_in, HANDLE w_out, HANDLE w_err, HANDLE w_in) {
  DWORD u = 0;
  DWORD dwAvail = 0;
  DWORD dwAvailErr = 0;
  DWORD dwRead = 0;
  __stosb(buf, 0, 4096);
  while (1) {
    if (!PeekNamedPipe(r_out, NULL, 0, NULL, &dwAvail, NULL))
      break;
    if (dwAvail > 0) {
      if (!ReadFile(r_out, buf, 4096, &dwRead, 0) || dwRead == 0)
        break;
      WriteFile(w_out, buf, dwRead, &u, 0);
    }
    if (!PeekNamedPipe(r_err, NULL, 0, NULL, &dwAvailErr, NULL))
      break;
    if (dwAvailErr > 0) {
      if (!ReadFile(r_err, buf, 4096, &dwRead, 0) || dwRead == 0)
        break;
      WriteFile(w_err, buf, dwRead, &u, 0);
    }
    if (!dwAvail && !dwAvailErr && WaitForSingleObject(hProc, 0) != WAIT_TIMEOUT)
      break;
    while (PeekNamedPipe(r_in, NULL, 0, NULL, &dwAvail, NULL)) {
      if (!dwAvail || !ReadFile(r_in, buf, 4096, &dwRead, 0) || dwRead == 0)
        break;
      WriteFile(w_in, buf, dwRead, &u, 0);
    }
    while (WaitForSingleObject(r_in, 0) == WAIT_OBJECT_0 && GetConsoleMode(r_in, &u)) {
      INPUT_RECORD r[512];
      if (ReadConsoleInputA(r_in, r, 512, &dwRead) && dwRead > 0) {
        for (DWORD i = 0; i < dwRead; i++) {
          if (r[i].EventType == KEY_EVENT && r[i].Event.KeyEvent.bKeyDown) {
            WriteFile(w_in, &r[i].Event.KeyEvent.uChar.AsciiChar, 1, &u, 0);
          }
        }
      }
    }
    Sleep(1);
  }
}

__forceinline static HANDLE OutReadPipe(DWORD pipe) {
  SECURITY_ATTRIBUTES sa;
  char buf[26] = "\\\\.\\pipe\\sudoo";
  __ultoa(pipe, buf+14);
  __stosb((PBYTE)&sa, 0, sizeof(SECURITY_ATTRIBUTES));
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = 1;
  return CreateNamedPipeA(buf, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT, 1, 4096, 4096, 0, &sa);
}

__forceinline static HANDLE InWritePipe(DWORD pipe) {
  SECURITY_ATTRIBUTES sa;
  char buf[26] = "\\\\.\\pipe\\sudoi";
  __ultoa(pipe, buf+14);
  __stosb((PBYTE)&sa, 0, sizeof(SECURITY_ATTRIBUTES));
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = 1;
  return CreateNamedPipeA(buf, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT, 1, 4096, 4096, 0, &sa);
}

static void RunAs(char* buf, wchar_t* cmdline, BOOL pipe, BOOL wait, int verbosity) {
  SHELLEXECUTEINFOW ShExecInfo;
  HANDLE out_read = 0;
  HANDLE in_write = 0;
  DWORD dwErr;
  DWORD exit_code = 0;
  wchar_t abc[4096];

  dwErr = GetModuleFileNameW(0, (wchar_t*)buf, 2048);
  if (!dwErr || dwErr == 2048) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] kernel32:GetModuleFileNameW() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      perr("[!] Could not create elevated process. Exiting...\r\n");
    }
    ExitProcess(-1);
  }

  if (pipe) {
    DWORD pid = GetCurrentProcessId();
    wchar_t* s = abc;
    *s++ = L'@';
    *s++ = L'!';
    *s++ = L'@';
    *s++ = L'|';
    __ultow(pid, s);
    while (*s >= L'0' && *s <= L'9') s++;
    if (cmdline) {
      *s++ = L' ';
      wcscpy(s, cmdline);
    } else {
      *s = 0;
    }
    out_read = OutReadPipe(pid);
    if (!out_read || out_read == INVALID_HANDLE_VALUE) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] kernel32:CreateNamedPipeA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        perr("[!] Could not create elevated process. Exiting...\r\n");
      }
      ExitProcess(-1);
    }
    in_write = InWritePipe(pid);
    if (!in_write || in_write == INVALID_HANDLE_VALUE) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] kernel32:CreateNamedPipeA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        perr("[!] Could not create elevated process. Exiting...\r\n");
      }
      CloseHandle(out_read);
      out_read = INVALID_HANDLE_VALUE;
      ExitProcess(-1);
    }
  }

  __stosb((PBYTE)&ShExecInfo, 0, sizeof(SHELLEXECUTEINFOW));
  ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
  ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_UNICODE | SEE_MASK_NO_CONSOLE | SEE_MASK_NOASYNC;
  ShExecInfo.hwnd = NULL;
  ShExecInfo.lpVerb = L"runas";
  ShExecInfo.lpFile = (wchar_t*)buf;
  ShExecInfo.lpParameters = pipe ? abc : cmdline;
  ShExecInfo.lpDirectory = NULL;
  ShExecInfo.nShow = SW_HIDE;
  ShExecInfo.hInstApp = NULL;
  if (!ShellExecuteExW(&ShExecInfo)) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      fmt_error("[!] shell32:ShellExecuteExW() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      perr("[!] Could not create elevated process. Exiting...\r\n");
    }
    if (pipe) {
      CloseHandle(out_read);
      out_read = INVALID_HANDLE_VALUE;
      CloseHandle(in_write);
      in_write = INVALID_HANDLE_VALUE;
    }
    ExitProcess(-1);
  }
  if (pipe) {
    if (WaitForSingleObject(ShExecInfo.hProcess,0) == WAIT_TIMEOUT && (ConnectNamedPipe(out_read, 0) || GetLastError() == ERROR_PIPE_CONNECTED)) {
      HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
      HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
      MarioLoop(buf, ShExecInfo.hProcess, out_read, out_read, hStdIn, hStdOut, hStdOut, in_write);
    } else if (verbosity > 0) {
      perr("[!] Could not connect pipe to elevated process\r\n");
    }
    CloseHandle(out_read);
    out_read = INVALID_HANDLE_VALUE;
    CloseHandle(in_write);
    in_write = INVALID_HANDLE_VALUE;
  }
  if (wait) {
    WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
    GetExitCodeProcess(ShExecInfo.hProcess, &exit_code);
  }
  ExitProcess(exit_code);
}

__forceinline static HANDLE GetStdOutPipe(DWORD pipe) {
  SECURITY_ATTRIBUTES sa;
  char buf[26] = "\\\\.\\pipe\\sudoo";
  __ultoa(pipe, buf+14);
  __stosb((PBYTE)&sa, 0, sizeof(SECURITY_ATTRIBUTES));
  sa.nLength= sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = 1;
  return CreateFileA(buf, FILE_WRITE_DATA|SYNCHRONIZE, 0, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
}

__forceinline static HANDLE GetStdInPipe(DWORD pipe) {
  SECURITY_ATTRIBUTES sa;
  char buf[26] = "\\\\.\\pipe\\sudoi";
  __ultoa(pipe, buf+14);
  __stosb((PBYTE)&sa, 0, sizeof(SECURITY_ATTRIBUTES));
  sa.nLength= sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = 1;
  return CreateFileA(buf, FILE_READ_DATA|SYNCHRONIZE, 0, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
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
  HANDLE hProc = NULL;
  HANDLE hStdIn = NULL;
  HANDLE hStdOut = NULL;
  HANDLE hStdErr = NULL;
  TOKEN_TYPE tokenPrimary = TokenPrimary;
  SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD dwErr;
  wchar_t *cmdline = NULL;
  wchar_t *s = NULL;
  DWORD exit_code = 0;
  BOOL wait = FALSE;
  BOOL change = TRUE;
  BOOL hide = FALSE;
  int verbosity = -1;
  BOOL new = FALSE;
  BOOL allpriv = TRUE;
  BOOL useenv = TRUE;
  BOOL do_test = FALSE;
  DWORD access = 1;
  DWORD dirlen = 0;
  int w = 0, h = 0, cols = 0, rows = 0;
  HANDLE out_read = NULL;
  HANDLE out_write = NULL;
  HANDLE err_read = NULL;
  HANDLE err_write = NULL;
  HANDLE in_read = NULL;
  HANDLE in_write = NULL;
  char buf[4096];
  DWORD dwRead = 0;
  DWORD dwAvail = 0;
  DWORD dwAvailErr = 0;
  DWORD dwFlags = 0;
  BOOL bSuccess = FALSE;
  unsigned int i;
  LPVOID lpEnvironment = NULL;
  DWORD pipe = 0;

  __stosb((PBYTE)&si, 0, sizeof(STARTUPINFOW));
  __stosb((PBYTE)&pi, 0, sizeof(PROCESS_INFORMATION));
  si.cb = sizeof(STARTUPINFOW);

  g_hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  g_hStdErr = GetStdHandle(STD_ERROR_HANDLE);
  
#ifndef _WIN64
  if (Is64BitOS()) {
    perr("[!] Processor architecture mismatch; sudo=x86, OS=x64\r\n\r\n");
    perr("Please use the 64-bit build for 64-bit OS.\r\n");
    ExitProcess(-2);
  }
#endif // !_WIN64

  dirlen = GetCurrentDirectoryW(0,0);
  if (!dirlen) {
    change = FALSE;
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
      pipe = __wtoul(s);
      while (*s >= L'0' && *s <= L'9') s++;
      while (*s == L' ' || *s == L'\t') s++;
    }
    cmdline = s;

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
              "  -e, --noenv               do not pass environment\r\n"
              "  -d, --nocd                do not change directory\r\n"
              "  -p, --nopriv              do not enable more privileges\r\n"
              "  -s, --silent              silent output\r\n"
              "  -v, --verbose             verbose output\r\n"
              "      --test                test privileges\r\n\r\n"
              "With no -a or -t, run as SYSTEM user\r\n");
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
      } else if ((*s == L'E' || *s == L'e') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        useenv = FALSE;
      } else if ((*s == L'N' || *s == L'n') &&
        (*(s+1) == L'O' || *(s+1) == L'o') &&
        (*(s+2) == L'E' || *(s+2) == L'e') &&
        (*(s+3) == L'N' || *(s+3) == L'n') &&
        (*(s+4) == L'V' || *(s+4) == L'v') &&
        (*(s+5) == L'\0' || *(s+5) == L' ' || *(s+5) == L'\t' || *(s+5) == L'/' || *(s+5) == L'-')) {
        s += 5;
        useenv = FALSE;
      } else if ((*s == L'D' || *s == L'd') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        change = FALSE;
      } else if ((*s == L'N' || *s == L'n') &&
        (*(s+1) == L'O' || *(s+1) == L'o') &&
        (*(s+2) == L'C' || *(s+2) == L'c') &&
        (*(s+3) == L'D' || *(s+3) == L'd') &&
        (*(s+4) == L'\0' || *(s+4) == L' ' || *(s+4) == L'\t' || *(s+4) == L'/' || *(s+4) == L'-')) {
        s += 4;
        change = FALSE;
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
        access = 2;
      } else if ((*s == L'T' || *s == L't') &&
        (*(s+1) == L'I' || *(s+1) == L'i') &&
        (*(s+2) == L'\0' || *(s+2) == L' ' || *(s+2) == L'\t' || *(s+2) == L'/' || *(s+2) == L'-')) {
        s += 2;
        access = 2;
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
        access = 2;
      } else if ((*s == L'P' || *s == L'p') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        allpriv = FALSE;
      } else if ((*s == L'N' || *s == L'n') &&
        (*(s+1) == L'O' || *(s+1) == L'o') &&
        (*(s+2) == L'P' || *(s+2) == L'p') &&
        (*(s+3) == L'R' || *(s+3) == L'r') &&
        (*(s+4) == L'I' || *(s+4) == L'i') &&
        (*(s+5) == L'V' || *(s+5) == L'v') &&
        (*(s+6) == L'\0' || *(s+6) == L' ' || *(s+6) == L'\t' || *(s+6) == L'/' || *(s+6) == L'-')) {
        s += 6;
        allpriv = FALSE;
      } else if ((*s == L'A' || *s == L'a') &&
        (*(s+1) == L'\0' || *(s+1) == L' ' || *(s+1) == L'\t' || *(s+1) == L'/' || *(s+1) == L'-')) {
        s++;
        access = 0;
      } else if ((*s == L'A' || *s == L'a') &&
        (*(s+1) == L'D' || *(s+1) == L'd') &&
        (*(s+2) == L'M' || *(s+2) == L'm') &&
        (*(s+3) == L'I' || *(s+3) == L'i') &&
        (*(s+4) == L'N' || *(s+4) == L'n') &&
        (*(s+5) == L'\0' || *(s+5) == L' ' || *(s+5) == L'\t' || *(s+5) == L'/' || *(s+5) == L'-')) {
        s += 5;
        access = 0;
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
        access = 0;
      } else if ((*s == L'S' || *s == L's') &&
        (*(s+1) == L'Y' || *(s+1) == L'y') &&
        (*(s+2) == L'S' || *(s+2) == L's') &&
        (*(s+3) == L'T' || *(s+3) == L't') &&
        (*(s+4) == L'E' || *(s+4) == L'e') &&
        (*(s+5) == L'M' || *(s+5) == L'm') &&
        (*(s+6) == L'\0' || *(s+6) == L' ' || *(s+5) == L'\t' || *(s+5) == L'/' || *(s+5) == L'-')) {
        s += 6;
        access = 1;
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
      ExitProcess(access > 0 ? (access == 1 ? !isSystem : !isTI) : !isAdmin);
    }
  }

  if (s && *s) {
    if (verbosity == -1) verbosity = 1;
    if (!new) {
      wait = TRUE;
      hide = TRUE;
    }
  } else {
    if (verbosity == -1) verbosity = 2;
//  wait = FALSE;
    hide = FALSE;
    new = TRUE;
  }

  if (pipe) {
    hStdOut = GetStdOutPipe(pipe);
    if (!hStdOut || hStdOut == INVALID_HANDLE_VALUE) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] kernel32:CreateFileA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        perr("[!] Could not connect pipe to parent process. Exiting...\r\n");
      }
      ExitProcess(-1);
    }
    hStdIn = GetStdInPipe(pipe);
    if (!hStdIn || hStdIn == INVALID_HANDLE_VALUE) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] kernel32:CreateFileA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        perr("[!] Could not connect pipe to parent process. Exiting...\r\n");
      }
      CloseHandle(hStdOut);
      hStdOut = INVALID_HANDLE_VALUE;
      ExitProcess(-1);
    }
    hStdErr = hStdOut;
    g_hStdOut = hStdOut;
    g_hStdErr = hStdErr;
  } else if (verbosity == 2) {
    perr("[+] Run As: ");
    if (access == 2) {
      perr("TrustedInstaller\r\n");
    } else if (access == 1) {
      perr("SYSTEM\r\n");
    } else {
      perr("Administrator\r\n");
    }
  }

  if (!IsAdminToken(0, verbosity)) {
    if (!pipe) {
      if (verbosity == 2) perr("[+] Requesting administrator privileges...\r\n");
      RunAs(buf, cmdline, (!new || verbosity > 0), wait, verbosity);
    } else {
      if (verbosity > 0) perr("[!] Could not acquire administrator privileges. Exiting...\r\n");
      ExitProcess(-1);
    }
  } else if (pipe && verbosity == 2) {
    perr("[+] Administrator privileges acquired\r\n");
  }

  if (s && *s) {
    if (change) {
      cmdline = (wchar_t*)LocalAlloc(LMEM_FIXED, (wcslen(s)+dirlen+27)*sizeof(wchar_t));
      wcscpy(cmdline, L"/d/x/s/v:off/r pushd \"");
      GetCurrentDirectoryW(dirlen, cmdline+22);
      wcscat(cmdline, L"\" & ");
    } else {
      cmdline = (wchar_t*)LocalAlloc(LMEM_FIXED, (wcslen(s)+16)*sizeof(wchar_t));
      wcscpy(cmdline, L"/d/x/s/v:off/r ");
    }
    wcscat(cmdline, s);
  } else {
    if (change) {
      cmdline = (wchar_t*)LocalAlloc(LMEM_FIXED, (wcslen(s)+dirlen+24)*sizeof(wchar_t));
      wcscpy(cmdline, L"/d/x/s/v:off/k pushd \"");
      GetCurrentDirectoryW(dirlen, cmdline+22);
      wcscat(cmdline, L"\"");
    } else {
      cmdline = 0;
    }
  }

  if (access > 0) {
    if (!EnableImpersonatePriv(verbosity)) {
      if (verbosity > 0) perr("[!] Could not acquire impersonation privileges. Exiting...\r\n");
      if (cmdline) LocalFree(cmdline);
      if (pipe) {
        CloseHandle(hStdOut);
        hStdOut = INVALID_HANDLE_VALUE;
        hStdErr = INVALID_HANDLE_VALUE;
        CloseHandle(hStdIn);
        hStdIn = INVALID_HANDLE_VALUE;
      }
      ExitProcess(-1);
    }
    if (verbosity == 2) perr("[+] Impersonation privileges acquired\r\n");

//  if (access == 2 && !GetPIDForProcess("trustedinstaller.exe")) {
//    DoStartSvc(verbosity);
//  }

    for (i = 0; i < countof(sysProcs); i++) {
      if (GetDupToken(sysProcs[i], &hToken, &hNewToken, verbosity)) {
        if (IsSystemToken(hNewToken, verbosity)) break;
        if (verbosity > 0) perr("[!] Not a SYSTEM token\r\n");
        CloseHandle(hNewToken);
        CloseHandle(hToken);
      }
    }

    if (i == countof(sysProcs)) {
      if (verbosity > 0) perr("[!] Failed to acquire SYSTEM privileges. Exiting...\r\n");
      if (cmdline) LocalFree(cmdline);
      if (pipe) {
        CloseHandle(hStdOut);
        hStdOut = INVALID_HANDLE_VALUE;
        hStdErr = INVALID_HANDLE_VALUE;
        CloseHandle(hStdIn);
        hStdIn = INVALID_HANDLE_VALUE;
      }
      ExitProcess(-1);
    }

    if (access == 2) {
      CloseHandle(hToken);
      if (ImpersonateLoggedOnUser(hNewToken)) {
        CloseHandle(hNewToken);
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
          if (!bSuccess && verbosity > 0) perr("[!] Not a TrustedInstaller token\r\n");
        }
      } else if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] advapi32:ImpersonateLoggedOnUser() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        perr("[!] Could not impersonate SYSTEM user\r\n");
      }
      CloseHandle(hNewToken);

      if (!bSuccess) {
        if (verbosity > 0) perr("[!] Failed to acquire TrustedInstaller privileges. Exiting...\r\n");
        if (cmdline) LocalFree(cmdline);
        if (pipe) {
          CloseHandle(hStdOut);
          hStdOut = INVALID_HANDLE_VALUE;
          hStdErr = INVALID_HANDLE_VALUE;
          CloseHandle(hStdIn);
          hStdIn = INVALID_HANDLE_VALUE;
        }
        ExitProcess(-1);
      }
    }

    if(!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenPrimary, &hNewToken)) {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] advapi32:DuplicateTokenEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        perr("[!] Could not duplicate access token. Exiting...\r\n");
      }
      if (cmdline) LocalFree(cmdline);
      if (pipe) {
        CloseHandle(hStdOut);
        hStdOut = INVALID_HANDLE_VALUE;
        hStdErr = INVALID_HANDLE_VALUE;
        CloseHandle(hStdIn);
        hStdIn = INVALID_HANDLE_VALUE;
      }
      CloseHandle(hToken);
      ExitProcess(-1);
    }
    if (verbosity == 2) perr("[+] Access token duplicated\r\n");
  }

  if (allpriv) {
    if (access == 0) {
      if (!OpenProcessToken((HANDLE)-1, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hNewToken)) {
        if (verbosity > 0)  {
          dwErr = GetLastError();
          fmt_error("[!] advapi32:OpenProcessToken() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
        }
        hNewToken = 0;
      }
    }
    if (!hNewToken || !EnableAllPriv(hNewToken, verbosity)) {
      if (verbosity > 0) perr("[!] Could not enable all privileges\r\n");
    } else if (verbosity == 2) {
      perr("[+] All privileges enabled\r\n");
    }
    if (access == 0 && hNewToken) {
      CloseHandle(hNewToken);
      hNewToken = 0;
    }
  }

  if (verbosity == 2) perr("[+] Spawning ComSpec...\r\n");
  if (hide) {
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!new) {
      SECURITY_ATTRIBUTES sa;
      __stosb((PBYTE)&sa, 0, sizeof(SECURITY_ATTRIBUTES));
      sa.nLength = sizeof(SECURITY_ATTRIBUTES);
      sa.bInheritHandle = 1;

      CreatePipe(&out_read, &out_write, &sa, 0);
      CreatePipe(&err_read, &err_write, &sa, 0);
      CreatePipe(&in_read, &in_write, &sa, 0);

      SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
      SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);
      SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0);

      si.dwFlags |= STARTF_USESTDHANDLES;
      si.hStdError = err_write;
      si.hStdOutput = out_write;
      si.hStdInput = in_read;
    }
  } else {
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
  dwFlags = new ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW;
  if (useenv) {
    if (CreateEnvironmentBlock(&lpEnvironment, NULL, TRUE)) {
      dwFlags |= CREATE_UNICODE_ENVIRONMENT;
    } else {
      if (verbosity > 0) {
        dwErr = GetLastError();
        fmt_error("[!] userenv:CreateEnvironmentBlock() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      }
      useenv = FALSE;
      lpEnvironment = NULL;
    }
  }
  if (access > 0) {
    bSuccess = CreateProcessWithTokenW(hNewToken, LOGON_NETCREDENTIALS_ONLY, (ReadEnvironmentVariable(L"ComSpec", (wchar_t*)buf, 2048) ? (wchar_t*)buf : L"cmd.exe"), cmdline ? cmdline : L"/d/x/v:off", dwFlags, lpEnvironment, NULL, &si, &pi);
  } else {
    bSuccess = CreateProcessW((ReadEnvironmentVariable(L"ComSpec", (wchar_t*)buf, 2048) ? (wchar_t*)buf : L"cmd.exe"), cmdline ? cmdline : L"/d/x/v:off", NULL, NULL, TRUE, dwFlags, lpEnvironment, NULL, &si, &pi);
  }
  if (!bSuccess) {
    if (verbosity > 0) {
      dwErr = GetLastError();
      if (access > 0) fmt_error("[!] advapi32:CreateProcessWithTokenW() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      else fmt_error("[!] kernel32:CreateProcessW() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"");
      perr("[!] Could not create elevated process. Exiting...\r\n");
    }
    if (useenv) DestroyEnvironmentBlock(lpEnvironment);
    if (cmdline) {
      LocalFree(cmdline);
      if (!new) {
        CloseHandle(out_read);
        out_read = INVALID_HANDLE_VALUE;
        CloseHandle(err_read);
        err_read = INVALID_HANDLE_VALUE;
        CloseHandle(in_read);
        in_read = INVALID_HANDLE_VALUE;
        CloseHandle(out_write);
        out_write = INVALID_HANDLE_VALUE;
        CloseHandle(err_write);
        err_write = INVALID_HANDLE_VALUE;
        CloseHandle(in_write);
        in_write = INVALID_HANDLE_VALUE;
      }
    }
    if (pipe) {
      CloseHandle(hStdOut);
      hStdOut = INVALID_HANDLE_VALUE;
      hStdErr = INVALID_HANDLE_VALUE;
      CloseHandle(hStdIn);
      hStdIn = INVALID_HANDLE_VALUE;
    }
    if (access > 0) {
      CloseHandle(hToken);
      CloseHandle(hNewToken);
    }
    ExitProcess(-1);
  }
  if (verbosity == 2) perr("[+] Success\r\n");
  if (useenv) DestroyEnvironmentBlock(lpEnvironment);
  if (cmdline) {
    LocalFree(cmdline);

    if (!new) {
      __stosb(buf, 0, 4096);
      if (!pipe) {
        hStdIn = GetStdHandle(STD_INPUT_HANDLE);
        hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        hStdErr = GetStdHandle(STD_ERROR_HANDLE);
      }
      MarioLoop(buf, pi.hProcess, out_read, err_read, hStdIn, hStdOut, hStdErr, in_write);
      CloseHandle(out_read);
      out_read = INVALID_HANDLE_VALUE;
      CloseHandle(err_read);
      err_read = INVALID_HANDLE_VALUE;
      CloseHandle(in_read);
      in_read = INVALID_HANDLE_VALUE;
      CloseHandle(out_write);
      out_write = INVALID_HANDLE_VALUE;
      CloseHandle(err_write);
      err_write = INVALID_HANDLE_VALUE;
      CloseHandle(in_write);
      in_write = INVALID_HANDLE_VALUE;
    }
  }

  if (pipe) {
    CloseHandle(hStdOut);
    hStdOut = INVALID_HANDLE_VALUE;
    hStdErr = INVALID_HANDLE_VALUE;
    CloseHandle(hStdIn);
    hStdIn = INVALID_HANDLE_VALUE;
  }

  if (wait) {
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
  }

  if (access > 0) {
    CloseHandle(hToken);
    CloseHandle(hNewToken);
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  ExitProcess(exit_code);
}
