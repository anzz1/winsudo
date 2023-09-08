// ntdll_lib_stub.c

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int __stdcall DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  return 1;
}

__declspec(dllexport) long __stdcall NtSetInformationProcess(
  HANDLE               ProcessHandle,
  ULONG                ProcessInformationClass,
  PVOID                ProcessInformation,
  ULONG                ProcessInformationLength
) {
  return 1;
}

__declspec(dllexport) long __stdcall RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation) {
  return 1;
}

__declspec(dllexport) long __stdcall ZwCreateToken(
  PHANDLE              TokenHandle,
  ACCESS_MASK          DesiredAccess,
  PVOID                ObjectAttributes,
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
) {
  return 1;
}
