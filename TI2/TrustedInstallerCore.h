#pragma once
#include <string>


void Log(const std::wstring& msg);  // Declaration only

bool EnableAllPrivileges();
bool StartTrustedInstallerService();
bool LaunchViaService(const std::wstring& exePath, const std::wstring& args);
bool LaunchAsTrustedInstaller(const std::wstring& command);
bool RunWithTiToken(const std::wstring& command);
void Log(const std::wstring& msg);
