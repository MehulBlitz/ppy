/*
 * Minimal GUI host for GH Injector Library
 */

#include <Windows.h>
#include <commdlg.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cerrno>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "../Injection.h"

#pragma comment(lib, "Comdlg32.lib")

namespace
{
	constexpr wchar_t WINDOW_CLASS_NAME[] = L"GHInjectorMiniGuiWindow";
	constexpr wchar_t WINDOW_TITLE[] = L"GH Injector Mini GUI";

	constexpr DWORD INJ_ERR_SUCCESS = 0x00000000;
	constexpr DWORD INJ_ERR_SYMBOL_INIT_NOT_DONE = 0x0000001C;
	constexpr DWORD INJ_ERR_IMPORT_HANDLER_NOT_DONE = 0x00000037;
	constexpr DWORD INJ_MM_MAP_FROM_MEMORY_FLAG = 0x04000000;
	constexpr DWORD INJ_MM_LINK_MODULE_FLAG = 0x08000000;

	constexpr DWORD DEFAULT_INIT_TIMEOUT_MS = 180000;
	constexpr DWORD DEFAULT_INJECTION_TIMEOUT_MS = 2000;

	constexpr UINT WM_APP_SET_STATUS = WM_APP + 1;
	constexpr UINT WM_APP_SET_PID = WM_APP + 2;
	constexpr UINT WM_APP_INJECT_DONE = WM_APP + 3;

	constexpr int ID_COMBO_PROCESS = 1001;
	constexpr int ID_BUTTON_REFRESH = 1002;
	constexpr int ID_BUTTON_FIND_PID = 1003;
	constexpr int ID_EDIT_PID = 1004;
	constexpr int ID_EDIT_DLL_PATH = 1005;
	constexpr int ID_BUTTON_BROWSE_DLL = 1006;
	constexpr int ID_EDIT_TIMEOUT = 1007;
	constexpr int ID_BUTTON_INJECT = 1008;
	constexpr int ID_STATIC_STATUS = 1009;
	constexpr int ID_EDIT_INIT_TIMEOUT = 1010;
	constexpr int ID_EDIT_DELAY = 1011;
	constexpr int ID_COMBO_MODE = 1012;
	constexpr int ID_COMBO_METHOD = 1013;
	constexpr int ID_COMBO_HEADER = 1014;
	constexpr int ID_CHECK_GENERATE_LOG = 1015;
	constexpr int ID_CHECK_AUTO_EXIT = 1016;
	constexpr int ID_CHECK_HIJACK_HANDLE = 1017;
	constexpr int ID_CHECK_CLOAK_THREAD = 1018;
	constexpr int ID_CHECK_RANDOM_DLL_NAME = 1019;
	constexpr int ID_CHECK_LOAD_DLL_COPY = 1020;
	constexpr int ID_CHECK_UNLINK_PEB = 1021;
	constexpr int ID_CHECK_MM_RUN_DLLMAIN = 1022;
	constexpr int ID_CHECK_MM_LDR_LOCK = 1023;
	constexpr int ID_CHECK_MM_RESOLVE_IMPORTS = 1024;
	constexpr int ID_CHECK_MM_DELAY_IMPORTS = 1025;
	constexpr int ID_CHECK_MM_EXECUTE_TLS = 1026;
	constexpr int ID_CHECK_MM_MAP_MEMORY = 1027;
	constexpr int ID_CHECK_MM_SET_PAGE_PROT = 1028;
	constexpr int ID_CHECK_MM_ENABLE_EX = 1029;
	constexpr int ID_CHECK_MM_INIT_COOKIE = 1030;
	constexpr int ID_CHECK_MM_CLEAN_DIR = 1031;
	constexpr int ID_CHECK_MM_SHIFT_BASE = 1032;
	constexpr int ID_CHECK_MM_LINK_PEB = 1033;

	struct ComboOption
	{
		const wchar_t * Label;
		DWORD Value;
	};

	struct AppState
	{
		HWND hComboProcess = nullptr;
		HWND hEditPid = nullptr;
		HWND hEditDllPath = nullptr;
		HWND hEditTimeout = nullptr;
		HWND hEditInitTimeout = nullptr;
		HWND hEditDelay = nullptr;
		HWND hButtonRefresh = nullptr;
		HWND hButtonFindPid = nullptr;
		HWND hButtonBrowse = nullptr;
		HWND hButtonInject = nullptr;
		HWND hStaticStatus = nullptr;
		HWND hComboMode = nullptr;
		HWND hComboMethod = nullptr;
		HWND hComboHeader = nullptr;
		HWND hCheckGenerateLog = nullptr;
		HWND hCheckAutoExit = nullptr;
		HWND hCheckHijackHandle = nullptr;
		HWND hCheckCloakThread = nullptr;
		HWND hCheckRandomDllName = nullptr;
		HWND hCheckLoadDllCopy = nullptr;
		HWND hCheckUnlinkPeb = nullptr;
		HWND hCheckMmRunDllMain = nullptr;
		HWND hCheckMmLdrLock = nullptr;
		HWND hCheckMmResolveImports = nullptr;
		HWND hCheckMmDelayImports = nullptr;
		HWND hCheckMmExecuteTls = nullptr;
		HWND hCheckMmMapMemory = nullptr;
		HWND hCheckMmSetPageProt = nullptr;
		HWND hCheckMmEnableEx = nullptr;
		HWND hCheckMmInitCookie = nullptr;
		HWND hCheckMmCleanDir = nullptr;
		HWND hCheckMmShiftBase = nullptr;
		HWND hCheckMmLinkPeb = nullptr;
		bool Busy = false;
	};

	struct InjectionSettings
	{
		DWORD InitTimeoutMs = DEFAULT_INIT_TIMEOUT_MS;
		DWORD DelayMs = 0;
		DWORD InjectTimeoutMs = DEFAULT_INJECTION_TIMEOUT_MS;
		INJECTION_MODE Mode = INJECTION_MODE::IM_LoadLibraryExW;
		LAUNCH_METHOD Method = LAUNCH_METHOD::LM_NtCreateThreadEx;
		DWORD Flags = 0;
		bool GenerateErrorLog = true;
		bool AutoExit = false;
	};

	constexpr ComboOption MODE_OPTIONS[] = {
		{ L"LoadLibraryExW", static_cast<DWORD>(INJECTION_MODE::IM_LoadLibraryExW) },
		{ L"LdrLoadDll", static_cast<DWORD>(INJECTION_MODE::IM_LdrLoadDll) },
		{ L"LdrpLoadDll", static_cast<DWORD>(INJECTION_MODE::IM_LdrpLoadDll) },
		{ L"LdrpLoadDllInternal", static_cast<DWORD>(INJECTION_MODE::IM_LdrpLoadDllInternal) },
		{ L"ManualMap", static_cast<DWORD>(INJECTION_MODE::IM_ManualMap) },
	};

	constexpr ComboOption METHOD_OPTIONS[] = {
		{ L"NtCreateThreadEx", static_cast<DWORD>(LAUNCH_METHOD::LM_NtCreateThreadEx) },
		{ L"ThreadHijack", static_cast<DWORD>(LAUNCH_METHOD::LM_HijackThread) },
		{ L"SetWindowsHookEx", static_cast<DWORD>(LAUNCH_METHOD::LM_SetWindowsHookEx) },
		{ L"QueueUserAPC", static_cast<DWORD>(LAUNCH_METHOD::LM_QueueUserAPC) },
		{ L"KernelCallback", static_cast<DWORD>(LAUNCH_METHOD::LM_KernelCallback) },
		{ L"FakeVEH", static_cast<DWORD>(LAUNCH_METHOD::LM_FakeVEH) },
	};

	constexpr ComboOption HEADER_OPTIONS[] = {
		{ L"Keep PE Header", 0 },
		{ L"Fake Header", INJ_FAKE_HEADER },
		{ L"Erase Header", INJ_ERASE_HEADER },
	};

	struct ProcessInfo
	{
		std::wstring Name;
		DWORD Pid = 0;
	};

	std::wstring ToLowerCopy(std::wstring value)
	{
		std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c)
		{
			return static_cast<wchar_t>(std::towlower(c));
		});

		return value;
	}

	std::wstring NormalizeProcessName(std::wstring name)
	{
		while (!name.empty() && std::iswspace(name.back()))
		{
			name.pop_back();
		}

		size_t first = 0;
		while (first < name.size() && std::iswspace(name[first]))
		{
			++first;
		}

		if (first > 0)
		{
			name.erase(0, first);
		}

		if (name.empty())
		{
			return name;
		}

		std::wstring lowered = ToLowerCopy(name);
		if (lowered.size() < 4 || lowered.substr(lowered.size() - 4) != L".exe")
		{
			name += L".exe";
		}

		return name;
	}

	std::wstring GetWindowTextString(HWND hWnd)
	{
		const int len = GetWindowTextLengthW(hWnd);
		if (len <= 0)
		{
			return std::wstring();
		}

		std::wstring buffer(static_cast<size_t>(len) + 1, L'\0');
		GetWindowTextW(hWnd, buffer.data(), len + 1);
		buffer.resize(wcslen(buffer.c_str()));
		return buffer;
	}

	bool ParseDword(const std::wstring & text, DWORD & outValue)
	{
		if (text.empty())
		{
			return false;
		}

		wchar_t * end = nullptr;
		errno = 0;
		const unsigned long value = wcstoul(text.c_str(), &end, 10);
		if (errno != 0 || !end || *end != L'\0' || value > 0xFFFFFFFFUL)
		{
			return false;
		}

		outValue = static_cast<DWORD>(value);
		return true;
	}

	DWORD FindPidByProcessName(const std::wstring & processName)
	{
		const std::wstring normalizedName = NormalizeProcessName(processName);
		if (normalizedName.empty())
		{
			return 0;
		}

		const std::wstring search = ToLowerCopy(normalizedName);

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
		{
			return 0;
		}

		PROCESSENTRY32W pe{};
		pe.dwSize = sizeof(pe);

		DWORD resultPid = 0;
		if (Process32FirstW(hSnapshot, &pe))
		{
			do
			{
				if (ToLowerCopy(pe.szExeFile) == search)
				{
					resultPid = pe.th32ProcessID;
					break;
				}
			} while (Process32NextW(hSnapshot, &pe));
		}

		CloseHandle(hSnapshot);
		return resultPid;
	}

	std::vector<ProcessInfo> GetRunningProcesses()
	{
		std::vector<ProcessInfo> processes;

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
		{
			return processes;
		}

		PROCESSENTRY32W pe{};
		pe.dwSize = sizeof(pe);

		if (Process32FirstW(hSnapshot, &pe))
		{
			do
			{
				if (pe.th32ProcessID != 0 && pe.szExeFile[0] != L'\0')
				{
					processes.push_back({ pe.szExeFile, pe.th32ProcessID });
				}
			} while (Process32NextW(hSnapshot, &pe));
		}

		CloseHandle(hSnapshot);

		std::sort(processes.begin(), processes.end(), [](const ProcessInfo & a, const ProcessInfo & b)
		{
			const std::wstring left = ToLowerCopy(a.Name);
			const std::wstring right = ToLowerCopy(b.Name);
			if (left == right)
			{
				return a.Pid < b.Pid;
			}

			return left < right;
		});

		return processes;
	}

	DWORD GetSelectedComboPid(HWND hComboProcess)
	{
		const int index = static_cast<int>(SendMessageW(hComboProcess, CB_GETCURSEL, 0, 0));
		if (index == CB_ERR)
		{
			return 0;
		}

		const LRESULT data = SendMessageW(hComboProcess, CB_GETITEMDATA, static_cast<WPARAM>(index), 0);
		if (data == CB_ERR)
		{
			return 0;
		}

		return static_cast<DWORD>(data);
	}

	void SetPidEdit(HWND hEditPid, DWORD pid)
	{
		if (pid == 0)
		{
			SetWindowTextW(hEditPid, L"");
			return;
		}

		wchar_t pidText[16] = { 0 };
		_snwprintf_s(pidText, _TRUNCATE, L"%lu", static_cast<unsigned long>(pid));
		SetWindowTextW(hEditPid, pidText);
	}

	void SelectComboItemByPid(HWND hComboProcess, DWORD pid)
	{
		if (pid == 0)
		{
			return;
		}

		const int count = static_cast<int>(SendMessageW(hComboProcess, CB_GETCOUNT, 0, 0));
		for (int i = 0; i < count; ++i)
		{
			const LRESULT data = SendMessageW(hComboProcess, CB_GETITEMDATA, static_cast<WPARAM>(i), 0);
			if (data != CB_ERR && static_cast<DWORD>(data) == pid)
			{
				SendMessageW(hComboProcess, CB_SETCURSEL, static_cast<WPARAM>(i), 0);
				break;
			}
		}
	}

	void RefreshProcessCombo(AppState & state)
	{
		const std::wstring currentText = GetWindowTextString(state.hComboProcess);
		const DWORD selectedPid = GetSelectedComboPid(state.hComboProcess);
		const std::wstring normalizedCurrent = NormalizeProcessName(currentText);
		const std::wstring normalizedLower = ToLowerCopy(normalizedCurrent);

		const std::vector<ProcessInfo> processes = GetRunningProcesses();

		SendMessageW(state.hComboProcess, CB_RESETCONTENT, 0, 0);

		int selectedIndex = CB_ERR;
		for (const ProcessInfo & info : processes)
		{
			wchar_t itemText[320] = { 0 };
			_snwprintf_s(itemText, _TRUNCATE, L"%ls (PID: %lu)", info.Name.c_str(), static_cast<unsigned long>(info.Pid));

			const int index = static_cast<int>(SendMessageW(state.hComboProcess, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(itemText)));
			if (index == CB_ERR || index == CB_ERRSPACE)
			{
				continue;
			}

			SendMessageW(state.hComboProcess, CB_SETITEMDATA, static_cast<WPARAM>(index), static_cast<LPARAM>(info.Pid));

			if (selectedIndex == CB_ERR)
			{
				if (selectedPid != 0 && info.Pid == selectedPid)
				{
					selectedIndex = index;
				}
				else if (selectedPid == 0 && !normalizedLower.empty() && ToLowerCopy(info.Name) == normalizedLower)
				{
					selectedIndex = index;
				}
			}
		}

		if (selectedIndex != CB_ERR)
		{
			SendMessageW(state.hComboProcess, CB_SETCURSEL, static_cast<WPARAM>(selectedIndex), 0);
			SetPidEdit(state.hEditPid, GetSelectedComboPid(state.hComboProcess));
		}
		else
		{
			SetWindowTextW(state.hComboProcess, currentText.c_str());
			SetPidEdit(state.hEditPid, FindPidByProcessName(currentText));
		}
	}

	void PostStatus(HWND hWnd, const std::wstring & status)
	{
		auto message = std::make_unique<std::wstring>(status);
		if (!PostMessageW(hWnd, WM_APP_SET_STATUS, 0, reinterpret_cast<LPARAM>(message.get())))
		{
			return;
		}

		message.release();
	}

	void SetStatusText(HWND hStaticStatus, const std::wstring & status)
	{
		SetWindowTextW(hStaticStatus, status.c_str());
	}

	void EnableActionButtons(AppState & state, bool enabled)
	{
		const BOOL flag = enabled ? TRUE : FALSE;
		EnableWindow(state.hComboProcess, enabled ? TRUE : FALSE);
		EnableWindow(state.hButtonRefresh, flag);
		EnableWindow(state.hButtonFindPid, flag);
		EnableWindow(state.hButtonBrowse, flag);
		EnableWindow(state.hButtonInject, flag);
		EnableWindow(state.hEditInitTimeout, flag);
		EnableWindow(state.hEditDelay, flag);
		EnableWindow(state.hEditTimeout, flag);
		EnableWindow(state.hComboMode, flag);
		EnableWindow(state.hComboMethod, flag);
		EnableWindow(state.hComboHeader, flag);
		EnableWindow(state.hCheckGenerateLog, flag);
		EnableWindow(state.hCheckAutoExit, flag);
		EnableWindow(state.hCheckHijackHandle, flag);
		EnableWindow(state.hCheckCloakThread, flag);
		EnableWindow(state.hCheckRandomDllName, flag);
		EnableWindow(state.hCheckLoadDllCopy, flag);
		EnableWindow(state.hCheckUnlinkPeb, flag);
		EnableWindow(state.hCheckMmRunDllMain, flag);
		EnableWindow(state.hCheckMmLdrLock, flag);
		EnableWindow(state.hCheckMmResolveImports, flag);
		EnableWindow(state.hCheckMmDelayImports, flag);
		EnableWindow(state.hCheckMmExecuteTls, flag);
		EnableWindow(state.hCheckMmMapMemory, flag);
		EnableWindow(state.hCheckMmSetPageProt, flag);
		EnableWindow(state.hCheckMmEnableEx, flag);
		EnableWindow(state.hCheckMmInitCookie, flag);
		EnableWindow(state.hCheckMmCleanDir, flag);
		EnableWindow(state.hCheckMmShiftBase, flag);
		EnableWindow(state.hCheckMmLinkPeb, flag);
	}

	int AddComboItem(HWND hCombo, const wchar_t * text, DWORD value)
	{
		const int index = static_cast<int>(SendMessageW(hCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text)));
		if (index == CB_ERR || index == CB_ERRSPACE)
		{
			return CB_ERR;
		}

		SendMessageW(hCombo, CB_SETITEMDATA, static_cast<WPARAM>(index), static_cast<LPARAM>(value));
		return index;
	}

	void InitComboOptions(HWND hCombo, const ComboOption * options, size_t count, DWORD defaultValue)
	{
		int defaultIndex = 0;
		for (size_t i = 0; i < count; ++i)
		{
			const int index = AddComboItem(hCombo, options[i].Label, options[i].Value);
			if (index != CB_ERR && options[i].Value == defaultValue)
			{
				defaultIndex = index;
			}
		}

		SendMessageW(hCombo, CB_SETCURSEL, static_cast<WPARAM>(defaultIndex), 0);
	}

	DWORD GetSelectedComboValue(HWND hCombo, DWORD fallback)
	{
		const int index = static_cast<int>(SendMessageW(hCombo, CB_GETCURSEL, 0, 0));
		if (index == CB_ERR)
		{
			return fallback;
		}

		const LRESULT value = SendMessageW(hCombo, CB_GETITEMDATA, static_cast<WPARAM>(index), 0);
		if (value == CB_ERR)
		{
			return fallback;
		}

		return static_cast<DWORD>(value);
	}

	bool IsChecked(HWND hCheck)
	{
		return SendMessageW(hCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
	}

	void SetChecked(HWND hCheck, bool checked)
	{
		SendMessageW(hCheck, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
	}

	void UpdateUiDependencies(AppState & state)
	{
		const auto mode = static_cast<INJECTION_MODE>(GetSelectedComboValue(state.hComboMode, static_cast<DWORD>(INJECTION_MODE::IM_LoadLibraryExW)));
		const auto method = static_cast<LAUNCH_METHOD>(GetSelectedComboValue(state.hComboMethod, static_cast<DWORD>(LAUNCH_METHOD::LM_NtCreateThreadEx)));

		const bool isManualMap = (mode == INJECTION_MODE::IM_ManualMap);
		const bool isNtCreateThreadEx = (method == LAUNCH_METHOD::LM_NtCreateThreadEx);

		const BOOL mmEnabled = isManualMap ? TRUE : FALSE;

		EnableWindow(state.hCheckMmRunDllMain, mmEnabled);
		EnableWindow(state.hCheckMmLdrLock, mmEnabled);
		EnableWindow(state.hCheckMmResolveImports, mmEnabled);
		EnableWindow(state.hCheckMmDelayImports, mmEnabled);
		EnableWindow(state.hCheckMmExecuteTls, mmEnabled);
		EnableWindow(state.hCheckMmMapMemory, mmEnabled);
		EnableWindow(state.hCheckMmSetPageProt, mmEnabled);
		EnableWindow(state.hCheckMmEnableEx, mmEnabled);
		EnableWindow(state.hCheckMmInitCookie, mmEnabled);
		EnableWindow(state.hCheckMmCleanDir, mmEnabled);
		EnableWindow(state.hCheckMmShiftBase, mmEnabled);
		EnableWindow(state.hCheckMmLinkPeb, mmEnabled);

		if (!isManualMap)
		{
			SetChecked(state.hCheckMmRunDllMain, false);
			SetChecked(state.hCheckMmLdrLock, false);
			SetChecked(state.hCheckMmResolveImports, false);
			SetChecked(state.hCheckMmDelayImports, false);
			SetChecked(state.hCheckMmExecuteTls, false);
			SetChecked(state.hCheckMmMapMemory, false);
			SetChecked(state.hCheckMmSetPageProt, false);
			SetChecked(state.hCheckMmEnableEx, false);
			SetChecked(state.hCheckMmInitCookie, false);
			SetChecked(state.hCheckMmCleanDir, false);
			SetChecked(state.hCheckMmShiftBase, false);
			SetChecked(state.hCheckMmLinkPeb, false);
		}

		EnableWindow(state.hCheckCloakThread, isNtCreateThreadEx ? TRUE : FALSE);
		if (!isNtCreateThreadEx)
		{
			SetChecked(state.hCheckCloakThread, false);
		}

		EnableWindow(state.hCheckUnlinkPeb, isManualMap ? FALSE : TRUE);
		if (isManualMap)
		{
			SetChecked(state.hCheckUnlinkPeb, false);
		}

		EnableWindow(state.hComboHeader, isManualMap ? FALSE : TRUE);
		if (isManualMap)
		{
			SendMessageW(state.hComboHeader, CB_SETCURSEL, 0, 0);
		}

		const bool runDllMain = isManualMap && IsChecked(state.hCheckMmRunDllMain);
		EnableWindow(state.hCheckMmLdrLock, runDllMain ? TRUE : FALSE);
		if (!runDllMain)
		{
			SetChecked(state.hCheckMmLdrLock, false);
		}

		if (runDllMain)
		{
			SetChecked(state.hCheckMmResolveImports, true);
			EnableWindow(state.hCheckMmResolveImports, FALSE);
		}
		else
		{
			EnableWindow(state.hCheckMmResolveImports, mmEnabled);
		}

		const bool setPageProtections = isManualMap && IsChecked(state.hCheckMmSetPageProt);
		EnableWindow(state.hCheckMmCleanDir, setPageProtections ? FALSE : mmEnabled);
		EnableWindow(state.hCheckMmShiftBase, setPageProtections ? FALSE : mmEnabled);
		if (setPageProtections)
		{
			SetChecked(state.hCheckMmCleanDir, false);
			SetChecked(state.hCheckMmShiftBase, false);
		}
	}

	DWORD BuildFlagsFromUi(const AppState & state)
	{
		DWORD flags = 0;

		flags |= GetSelectedComboValue(state.hComboHeader, 0);

		if (IsChecked(state.hCheckUnlinkPeb)) flags |= INJ_UNLINK_FROM_PEB;
		if (IsChecked(state.hCheckCloakThread)) flags |= INJ_THREAD_CREATE_CLOAKED;
		if (IsChecked(state.hCheckRandomDllName)) flags |= INJ_SCRAMBLE_DLL_NAME;
		if (IsChecked(state.hCheckLoadDllCopy)) flags |= INJ_LOAD_DLL_COPY;
		if (IsChecked(state.hCheckHijackHandle)) flags |= INJ_HIJACK_HANDLE;

		if (IsChecked(state.hCheckMmCleanDir)) flags |= INJ_MM_CLEAN_DATA_DIR;
		if (IsChecked(state.hCheckMmResolveImports)) flags |= INJ_MM_RESOLVE_IMPORTS;
		if (IsChecked(state.hCheckMmDelayImports)) flags |= INJ_MM_RESOLVE_DELAY_IMPORTS;
		if (IsChecked(state.hCheckMmExecuteTls)) flags |= INJ_MM_EXECUTE_TLS;
		if (IsChecked(state.hCheckMmEnableEx)) flags |= INJ_MM_ENABLE_EXCEPTIONS;
		if (IsChecked(state.hCheckMmSetPageProt)) flags |= INJ_MM_SET_PAGE_PROTECTIONS;
		if (IsChecked(state.hCheckMmInitCookie)) flags |= INJ_MM_INIT_SECURITY_COOKIE;
		if (IsChecked(state.hCheckMmRunDllMain)) flags |= INJ_MM_RUN_DLL_MAIN;
		if (IsChecked(state.hCheckMmLdrLock)) flags |= INJ_MM_RUN_UNDER_LDR_LOCK;
		if (IsChecked(state.hCheckMmShiftBase)) flags |= INJ_MM_SHIFT_MODULE_BASE;
		if (IsChecked(state.hCheckMmMapMemory)) flags |= INJ_MM_MAP_FROM_MEMORY_FLAG;
		if (IsChecked(state.hCheckMmLinkPeb)) flags |= INJ_MM_LINK_MODULE_FLAG;

		return flags;
	}

	bool WaitForProgress(
		HWND hWnd,
		f_GetDownloadProgressEx getDownloadProgressEx,
		int index,
		bool wow64,
		DWORD timeoutMs,
		const wchar_t * stage)
	{
		const ULONGLONG start = GetTickCount64();
		while (getDownloadProgressEx(index, wow64) < 1.0f)
		{
			if (timeoutMs != 0 && (GetTickCount64() - start) >= timeoutMs)
			{
				std::wstring status = L"Timeout waiting for ";
				status += stage;
				status += L".";
				PostStatus(hWnd, status);
				return false;
			}

			Sleep(25);
		}

		return true;
	}

	bool WaitForState(
		HWND hWnd,
		const wchar_t * stage,
		DWORD inProgressCode,
		DWORD timeoutMs,
		const f_GetSymbolState getState,
		DWORD & outState)
	{
		const ULONGLONG start = GetTickCount64();
		while (true)
		{
			outState = getState();
			if (outState == INJ_ERR_SUCCESS)
			{
				return true;
			}

			if (outState != inProgressCode)
			{
				std::wstring status = L"Failure in ";
				status += stage;
				status += L".";
				PostStatus(hWnd, status);
				return false;
			}

			if (timeoutMs != 0 && (GetTickCount64() - start) >= timeoutMs)
			{
				std::wstring status = L"Timeout while waiting for ";
				status += stage;
				status += L".";
				PostStatus(hWnd, status);
				return false;
			}

			Sleep(25);
		}
	}

	void StartInjectionWorker(
		HWND hWnd,
		const std::wstring processName,
		const DWORD preferredPid,
		const std::wstring dllPath,
		const InjectionSettings settings)
	{
		std::thread([hWnd, processName, preferredPid, dllPath, settings]()
		{
			DWORD resultCode = 0;
			DWORD pid = preferredPid;

			if (pid == 0)
			{
				PostStatus(hWnd, L"Resolving process id...");
				pid = FindPidByProcessName(processName);
			}
			else
			{
				PostStatus(hWnd, L"Using selected process id...");
			}

			if (pid == 0)
			{
				resultCode = ERROR_NOT_FOUND;
				PostStatus(hWnd, L"Process not found.");
				PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
				return;
			}

			PostMessageW(hWnd, WM_APP_SET_PID, static_cast<WPARAM>(pid), 0);

			std::error_code ec;
			if (!std::filesystem::exists(dllPath, ec) || ec)
			{
				resultCode = ERROR_FILE_NOT_FOUND;
				PostStatus(hWnd, L"Payload DLL path is invalid.");
				PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
				return;
			}

			PostStatus(hWnd, L"Loading GH Injector module...");
			HMODULE hInjection = LoadLibraryW(GH_INJ_MOD_NAMEW);
			if (!hInjection)
			{
				resultCode = GetLastError();
				PostStatus(hWnd, L"Could not load GH Injector module.");
				PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
				return;
			}

			const auto InjectW = reinterpret_cast<f_InjectW>(GetProcAddress(hInjection, "InjectW"));
			const auto GetSymbolState = reinterpret_cast<f_GetSymbolState>(GetProcAddress(hInjection, "GetSymbolState"));
			const auto GetImportState = reinterpret_cast<f_GetImportState>(GetProcAddress(hInjection, "GetImportState"));
			const auto StartDownload = reinterpret_cast<f_StartDownload>(GetProcAddress(hInjection, "StartDownload"));
			const auto GetDownloadProgressEx = reinterpret_cast<f_GetDownloadProgressEx>(GetProcAddress(hInjection, "GetDownloadProgressEx"));

			if (!InjectW || !GetSymbolState || !GetImportState || !StartDownload)
			{
				resultCode = ERROR_PROC_NOT_FOUND;
				PostStatus(hWnd, L"Missing required exports in GH Injector module.");
				FreeLibrary(hInjection);
				PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
				return;
			}

			PostStatus(hWnd, L"Starting symbol download...");
			StartDownload();

			if (GetDownloadProgressEx)
			{
				if (!WaitForProgress(hWnd, GetDownloadProgressEx, PDB_DOWNLOAD_INDEX_NTDLL, false, settings.InitTimeoutMs, L"native ntdll symbols"))
				{
					resultCode = WAIT_TIMEOUT;
					FreeLibrary(hInjection);
					PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
					return;
				}

#ifdef _WIN64
				if (!WaitForProgress(hWnd, GetDownloadProgressEx, PDB_DOWNLOAD_INDEX_NTDLL, true, settings.InitTimeoutMs, L"wow64 ntdll symbols"))
				{
					resultCode = WAIT_TIMEOUT;
					FreeLibrary(hInjection);
					PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
					return;
				}
#endif
			}

			DWORD state = 0;
			if (!WaitForState(hWnd, L"symbol initialization", INJ_ERR_SYMBOL_INIT_NOT_DONE, settings.InitTimeoutMs, GetSymbolState, state))
			{
				resultCode = state;
				FreeLibrary(hInjection);
				PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
				return;
			}

			if (!WaitForState(hWnd, L"import initialization", INJ_ERR_IMPORT_HANDLER_NOT_DONE, settings.InitTimeoutMs, GetImportState, state))
			{
				resultCode = state;
				FreeLibrary(hInjection);
				PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
				return;
			}

			if (settings.DelayMs != 0)
			{
				PostStatus(hWnd, L"Delay before injection...");
				Sleep(settings.DelayMs);
			}

			INJECTIONDATAW data{};
			wcsncpy_s(data.szDllPath, dllPath.c_str(), _TRUNCATE);
			data.ProcessID = pid;
			data.Mode = settings.Mode;
			data.Method = settings.Method;
			data.Flags = settings.Flags;
			data.Timeout = settings.InjectTimeoutMs;
			data.hHandleValue = 0;
			data.GenerateErrorLog = settings.GenerateErrorLog;

			PostStatus(hWnd, L"Injecting...");
			resultCode = InjectW(&data);
			if (resultCode == INJ_ERR_SUCCESS)
			{
				PostStatus(hWnd, L"Injection succeeded.");
			}
			else
			{
				PostStatus(hWnd, L"Injection failed.");
			}

			FreeLibrary(hInjection);
			PostMessageW(hWnd, WM_APP_INJECT_DONE, resultCode == INJ_ERR_SUCCESS ? TRUE : FALSE, static_cast<LPARAM>(resultCode));
		}).detach();
	}

	void OpenDllFileDialog(HWND hWndParent, HWND hEditDllPath)
	{
		wchar_t filePath[MAX_PATH * 4] = { 0 };

		OPENFILENAMEW ofn{};
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = hWndParent;
		ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
		ofn.lpstrFile = filePath;
		ofn.nMaxFile = static_cast<DWORD>(sizeof(filePath) / sizeof(filePath[0]));
		ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

		if (GetOpenFileNameW(&ofn))
		{
			SetWindowTextW(hEditDllPath, filePath);
		}
	}

	void InitializeControls(HWND hWnd, AppState & state)
	{
		CreateWindowExW(0, L"STATIC", L"Process Name:", WS_CHILD | WS_VISIBLE,
			16, 16, 110, 22, hWnd, nullptr, nullptr, nullptr);

		state.hComboProcess = CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", L"notepad.exe",
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWN | CBS_AUTOHSCROLL,
			128, 14, 300, 260, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_COMBO_PROCESS)), nullptr, nullptr);

		state.hButtonRefresh = CreateWindowExW(0, L"BUTTON", L"Refresh",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			438, 14, 80, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_BUTTON_REFRESH)), nullptr, nullptr);

		state.hButtonFindPid = CreateWindowExW(0, L"BUTTON", L"Find PID",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			528, 14, 96, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_BUTTON_FIND_PID)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"PID:", WS_CHILD | WS_VISIBLE,
			16, 54, 110, 22, hWnd, nullptr, nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Architecture:", WS_CHILD | WS_VISIBLE,
			280, 54, 90, 22, hWnd, nullptr, nullptr, nullptr);

#ifdef _WIN64
		CreateWindowExW(0, L"STATIC", L"x64", WS_CHILD | WS_VISIBLE,
			374, 54, 40, 22, hWnd, nullptr, nullptr, nullptr);
#else
		CreateWindowExW(0, L"STATIC", L"x86", WS_CHILD | WS_VISIBLE,
			374, 54, 40, 22, hWnd, nullptr, nullptr, nullptr);
#endif

		state.hEditPid = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
			WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
			128, 52, 130, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDIT_PID)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"DLL Path:", WS_CHILD | WS_VISIBLE,
			16, 90, 110, 22, hWnd, nullptr, nullptr, nullptr);

		state.hEditDllPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
			WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
			128, 88, 406, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDIT_DLL_PATH)), nullptr, nullptr);

		state.hButtonBrowse = CreateWindowExW(0, L"BUTTON", L"Browse...",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			544, 88, 80, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_BUTTON_BROWSE_DLL)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Init Timeout (ms):", WS_CHILD | WS_VISIBLE,
			16, 126, 110, 22, hWnd, nullptr, nullptr, nullptr);

		state.hEditInitTimeout = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"180000",
			WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
			128, 124, 110, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDIT_INIT_TIMEOUT)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Delay (ms):", WS_CHILD | WS_VISIBLE,
			250, 126, 80, 22, hWnd, nullptr, nullptr, nullptr);

		state.hEditDelay = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"0",
			WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
			334, 124, 72, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDIT_DELAY)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Timeout (ms):", WS_CHILD | WS_VISIBLE,
			420, 126, 90, 22, hWnd, nullptr, nullptr, nullptr);

		state.hEditTimeout = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"180000",
			WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
			514, 124, 96, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDIT_TIMEOUT)), nullptr, nullptr);

		state.hButtonInject = CreateWindowExW(0, L"BUTTON", L"Inject",
			WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
			620, 122, 80, 28, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_BUTTON_INJECT)), nullptr, nullptr);

		state.hCheckGenerateLog = CreateWindowExW(0, L"BUTTON", L"Generate error log",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			16, 156, 180, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_GENERATE_LOG)), nullptr, nullptr);

		state.hCheckAutoExit = CreateWindowExW(0, L"BUTTON", L"Auto exit",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			210, 156, 120, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_AUTO_EXIT)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Injection Mode:", WS_CHILD | WS_VISIBLE,
			16, 188, 110, 22, hWnd, nullptr, nullptr, nullptr);

		state.hComboMode = CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST,
			128, 186, 190, 180, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_COMBO_MODE)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Launch Method:", WS_CHILD | WS_VISIBLE,
			336, 188, 100, 22, hWnd, nullptr, nullptr, nullptr);

		state.hComboMethod = CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST,
			438, 186, 190, 180, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_COMBO_METHOD)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"PE Header:", WS_CHILD | WS_VISIBLE,
			646, 188, 80, 22, hWnd, nullptr, nullptr, nullptr);

		state.hComboHeader = CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST,
			726, 186, 170, 180, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_COMBO_HEADER)), nullptr, nullptr);

		state.hCheckHijackHandle = CreateWindowExW(0, L"BUTTON", L"Hijack handle",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			16, 218, 150, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_HIJACK_HANDLE)), nullptr, nullptr);

		state.hCheckCloakThread = CreateWindowExW(0, L"BUTTON", L"Cloak thread",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			190, 218, 130, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_CLOAK_THREAD)), nullptr, nullptr);

		state.hCheckRandomDllName = CreateWindowExW(0, L"BUTTON", L"Random file name",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			336, 218, 150, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_RANDOM_DLL_NAME)), nullptr, nullptr);

		state.hCheckLoadDllCopy = CreateWindowExW(0, L"BUTTON", L"Load DLL copy",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			504, 218, 140, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_LOAD_DLL_COPY)), nullptr, nullptr);

		state.hCheckUnlinkPeb = CreateWindowExW(0, L"BUTTON", L"Unlink from PEB",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			662, 218, 140, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_UNLINK_PEB)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Manual Map Options:", WS_CHILD | WS_VISIBLE,
			16, 248, 180, 22, hWnd, nullptr, nullptr, nullptr);

		state.hCheckMmRunDllMain = CreateWindowExW(0, L"BUTTON", L"Run DllMain",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			16, 274, 150, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_RUN_DLLMAIN)), nullptr, nullptr);

		state.hCheckMmLdrLock = CreateWindowExW(0, L"BUTTON", L"Lock loader lock",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			190, 274, 150, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_LDR_LOCK)), nullptr, nullptr);

		state.hCheckMmResolveImports = CreateWindowExW(0, L"BUTTON", L"Resolve imports",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			364, 274, 150, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_RESOLVE_IMPORTS)), nullptr, nullptr);

		state.hCheckMmDelayImports = CreateWindowExW(0, L"BUTTON", L"Resolve delay imports",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			538, 274, 170, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_DELAY_IMPORTS)), nullptr, nullptr);

		state.hCheckMmExecuteTls = CreateWindowExW(0, L"BUTTON", L"Execute TLS",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			732, 274, 130, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_EXECUTE_TLS)), nullptr, nullptr);

		state.hCheckMmMapMemory = CreateWindowExW(0, L"BUTTON", L"Load from memory",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			16, 300, 150, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_MAP_MEMORY)), nullptr, nullptr);

		state.hCheckMmSetPageProt = CreateWindowExW(0, L"BUTTON", L"Set page protections",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			190, 300, 170, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_SET_PAGE_PROT)), nullptr, nullptr);

		state.hCheckMmEnableEx = CreateWindowExW(0, L"BUTTON", L"Enable exceptions",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			364, 300, 150, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_ENABLE_EX)), nullptr, nullptr);

		state.hCheckMmInitCookie = CreateWindowExW(0, L"BUTTON", L"Initialize security cookie",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			538, 300, 194, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_INIT_COOKIE)), nullptr, nullptr);

		state.hCheckMmCleanDir = CreateWindowExW(0, L"BUTTON", L"Clean data directories",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			732, 300, 164, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_CLEAN_DIR)), nullptr, nullptr);

		state.hCheckMmShiftBase = CreateWindowExW(0, L"BUTTON", L"Shift module base",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			16, 326, 150, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_SHIFT_BASE)), nullptr, nullptr);

		state.hCheckMmLinkPeb = CreateWindowExW(0, L"BUTTON", L"Link to PEB",
			WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
			190, 326, 120, 22, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_CHECK_MM_LINK_PEB)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Status:", WS_CHILD | WS_VISIBLE,
			16, 166, 110, 22, hWnd, nullptr, nullptr, nullptr);

		state.hStaticStatus = CreateWindowExW(0, L"STATIC", L"Idle.", WS_CHILD | WS_VISIBLE,
			128, 356, 768, 48, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_STATIC_STATUS)), nullptr, nullptr);

		InitComboOptions(state.hComboMode, MODE_OPTIONS, sizeof(MODE_OPTIONS) / sizeof(MODE_OPTIONS[0]), static_cast<DWORD>(INJECTION_MODE::IM_ManualMap));
		InitComboOptions(state.hComboMethod, METHOD_OPTIONS, sizeof(METHOD_OPTIONS) / sizeof(METHOD_OPTIONS[0]), static_cast<DWORD>(LAUNCH_METHOD::LM_FakeVEH));
		InitComboOptions(state.hComboHeader, HEADER_OPTIONS, sizeof(HEADER_OPTIONS) / sizeof(HEADER_OPTIONS[0]), 0);

		SetChecked(state.hCheckGenerateLog, true);
		SetChecked(state.hCheckAutoExit, false);
		SetChecked(state.hCheckMmRunDllMain, true);
		SetChecked(state.hCheckMmLdrLock, true);
		SetChecked(state.hCheckMmResolveImports, true);
		SetChecked(state.hCheckMmDelayImports, true);
		SetChecked(state.hCheckMmExecuteTls, true);
		SetChecked(state.hCheckMmSetPageProt, true);
		SetChecked(state.hCheckMmEnableEx, true);
		SetChecked(state.hCheckMmInitCookie, true);
		UpdateUiDependencies(state);

		RefreshProcessCombo(state);
	}
}

LRESULT CALLBACK WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	auto * state = reinterpret_cast<AppState *>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));

	switch (message)
	{
	case WM_CREATE:
	{
		auto * appState = new AppState();
		SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(appState));
		InitializeControls(hWnd, *appState);
		return 0;
	}

	case WM_COMMAND:
		if (!state)
		{
			break;
		}

		switch (LOWORD(wParam))
		{
		case ID_COMBO_PROCESS:
			if (HIWORD(wParam) == CBN_SELCHANGE)
			{
				SetPidEdit(state->hEditPid, GetSelectedComboPid(state->hComboProcess));
			}
			return 0;

		case ID_COMBO_MODE:
		case ID_COMBO_METHOD:
			if (HIWORD(wParam) == CBN_SELCHANGE)
			{
				UpdateUiDependencies(*state);
			}
			return 0;

		case ID_CHECK_MM_RUN_DLLMAIN:
		case ID_CHECK_MM_SET_PAGE_PROT:
		case ID_CHECK_CLOAK_THREAD:
			if (HIWORD(wParam) == BN_CLICKED)
			{
				UpdateUiDependencies(*state);
			}
			return 0;

		case ID_BUTTON_REFRESH:
			RefreshProcessCombo(*state);
			SetStatusText(state->hStaticStatus, L"Process list refreshed.");
			return 0;

		case ID_BUTTON_FIND_PID:
		{
			const std::wstring process = GetWindowTextString(state->hComboProcess);
			const DWORD pid = FindPidByProcessName(process);
			if (pid == 0)
			{
				SetPidEdit(state->hEditPid, 0);
				SetStatusText(state->hStaticStatus, L"Process not found.");
				MessageBoxW(hWnd, L"Could not find a running process with that name.", WINDOW_TITLE, MB_ICONWARNING | MB_OK);
			}
			else
			{
				SelectComboItemByPid(state->hComboProcess, pid);
				SetPidEdit(state->hEditPid, pid);
				SetStatusText(state->hStaticStatus, L"Process found.");
			}

			return 0;
		}

		case ID_BUTTON_BROWSE_DLL:
			OpenDllFileDialog(hWnd, state->hEditDllPath);
			return 0;

		case ID_BUTTON_INJECT:
		{
			if (state->Busy)
			{
				return 0;
			}

			const std::wstring process = GetWindowTextString(state->hComboProcess);
			const DWORD selectedPid = GetSelectedComboPid(state->hComboProcess);
			const std::wstring dllPath = GetWindowTextString(state->hEditDllPath);
			const std::wstring initTimeoutText = GetWindowTextString(state->hEditInitTimeout);
			const std::wstring delayText = GetWindowTextString(state->hEditDelay);
			const std::wstring timeoutText = GetWindowTextString(state->hEditTimeout);

			if (process.empty() && selectedPid == 0)
			{
				MessageBoxW(hWnd, L"Please select or enter a process name.", WINDOW_TITLE, MB_ICONWARNING | MB_OK);
				return 0;
			}

			if (dllPath.empty())
			{
				MessageBoxW(hWnd, L"Please select a payload DLL.", WINDOW_TITLE, MB_ICONWARNING | MB_OK);
				return 0;
			}

			InjectionSettings settings{};

			if (!ParseDword(initTimeoutText, settings.InitTimeoutMs))
			{
				MessageBoxW(hWnd, L"Init timeout must be a valid unsigned number.", WINDOW_TITLE, MB_ICONWARNING | MB_OK);
				return 0;
			}

			if (!ParseDword(delayText, settings.DelayMs))
			{
				MessageBoxW(hWnd, L"Delay must be a valid unsigned number.", WINDOW_TITLE, MB_ICONWARNING | MB_OK);
				return 0;
			}

			if (!ParseDword(timeoutText, settings.InjectTimeoutMs))
			{
				MessageBoxW(hWnd, L"Injection timeout must be a valid unsigned number.", WINDOW_TITLE, MB_ICONWARNING | MB_OK);
				return 0;
			}

			if (settings.InitTimeoutMs == 0)
			{
				settings.InitTimeoutMs = DEFAULT_INIT_TIMEOUT_MS;
			}

			if (settings.InjectTimeoutMs == 0)
			{
				settings.InjectTimeoutMs = DEFAULT_INJECTION_TIMEOUT_MS;
			}

			settings.Mode = static_cast<INJECTION_MODE>(GetSelectedComboValue(state->hComboMode, static_cast<DWORD>(INJECTION_MODE::IM_LoadLibraryExW)));
			settings.Method = static_cast<LAUNCH_METHOD>(GetSelectedComboValue(state->hComboMethod, static_cast<DWORD>(LAUNCH_METHOD::LM_NtCreateThreadEx)));
			settings.Flags = BuildFlagsFromUi(*state);
			settings.GenerateErrorLog = IsChecked(state->hCheckGenerateLog);
			settings.AutoExit = IsChecked(state->hCheckAutoExit);

			state->Busy = true;
			EnableActionButtons(*state, false);
			SetStatusText(state->hStaticStatus, L"Starting...");

			StartInjectionWorker(hWnd, process, selectedPid, dllPath, settings);
			return 0;
		}

		default:
			break;
		}
		break;

	case WM_APP_SET_STATUS:
	{
		auto * status = reinterpret_cast<std::wstring *>(lParam);
		if (state && status)
		{
			SetStatusText(state->hStaticStatus, *status);
		}

		delete status;
		return 0;
	}

	case WM_APP_SET_PID:
		if (state)
		{
			SetPidEdit(state->hEditPid, static_cast<DWORD>(wParam));
		}
		return 0;

	case WM_APP_INJECT_DONE:
		if (state)
		{
			state->Busy = false;
			EnableActionButtons(*state, true);
			UpdateUiDependencies(*state);

			const DWORD code = static_cast<DWORD>(lParam);
			if (wParam == TRUE)
			{
				MessageBoxW(hWnd, L"Injection completed successfully.", WINDOW_TITLE, MB_ICONINFORMATION | MB_OK);

				if (IsChecked(state->hCheckAutoExit))
				{
					PostMessageW(hWnd, WM_CLOSE, 0, 0);
				}
			}
			else
			{
				wchar_t messageText[256] = { 0 };
				_snwprintf_s(
					messageText,
					_TRUNCATE,
					L"Injection failed. Error code: 0x%08lX\n\nIf generated, check GH_Inj_Log.txt.",
					static_cast<unsigned long>(code)
				);
				MessageBoxW(hWnd, messageText, WINDOW_TITLE, MB_ICONERROR | MB_OK);
			}
		}
		return 0;

	case WM_DESTROY:
		if (state)
		{
			SetWindowLongPtrW(hWnd, GWLP_USERDATA, 0);
			delete state;
		}

		PostQuitMessage(0);
		return 0;

	default:
		break;
	}

	return DefWindowProcW(hWnd, message, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow)
{
	WNDCLASSW wc{};
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = hInstance;
	wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	wc.lpszClassName = WINDOW_CLASS_NAME;

	if (!RegisterClassW(&wc))
	{
		return 1;
	}

	HWND hWnd = CreateWindowExW(
		0,
		WINDOW_CLASS_NAME,
		WINDOW_TITLE,
		WS_OVERLAPPED | WS_SYSMENU | WS_MINIMIZEBOX | WS_CAPTION,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		940,
		470,
		nullptr,
		nullptr,
		hInstance,
		nullptr
	);

	if (!hWnd)
	{
		return 1;
	}

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	MSG msg{};
	while (GetMessageW(&msg, nullptr, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}

	return static_cast<int>(msg.wParam);
}
