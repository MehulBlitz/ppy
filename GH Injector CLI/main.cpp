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

	struct AppState
	{
		HWND hComboProcess = nullptr;
		HWND hEditPid = nullptr;
		HWND hEditDllPath = nullptr;
		HWND hEditTimeout = nullptr;
		HWND hButtonRefresh = nullptr;
		HWND hButtonFindPid = nullptr;
		HWND hButtonBrowse = nullptr;
		HWND hButtonInject = nullptr;
		HWND hStaticStatus = nullptr;
		bool Busy = false;
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
		EnableWindow(state.hComboProcess, enabled ? TRUE : FALSE);
		EnableWindow(state.hButtonRefresh, enabled ? TRUE : FALSE);
		EnableWindow(state.hButtonFindPid, enabled ? TRUE : FALSE);
		EnableWindow(state.hButtonBrowse, enabled ? TRUE : FALSE);
		EnableWindow(state.hButtonInject, enabled ? TRUE : FALSE);
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
		const DWORD initTimeoutMs)
	{
		std::thread([hWnd, processName, preferredPid, dllPath, initTimeoutMs]()
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
				if (!WaitForProgress(hWnd, GetDownloadProgressEx, PDB_DOWNLOAD_INDEX_NTDLL, false, initTimeoutMs, L"native ntdll symbols"))
				{
					resultCode = WAIT_TIMEOUT;
					FreeLibrary(hInjection);
					PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
					return;
				}

#ifdef _WIN64
				if (!WaitForProgress(hWnd, GetDownloadProgressEx, PDB_DOWNLOAD_INDEX_NTDLL, true, initTimeoutMs, L"wow64 ntdll symbols"))
				{
					resultCode = WAIT_TIMEOUT;
					FreeLibrary(hInjection);
					PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
					return;
				}
#endif
			}

			DWORD state = 0;
			if (!WaitForState(hWnd, L"symbol initialization", INJ_ERR_SYMBOL_INIT_NOT_DONE, initTimeoutMs, GetSymbolState, state))
			{
				resultCode = state;
				FreeLibrary(hInjection);
				PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
				return;
			}

			if (!WaitForState(hWnd, L"import initialization", INJ_ERR_IMPORT_HANDLER_NOT_DONE, initTimeoutMs, GetImportState, state))
			{
				resultCode = state;
				FreeLibrary(hInjection);
				PostMessageW(hWnd, WM_APP_INJECT_DONE, FALSE, static_cast<LPARAM>(resultCode));
				return;
			}

			INJECTIONDATAW data{};
			wcsncpy_s(data.szDllPath, dllPath.c_str(), _TRUNCATE);
			data.ProcessID = pid;
			data.Mode = INJECTION_MODE::IM_LoadLibraryExW;
			data.Method = LAUNCH_METHOD::LM_NtCreateThreadEx;
			data.Flags = 0;
			data.Timeout = DEFAULT_INJECTION_TIMEOUT_MS;
			data.hHandleValue = 0;
			data.GenerateErrorLog = true;

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

		state.hEditTimeout = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"180000",
			WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
			128, 124, 110, 24, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDIT_TIMEOUT)), nullptr, nullptr);

		state.hButtonInject = CreateWindowExW(0, L"BUTTON", L"Inject",
			WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
			544, 122, 80, 28, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_BUTTON_INJECT)), nullptr, nullptr);

		CreateWindowExW(0, L"STATIC", L"Status:", WS_CHILD | WS_VISIBLE,
			16, 166, 110, 22, hWnd, nullptr, nullptr, nullptr);

		state.hStaticStatus = CreateWindowExW(0, L"STATIC", L"Idle.", WS_CHILD | WS_VISIBLE,
			128, 166, 496, 48, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_STATIC_STATUS)), nullptr, nullptr);

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

			DWORD timeoutMs = 0;
			if (!ParseDword(timeoutText, timeoutMs))
			{
				MessageBoxW(hWnd, L"Init timeout must be a valid unsigned number.", WINDOW_TITLE, MB_ICONWARNING | MB_OK);
				return 0;
			}

			if (timeoutMs == 0)
			{
				timeoutMs = DEFAULT_INIT_TIMEOUT_MS;
			}

			state->Busy = true;
			EnableActionButtons(*state, false);
			SetStatusText(state->hStaticStatus, L"Starting...");

			StartInjectionWorker(hWnd, process, selectedPid, dllPath, timeoutMs);
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

			const DWORD code = static_cast<DWORD>(lParam);
			if (wParam == TRUE)
			{
				MessageBoxW(hWnd, L"Injection completed successfully.", WINDOW_TITLE, MB_ICONINFORMATION | MB_OK);
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
		660,
		280,
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
