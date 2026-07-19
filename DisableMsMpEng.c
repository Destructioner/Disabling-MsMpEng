#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <conio.h>

#define _ACCESS_DENIED_ "[ADMIN PRIVILEGES REQUIRED!!!]\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n"

LSTATUS vault_createkey_dword(const char *key_name, DWORD value_set) {
	HKEY key_regedit;
	
	size_t length_str_key_path = strlen(key_name);
	size_t length_str_key = 0;
	
	for (; key_name[length_str_key] != '\\'; ++length_str_key);
	++length_str_key;
	
	if (strstr(key_name, "HKEY_CURRENT_USER") != NULL) {
		key_regedit = HKEY_CURRENT_USER;
	}
	
	else if (strstr(key_name, "HKEY_LOCAL_MACHINE") != NULL) {
		key_regedit = HKEY_LOCAL_MACHINE;
	}
	
	else if (strstr(key_name, "HKEY_CLASSES_ROOT") != NULL) {
		key_regedit = HKEY_CLASSES_ROOT;
	}
	
	else if (strstr(key_name, "HKEY_USERS") != NULL) {
		key_regedit = HKEY_USERS;
	}
	
	char temp_path[256] = {0};
	char temp_name_key[256] = {0};
	
	memset(temp_path, 0, 256);
	memset(temp_name_key, 0, 256);
	
	for (; key_name[length_str_key_path] != '\\'; --length_str_key_path);
	
	strncpy(temp_path, key_name + length_str_key, length_str_key_path - length_str_key);
	++length_str_key_path;
	
	strcpy(temp_name_key, key_name + length_str_key_path);
	

	return RegSetKeyValue(key_regedit, temp_path, temp_name_key, REG_DWORD, &value_set, sizeof(DWORD));
}



const char *regedit_params[] = {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\AllowFastServiceStartup\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\ServiceKeepAlive\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableOAVProtection\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableOnAccessProtection\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableScanOnRealtimeProtection\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\\DisableBlockAtFirstSeen\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\\LocalSettingOverrideSpynetReporting\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\\SubmitSamplesConsent\0", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\\Start\0", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MDCoreSvc\\Start\0", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\SaveZoneInformation\0", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\EnableSmartScreen\0"};
DWORD value_param[] = {0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 2, 4, 4, 1, 0};

int main(void) {
	system("color a");
	system("cls");
	
	size_t size_params = sizeof(regedit_params) / sizeof(*regedit_params);
	
	for (size_t iter_param = 0; iter_param < size_params; ++iter_param) {
		printf("[Set value %ld %s]\r\n", value_param[iter_param], regedit_params[iter_param]);
		
		if (vault_createkey_dword(regedit_params[iter_param], value_param[iter_param]) == ERROR_ACCESS_DENIED) {
			printf(_ACCESS_DENIED_);
			getch();
		}
	}
	
	
	printf("\r\n\r\n-------------------------\r\n[[COMPLETED]]\r\n-------------------------\r\n\r\n");
	getch();
	return 0;
}
