#include <stdio.h>
#include <Windows.h>
#include <strsafe.h>
#include <conio.h>


DWORD TypeParametr = 0;
HKEY AntiMalware_Dir = 0;

int Check_KeyWindowsDefender(const char *KeyName, DWORD ValueSet) {
	DWORD SizeValue = sizeof(DWORD);
	DWORD ValueParametr = 0;
	
	LONG CodeRead = RegGetValue(AntiMalware_Dir, 0, KeyName, RRF_RT_REG_DWORD, &TypeParametr, &ValueParametr, &SizeValue);
	
	printf("\r\n\r\n");
	if (! CodeRead) {
		printf("[Value %s : %ld]\r\n", KeyName, ValueParametr);
			
		LSTATUS KeyName_SetValue = RegSetKeyValueA(AntiMalware_Dir, 0, KeyName, REG_DWORD, &ValueSet, SizeValue);
		
		switch (KeyName_SetValue) {
			case 5:
				return 5;
					
			case 0:
				printf("[Set value %s : %ld]\r\n", KeyName, ValueSet);
				return 1;
		}
	}
	
	else {
		LSTATUS _Create_KeyWin = RegSetValueEx(AntiMalware_Dir, KeyName, 0, REG_DWORD, (const BYTE *) &ValueSet, SizeValue);
		
		if (_Create_KeyWin == ERROR_SUCCESS) {
			printf("[Create %s : %ld]\r\n", KeyName, ValueSet);
		}
		
		return 1;
	}
	
	return 0;
}


int main(void) {
	system("color a");
	system("cls");
	
	LONG DescMalware = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\0", 0, KEY_ALL_ACCESS, &AntiMalware_Dir);
	
	if (DescMalware == ERROR_SUCCESS) {
		printf("[Opened SOFTWARE\\Policies\\Microsoft\\Windows Defender]\r\n");
		
		if (Check_KeyWindowsDefender("AllowFastServiceStartup\0", 0) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
			return 5;
		}
		
		if (Check_KeyWindowsDefender("ServiceKeepAlive\0", 0) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
			return 5;
		}
		
		if (Check_KeyWindowsDefender("DisableAntiSpyware\0", 1) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
			return 5;
		}
		
	}
	
	else {
		printf("[ERROR OPENED SOFTWARE\\Policies\\Microsoft\\Windows Defender\r\n");
		return 1;
	}
	
	
	
	HKEY MalwareOther_SUB = 0;
	
	LSTATUS _DescMalware = RegCreateKeyEx(AntiMalware_Dir, "Real-Time Protection\0", 0, 0, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_ALL_ACCESS, 0, &MalwareOther_SUB, 0);
	if (_DescMalware == ERROR_SUCCESS) {
		printf("\r\n[Create Real-Time Protection dir]\r\n");
	}
	
	else {
		printf("\r\n[ERROR CREATE REAL-TIME PROTECTION DIR]\r\n");
		getch();
		
		return 1;
	}
	
	RegCloseKey(MalwareOther_SUB);
	RegCloseKey(AntiMalware_Dir);
	
	DescMalware = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\0", 0, KEY_ALL_ACCESS, &AntiMalware_Dir);
	
	if (DescMalware == ERROR_SUCCESS) {
		printf("[Opened HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection]\r\n");
		
		if (Check_KeyWindowsDefender("DisableOAVProtection\0", 1) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
		
		if (Check_KeyWindowsDefender("DisableRealtimeMonitoring\0", 1) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
		
		if (Check_KeyWindowsDefender("DisableBehaviorMonitoring\0", 1) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
		
		if (Check_KeyWindowsDefender("DisableOnAccessProtection\0", 1) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
		
		if (Check_KeyWindowsDefender("DisableScanOnRealtimeProtection\0", 1) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
	}
	
	else {
		printf("[ERROR OPENED HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection]\r\n\r\n");
	}
	
	RegCloseKey(MalwareOther_SUB);
	RegCloseKey(AntiMalware_Dir);
	
	
	
	
	LONG StartSUB_Malware = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\0", 0, KEY_ALL_ACCESS, &AntiMalware_Dir);
	
	if (StartSUB_Malware == ERROR_SUCCESS) {
		DescMalware = RegCreateKeyEx(AntiMalware_Dir, "Spynet\0", 0, 0, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_ALL_ACCESS, 0, &MalwareOther_SUB, 0);
		if (DescMalware == ERROR_SUCCESS) {
			printf("\r\n[Create Spynet dir]\r\n");
		}
	
		else {
			printf("\r\n[ERROR CREATE SPYNET DIR]\r\n");
			getch();
			
			return 1;
		}
	}
	
	RegCloseKey(MalwareOther_SUB);
	RegCloseKey(AntiMalware_Dir);
	
	StartSUB_Malware = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\0", 0, KEY_ALL_ACCESS, &AntiMalware_Dir);
	
	if (StartSUB_Malware == ERROR_SUCCESS) {
		printf("[Opened HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet]\r\n");
		
		if (Check_KeyWindowsDefender("DisableBlockAtFirstSeen\0", 1) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
		
		if (Check_KeyWindowsDefender("LocalSettingOverrideSpynetReporting\0", 0) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
		
		if (Check_KeyWindowsDefender("SubmitSamplesConsent\0", 2) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
	}
	
	RegCloseKey(AntiMalware_Dir);
	
	DescMalware = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WinDefend\0", 0, KEY_ALL_ACCESS, &AntiMalware_Dir);
	
	if (DescMalware == ERROR_SUCCESS) {
		printf("\r\n[Opened SYSTEM\\CurrentControlSet\\Services\\WinDefend]\r\n");
		
		if (Check_KeyWindowsDefender("Start\0", 4) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
	}
	
	RegCloseKey(AntiMalware_Dir);
	
	DescMalware = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\MDCoreSvc\0", 0, KEY_ALL_ACCESS, &AntiMalware_Dir);
	
	if (DescMalware == ERROR_SUCCESS) {
		printf("\r\n[Opened SYSTEM\\CurrentControlSet\\Services\\MDCoreSvc]\r\n");
		
		if (Check_KeyWindowsDefender("Start\0", 4) == 5) {
			printf("\r\n\r\n----------------------------------------------------\r\n[[ACCESS_DENIED]]\r\n----------------------------------------------------\r\n");
		}
	}
	
	
	printf("\r\n\r\n-------------------------\r\n[[COMPLETED]]\r\n-------------------------\r\n\r\n");
	getch();
	return 0;
}