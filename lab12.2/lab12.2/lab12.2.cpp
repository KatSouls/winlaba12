
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>


using namespace std;
// Идентификатор процесса (PID) - уникальный номер процесса в многозадачной ОС. В Windows PID хранится в пермеенной целочисленного типа

int GetProcesByName(wstring name)
{
	//Создает моментальный снимок указанных процессов, а также куч, модулей и потоков, используемых этими процессами.
	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);    // TH32CS_SNAPPROCESS - Включает все процессы в системе в моментальном снимке, 
																		  //Идентификатор процесса, который будет включен в моментальный снимок. 
																		  //Этот параметр может быть равен нулю, чтобы указать текущий процесс.

	//Описывает запись из списка процессов, находящихся в адресном пространстве системы при создании моментального снимка.
	PROCESSENTRY32 pInfo = { 0 }; pInfo.dwSize = sizeof(PROCESSENTRY32);
	while (Process32Next(snapShot, &pInfo))
	{//Извлекает сведения о следующем процессе, записанном в системном моментальном снимке.
		//snapShot - Дескриптор моментального снимка, возвращенный из предыдущего вызова функции
		//&pInfo - Указатель на структуру PROCESSENTRY32 .
		if (pInfo.szExeFile == name)
		{
			CloseHandle(snapShot);
			return pInfo.th32ProcessID;
		}
	}
	CloseHandle(snapShot);
	return 0;
}


int main() {

	int pID = GetProcesByName(L"Telegram.exe");    //название окнаа на английском, потому что идём через функцию, что ищет процесс по имени
	cout << pID;
	return 0;
}