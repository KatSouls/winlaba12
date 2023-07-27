#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include "accctrl.h"
#include "aclapi.h"
#include <iostream>
#pragma comment(lib, "advapi32.lib")

int main(void)
{
    setlocale(0, "ru");
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;


    // Получает дескриптор объекта file.
    hFile = CreateFile(
        TEXT("text.txt"),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    // Проверяет GetLastError на наличие кода ошибки CreateFile.
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("CreateFile error = %d\n"), dwErrorCode);
        return -1;
    }



    //Получает (SID) идентификатор владельца файла.
    dwRtnCode = GetSecurityInfo(            //Если функция завершается успешно, возвращаемое значение ERROR_SUCCESS.
                                            //Если функция завершается ошибкой, возвращаемое значение является ненулевым кодом ошибки, определенным в WinError.h.
        hFile,                              // Дескриптор объекта, из которого извлекаются сведения о безопасности
        SE_FILE_OBJECT,                     // SE_OBJECT_TYPE значение перечисления, указывающее тип объекта.
        OWNER_SECURITY_INFORMATION,         // Набор битовых флагов, указывающий тип извлекаемых сведений о безопасности. 
                                            // Этот параметр может быть сочетанием битовых флагов SECURITY_INFORMATION.
        &pSidOwner,                         // Указатель на переменную, которая получает указатель на идентификатор безопасности
                                            // владельца в дескриптооре безопасности, возвращенном в &pSD.
        NULL,                               // Указатель на переменную, которая получает указатель на идентификатор безопасности основной группы
                                            // в возвращенном дескриптооре безопасности.
        NULL,                               // Указатель на переменную, которая получает указатель на DACL в возвращенном дескриптооре безопасности.
        NULL,                               // Указатель на переменную, которая получает указатель на SACL в возвращенном дескриптооре безопасности.
        &pSD);                              // Указатель на переменную, которая получает указатель на дескриптор безопасности объекта.

    // Проверяет GetLastError на наличие ошибки GetSecurityInfo.
    if (dwRtnCode != ERROR_SUCCESS) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("GetSecurityInfo error = %d\n"), dwErrorCode);
        return -1;
    }

    // Первый вызов LookupAccountSid для получения размеров буфера.

    bRtnBool = LookupAccountSid(           // LookupAccountSid - извлекает имя учетной записи, соответствующее указанному идентификатору безопасности.
        NULL,                              // имя компьютера
        pSidOwner,                         // указатель на SID
        AcctName,                          // имя учетной записи
        (LPDWORD)&dwAcctName,              // длина имени учетной записи
        DomainName,                        // имя домена
        (LPDWORD)&dwDomainName,            // длина имени домена
        &eUse);                            // тип SID

    // Перераспределяет память для буферов.
    AcctName = (LPTSTR)GlobalAlloc(
        GMEM_FIXED,
        dwAcctName);

    // Проверяет GetLastError на наличие ошибки GlobalAlloc.
    if (AcctName == NULL) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
        return -1;
    }

    DomainName = (LPTSTR)GlobalAlloc(
        GMEM_FIXED,
        dwDomainName);

    // Проверяет GetLastError на наличие ошибки GlobalAlloc.
    if (DomainName == NULL) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
        return -1;

    }

    // Второй вызов LookupAccountSid для получения имени учетной записи.
    bRtnBool = LookupAccountSid(
        NULL,                   // имя локального или удаленного компьютера
        pSidOwner,              // идентификатор безопасности
        AcctName,               // буфер имен учетных записей
        (LPDWORD)&dwAcctName,   // размер буфера имени учетной записи
        DomainName,             // доменное имя
        (LPDWORD)&dwDomainName, // размер буфера доменных имен
        &eUse);                 // Тип SID

// Проверяет GetLastError на наличие условия ошибки LookupAccountSid.
    if (bRtnBool == FALSE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();

        if (dwErrorCode == ERROR_NONE_MAPPED)
            _tprintf(TEXT
            ("Account owner not found for specified SID.\n"));
        else
            _tprintf(TEXT("Error in LookupAccountSid.\n"));
        return -1;

    }
    else if (bRtnBool == TRUE)

        // Выводит имя учетной записи.
        _tprintf(TEXT("Account owner = %s\n"), AcctName);

    return 0;
}/*
S-1-1-0 Группа, включающая всех пользователей
S-1-2-0 Пользователи, которые входят в терминалы, подключенные к системе локально (физически).
S-1-5-2 Группа, включающая всех пользователей, выполнивших вход через сетевое подключение.
S-1-5-32-544 Встроенная группа. После первоначальной установки операционной системы единственным
членом группы является учетная запись администратора
S-1-5-32-546  Встроенная группа. По умолчанию единственным членом является гостевая учетная запись.
Группа гостей позволяет случайным или одноразовым пользователям входить с ограниченными привилегиями
во встроенную гостевую учетную запись компьютера.
*/