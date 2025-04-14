#pragma once

#include <iostream>
#include "byte_encryption.h"

// Execute some process
std::string exec(EncryptedBytes &cmd_string, std::string command);

bool isDebuggerAttached();
