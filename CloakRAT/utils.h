#pragma once

#include <iostream>
#include "string_encryption.h"

// Execute some process
std::string exec(EncryptedString &cmd_string, std::string command);

bool isDebuggerAttached();
