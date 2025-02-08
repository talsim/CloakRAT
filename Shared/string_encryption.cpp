
// We will encrypt with a XOR key at compile-time
// At runtime, we will introduce a dynamic key that will be mixed with the compile-time base key, to derive a new key - the effective XOR key.
// Then we will re-encrypt the strings on program startup (maybe in the tls callback) or before usage (havent really decided yet) using the effective key.


constexpr char BASE_KEY[] = {0xFF, 0x46, 0x81, 0xCC, 0xCE};  // computeBaseKey();