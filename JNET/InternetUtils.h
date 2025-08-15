#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "Defng.h" // Assuming this defines bytes_2 and bytes_4

// 1. Endianness Detection (More robust)
bool isMachineBigEndian() {
    const uint32_t num = 0x00000001;
    return (*((const uint8_t*)&num) == 0x00);
}

// 2. Universal byte-swapping functions
//    These functions unconditionally swap the byte order.
//    They are used as building blocks for the `convertTo...` functions.
inline bytes_2 switchByteOrder16(bytes_2 value) {
    return (value << 8) | (value >> 8);
}

inline bytes_4 switchByteOrder32(bytes_4 value) {
    return ((value >> 24) & 0x000000FF) |
           ((value >> 8)  & 0x0000FF00) |
           ((value << 8)  & 0x00FF0000) |
           ((value << 24) & 0xFF000000);
}

// 3. Host-to-Network byte order conversion functions
//    These check for endianness and only swap if necessary.
inline bytes_2 convertToBigEndian16(bytes_2 value) {
    if (isMachineBigEndian()) {
        return value; // Already big-endian
    }
    return switchByteOrder16(value); // Convert from little-endian
}

inline bytes_4 convertToBigEndian32(bytes_4 value) {
    if (isMachineBigEndian()) {
        return value; // Already big-endian
    }
    return switchByteOrder32(value); // Convert from little-endian
}

// 4. Robust IP Address Parser
//    This is a more reliable way to parse an IP string into a 32-bit
//    integer in network byte order, independent of host endianness.
bytes_4 v4addr(const std::string& ip) {
    bytes_4 addressInBytes = 0;
    std::string sectionString;
    size_t start = 0;
    
    // Parse the 4 octets
    for (int i = 0; i < 4; ++i) {
        size_t end = ip.find('.', start);
        if (end == std::string::npos) {
            end = ip.length();
        }
        sectionString = ip.substr(start, end - start);
        bytes_4 octet = static_cast<bytes_4>(std::stoi(sectionString));
        
        // Assemble the octets into a 32-bit integer in network byte order.
        addressInBytes |= (octet << (24 - i * 8));

        start = end + 1;
        if (start > ip.length()) {
            break;
        }
    }

    return addressInBytes;
}