#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "Defng.h"

inline bool isMachineBigEndian() {
    const uint32_t num = 0x00000001;
    return (*((const uint8_t*)&num) == 0x00);
}


inline bytes_2 switchByteOrder16(bytes_2 value) {
    return (value << 8) | (value >> 8);
}

inline bytes_4 switchByteOrder32(bytes_4 value) {
    return ((value >> 24) & 0x000000FF) |
           ((value >> 8)  & 0x0000FF00) |
           ((value << 8)  & 0x00FF0000) |
           ((value << 24) & 0xFF000000);
}


inline bytes_2 convertToBigEndian16(bytes_2 value) {
    if (isMachineBigEndian()) {
        return value;
    }
    return switchByteOrder16(value);
}

inline bytes_4 convertToBigEndian32(bytes_4 value) {
    if (isMachineBigEndian()) {
        return value;
    }
    return switchByteOrder32(value);
}
inline bytes_2 netToHost16(bytes_2 value){
    if (isMachineBigEndian()){return value;}
    else {return switchByteOrder16(value);}
}
inline bytes_4 netToHost31(bytes_4 value){
    if (isMachineBigEndian()){return value;}
    else {return switchByteOrder32(value);}
}
inline bytes_4 v4addr(const std::string& ip) {
    bytes_4 addressInBytes = 0;
    std::string sectionString;
    size_t start = 0;
    

    for (int i = 0; i < 4; ++i) {
        size_t end = ip.find('.', start);
        if (end == std::string::npos) {
            end = ip.length();
        }
        sectionString = ip.substr(start, end - start);
        bytes_4 octet = static_cast<bytes_4>(std::stoi(sectionString));
        
        addressInBytes |= (octet << (24 - i * 8));

        start = end + 1;
        if (start > ip.length()) {
            break;
        }
    }

    return addressInBytes;
}
inline std::string bArrayToString(const uint8_t arr[], size_t size) {
    std::string result;
    for (size_t i = 0; i < size; i++) {
        result += std::to_string(arr[i]);
    }
    return result;
}
inline std::string bArrayToIPv4String(const uint8_t arr[4]) {
    return std::to_string(arr[0]) + "." +
           std::to_string(arr[1]) + "." +
           std::to_string(arr[2]) + "." +
           std::to_string(arr[3]);
}
