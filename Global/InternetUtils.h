#pragma once
#include<iostream>
#include"Defng.h"
bool isMachineBigEndian()
{
    const bytes_2 num = 1; //00000001 (on big endian)
    const byte* ptr = reinterpret_cast< const byte*>(&num);
    if (ptr[0] == 0) {
        return true;
    }
    return false;
}
bytes_2 convertToBigEndian(bytes_2 value){
    if (!isMachineBigEndian()){
        return (value >> 8) | (value << 8);//Litte endian to big endian convert by switching the bytes placement then combining
    }
    return value;
}
bytes_2 switchbo16(bytes_2 value){ //Switch byte order
    return (value >> 8) | (value << 8);
}
bytes_4 switchbo32(bytes_4 value){ //Switch byte order 32
        return  ((value & 0x000000FF) << 24) | 
            ((value & 0x0000FF00) << 8)  | 
            ((value & 0x00FF0000) >> 8)  | 
            ((value & 0xFF000000) >> 24);
} //Im using the masks to extract the bytes
bytes_4 v4addr(std::string ip) {
    bytes_4 addressInBytes = 0;
    byte* pointer = reinterpret_cast<byte*>(&addressInBytes);
    std::string sectionString;

    for (size_t i = 0; i <= ip.length(); i++) {
        if (i == ip.length() || ip[i] == '.') {
            *pointer = static_cast<byte>(std::stoi(sectionString));
            pointer++;
            sectionString.clear();
        } else {
            sectionString += ip[i];
        }
    }

    return isMachineBigEndian() ? switchbo32(addressInBytes)  : addressInBytes;
}