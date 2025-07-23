#include "IPV4.h"

bytes_2 IPV4::checksum() {
    bytes_4 sum = 0;
    bytes_2* ptr = reinterpret_cast<bytes_2*>(&header);
    size_t length = sizeof(header); 
    while (length > 1) {
        sum += *ptr;
        ptr = (bytes_2*)((byte*)ptr + 2);
        length -= 2;
    }
    if (length == 1) {
        sum += *(byte*)ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~((bytes_2)sum);
}
