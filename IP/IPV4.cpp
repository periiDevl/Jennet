#include "IPV4.h"
bytes_2 IPV4::checksum(){
    bytes_4 sum;

}
bytes_2 calculateChecksum(bytes_2* data, size_t length) {
    bytes_4 sum = 0;
    for (; length > 1; length -= 2)
        sum += *data++;
    if (length == 1)
        sum += *(byte*)data;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~((bytes_2)sum);
}