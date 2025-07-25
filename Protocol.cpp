#include"Protocol.h"
#include"cassert"

Protocol::Protocol() {
}

Protocol::~Protocol() {
}
void Protocol::applyChecksum() {
    std::cout << "PROTOCOL CLASS DOES NOT HAVE A CHECKSUM FUNCTION" << std::endl;
}


bytes_2 Protocol::internetChecksum(const void* data, size_t length) {
    bytes_4 sum = 0;
    const bytes_2* ptr = reinterpret_cast<const bytes_2*>(data);

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1) {
        sum += *(reinterpret_cast<const byte*>(ptr));
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~static_cast<bytes_2>(sum);
}
