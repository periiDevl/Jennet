
#pragma once
#include"Defng.h"
#include"Packet.h"
#include"InternetUtils.h"
template <typename HeaderType>
class Protocol
{
protected:
    virtual bytes_2 internetChecksum(const void* data, size_t length){
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
    virtual bytes_2 internetChecksumTCP(const void* data, size_t length){
        bytes_4 sum = 0;
        const bytes_2* ptr = reinterpret_cast<const bytes_2*>(data);
        
        while (length > 1) {
            sum += convertToBigEndian16(*ptr);
            ptr++;
            length -= 2;
        }

        if (length == 1) {
            sum += (*(reinterpret_cast<const byte*>(ptr))) << 8;
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return ~static_cast<bytes_2>(sum);
    }
    virtual void applyChecksum(){
        std::cout << "PROTOCOL CLASS DOES NOT HAVE CHECKSUM";}
public:
    HeaderType* header = nullptr;

    void include(Packet& packet)
    {
        header = reinterpret_cast<HeaderType*>(packet.packet + packet.getReserve());
        //packet.reserve(sizeof(HeaderType));
    }
    Protocol(){};
    ~Protocol(){};
};
